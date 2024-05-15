use crate::engine::leaf_operations::{bool_block, i64_to_ordered_u64, int_blocks, str_to_big_uint};
use crate::engine::table_selection::EncClearCell;
use crate::Cell;
use rayon::prelude::*;
use tfhe::integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext, ServerKey};

pub mod enc_query;
pub mod leaf_operations;
pub mod table;
pub mod table_selection;

fn bools_into_radix(bools: Vec<BooleanBlock>, sk: &ServerKey) -> RadixCiphertext {
    let block_vec: Vec<_> = bools
        .into_iter()
        .map(|bool| bool.into_radix::<RadixCiphertext>(1, sk).into_blocks()[0].clone())
        .collect();
    RadixCiphertext::from(block_vec)
}

pub fn distinct(
    rows: &[Vec<Cell>],
    selected_columns: &[BooleanBlock],
    selected_rows: &[BooleanBlock],
    sk: &ServerKey,
) -> Vec<BooleanBlock> {
    // Processing each row in parallel to determine its uniqueness
    let is_unique_bools: Vec<_> = (0..rows.len())
        .into_par_iter()
        .map(|i| {
            // First row always considered unique, next equal rows will not
            if i == 0 {
                return sk.create_trivial_boolean_block(true);
            }
            // Compare current row i with all preceding rows (j)
            let matches: Vec<_> = (0..i)
                .into_par_iter()
                .map(|j| {
                    selected_rows_eq(
                        (&rows[j], &selected_rows[j]),
                        (&rows[i], &selected_rows[i]),
                        selected_columns,
                        sk,
                    )
                })
                .collect();

            // Convert all the bools into a single RadixCiphertext: This number will be 0 if there were
            // no equal preceding rows (all false) or non-zero if there was any (at least one true)
            sk.scalar_eq_parallelized(&bools_into_radix(matches, sk), 0)
        })
        .collect();

    selected_rows
        .par_iter()
        .zip(is_unique_bools)
        .map(|(selected_row, is_unique)| sk.boolean_bitand(selected_row, &is_unique))
        .collect()
}

pub fn distinct_enc(
    rows: &[Vec<EncClearCell>],
    selected_columns: &[BooleanBlock],
    selected_rows: &[BooleanBlock],
    sk: &ServerKey,
) -> Vec<BooleanBlock> {
    // Processing each row in parallel to determine its uniqueness
    let is_unique_bools: Vec<_> = (0..rows.len())
        .into_par_iter()
        .map(|i| {
            // First row always considered unique, next equal rows will not
            if i == 0 {
                return sk.create_trivial_boolean_block(true);
            }
            // Compare current row i with all preceding rows (j)
            let matches: Vec<_> = (0..i)
                .into_par_iter()
                .map(|j| {
                    selected_rows_eq_enc(
                        (&rows[j], &selected_rows[j]),
                        (&rows[i], &selected_rows[i]),
                        selected_columns,
                        sk,
                    )
                })
                .collect();

            // Convert all the bools into a single RadixCiphertext: This number will be 0 if there were
            // no equal preceding rows (all false) or non-zero if there was any (at least one true)
            sk.scalar_eq_parallelized(&bools_into_radix(matches, sk), 0)
        })
        .collect();

    selected_rows
        .par_iter()
        .zip(is_unique_bools)
        .map(|(selected_row, is_unique)| sk.boolean_bitand(selected_row, &is_unique))
        .collect()
}

// Checks whether all the selected values in the two columns are equal
fn selected_rows_eq(
    first_row: (&[Cell], &BooleanBlock),
    second_row: (&[Cell], &BooleanBlock),
    selected_columns: &[BooleanBlock],
    sk: &ServerKey,
) -> BooleanBlock {
    assert_eq!(first_row.0.len(), selected_columns.len());
    assert_eq!(second_row.0.len(), selected_columns.len());

    // For each distinct pair of cells, only consider as distinct if the column is selected
    let distinct_cells: Vec<_> = selected_columns
        .iter()
        .zip(first_row.0.iter().zip(second_row.0))
        .filter_map(|(is_col_selected, (row1_cell, row2_cell))| {
            (row1_cell != row2_cell).then_some(is_col_selected.clone())
        })
        .collect();

    let (rows_are_eq, both_rows_selected) = rayon::join(
        || {
            if !distinct_cells.is_empty() {
                // Convert all the bools into a single RadixCiphertext: This number will be 0 if all
                // distinct cells were not selected, or non-zero if there was at least a selected pair
                sk.scalar_eq_parallelized(&bools_into_radix(distinct_cells, sk), 0)
            } else {
                // All pair of cells were equal
                sk.create_trivial_boolean_block(true)
            }
        },
        || sk.boolean_bitand(first_row.1, second_row.1),
    );

    // To be considered equal, both rows must have been selected
    sk.boolean_bitand(&rows_are_eq, &both_rows_selected)
}

fn selected_rows_eq_enc(
    first_row: (&[EncClearCell], &BooleanBlock),
    second_row: (&[EncClearCell], &BooleanBlock),
    selected_columns: &[BooleanBlock],
    sk: &ServerKey,
) -> BooleanBlock {
    // The selected columns vector is as long as the longest row (the client adds padding falses
    // in order to avoid leaking the table or a subset of the tables). For shorter rows we simply
    // ignore the exceeding column bools.
    //
    // Also, we may have two rows of different length. In this case we can ignore the exceeding
    // cells from the longer row, because anyway if the exceeding cells are selected, then the
    // shorter row CANNOT be equal as it's not from the selected table.
    let distinct_cells: Vec<_> = selected_columns
        .iter()
        .zip(first_row.0.iter().zip(second_row.0))
        .filter_map(|(is_col_selected, (row1_cell, row2_cell))| {
            match (row1_cell, row2_cell) {
                // Both are in the clear so if the cells are not equal it's only distinct
                // if column is selected and both cells are from a selected table
                // I.e. two distinct cells are ignored if at least one of them is not part of the
                // selected table or the column itself is not selected.
                (EncClearCell::Clear((cell1, selected1)), EncClearCell::Clear((cell2, selected2))) => {
                    (cell1 != cell2).then_some({
                        let both_selected = sk.boolean_bitand(selected1, selected2);
                        sk.boolean_bitand(is_col_selected, &both_selected)
                    })
                }
                // Same, but one of the cells is encrypted
                (EncClearCell::Clear((cell, selected)), EncClearCell::Enc(enc_cell))
                | (EncClearCell::Enc(enc_cell), EncClearCell::Clear((cell, selected))) => {
                    // If both cells are from the selected table, both are of the same type as they
                    // are from the same column. We don't need to compare the type flags.
                    let data = &enc_cell.first_inner().0;
                    let ne = match cell {
                        Cell::Bool(b) => sk.scalar_ne_parallelized(&bool_block(data), *b as u8),
                        Cell::Int(int) => sk.scalar_ne_parallelized(&int_blocks(data), i64_to_ordered_u64(*int)),
                        Cell::UInt(uint) => sk.scalar_ne_parallelized(&int_blocks(data), *uint),
                        Cell::Str(str) => sk.scalar_ne_parallelized(data, str_to_big_uint(str)),
                    };
                    let enc_cell_selected = &enc_cell.first_inner().1;
                    let both_selected = sk.boolean_bitand(selected, enc_cell_selected);
                    let distinct_selected = sk.boolean_bitand(&ne, &both_selected);
                    Some(sk.boolean_bitand(is_col_selected, &distinct_selected))
                }
                // Both cells are encrypted
                (EncClearCell::Enc(enc_cell1), EncClearCell::Enc(enc_cell2)) => {
                    // If both cells are from the selected table, both are of the same type as they
                    // are from the same column. We don't need to compare the type flags.
                    let ne = sk.ne_parallelized(&enc_cell1.first_inner().0, &enc_cell2.first_inner().0);
                    let both_selected = sk.boolean_bitand(&enc_cell1.first_inner().1, &enc_cell2.first_inner().1);
                    let distinct_selected = sk.boolean_bitand(&ne, &both_selected);
                    Some(sk.boolean_bitand(is_col_selected, &distinct_selected))
                }
            }
        })
        .collect();

    let (rows_are_eq, both_rows_selected) = rayon::join(
        || {
            if !distinct_cells.is_empty() {
                // Convert all the bools into a single RadixCiphertext: This number will be 0 if all
                // distinct cells were not selected, or non-zero if there was at least a selected pair
                sk.scalar_eq_parallelized(&bools_into_radix(distinct_cells, sk), 0)
            } else {
                // All pair of cells were equal
                sk.create_trivial_boolean_block(true)
            }
        },
        || sk.boolean_bitand(first_row.1, second_row.1),
    );

    // To be considered equal, both rows must have been selected
    sk.boolean_bitand(&rows_are_eq, &both_rows_selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gen_keys, AsciiStr};

    #[test]
    fn test_distinct_rows() {
        let (ck, sk) = gen_keys();

        let rows = vec![
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("Alice".to_string())),
                Cell::Str(AsciiStr::new("Project A".to_string())),
            ],
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("Alice".to_string())),
                Cell::Str(AsciiStr::new("Project A".to_string())),
            ], // Duplicate of the first
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("Alice".to_string())),
                Cell::Str(AsciiStr::new("Project B".to_string())),
            ], // Same person, different project
            vec![
                Cell::Int(2),
                Cell::UInt(200),
                Cell::Str(AsciiStr::new("Bob".to_string())),
                Cell::Str(AsciiStr::new("Project X".to_string())),
            ],
            vec![
                Cell::Int(2),
                Cell::UInt(200),
                Cell::Str(AsciiStr::new("Bob".to_string())),
                Cell::Str(AsciiStr::new("Project X".to_string())),
            ], // Duplicate of Bob
            vec![
                Cell::Int(3),
                Cell::UInt(300),
                Cell::Str(AsciiStr::new("Charlie".to_string())),
                Cell::Str(AsciiStr::new("Project Y".to_string())),
            ],
            vec![
                Cell::Int(3),
                Cell::UInt(300),
                Cell::Str(AsciiStr::new("Charlie".to_string())),
                Cell::Str(AsciiStr::new("Project Z".to_string())),
            ], // Charlie different project
            vec![
                Cell::Int(3),
                Cell::UInt(300),
                Cell::Str(AsciiStr::new("Charlie".to_string())),
                Cell::Str(AsciiStr::new("Project Y".to_string())),
            ], // Duplicate of a previous Charlie
            vec![
                Cell::Int(4),
                Cell::UInt(400),
                Cell::Str(AsciiStr::new("Dana".to_string())),
                Cell::Str(AsciiStr::new("Project W".to_string())),
            ],
            vec![
                Cell::Int(4),
                Cell::UInt(401),
                Cell::Str(AsciiStr::new("Dana".to_string())),
                Cell::Str(AsciiStr::new("Project W".to_string())),
            ], // Slight variation in UInt
            vec![
                Cell::Int(5),
                Cell::UInt(500),
                Cell::Str(AsciiStr::new("Eve".to_string())),
                Cell::Str(AsciiStr::new("Project V".to_string())),
            ],
            vec![
                Cell::Int(5),
                Cell::UInt(500),
                Cell::Str(AsciiStr::new("Eve".to_string())),
                Cell::Str(AsciiStr::new("Project V".to_string())),
            ], // Duplicate of Eve
        ];

        let selected_columns = vec![
            ck.encrypt_bool(true),  // Consider first column (Int)
            ck.encrypt_bool(false), // Ignore UInt
            ck.encrypt_bool(true),  // Consider Str for name
            ck.encrypt_bool(true),  // Consider Str for project
        ];

        let selected_rows = vec![ck.encrypt_bool(true); rows.len()];

        let result_blocks = distinct(&rows, &selected_columns, &selected_rows, &sk);
        let results = result_blocks.iter().map(|b| ck.decrypt_bool(b)).collect::<Vec<bool>>();

        // Note that even though the two "Dana" rows are distinct, they are only so because of the
        // UInt column values. However, that column is not selected, and the two resulting rows
        // (ignoring the UInt column) are considered equal.
        assert_eq!(
            results,
            vec![true, false, true, true, false, true, true, false, true, false, true, false],
        );
    }

    #[test]
    fn test_very_complex_distinct() {
        let (ck, sk) = gen_keys();

        let rows = vec![
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("alice".to_string())),
                Cell::Str(AsciiStr::new("Project A".to_string())),
                Cell::Str(AsciiStr::new("Team 1".to_string())),
            ],
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("Alice".to_string())),
                Cell::Str(AsciiStr::new("Project A".to_string())),
                Cell::Str(AsciiStr::new("Team 1".to_string())),
            ],
            vec![
                Cell::Int(1),
                Cell::UInt(100),
                Cell::Str(AsciiStr::new("alice ".to_string())),
                Cell::Str(AsciiStr::new("Project A".to_string())),
                Cell::Str(AsciiStr::new("Team 1".to_string())),
            ],
            vec![
                Cell::Int(2),
                Cell::UInt(200),
                Cell::Str(AsciiStr::new("Bob".to_string())),
                Cell::Str(AsciiStr::new("Project X".to_string())),
                Cell::Str(AsciiStr::new("Team 2".to_string())),
            ],
            vec![
                Cell::Int(2),
                Cell::UInt(200),
                Cell::Str(AsciiStr::new("Bob".to_string())),
                Cell::Str(AsciiStr::new("Project X".to_string())),
                Cell::Str(AsciiStr::new("Team 2".to_string())),
            ],
            vec![
                Cell::Int(-1),
                Cell::UInt(200),
                Cell::Str(AsciiStr::new("bob".to_string())),
                Cell::Str(AsciiStr::new("Project X".to_string())),
                Cell::Str(AsciiStr::new("Team 2".to_string())),
            ],
            vec![
                Cell::Int(3),
                Cell::UInt(300),
                Cell::Str(AsciiStr::new("Charlie".to_string())),
                Cell::Str(AsciiStr::new("Project Y".to_string())),
                Cell::Str(AsciiStr::new("Team 3".to_string())),
            ],
            vec![
                Cell::Int(3),
                Cell::UInt(300),
                Cell::Str(AsciiStr::new("Charlie".to_string())),
                Cell::Str(AsciiStr::new("Project Z".to_string())),
                Cell::Str(AsciiStr::new("Team 3".to_string())),
            ],
            vec![
                Cell::Int(4),
                Cell::UInt(400),
                Cell::Str(AsciiStr::new("Dana".to_string())),
                Cell::Str(AsciiStr::new("Project W".to_string())),
                Cell::Str(AsciiStr::new("Team 4".to_string())),
            ],
            vec![
                Cell::Int(4),
                Cell::UInt(401),
                Cell::Str(AsciiStr::new("Dana".to_string())),
                Cell::Str(AsciiStr::new("Project W".to_string())),
                Cell::Str(AsciiStr::new("Team 4".to_string())),
            ],
            vec![
                Cell::Int(5),
                Cell::UInt(500),
                Cell::Str(AsciiStr::new("Eve".to_string())),
                Cell::Str(AsciiStr::new("Project V".to_string())),
                Cell::Str(AsciiStr::new("Team 5".to_string())),
            ],
            vec![
                Cell::Int(5),
                Cell::UInt(600),
                Cell::Str(AsciiStr::new("Eve".to_string())),
                Cell::Str(AsciiStr::new("Project V".to_string())),
                Cell::Str(AsciiStr::new("Team 6".to_string())),
            ],
        ];

        let selected_columns = vec![
            ck.encrypt_bool(true),  // Consider first column (Int)
            ck.encrypt_bool(false), // Ignore UInt
            ck.encrypt_bool(true),  // Consider Str for name (testing case sensitivity indirectly)
            ck.encrypt_bool(true),  // Consider Str for project
            ck.encrypt_bool(false), // Ignore Team column
        ];

        let selected_rows = vec![ck.encrypt_bool(true); rows.len()];

        let result_blocks = distinct(&rows, &selected_columns, &selected_rows, &sk);
        let results = result_blocks.iter().map(|b| ck.decrypt_bool(b)).collect::<Vec<bool>>();

        assert_eq!(
            results,
            vec![true, true, true, true, false, true, true, true, true, false, true, false],
        );
    }
}
