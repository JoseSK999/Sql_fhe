use crate::engine::bools_into_radix;
use crate::engine::enc_query::EncSqlExpr;
use crate::engine::leaf_operations::{
    cipher_comparison, scalar_comparison, str_to_big_uint, trivial_cell, trivial_encrypt_str, EncCells,
};
use crate::{Cell, ClearTable};
use rayon::prelude::*;
use tfhe::integer::{BooleanBlock, RadixCiphertext, ServerKey};

// We need to create the union of all the tables as we don't know which one is selected.
// Overlapping cells from different tables will need to be selected in FHE to choose the one from
// the correct table. However, non-overlapping cells can be used in the clear together with the
// selection bool (true if the corresponding table is selected).
//
// +-------------------------+-----------+
// |  Table 1 and Table 2    |  Table 2  |
// |        Overlap          |   Outer   |
// |    (Encrypted Cells)    |   Cells   |
// +-------------------------+           |
// |             (Clear Cells)           |
// +-------------------------------------+
pub enum EncClearCell {
    Enc(EncCells),
    Clear((Cell, BooleanBlock)),
}

fn transform_overlap(
    prev_cell: &EncClearCell,
    current_cell: &Cell,
    current_is_selected: &BooleanBlock,
    sk: &ServerKey,
) -> EncClearCell {
    match prev_cell {
        EncClearCell::Clear((cell, is_selected)) => {
            let (data, type_flag) = trivial_cell(cell, sk);
            let prev = (&data, &type_flag, is_selected);

            select_cell(prev, current_cell, current_is_selected, sk)
        }
        EncClearCell::Enc(enc) => {
            let (data, is_selected) = &enc.first_inner();
            let prev = (data, &enc.type_flag, is_selected);

            select_cell(prev, current_cell, current_is_selected, sk)
        }
    }
}

fn select_cell(
    prev_cell: (&RadixCiphertext, &RadixCiphertext, &BooleanBlock),
    current_cell: &Cell,
    current_is_selected: &BooleanBlock,
    sk: &ServerKey,
) -> EncClearCell {
    let (data, type_flag, is_selected) = prev_cell;
    let (current_data, current_type_flag) = trivial_cell(current_cell, sk);

    let ((selected_data, selected_type), final_is_selected) = rayon::join(
        || {
            rayon::join(
                || sk.if_then_else_parallelized(current_is_selected, &current_data, data),
                || sk.if_then_else_parallelized(current_is_selected, &current_type_flag, type_flag),
            )
        },
        || sk.boolean_bitor(current_is_selected, is_selected),
    );

    // We select the current cell if 'current_is_selected'. Otherwise, we use the previous cell
    // with 'final_is_selected'. This means that if the previous cell was not selected either
    // we mark the encrypted cell as null (i.e. repurpose the padding bool as a select bool)
    //
    // When PartiallyEncTable is built, one of the tables will have been selected (enforced
    // by the query builder)
    let enc_cell = EncCells {
        inner: vec![(selected_data, final_is_selected)],
        type_flag: selected_type,
    };

    EncClearCell::Enc(enc_cell)
}

fn transform_single(cell: &Cell, table_selected: &BooleanBlock) -> EncClearCell {
    EncClearCell::Clear((cell.clone(), table_selected.clone()))
}

pub struct PartiallyEncTable {
    // Homomorphically selected column names. The length of the column list is the maximum length
    // but if the currently selected table has fewer columns, the last names will be nulls
    pub(crate) columns: Vec<RadixCiphertext>,
    // Homomorphically selected rows
    pub(crate) rows: Vec<Vec<EncClearCell>>,
}

pub fn select_table<'a>(tables: &'a [ClearTable], from: &RadixCiphertext, sk: &ServerKey) -> Table<'a> {
    if tables.len() == 1 {
        return Table::Clear(&tables[0]);
    }

    // Get the bools indicating which table was selected, by comparing the names with 'from'
    let matches: Vec<_> = tables
        .par_iter()
        .map(|table| sk.scalar_eq_parallelized(from, str_to_big_uint(&table.name().into())))
        .collect();

    let (columns, rows) = rayon::join(
        || select_columns(tables, &matches, sk),
        || select_rows(tables, &matches, sk),
    );

    Table::PartiallyEnc(PartiallyEncTable { columns, rows })
}

fn select_columns(
    tables: &[ClearTable],
    selected_table_bools: &[BooleanBlock],
    sk: &ServerKey,
) -> Vec<RadixCiphertext> {
    // We need to select our current table column names in FHE
    let max_col_number = tables
        .iter()
        .map(|table| table.column_headers().len())
        .max()
        .expect("At least one table");
    let mut columns: Vec<RadixCiphertext> = vec![trivial_encrypt_str(&"".into(), sk); max_col_number];

    for (table, is_selected) in tables.iter().zip(selected_table_bools) {
        // For each column in the current column list, select the correct name
        let new_names: Vec<_> = table
            .column_names()
            .par_iter()
            .enumerate()
            .map(|(i, col)| {
                sk.if_then_else_parallelized(
                    is_selected,
                    // If table is selected store the column names, overriding the nulls
                    &trivial_encrypt_str(col, sk),
                    &columns[i],
                )
            })
            .collect();

        for (i, new) in new_names.into_iter().enumerate() {
            columns[i] = new;
        }
    }
    columns
}

// Perform homomorphic selection of cells, excluding those in a table without overlaps from other tables
fn select_rows(
    tables: &[ClearTable],
    selected_table_bools: &[BooleanBlock],
    sk: &ServerKey,
) -> Vec<Vec<EncClearCell>> {
    let max_row_number = tables
        .iter()
        .map(|table| table.rows().len())
        .max()
        .expect("At least one table");

    (0..max_row_number)
        .into_par_iter()
        .map(|row_idx| {
            // Determine the maximum column count for this particular row across all tables
            let max_cols_in_row = tables
                .iter()
                .filter_map(|table| table.rows().get(row_idx))
                .map(|row| row.len())
                .max()
                .expect("At least a table with the max 'row_idx'");

            // Iterate over each column position in this row
            (0..max_cols_in_row)
                .into_par_iter()
                .map(|col_idx| {
                    let mut cell_accumulator: Option<EncClearCell> = None;

                    // Check each table for a cell at this position
                    for (table, is_selected) in tables.iter().zip(selected_table_bools) {
                        if let Some(row) = table.rows().get(row_idx) {
                            if let Some(cell) = row.get(col_idx) {
                                cell_accumulator = if let Some(acc_cell) = cell_accumulator {
                                    // Apply the overlapping transformation function
                                    Some(transform_overlap(&acc_cell, cell, is_selected, sk))
                                } else {
                                    // Initialize the accumulator with the first cell found
                                    Some(transform_single(cell, is_selected))
                                };
                            }
                        }
                    }
                    // Collect the transformed cells into the big row
                    cell_accumulator.expect("At least a cell in 'row_idx' at 'col_idx' in any table")
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

// We need to call the correct comparison function depending on the variant of the lhs
fn scalar_or_cipher_comparison(
    lhs: &EncClearCell,
    rhs: &EncCells,
    leaf_op: &RadixCiphertext,
    sk: &ServerKey,
) -> BooleanBlock {
    match lhs {
        EncClearCell::Clear((cell, is_selected)) => {
            let result = scalar_comparison(cell, rhs, leaf_op, sk);
            // The comparison must be true AND the table of the cell must be selected
            sk.boolean_bitand(&result, is_selected)
        }
        EncClearCell::Enc(enc_cell) => {
            let result = cipher_comparison(enc_cell, rhs, leaf_op, sk);
            // Again, we may have a true result but the cell table must also have been selected
            sk.boolean_bitand(&result, &enc_cell.first_inner().1)
        }
    }
}

impl PartiallyEncTable {
    // Returns a bool for each row, indicating if there's a leaf condition match in it or not.
    // For a row to be matched, the condition must be true for a cell in the specified column.
    pub fn evaluate_leaf(
        &self,
        leaf_condition: (&RadixCiphertext, &RadixCiphertext, &EncCells),
        sk: &ServerKey,
    ) -> Vec<BooleanBlock> {
        let (column, op, enc_cells) = leaf_condition;
        let rows_par_iter = self.rows.par_iter();

        rows_par_iter
            .map(|row| {
                // Get the bools for each cell in the row indicating if there was a match
                let matches: Vec<_> = self
                    .columns
                    .par_iter()
                    .zip(row)
                    .map(|(current_col, cell)| {
                        // If the column matches that means the two cells are of the same type.
                        // The query builder enforced that all leaves have the proper cell type.
                        let (cell_match, column_match) = rayon::join(
                            || scalar_or_cipher_comparison(cell, enc_cells, op, sk),
                            || sk.eq_parallelized(column, current_col),
                        );

                        sk.boolean_bitand(&cell_match, &column_match)
                    })
                    .collect();

                // Convert all the bools into a single RadixCiphertext: This number will be 0 if there
                // was no match (all false) or non-zero if there was a match (at least one true)
                sk.scalar_ne_parallelized(&bools_into_radix(matches, sk), 0)
            })
            .collect()
    }
}

pub enum Table<'a> {
    Clear(&'a ClearTable),
    PartiallyEnc(PartiallyEncTable),
}

impl<'a> Table<'a> {
    // Returns a bool for each row, indicating if there's a query match in it or not.
    // Evaluates the full EncSqlExpr to determine matched rows.
    pub fn evaluate_expression(&self, expression: &EncSqlExpr, sk: &ServerKey) -> Vec<BooleanBlock> {
        match expression {
            EncSqlExpr::EncNode {
                left,
                op,
                right,
                negated,
            } => {
                let (left_matches, right_matches) = rayon::join(
                    || self.evaluate_expression(left, sk),
                    || self.evaluate_expression(right, sk),
                );

                let (and_result, or_result) = rayon::join(
                    || {
                        left_matches
                            .par_iter()
                            .zip(&right_matches)
                            .map(|(l, r)| sk.boolean_bitand(l, r))
                            .collect::<Vec<_>>()
                    },
                    || {
                        left_matches
                            .par_iter()
                            .zip(&right_matches)
                            .map(|(l, r)| sk.boolean_bitor(l, r))
                            .collect::<Vec<_>>()
                    },
                );

                // Select the result based on the operation flag
                let op_is_and = &sk.boolean_bitnot(op);
                let op_is_or = op;
                and_result
                    .par_iter()
                    .zip(&or_result)
                    .map(|(and, or)| {
                        // (op && or) || (!op && and)
                        let result_for_and = sk.boolean_bitand(and, op_is_and);
                        let result_for_or = sk.boolean_bitand(or, op_is_or);
                        let selected = sk.boolean_bitor(&result_for_and, &result_for_or);

                        // If negated is set, invert the result (T XOR T = F, F XOR T = T)
                        // Else if it's not set, copy the result (T XOR F = T, F XOR F = F)
                        sk.boolean_bitxor(&selected, negated)
                    })
                    .collect::<Vec<_>>()
            }
            EncSqlExpr::EncLeaf {
                left,
                op,
                right,
                negated,
            } => {
                let vec = match self {
                    Table::Clear(clear) => clear.evaluate_leaf((left, op, right), sk),
                    Table::PartiallyEnc(partially_enc) => partially_enc.evaluate_leaf((left, op, right), sk),
                };
                // Again, if negated is set invert the bools, else copy them
                vec.par_iter()
                    .map(|re| sk.boolean_bitxor(re, negated))
                    .collect::<Vec<_>>()
            }
        }
    }

    // Make all the cells from the ClearTable or the PartiallyEncTable be encrypted by masking
    pub fn mask_table(&self, sk: &ServerKey) -> Vec<Vec<EncCells>> {
        match self {
            Table::Clear(table) => table
                .rows()
                .par_iter()
                .map(|row| row.par_iter().map(|cell| mask_cell(cell, None, sk)).collect())
                .collect(),
            Table::PartiallyEnc(PartiallyEncTable { rows, .. }) => rows
                .par_iter()
                .map(|row| {
                    row.par_iter()
                        .map(|enc_clear_cell| match enc_clear_cell {
                            EncClearCell::Enc(enc_cell) => enc_cell.clone(),
                            EncClearCell::Clear((cell, is_selected)) => mask_cell(cell, Some(is_selected), sk),
                        })
                        .collect()
                })
                .collect(),
        }
    }
}

fn mask_cell(cell: &Cell, is_selected: Option<&BooleanBlock>, sk: &ServerKey) -> EncCells {
    let (data, type_flag) = trivial_cell(cell, sk);
    // If there's a None it's because there was only one table (thus the whole table is selected)
    let is_selected = is_selected.cloned().unwrap_or(sk.create_trivial_boolean_block(true));

    let max_data = sk.create_trivial_max_radix(128);
    let max_type_flag = sk.create_trivial_max_radix(1);

    let (masked_data, masked_type_flag) = rayon::join(
        || sk.bitand_parallelized(&data, &max_data),
        || sk.bitand_parallelized(&type_flag, &max_type_flag),
    );
    EncCells {
        inner: vec![(masked_data, is_selected)],
        type_flag: masked_type_flag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::leaf_operations::{decrypt_str, encrypt_str};
    use crate::gen_keys;
    use tfhe::integer::ClientKey;

    fn decrypt_rows_and_selected_enc(
        partially_enc_table: PartiallyEncTable,
        ck: &ClientKey,
    ) -> (Vec<Vec<Cell>>, Vec<Vec<(bool, bool)>>) {
        let mut selected_enc_rows = Vec::new();
        let dec_rows = partially_enc_table
            .rows
            .iter()
            .filter_map(|row| {
                let mut selected_enc_row = Vec::new();
                // Decrypted row values, ignoring not selected cells
                let dec_row = row
                    .iter()
                    .filter_map(|cell| match cell {
                        EncClearCell::Clear((cell, is_selected)) => {
                            let is_selected = ck.decrypt_bool(is_selected);
                            selected_enc_row.push((is_selected, false));
                            is_selected.then_some(cell.clone())
                        }
                        EncClearCell::Enc(enc_cells) => {
                            let is_selected = ck.decrypt_bool(&enc_cells.first_inner().1);
                            selected_enc_row.push((is_selected, true));
                            is_selected.then_some(enc_cells.decrypt_first(ck))
                        }
                    })
                    .collect::<Vec<_>>();

                selected_enc_rows.push(selected_enc_row);

                // Get the decrypted row only if it has selected cells
                (!dec_row.is_empty()).then_some(dec_row)
            })
            .collect::<Vec<_>>();

        (dec_rows, selected_enc_rows)
    }

    fn example_tables() -> Vec<ClearTable> {
        let table_1 = ClearTable::new(
            "table_1".to_string(),
            vec!["id:uint64".into(), "name:string".into(), "real_madrid_fan:bool".into()],
            vec![
                vec![0u64.into(), "Pedro".into(), true.into()],
                vec![1u64.into(), "Samuel".into(), false.into()],
                vec![2u64.into(), "Carlos".into(), true.into()],
            ],
        );
        let table_2 = ClearTable::new(
            "table_2".to_string(),
            vec![
                "transaction_id:uint64".into(),
                "product_name:string".into(),
                "quantity:int64".into(),
                "in_stock:bool".into(),
            ],
            vec![
                vec![101u64.into(), "Apple".into(), 5i64.into(), true.into()],
                vec![102u64.into(), "Banana".into(), 20i64.into(), true.into()],
                vec![103u64.into(), "Cherry".into(), 0i64.into(), false.into()],
                vec![104u64.into(), "Date".into(), 10i64.into(), true.into()],
                vec![105u64.into(), "Elderberry".into(), (-1i64).into(), false.into()],
            ],
        );
        let table_3 = ClearTable::new(
            "table_3".to_string(),
            vec!["big_nums:uint64".into()],
            vec![
                vec![u64::MAX.into()],
                vec![(u64::MAX - 1).into()],
                vec![(u64::MAX - 2).into()],
                vec![(u64::MAX - 3).into()],
                vec![(u64::MAX - 4).into()],
                vec![(u64::MAX - 5).into()],
                vec![(u64::MAX - 6).into()],
                vec![(u64::MAX - 7).into()],
            ],
        );

        vec![table_1, table_2, table_3]
    }

    #[test]
    fn test_select_table_1() {
        let (ck, sk) = gen_keys();
        let tables = example_tables();
        let enc_from = encrypt_str(&"table_1".into(), &ck);

        if let Table::PartiallyEnc(partially_enc_table) = select_table(&tables, &enc_from, &sk) {
            let columns: Vec<_> = partially_enc_table
                .columns
                .iter()
                .map(|col| decrypt_str(col, &ck))
                .collect();
            // Last column name in the partially encrypted table should be null, as we selected
            // the table with 3 columns rather than the one with 4
            assert_eq!(
                columns,
                vec!["id".into(), "name".into(), "real_madrid_fan".into(), "".into()]
            );

            //       C0               C1               C2                C3
            // +-------------------------------------------------+-----------------+
            // |    Tables    |         Tables 1 & 2             |                 |  R0
            // |   1, 2, & 3  |            Overlap               |      Table 2    |  R1
            // |    Overlap   |                                  |       Outer     |  R2
            // +--------------|----------------------------------|       Cells     |
            // | Tables 2 & 3 |                                                    |  R3
            // |    Overlap   |                        (Clear)                     |  R4
            // +--------------+----------------------------------------------------|
            // |   Table 3    |  R5
            // |  Outer Cells |  R6
            // |    (Clear)   |  R7
            // +--------------+
            // The bools for each cell, indicating if it's selected and encrypted, in that order
            let selected_enc = vec![
                vec![(true, true), (true, true), (true, true), (false, false)],
                vec![(true, true), (true, true), (true, true), (false, false)],
                vec![(true, true), (true, true), (true, true), (false, false)],
                vec![(false, true), (false, false), (false, false), (false, false)],
                vec![(false, true), (false, false), (false, false), (false, false)],
                vec![(false, false)],
                vec![(false, false)],
                vec![(false, false)],
            ];
            let (dec_rows, dec_selected_enc) = decrypt_rows_and_selected_enc(partially_enc_table, &ck);

            assert_eq!(dec_rows, tables[0].rows());
            assert_eq!(dec_selected_enc, selected_enc);
        } else {
            panic!("Tables produce a PartiallyEncTable")
        }
    }

    #[test]
    fn test_select_table_2() {
        let (ck, sk) = gen_keys();
        let tables = example_tables();
        let enc_from = encrypt_str(&"table_2".into(), &ck);

        if let Table::PartiallyEnc(partially_enc_table) = select_table(&tables, &enc_from, &sk) {
            let columns: Vec<_> = partially_enc_table
                .columns
                .iter()
                .map(|col| decrypt_str(col, &ck))
                .collect();
            assert_eq!(
                columns,
                vec![
                    "transaction_id".into(),
                    "product_name".into(),
                    "quantity".into(),
                    "in_stock".into()
                ]
            );

            //       C0               C1               C2                C3
            // +-------------------------------------------------+-----------------+
            // |    Tables    |         Tables 1 & 2             |                 |  R0
            // |   1, 2, & 3  |            Overlap               |      Table 2    |  R1
            // |    Overlap   |                                  |       Outer     |  R2
            // +--------------|----------------------------------|       Cells     |
            // | Tables 2 & 3 |                                                    |  R3
            // |    Overlap   |                        (Clear)                     |  R4
            // +--------------+----------------------------------------------------|
            // |   Table 3    |  R5
            // |  Outer Cells |  R6
            // |    (Clear)   |  R7
            // +--------------+
            // The bools for each cell, indicating if it's selected and encrypted, in that order
            let selected_enc = vec![
                vec![(true, true), (true, true), (true, true), (true, false)],
                vec![(true, true), (true, true), (true, true), (true, false)],
                vec![(true, true), (true, true), (true, true), (true, false)],
                vec![(true, true), (true, false), (true, false), (true, false)],
                vec![(true, true), (true, false), (true, false), (true, false)],
                vec![(false, false)],
                vec![(false, false)],
                vec![(false, false)],
            ];
            let (dec_rows, dec_selected_enc) = decrypt_rows_and_selected_enc(partially_enc_table, &ck);

            assert_eq!(dec_rows, tables[1].rows());
            assert_eq!(dec_selected_enc, selected_enc);
        } else {
            panic!("Tables produce a PartiallyEncTable")
        }
    }

    #[test]
    fn test_select_table_3() {
        let (ck, sk) = gen_keys();
        let tables = example_tables();
        let enc_from = encrypt_str(&"table_3".into(), &ck);

        if let Table::PartiallyEnc(partially_enc_table) = select_table(&tables, &enc_from, &sk) {
            let columns: Vec<_> = partially_enc_table
                .columns
                .iter()
                .map(|col| decrypt_str(col, &ck))
                .collect();
            assert_eq!(columns, vec!["big_nums".into(), "".into(), "".into(), "".into()]);

            //       C0               C1               C2                C3
            // +-------------------------------------------------+-----------------+
            // |    Tables    |         Tables 1 & 2             |                 |  R0
            // |   1, 2, & 3  |            Overlap               |      Table 2    |  R1
            // |    Overlap   |                                  |       Outer     |  R2
            // +--------------|----------------------------------|       Cells     |
            // | Tables 2 & 3 |                                                    |  R3
            // |    Overlap   |                        (Clear)                     |  R4
            // +--------------+----------------------------------------------------|
            // |   Table 3    |  R5
            // |  Outer Cells |  R6
            // |    (Clear)   |  R7
            // +--------------+
            // The bools for each cell, indicating if it's selected and encrypted, in that order
            let selected_enc = vec![
                vec![(true, true), (false, true), (false, true), (false, false)],
                vec![(true, true), (false, true), (false, true), (false, false)],
                vec![(true, true), (false, true), (false, true), (false, false)],
                vec![(true, true), (false, false), (false, false), (false, false)],
                vec![(true, true), (false, false), (false, false), (false, false)],
                vec![(true, false)],
                vec![(true, false)],
                vec![(true, false)],
            ];
            let (dec_rows, dec_selected_enc) = decrypt_rows_and_selected_enc(partially_enc_table, &ck);

            assert_eq!(dec_rows, tables[2].rows());
            assert_eq!(dec_selected_enc, selected_enc);
        } else {
            panic!("Tables produce a PartiallyEncTable")
        }
    }
}
