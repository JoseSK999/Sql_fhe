use super::table::CellTypeId;
use crate::{AsciiStr, Cell};

use crate::engine::bools_into_radix;
use rayon::prelude::*;
use tfhe::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use tfhe::integer::block_decomposition::DecomposableInto;
use tfhe::integer::{BooleanBlock, ClientKey, RadixCiphertext, ServerKey};

// Max length of the encrypted SQL data in u64, i.e. 4 * 64 = 256 bits
const N: usize = 4;

pub fn str_to_big_uint(str: &AsciiStr) -> StaticUnsignedBigInt<N> {
    let mut bytes = str.inner().as_bytes().to_vec();

    // Resize with nulls at the end such that it matches the N const u64 length (for the
    // StaticUnsignedBigInt)
    bytes.resize(N * 8, 0);

    let mut big_uint = StaticUnsignedBigInt::<N>::from(0u8);
    big_uint.copy_from_be_byte_slice(&bytes);

    big_uint
}

pub fn big_uint_to_str(big_uint: StaticUnsignedBigInt<N>) -> AsciiStr {
    let mut bytes = vec![0u8; N * 8];
    big_uint.copy_to_be_byte_slice(&mut bytes);

    // Truncate trailing nulls which were added for padding
    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    let string = std::str::from_utf8(&bytes).expect("Non-ASCII data encountered");

    AsciiStr::new(string.to_owned())
}

pub fn encrypt_str(str: &AsciiStr, ck: &ClientKey) -> RadixCiphertext {
    ck.encrypt_radix(str_to_big_uint(str), 128)
}

pub fn trivial_encrypt_str(str: &AsciiStr, sk: &ServerKey) -> RadixCiphertext {
    sk.create_trivial_radix(str_to_big_uint(str), 128)
}

pub fn decrypt_str(str: &RadixCiphertext, ck: &ClientKey) -> AsciiStr {
    big_uint_to_str(ck.decrypt_radix(str))
}

// Converts an i64 value to u64 while preserving the correct ordering. Normally, casting a negative
// i64 to u64 results in a very large number because the sign bit is interpreted as part of the
// number's magnitude in u64. Instead, we flip the MSB:
// - Negative numbers (which start with a 1 bit) become smaller in the u64 space, as their leading
//   1 becomes a 0.
// - Positive numbers (starting with a 0 bit) become larger since their leading 0 turns to 1.
//
// This way, when we compare i64 values with tfhe-rs (converted to u64), negative values are
// correctly considered smaller than positive ones.
pub fn i64_to_ordered_u64(value: i64) -> u64 {
    (value as u64) ^ (1 << 63)
}

pub fn ordered_u64_to_i64(value: u64) -> i64 {
    // Convert back by flipping the sign bit again
    (value ^ (1 << 63)) as i64
}

// Can hold the encryption of several Cells of the same type. Contains at least one encrypted Cell.
// For instance the IN operator can use a variable number of values (of the same type).
#[derive(Clone)]
pub struct EncCells {
    // The boolean indicates if the value is NOT padding
    pub(crate) inner: Vec<(RadixCiphertext, BooleanBlock)>,
    pub(crate) type_flag: RadixCiphertext,
}

// Helper fn to trivially encrypt part of the EncCells type
pub(super) fn trivial_cell(cell: &Cell, sk: &ServerKey) -> (RadixCiphertext, RadixCiphertext) {
    let trivial_type_flag = match cell.data_type() {
        CellTypeId::Bool => sk.create_trivial_radix(0u8, 1),
        CellTypeId::Int => sk.create_trivial_radix(1u8, 1),
        CellTypeId::UInt => sk.create_trivial_radix(2u8, 1),
        CellTypeId::Str => sk.create_trivial_radix(3u8, 1),
    };
    let trivial_radix = match cell {
        Cell::Bool(b) => sk.create_trivial_radix(*b as u8, 128),
        Cell::Int(int) => sk.create_trivial_radix(i64_to_ordered_u64(*int), 128),
        Cell::UInt(uint) => sk.create_trivial_radix(*uint, 128),
        Cell::Str(str) => trivial_encrypt_str(str, sk),
    };

    (trivial_radix, trivial_type_flag)
}

impl EncCells {
    pub fn new(cells: &[Cell], size: usize, ck: &ClientKey) -> Self {
        assert!(!cells.is_empty(), "At least a cell to encrypt");
        assert!(cells.len() <= size, "Leaf cells exceed the supplied size");

        let first_type = cells[0].data_type();
        assert!(
            cells.iter().all(|cell| cell.data_type() == first_type),
            "Not all cells have the same type"
        );

        // The type flag is a single block of 2 bits, allowing to signal the four Cell types
        let type_flag = match first_type {
            CellTypeId::Bool => ck.encrypt_radix(0u8, 1),
            CellTypeId::Int => ck.encrypt_radix(1u8, 1),
            CellTypeId::UInt => ck.encrypt_radix(2u8, 1),
            CellTypeId::Str => ck.encrypt_radix(3u8, 1),
        };

        let mut inner = Vec::new();
        for cell in cells {
            match cell {
                Cell::Bool(b) => {
                    let enc_bool = ck.encrypt_radix(*b as u8, 128);
                    inner.push((enc_bool, ck.encrypt_bool(true)))
                }
                Cell::Int(int) => {
                    let enc_int = ck.encrypt_radix(i64_to_ordered_u64(*int), 128);
                    inner.push((enc_int, ck.encrypt_bool(true)))
                }
                Cell::UInt(uint) => {
                    let enc_uint = ck.encrypt_radix(*uint, 128);
                    inner.push((enc_uint, ck.encrypt_bool(true)))
                }
                // TODO the radixciphertext is max 7 bits * 32 = 224 bits (112 blocks instead of 128)
                // We need to take 7 bits at a time from the asciis and create a StaticUnsignedBigInt
                Cell::Str(str) => {
                    let enc_str = encrypt_str(str, ck);
                    inner.push((enc_str, ck.encrypt_bool(true)))
                }
            }
        }

        // Add padding values to fill the encrypted cells size
        for _ in 0..size - cells.len() {
            inner.push((ck.encrypt_radix(0u64, 128), ck.encrypt_bool(false)))
        }

        EncCells { inner, type_flag }
    }

    pub fn first_inner(&self) -> &(RadixCiphertext, BooleanBlock) {
        self.inner.first().expect("At least a cell in EncCells")
    }

    // The first encrypted cell is guaranteed to not be padding if the builder is used
    pub fn decrypt_first(&self, ck: &ClientKey) -> Cell {
        let type_flag: u8 = ck.decrypt_radix(&self.type_flag);

        match type_flag {
            0 => Cell::Bool(ck.decrypt_radix::<u8>(&self.first_inner().0) != 0),
            1 => Cell::Int(ordered_u64_to_i64(ck.decrypt_radix(&self.first_inner().0))),
            2 => Cell::UInt(ck.decrypt_radix(&self.first_inner().0)),
            3 => Cell::Str(decrypt_str(&self.first_inner().0, ck)),
            _ => panic!("Type flag not supported"),
        }
    }
}

fn op_is(leaf_op: &RadixCiphertext, sk: &ServerKey) -> [BooleanBlock; 5] {
    let (((op_is_eq, op_is_lt), (op_is_gt, op_is_bt)), op_is_in) = rayon::join(
        || {
            rayon::join(
                || {
                    rayon::join(
                        || sk.scalar_eq_parallelized(leaf_op, 0),
                        || sk.scalar_eq_parallelized(leaf_op, 1),
                    )
                },
                || {
                    rayon::join(
                        || sk.scalar_eq_parallelized(leaf_op, 2),
                        || sk.scalar_eq_parallelized(leaf_op, 3),
                    )
                },
            )
        },
        || sk.scalar_eq_parallelized(leaf_op, 4),
    );

    [op_is_eq, op_is_lt, op_is_gt, op_is_bt, op_is_in]
}

fn combine_results(results: &[BooleanBlock; 5], op_is: &[BooleanBlock; 5], sk: &ServerKey) -> BooleanBlock {
    // Combine results with their corresponding operation condition
    let (((eq_result, lt_result), (gt_result, bt_result)), in_result) = rayon::join(
        || {
            rayon::join(
                || {
                    rayon::join(
                        || sk.boolean_bitand(&results[0], &op_is[0]),
                        || sk.boolean_bitand(&results[1], &op_is[1]),
                    )
                },
                || {
                    rayon::join(
                        || sk.boolean_bitand(&results[2], &op_is[2]),
                        || sk.boolean_bitand(&results[3], &op_is[3]),
                    )
                },
            )
        },
        || sk.boolean_bitand(&results[4], &op_is[4]),
    );

    // Now, combine all these results using boolean OR to get the final selected result.
    let (eq_or_lt, gt_or_bt) = rayon::join(
        || sk.boolean_bitor(&eq_result, &lt_result),
        || sk.boolean_bitor(&gt_result, &bt_result),
    );
    // If NoOp was selected, then no previous result was true, and we return false
    sk.boolean_bitor(&sk.boolean_bitor(&eq_or_lt, &gt_or_bt), &in_result)
}

// Helper function to get the corresponding FHE method with a generic scalar type
fn generic_scalar_comparison<Scalar: DecomposableInto<u64>>(
    scalar: Scalar,
    enc: &[(RadixCiphertext, BooleanBlock)],
    leaf_op: &RadixCiphertext,
    sk: &ServerKey,
) -> BooleanBlock {
    let ((eq, lt), op_is) = rayon::join(
        || {
            rayon::join(
                || sk.scalar_eq_parallelized(&enc[0].0, scalar),
                // (cell > enc_cell) is equal to (enc_cell < cell), and so on. We have to invert
                // the operation as the provided sk methods have the scalar on the right side
                || sk.scalar_gt_parallelized(&enc[0].0, scalar),
            )
        },
        || op_is(leaf_op, sk),
    );

    let (gt, (bt, in_re)) = rayon::join(
        // If it's not eq nor lt, it's gt
        || sk.boolean_bitand(&sk.boolean_bitnot(&eq), &sk.boolean_bitnot(&lt)),
        || {
            rayon::join(
                || {
                    let upper_bound = &enc[1].0;
                    let (ge_than_lower, le_than_upper) = rayon::join(
                        // Ge is the same as NOT lt (which we have computed for the rhs.first_inner())
                        || sk.boolean_bitnot(&lt),
                        || sk.scalar_ge_parallelized(upper_bound, scalar),
                    );
                    sk.boolean_bitand(&ge_than_lower, &le_than_upper)
                },
                || {
                    // Checks if one of the encrypted cell values is equal to the scalar, ignoring padding
                    // encrypted cells
                    let matches: Vec<_> = enc
                        .par_iter()
                        .enumerate()
                        .map(|(i, (enc_cell, is_not_padding))| {
                            if i == 0 {
                                // We have already computed eq with the first enc cell
                                sk.boolean_bitand(&eq, is_not_padding)
                            } else {
                                let eq = sk.scalar_eq_parallelized(enc_cell, scalar);
                                sk.boolean_bitand(&eq, is_not_padding)
                            }
                        })
                        .collect();

                    // Convert all the bools into a single RadixCiphertext: This number will be 0 if there
                    // was no match (all false) or non-zero if there was a match (at least one true)
                    sk.scalar_ne_parallelized(&bools_into_radix(matches, sk), 0)
                },
            )
        },
    );

    let results = [eq, lt, gt, bt, in_re];
    combine_results(&results, &op_is, sk)
}

// Checks the Leaf Operation assuming the two cells are of the same type (this function is only
// used when we know it). Lhs is a cleartext cell that we convert into scalar values.
pub fn scalar_comparison(lhs: &Cell, rhs: &EncCells, leaf_op: &RadixCiphertext, sk: &ServerKey) -> BooleanBlock {
    match lhs {
        Cell::Bool(b) => generic_scalar_comparison::<u8>(*b as u8, &rhs.inner, leaf_op, sk),
        Cell::Int(int) => generic_scalar_comparison::<u64>(i64_to_ordered_u64(*int), &rhs.inner, leaf_op, sk),
        Cell::UInt(uint) => generic_scalar_comparison::<u64>(*uint, &rhs.inner, leaf_op, sk),
        Cell::Str(str) => {
            generic_scalar_comparison::<StaticUnsignedBigInt<4>>(str_to_big_uint(str), &rhs.inner, leaf_op, sk)
        }
    }
}

// Checks the Leaf Operation assuming the two cells are of the same type (this function is only
// used when we know it).
pub fn cipher_comparison(
    lhs: &EncCells,
    rhs: &EncCells,
    leaf_op: &RadixCiphertext,
    sk: &ServerKey,
) -> BooleanBlock {
    let ((eq, lt), op_is) = rayon::join(
        || {
            rayon::join(
                || sk.eq_parallelized(&lhs.first_inner().0, &rhs.first_inner().0),
                || sk.lt_parallelized(&lhs.first_inner().0, &rhs.first_inner().0),
            )
        },
        || op_is(leaf_op, sk),
    );

    let (gt, (bt, in_re)) = rayon::join(
        // If it's not eq nor lt, it's gt
        || sk.boolean_bitand(&sk.boolean_bitnot(&eq), &sk.boolean_bitnot(&lt)),
        || {
            rayon::join(
                || {
                    // It's guaranteed that there are at least two encrypted cells as rhs
                    let upper_bound = &rhs.inner[1].0;
                    let (ge_than_lower, le_than_upper) = rayon::join(
                        // Ge is the same as NOT lt (which we have computed for the rhs.first_inner())
                        || sk.boolean_bitnot(&lt),
                        || sk.le_parallelized(&lhs.first_inner().0, upper_bound),
                    );
                    sk.boolean_bitand(&ge_than_lower, &le_than_upper)
                },
                || {
                    // Checks if one of the encrypted rhs values is equal to the lhs, ignoring padding
                    // encrypted cells
                    let matches: Vec<_> = rhs
                        .inner
                        .par_iter()
                        .enumerate()
                        .map(|(i, (enc_cell, is_not_padding))| {
                            if i == 0 {
                                // We have already computed eq with the first enc cell
                                sk.boolean_bitand(&eq, is_not_padding)
                            } else {
                                let eq = sk.eq_parallelized(&lhs.first_inner().0, enc_cell);
                                sk.boolean_bitand(&eq, is_not_padding)
                            }
                        })
                        .collect();

                    // Convert all the bools into a single RadixCiphertext: This number will be 0 if there
                    // was no match (all false) or non-zero if there was a match (at least one true)
                    sk.scalar_ne_parallelized(&bools_into_radix(matches, sk), 0)
                },
            )
        },
    );

    let results = [eq, lt, gt, bt, in_re];
    combine_results(&results, &op_is, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen_keys;
    use crate::sql::LeafOp;

    #[test]
    fn test_str_to_big_uint() {
        let original_str = "Hello, world!";
        let ascii_str = AsciiStr::new(original_str.to_string());

        let big_uint = str_to_big_uint(&ascii_str);
        let converted_str = big_uint_to_str(big_uint);

        assert_eq!(ascii_str, converted_str);
    }

    #[test]
    fn test_full_str_to_big_uint() {
        let original_str = "j".repeat(32);
        let ascii_str = AsciiStr::new(original_str.to_string());

        let big_uint = str_to_big_uint(&ascii_str);
        let converted_str = big_uint_to_str(big_uint);

        assert_eq!(ascii_str, converted_str);
    }

    #[test]
    fn test_empty_str_to_big_uint() {
        let original_str = "";
        let ascii_str = AsciiStr::new(original_str.to_string());

        let big_uint = str_to_big_uint(&ascii_str);
        let converted_str = big_uint_to_str(big_uint);

        assert_eq!(ascii_str, converted_str);
    }

    // Helper function to get the encrypted operator
    fn encrypt_leaf_op(leaf_op: LeafOp, ck: &ClientKey) -> RadixCiphertext {
        match leaf_op {
            LeafOp::Eq => ck.encrypt_radix(0u8, 2),
            LeafOp::Lt => ck.encrypt_radix(1u8, 2),
            LeafOp::Gt => ck.encrypt_radix(2u8, 2),
            _ => panic!("Unused leaf op in the tests"),
        }
    }
    fn bool_cmp(lhs: bool, rhs: bool, op: LeafOp) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let rhs = EncCells::new(&[rhs.into()], 2, &ck);

        let op = encrypt_leaf_op(op, &ck);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn int_cmp(lhs: i64, rhs: i64, op: LeafOp) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let rhs = EncCells::new(&[rhs.into()], 2, &ck);

        let op = encrypt_leaf_op(op, &ck);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn uint_cmp(lhs: u64, rhs: u64, op: LeafOp) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let rhs = EncCells::new(&[rhs.into()], 2, &ck);

        let op = encrypt_leaf_op(op, &ck);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn str_cmp(lhs: &str, rhs: &str, op: LeafOp) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let rhs = EncCells::new(&[rhs.into()], 2, &ck);

        let op = encrypt_leaf_op(op, &ck);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn int_in(lhs: i64, rhs: &[i64]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let set: Vec<_> = rhs.iter().map(|&int| int.into()).collect();
        let padding = 2;
        let rhs = EncCells::new(&set, set.len() + padding, &ck);

        let in_op = ck.encrypt_radix(4u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn uint_in(lhs: u64, rhs: &[u64]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let set: Vec<_> = rhs.iter().map(|&uint| uint.into()).collect();
        let padding = 2;
        let rhs = EncCells::new(&set, set.len() + padding, &ck);

        let in_op = ck.encrypt_radix(4u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn str_in(lhs: &str, rhs: &[&str]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let set: Vec<_> = rhs.iter().map(|&str| str.into()).collect();
        let padding = 2;
        let rhs = EncCells::new(&set, set.len() + padding, &ck);

        let in_op = ck.encrypt_radix(4u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn int_between(lhs: i64, rhs: [i64; 2]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let range: Vec<_> = rhs.iter().map(|&int| int.into()).collect();
        let rhs = EncCells::new(&range, 2, &ck);

        let in_op = ck.encrypt_radix(3u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn uint_between(lhs: u64, rhs: [u64; 2]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let range: Vec<_> = rhs.iter().map(|&int| int.into()).collect();
        let rhs = EncCells::new(&range, 2, &ck);

        let in_op = ck.encrypt_radix(3u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }
    fn str_between(lhs: &str, rhs: [&str; 2]) -> bool {
        let (ck, sk) = gen_keys();

        let enc_lhs = EncCells::new(&[lhs.into()], 1, &ck);
        let lhs = lhs.into();
        let range: Vec<_> = rhs.iter().map(|&int| int.into()).collect();
        let rhs = EncCells::new(&range, 2, &ck);

        let in_op = ck.encrypt_radix(3u8, 2);
        let enc_result1 = scalar_comparison(&lhs, &rhs, &in_op, &sk);
        let enc_result2 = cipher_comparison(&enc_lhs, &rhs, &in_op, &sk);

        let result1 = ck.decrypt_bool(&enc_result1);
        let result2 = ck.decrypt_bool(&enc_result2);
        assert_eq!(result1, result2);
        result1
    }

    #[test]
    fn test_bool() {
        assert!(bool_cmp(true, true, LeafOp::Eq));
        assert!(bool_cmp(false, false, LeafOp::Eq));
        assert!(!bool_cmp(true, false, LeafOp::Eq));
        assert!(!bool_cmp(false, true, LeafOp::Eq));
    }

    #[test]
    fn test_int_eq() {
        assert!(int_cmp(10_000, 10_000, LeafOp::Eq));
        assert!(!int_cmp(10_000, 10_001, LeafOp::Eq));
    }

    #[test]
    fn test_int_cmp_edge_cases() {
        // Compare minimum i64 with 0 and maximum i64
        assert!(int_cmp(i64::MIN, 0, LeafOp::Lt));
        assert!(int_cmp(i64::MIN, i64::MAX, LeafOp::Lt));

        // Boundary crossing: -1 vs 0 and 1
        assert!(int_cmp(-1, 0, LeafOp::Lt));
        assert!(int_cmp(-1, 1, LeafOp::Lt));

        // Same magnitude, different signs
        assert!(int_cmp(-100, 100, LeafOp::Lt));

        // Large magnitude differences
        assert!(int_cmp(i64::MIN + 1, 2, LeafOp::Lt));
        assert!(int_cmp(-2, i64::MAX, LeafOp::Lt));

        // Adjacent negative numbers
        assert!(int_cmp(-2, -1, LeafOp::Lt));

        // Zero comparison
        assert!(int_cmp(0, 0, LeafOp::Eq));

        // Directly adjacent numbers
        assert!(int_cmp(100, 101, LeafOp::Lt));
        assert!(int_cmp(-101, -100, LeafOp::Lt));

        // Flipping signs with adjacent values
        assert!(int_cmp(-1, 1, LeafOp::Lt));
        assert!(int_cmp(1, -1, LeafOp::Gt));

        // Testing equality with the same negative value
        assert!(int_cmp(-100, -100, LeafOp::Eq));

        // Large positive and negative values comparison
        assert!(int_cmp(-1_000_000_000, 1_000_000_000, LeafOp::Lt));
    }

    #[test]
    fn test_int_lt() {
        assert!(int_cmp(i64::MIN, i64::MIN + 1, LeafOp::Lt));
        assert!(int_cmp(-100, 0, LeafOp::Lt));
        assert!(!int_cmp(0, 0, LeafOp::Lt));
        assert!(!int_cmp(100, -100, LeafOp::Lt));
    }

    #[test]
    fn test_int_gt() {
        assert!(int_cmp(i64::MAX, i64::MAX - 1, LeafOp::Gt));
        assert!(int_cmp(100, -100, LeafOp::Gt));
        assert!(!int_cmp(100, 100, LeafOp::Gt));
        assert!(!int_cmp(-100, -99, LeafOp::Gt));
    }

    #[test]
    fn test_int_in() {
        let set = [i64::MAX, 0, -1, -987_534_094, i64::MIN];
        assert!(int_in(-987_534_094, &set));
        assert!(!int_in(-987_534_095, &set));
    }

    #[test]
    fn test_int_between() {
        assert!(int_between(-100, [-100, 100]));
        assert!(int_between(100, [-100, 100]));
        assert!(int_between(0, [-100, 100]));

        assert!(int_between(i64::MIN + 1, [i64::MIN, 100_000]));
        assert!(int_between(i64::MIN + 100_000, [i64::MIN, 100_000]));
        assert!(int_between(i64::MIN + 100_000_000, [i64::MIN, 100_000]));

        assert!(!int_between(-101, [-100, 100]));
        assert!(!int_between(i64::MIN, [-100, 100]));
        assert!(!int_between(i64::MAX, [-100, 100]));
    }

    #[test]
    fn test_uint_eq() {
        assert!(uint_cmp(10_000, 10_000, LeafOp::Eq));
        assert!(!uint_cmp(10_000, 10_001, LeafOp::Eq));
    }

    #[test]
    fn test_uint_lt() {
        assert!(uint_cmp(0, u64::MAX, LeafOp::Lt));
        assert!(uint_cmp(0, 100, LeafOp::Lt));
        assert!(!uint_cmp(100, 100, LeafOp::Lt));
        assert!(!uint_cmp(101, 100, LeafOp::Lt));
    }

    #[test]
    fn test_uint_gt() {
        assert!(uint_cmp(u64::MAX, u64::MAX - 1, LeafOp::Gt));
        assert!(uint_cmp(u64::MAX, 0, LeafOp::Gt));
        assert!(!uint_cmp(u64::MAX, u64::MAX, LeafOp::Gt));
        assert!(!uint_cmp(0, 683_975, LeafOp::Gt));
    }

    #[test]
    fn test_uint_in() {
        let set = [u64::MAX, 0, 2, 3, 1_987_534_094, 974];
        assert!(uint_in(974, &set));
        assert!(!uint_in(1, &set));
    }

    #[test]
    fn test_uint_between() {
        assert!(uint_between(0, [0, 200]));
        assert!(uint_between(200, [0, 200]));
        assert!(uint_between(100, [0, 200]));
        assert!(uint_between(u64::MAX - 1, [0, u64::MAX]));

        assert!(!uint_between(201, [100, 200]));
        assert!(!uint_between(99, [100, 200]));
        assert!(!uint_between(u64::MAX, [100, 200]));
        assert!(!uint_between(0, [100, 200]));
    }

    #[test]
    fn test_str_eq() {
        assert!(str_cmp("Hello, world!", "Hello, world!", LeafOp::Eq));
        assert!(!str_cmp("Hello, World!", "Hello, world!", LeafOp::Eq));
    }

    #[test]
    fn test_str_lt() {
        let lhs = "a".repeat(32);
        let rhs = "a".repeat(31) + "b";
        assert!(str_cmp(&lhs, &rhs, LeafOp::Lt));
        assert!(str_cmp("Alice", "alice", LeafOp::Lt));
        assert!(!str_cmp("alice", "alice", LeafOp::Lt));
        assert!(!str_cmp(&rhs, &lhs, LeafOp::Lt));
    }

    #[test]
    fn test_str_gt() {
        assert!(str_cmp("Carol", "Bob", LeafOp::Gt));
        assert!(str_cmp("~", " ", LeafOp::Gt));
        assert!(!str_cmp("~", "~", LeafOp::Gt));
        assert!(!str_cmp(" ", "~", LeafOp::Gt));
    }

    #[test]
    fn test_str_in() {
        let set = ["Joselillo", "Jesus", "Josefina", "Jose"];
        assert!(str_in("Josefina", &set));
        assert!(!str_in("josefina", &set));
    }

    #[test]
    fn test_str_between() {
        assert!(str_between("apple", ["apple", "banana"]));
        assert!(str_between("banana", ["apple", "banana"]));
        assert!(str_between("apricot", ["apple", "banana"]));

        assert!(!str_between("aardvark", ["apple", "banana"]));
        assert!(!str_between("cherry", ["apple", "banana"]));
        assert!(!str_between("apple!!", ["apple", "apple!"]));
    }

    #[test]
    #[should_panic]
    fn test_str_non_ascii_rejection() {
        let _ = AsciiStr::new("é".to_string());
    }

    #[test]
    #[should_panic]
    fn test_str_33_chars_rejection() {
        let _ = AsciiStr::new("a".repeat(33));
    }
}
