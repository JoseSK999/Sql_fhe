use super::leaf_operations::{scalar_comparison, str_to_big_uint, EncCells};

use crate::engine::bools_into_radix;
use csv::ReaderBuilder;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::path::PathBuf;
use tfhe::integer::{BooleanBlock, RadixCiphertext, ServerKey};

// Ascii string with at most 32 characters, used in the table as the text type
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsciiStr {
    inner: String,
}

impl fmt::Debug for AsciiStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.inner)
    }
}

impl AsciiStr {
    pub fn new(str: String) -> Self {
        assert!(str.is_ascii(), "String should be ASCII");
        assert!(str.len() <= 32, "Max 32 ASCII characters");
        assert!(!str.contains('\0'), "Null character not allowed");

        AsciiStr { inner: str }
    }

    pub fn inner(&self) -> &str {
        &self.inner
    }
}

impl From<&str> for AsciiStr {
    fn from(value: &str) -> Self {
        AsciiStr::new(value.to_string())
    }
}

// A cell in the table, which can hold different data types
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cell {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Str(AsciiStr),
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cell::Bool(b) => write!(f, "{}", b),
            Cell::Int(i) => write!(f, "{}", i),
            Cell::UInt(u) => write!(f, "{}", u),
            Cell::Str(s) => write!(f, "\"{}\"", s.inner),
        }
    }
}

impl From<bool> for Cell {
    fn from(value: bool) -> Self {
        Cell::Bool(value)
    }
}
impl From<i64> for Cell {
    fn from(value: i64) -> Self {
        Cell::Int(value)
    }
}
impl From<u64> for Cell {
    fn from(value: u64) -> Self {
        Cell::UInt(value)
    }
}
impl From<&str> for Cell {
    fn from(value: &str) -> Self {
        Cell::Str(value.into())
    }
}

// The ID of each Cell data type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CellTypeId {
    Bool,
    Int,
    UInt,
    Str,
}

impl Cell {
    pub fn data_type(&self) -> CellTypeId {
        match self {
            Cell::Bool(_) => CellTypeId::Bool,
            Cell::Int(_) => CellTypeId::Int,
            Cell::UInt(_) => CellTypeId::UInt,
            Cell::Str(_) => CellTypeId::Str,
        }
    }
}

// The column definition, consisting on a short Ascii name and the data type (all cells in the
// column must be of this Cell variant)
#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub(crate) name: AsciiStr,
    pub(crate) type_def: CellTypeId,
}

impl ColumnDef {
    pub fn name(&self) -> &AsciiStr {
        &self.name
    }

    pub fn type_def(&self) -> CellTypeId {
        self.type_def
    }
}

type Row = Vec<Cell>;

// The table, including its name, columns header and rows (vectors of cells)
#[derive(Debug, Clone)]
pub struct ClearTable {
    name: String,
    columns_def: Vec<ColumnDef>,
    rows: Vec<Row>,
}

impl ClearTable {
    pub fn read_from_csv(path: &PathBuf, table_name: String) -> Self {
        let file = File::open(path).expect("File cannot be opened");
        let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

        // Read headers and preserve type annotations
        let headers = rdr.headers().expect("Cannot read headers").clone();
        let mut rows = Vec::new();

        for result in rdr.records() {
            let record = result.expect("Failed to read record");
            let row = record
                .iter()
                .zip(headers.iter())
                .map(|(value, header)| {
                    assert!(header.contains(':'), "\":\" separator required");
                    let (_, col_type) = header.split_once(':').unwrap();

                    match col_type {
                        "bool" => Cell::Bool(value.parse().unwrap()),
                        "int8" => Cell::Int(value.parse::<i8>().unwrap() as i64),
                        "int16" => Cell::Int(value.parse::<i16>().unwrap() as i64),
                        "int32" => Cell::Int(value.parse::<i32>().unwrap() as i64),
                        "int64" => Cell::Int(value.parse().unwrap()),
                        "uint8" => Cell::UInt(value.parse::<u8>().unwrap() as u64),
                        "uint16" => Cell::UInt(value.parse::<u16>().unwrap() as u64),
                        "uint32" => Cell::UInt(value.parse::<u32>().unwrap() as u64),
                        "uint64" => Cell::UInt(value.parse().unwrap()),
                        "string" => Cell::Str(value.into()),
                        _ => panic!("Unsupported type in header: {}", header),
                    }
                })
                .collect();
            rows.push(row);
        }

        ClearTable::new(table_name, headers.iter().map(|h| h.to_string()).collect(), rows)
    }

    pub fn new(name: String, column_headers: Vec<String>, rows: Vec<Row>) -> Self {
        assert!(!name.is_empty(), "Non-empty name required");
        assert!(!column_headers.is_empty(), "Non-empty column name list required");

        // Verify the column definitions
        let mut columns_def = Vec::new();
        for column_header in &column_headers {
            assert!(column_header.contains(':'), "\":\" separator required");

            let (name, column_type) = column_header.split_once(':').unwrap();
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "Column names must only contain ASCII alphanumeric or '_' chars"
            );

            let type_id = match column_type {
                "bool" => CellTypeId::Bool,
                "int8" | "int16" | "int32" | "int64" => CellTypeId::Int,
                "uint8" | "uint16" | "uint32" | "uint64" => CellTypeId::UInt,
                "string" => CellTypeId::Str,
                _ => panic!("Invalid column type definition"),
            };
            let column_def = ColumnDef {
                name: AsciiStr::new(name.to_owned()),
                type_def: type_id,
            };

            columns_def.push(column_def);
        }

        // Ensure all column names are distinct
        let mut names = HashSet::new();
        for item in &columns_def {
            if !names.insert(&item.name) {
                // If insert returns false, it means the item was already in the set
                panic!(
                    "{}",
                    format!("Column name {:?} appears more than once", item.name.inner)
                )
            }
        }

        // Verify rows
        assert!(!rows.is_empty(), "There must be at least a row");
        assert!(!rows[0].is_empty(), "Rows must contain at least a value");
        let num_columns = column_headers.len();

        for i in 0..num_columns {
            for row in &rows {
                assert_eq!(
                    row.len(),
                    num_columns,
                    "Rows length must match the length of column definitions"
                );
                assert_eq!(
                    row[i].data_type(),
                    columns_def[i].type_def,
                    "Column types must match the column definition"
                );
            }
        }
        ClearTable {
            name,
            columns_def,
            rows,
        }
    }

    // Functions to read fields
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn column_headers(&self) -> Vec<ColumnDef> {
        self.columns_def.clone()
    }

    pub fn column_names(&self) -> Vec<&AsciiStr> {
        self.columns_def.iter().map(|column_def| &column_def.name).collect()
    }

    pub fn column_types(&self) -> impl Iterator<Item = CellTypeId> + '_ {
        self.columns_def.iter().map(|column_def| column_def.type_def)
    }

    pub fn get_column_type(&self, column: &AsciiStr) -> Option<CellTypeId> {
        self.columns_def.iter().find_map(|column_def| {
            if column_def.name == *column {
                Some(column_def.type_def)
            } else {
                None
            }
        })
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    // Returns a bool for each row, indicating if there's a leaf condition match in it or not.
    // For a row to be matched, the condition must be true for a cell in the specified column.
    pub fn evaluate_leaf(
        &self,
        leaf_condition: (&RadixCiphertext, &RadixCiphertext, &EncCells),
        sk: &ServerKey,
    ) -> Vec<BooleanBlock> {
        let (column, op, enc_cells) = leaf_condition;
        let rows_par_iter = self.rows().par_iter();

        rows_par_iter
            .map(|row| {
                // Get the bools for each cell in the row indicating if there was a match
                let matches: Vec<_> = self
                    .column_names()
                    .par_iter()
                    .zip(row)
                    .map(|(current_col, cell)| {
                        // If the column matches that means the two cells are of the same type.
                        // The query builder enforced that all leaves have the proper cell type.
                        let (cell_match, column_match) = rayon::join(
                            || scalar_comparison(cell, enc_cells, op, sk),
                            || sk.scalar_eq_parallelized(column, str_to_big_uint(current_col)),
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
