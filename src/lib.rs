mod engine;
mod sql;

use crate::engine::{distinct, distinct_enc};
// Re-exports of core types
pub use crate::engine::enc_query::EncSqlSelect;
pub use crate::engine::table::{AsciiStr, Cell, CellTypeId, ClearTable, ColumnDef};
pub use crate::sql::{sql_backend::duckdb_result, DuckDBSelect, SqlSelect};

use crate::engine::leaf_operations::EncCells;
use crate::engine::table_selection::{select_table, Table};
use rayon::prelude::*;
use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::Dialect;
use sqlparser::parser::Parser;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::path::Path;
use std::{fmt, fs};
use tfhe::integer::{BooleanBlock, ClientKey, ServerKey};
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
};
use tfhe::shortint::PBSParameters;

/// Convenient function to parse an sql SELECT statement
pub fn parse_sql_select(dialect: &dyn Dialect, sql: &str) -> sqlparser::ast::Select {
    let ast = Parser::parse_sql(dialect, sql).expect("Failed to parse SQL");

    match ast.first().expect("No statement found") {
        Statement::Query(query) => match query.body.deref() {
            SetExpr::Select(select) => *select.clone(),
            _ => panic!("Expected a SELECT expression"),
        },
        _ => panic!("Expected a query statement"),
    }
}

pub fn default_cpu_parameters() -> PBSParameters {
    if cfg!(not(feature = "multi_bit_pbs")) {
        PBSParameters::PBS(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
    } else {
        PBSParameters::MultiBitPBS(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS)
    }
}

pub fn gen_keys() -> (ClientKey, ServerKey) {
    let ck = ClientKey::new(default_cpu_parameters());
    let sk = ServerKey::new_radix_server_key(&ck);

    (ck, sk)
}

pub fn load_tables(path: &str) -> Vec<ClearTable> {
    let mut tables = Vec::new();
    let path = Path::new(path);

    if path.is_dir() {
        for entry in fs::read_dir(path).expect("Directory cannot be read") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();
            if path.is_file() && path.extension().and_then(std::ffi::OsStr::to_str) == Some("csv") {
                if let Some(name) = path.file_stem().and_then(std::ffi::OsStr::to_str) {
                    let table = ClearTable::read_from_csv(&path, name.to_string());
                    tables.push(table);
                }
            }
        }
    } else {
        panic!("Not a directory")
    }
    assert!(!tables.is_empty(), "No table was read from csv files");

    // Ensure all table names are distinct
    let mut names = HashSet::new();
    for item in &tables {
        if !names.insert(item.name()) {
            // If insert returns false, it means the item was already in the set
            panic!("{}", format!("Table name {:?} appears more than once", item.name()))
        }
    }

    tables
}

// Helper function to get the headers the server will send to the client
pub fn get_tables_headers(tables: &[ClearTable]) -> Vec<(Vec<ColumnDef>, AsciiStr)> {
    tables
        .iter()
        .map(|table| (table.column_headers(), table.name().into()))
        .collect()
}

// Helper function to get the headers from the table the client is interested in
pub fn get_headers_for<'a>(table_name: &str, headers: &'a [(Vec<ColumnDef>, AsciiStr)]) -> &'a [ColumnDef] {
    headers
        .iter()
        .find_map(|(h, name)| (name.inner() == table_name).then_some(h))
        .unwrap()
}

// Helper function to get the maximum column length from all the tables. This is needed to pad the
// column selection bools in order to hide information about the table we are interested in
pub fn get_max_col_len(headers: &[(Vec<ColumnDef>, AsciiStr)]) -> usize {
    headers
        .iter()
        .map(|table| table.0.len())
        .max()
        .expect("At least one table expected")
}

/// Encrypts a sqlparser::ast::Select query. Requires the column headers in order to parse and
/// validate the query values, an optional AST leaf size and the client key.
///
/// The AST leaf size is the number of encrypted values in each leaf: The IN operator can use many
/// values, so we need all leaves to have a constant size in order to not leak the specific leaves
/// where IN is used.
///
/// If None is specified, the size of the leaves will be the maximum leaf size found in the query
/// if it's greater than 2. Otherwise, default is 2 such that we don't reveal that we are not using
/// the IN / BETWEEN operators.
pub fn encrypt_query(
    query: sqlparser::ast::Select,
    column_headers: &[ColumnDef],
    max_col_len: usize,
    leaf_size: Option<usize>,
    ck: &ClientKey,
) -> EncSqlSelect {
    assert!(
        column_headers.len() <= max_col_len,
        "'column_headers' cannot be longer than 'max_col_len'",
    );
    if let Some(size) = leaf_size {
        assert!(
            size >= 2,
            "Minimum leaf size is 2 in order to hide uses of IN / BETWEEN"
        );
    }
    let clear = SqlSelect::from_sqlparser_ast(query, column_headers);

    EncSqlSelect::new(&clear, leaf_size, column_headers, max_col_len, ck)
}

pub struct EncResult {
    selected_rows: Vec<BooleanBlock>,
    enc_rows: Vec<Vec<EncCells>>,
}

pub fn run_fhe_query(tables: &[ClearTable], enc_query: &EncSqlSelect, sk: &ServerKey) -> EncResult {
    let table = select_table(tables, enc_query.from(), sk);
    let where_clause = enc_query.where_clause().expect("Assuming there's a where clause");

    // Get the bools indicating which rows are selected
    let mut selected_rows = table.evaluate_expression(where_clause, sk);
    let distinct_selected_rows = match &table {
        Table::Clear(clear) => distinct(clear.rows(), enc_query.select_columns(), &selected_rows, sk),
        Table::PartiallyEnc(partially_enc) => {
            distinct_enc(&partially_enc.rows, enc_query.select_columns(), &selected_rows, sk)
        }
    };

    let (_, enc_rows) = rayon::join(
        || {
            // Choose between the selected rows or the DISTINCT selected rows
            selected_rows = selected_rows
                .par_iter()
                .zip(&distinct_selected_rows)
                .map(|(s, d)| {
                    let (distinct, not_distinct) = rayon::join(
                        || sk.boolean_bitand(enc_query.distinct(), d),
                        || sk.boolean_bitand(&sk.boolean_bitnot(enc_query.distinct()), s),
                    );

                    sk.boolean_bitor(&distinct, &not_distinct)
                })
                .collect();
        },
        || table.mask_table(sk),
    );

    EncResult {
        selected_rows,
        enc_rows,
    }
}

// Decrypt the encrypted table and selection bools and collect the selected rows in a hashmap
pub fn decrypt_selection(
    enc_result: EncResult,
    selected_columns: &[&str],
    column_headers: &[ColumnDef],
    ck: &ClientKey,
) -> ClearResult {
    let clear_rows: Vec<Vec<Cell>> = enc_result
        .enc_rows
        .iter()
        .map(|row| {
            row.iter()
                .filter_map(|enc_cell| {
                    let is_selected = &enc_cell.first_inner().1;
                    ck.decrypt_bool(is_selected).then_some(enc_cell.decrypt_first(ck))
                })
                .collect()
        })
        .collect();

    let clear_selected_rows: Vec<bool> = enc_result
        .selected_rows
        .iter()
        .map(|bool| ck.decrypt_bool(bool))
        .collect();

    let mut result = HashMap::new();

    for (row, is_row_selected) in clear_rows.iter().zip(clear_selected_rows) {
        // An empty row means that all cells are from not selected tables
        if !is_row_selected || row.is_empty() {
            continue;
        }

        let row_result = if selected_columns.contains(&"*") {
            row.clone()
        } else {
            let headers_idx: HashMap<&str, usize> = column_headers
                .iter()
                .enumerate()
                .map(|(index, header)| (header.name().inner(), index))
                .collect();

            // In the order of 'selected_columns' retrieve their header index and use it to get the cell
            selected_columns
                .iter()
                .filter_map(|col_name| headers_idx.get(col_name).and_then(|&idx| row.get(idx).cloned()))
                .collect()
        };
        if !row_result.is_empty() {
            // Increment the count of this row in the HashMap
            *result.entry(row_result).or_insert(0) += 1;
        }
    }

    ClearResult { rows: result }
}

pub struct ClearResult {
    rows: HashMap<Vec<Cell>, u32>,
}

impl ClearResult {
    pub fn rows(&self) -> &HashMap<Vec<Cell>, u32> {
        &self.rows
    }
}

impl fmt::Display for ClearResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Collect and sort rows based on both Vec<Cell> and count
        let mut sorted_rows: Vec<_> = self.rows.iter().collect();
        sorted_rows.sort_by(|(a_vec, a_count), (b_vec, b_count)| a_vec.cmp(b_vec).then(a_count.cmp(b_count)));

        // Format each row for display
        for (vec, count) in sorted_rows {
            let row_string = vec.iter().map(Cell::to_string).collect::<Vec<_>>().join(",");
            writeln!(f, "{} - Count: {}", row_string, count)?;
        }
        Ok(())
    }
}
