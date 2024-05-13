use crate::sql::DuckDBSelect;
use crate::{AsciiStr, Cell, CellTypeId, ClearResult, ClearTable};
use duckdb::types::ValueRef;
use duckdb::{params_from_iter, ToSql};
use std::collections::HashMap;

// Convert the duckdb result values into our custom Cell type
impl<'a> From<ValueRef<'a>> for Cell {
    fn from(value: ValueRef) -> Self {
        match value {
            ValueRef::Boolean(b) => Cell::Bool(b),
            ValueRef::BigInt(int) => Cell::Int(int),
            ValueRef::UBigInt(uint) => Cell::UInt(uint),
            ValueRef::Text(str) => Cell::Str(AsciiStr::new(String::from_utf8(str.to_vec()).unwrap())),
            _ => panic!("Unsupported cell type"),
        }
    }
}

// Returns the duckdb result as a hashmap of selected rows
pub fn duckdb_result(table: &ClearTable, query: &DuckDBSelect) -> duckdb::Result<ClearResult> {
    let conn = duckdb::Connection::open_in_memory().unwrap(); // Creates a new, temporary in-memory database

    // Creating a table
    let sql_create = sql_create(table);
    conn.execute(&sql_create, []).unwrap();

    // Inserting the cells, converting them to the ToSql trait object
    let sql_insert = sql_insert(table);
    let mut values: Vec<Box<dyn ToSql>> = Vec::new();
    for row in table.rows() {
        for cell in row {
            values.push(cell.into())
        }
    }
    conn.execute(&sql_insert, params_from_iter(values)).unwrap();

    // Perform the duckdb query
    let mut stmt = conn.prepare(query.sql()).unwrap();
    let mut rows = stmt.query(params_from_iter(query.params())).unwrap();
    let mut row_values = HashMap::new();

    // For each matching row ...
    while let Some(row) = rows.next().unwrap() {
        let mut idx = 0;
        let mut values = Vec::new();
        // ... get each queried value
        while let Ok(value) = row.get_ref(idx) {
            values.push(value.into());
            idx += 1;
        }

        // Increment the count of this particular set of cell values in the outer HashMap
        *row_values.entry(values).or_insert(0) += 1;
    }

    Ok(ClearResult { rows: row_values })
}

// SQL string to create the table in duckdb
fn sql_create(table: &ClearTable) -> String {
    // "CREATE TABLE name (..."
    let mut create = "CREATE TABLE ".to_owned() + table.name() + " (";
    let mut column_definitions = Vec::new();

    for (column_name, column_type) in table.column_names().iter().zip(table.column_types()) {
        let type_str = match column_type {
            CellTypeId::Bool => "BOOLEAN",
            CellTypeId::Int => "BIGINT",
            CellTypeId::UInt => "UBIGINT",
            CellTypeId::Str => "TEXT",
        };

        column_definitions.push(format!("{} {}", column_name.inner(), type_str));
    }

    // Join all column definitions with commas and push the result
    // E.g. "CREATE TABLE name (column_1 TYPE, column_2 TYPE, ... )"
    let columns_str = column_definitions.join(", ");
    create.push_str(&columns_str);
    create.push(')');

    println!("{create}");
    create
}

// SQL string to populate the table in duckdb
fn sql_insert(table: &ClearTable) -> String {
    // "INSERT INTO name VALUES ..."
    let mut insert = "INSERT INTO ".to_owned() + table.name() + " VALUES";

    let mut rows_str = Vec::new();
    for row in table.rows() {
        // Create a string of "?" placeholders separated by commas, matching the number of cells in the row
        let placeholders: Vec<&str> = vec!["?"; row.len()];
        rows_str.push(format!("({})", placeholders.join(",")));
    }

    // Join all row strings with commas and push
    // E.g. "INSERT INTO name VALUES (?,?), (?,?), ..."
    let rows_insert_str = rows_str.join(", ");
    insert.push_str(&rows_insert_str);

    println!("{insert}");
    insert
}
