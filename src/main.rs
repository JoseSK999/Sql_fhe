use sql_fhe::{
    decrypt_selection, duckdb_result, encrypt_query, gen_keys, get_headers_for, get_max_col_len,
    get_tables_headers, load_tables, run_fhe_query,
};
use sql_fhe::{parse_sql_select, SqlSelect};
use sqlparser::dialect::GenericDialect;
use std::time::Instant;

fn main() -> duckdb::Result<()> {
    // SERVER loads the DB and sends the column headers to the client
    let tables = load_tables("src/data");
    let headers = get_tables_headers(&tables);

    // CLIENT generates the keys, loads his SQL query and encrypts it, validating it with the headers
    let (ck, sk) = gen_keys();

    let table_name = "table_2";
    let selected_columns = vec!["name"];
    let sql = format!(
        "SELECT DISTINCT {} FROM {} WHERE senior",
        selected_columns.join(", "),
        table_name,
    );
    let sql_select = parse_sql_select(&GenericDialect, &sql);

    let table_headers = get_headers_for(table_name, &headers);
    let max_col_len = get_max_col_len(&headers);

    let clear = SqlSelect::from_sqlparser_ast(sql_select.clone(), table_headers);
    println!("{:#?}", clear);
    let sql_re = duckdb_result(tables.iter().find(|t| t.name() == table_name).unwrap(), &clear.into())?;
    let enc = encrypt_query(sql_select, table_headers, max_col_len, None, &ck);

    // SERVER runs the query homomorphically
    let start = Instant::now();
    let enc_re = run_fhe_query(&tables, &enc, &sk);
    let end = Instant::now();

    // CLIENT decrypts the result and compares it with the duckdb result
    let clear_re = decrypt_selection(enc_re, &selected_columns, table_headers, &ck);

    println!("\x1b[33;1mRuntime:\x1b[0m {:?}\n", end.duration_since(start));
    println!("\x1b[36;1mClear DB query result:\x1b[0m\n{}", sql_re);
    println!("\x1b[35;1mEncrypted DB query result:\x1b[0m\n{}", clear_re);

    assert_eq!(clear_re.rows(), sql_re.rows());
    println!("Results match: \x1b[32mYES\x1b[0m");

    Ok(())
}
