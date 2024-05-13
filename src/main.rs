use clap::{Arg, Command};
use sql_fhe::{
    decrypt_selection, duckdb_result, encrypt_query, gen_keys, get_headers_for, get_max_col_len,
    get_tables_headers, load_tables, run_fhe_query,
};
use sql_fhe::{parse_sql_select, SqlSelect};
use sqlparser::dialect::GenericDialect;
use std::time::Instant;

fn main() -> duckdb::Result<()> {
    let matches = Command::new("SQL in FHE")
        .arg(
            Arg::new("input-db")
                .long("input-db")
                .value_name("PATH")
                .help("Path to the database directory")
                .required(true),
        )
        .arg(
            Arg::new("query-file")
                .long("query-file")
                .value_name("PATH")
                .help("Path to the file containing the SQL query")
                .required(true),
        )
        .get_matches();

    let db_path = matches.get_one::<String>("input-db").expect("required argument");
    let query_file_path = matches.get_one::<String>("query-file").expect("required argument");

    // SERVER loads the DB and sends the column headers to the client
    let tables = load_tables(db_path);
    let headers = get_tables_headers(&tables);

    // CLIENT generates the keys, loads his SQL query and encrypts it, validating it with the headers
    let (ck, sk) = gen_keys();

    let sql = std::fs::read_to_string(query_file_path).expect("Failed to read query file");
    let sql_select = parse_sql_select(&GenericDialect, &sql);
    let table_name = sql_select.from.first().map(|t| t.relation.to_string()).unwrap();

    let table_headers = get_headers_for(&table_name, &headers);
    let max_col_len = get_max_col_len(&headers);

    let enc = encrypt_query(sql_select.clone(), table_headers, max_col_len, None, &ck);

    // SERVER runs the query homomorphically
    let start = Instant::now();
    let enc_re = run_fhe_query(&tables, &enc, &sk);
    let end = Instant::now();

    // CLIENT decrypts the result and compares it with the duckdb result
    let clear = SqlSelect::from_sqlparser_ast(sql_select, table_headers);
    let selected_columns: Vec<_> = clear.columns().iter().map(|n| n.inner()).collect();

    let clear_re = decrypt_selection(enc_re, &selected_columns, table_headers, &ck);
    let sql_re = duckdb_result(tables.iter().find(|t| t.name() == table_name).unwrap(), &clear.into())?;

    println!("\x1b[33;1mRuntime:\x1b[0m {:?}\n", end.duration_since(start));
    println!("\x1b[36;1mClear DB query result:\x1b[0m\n{}", sql_re);
    println!("\x1b[35;1mEncrypted DB query result:\x1b[0m\n{}", clear_re);

    assert_eq!(clear_re.rows(), sql_re.rows());
    println!("Results match: \x1b[32mYES\x1b[0m");

    Ok(())
}
