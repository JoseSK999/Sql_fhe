use sql_fhe::{
    decrypt_selection, encrypt_query, gen_keys, get_headers_for, get_max_col_len, get_tables_headers, load_tables,
    parse_sql_select, run_fhe_query,
};
use sql_fhe::{duckdb_result, ClearTable, SqlSelect};
use sqlparser::dialect::GenericDialect;

fn test_query_on_tables(query: &str, tables: Vec<ClearTable>) -> duckdb::Result<()> {
    let (ck, sk) = gen_keys();
    let sql_select = parse_sql_select(&GenericDialect, query);

    let from = sql_select
        .from
        .first()
        .and_then(|t| Some(t.relation.to_string()))
        .unwrap();
    let headers = get_tables_headers(&tables);
    let table_headers = get_headers_for(&from, &headers);
    let max_col_len = get_max_col_len(&headers);

    // Run the FHE function and compare results with duckdb
    let enc_select = encrypt_query(sql_select.clone(), &table_headers, max_col_len, Some(4), &ck);

    let clear_select = SqlSelect::from_sqlparser_ast(sql_select, &table_headers);
    let selected_columns: Vec<_> = clear_select.columns().iter().map(|n| n.inner()).collect();

    let sql_result = duckdb_result(
        &tables.iter().find(|t| t.name() == from).unwrap(),
        &clear_select.clone().into(),
    )?;

    let enc_result = run_fhe_query(&tables, &enc_select, &sk);
    let clear_result = decrypt_selection(enc_result, &selected_columns, &table_headers, &ck);

    println!("\nSQL RESULT: \n{}\nFHE RESULT: \n{}", sql_result, clear_result);
    assert_eq!(clear_result.rows(), sql_result.rows());
    Ok(())
}

#[test]
fn test_1_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT DISTINCT research_area \
    FROM test_table_1 \
    WHERE active = true;";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_2_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT id, participant, score, grant_val FROM test_table_1 WHERE \
    (score >= 50 AND rating BETWEEN 2 AND 4) \
    OR (grant_val < 0 AND research_area IN ('Astrophysics', 'Quantum Mechanics')) \
    OR (participant <> 'Dr. Alpha' AND research_area > 'Microbiology' AND research_area < 'Zoology');";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_3_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT participant, score, research_area \
    FROM test_table_1 \
    WHERE NOT (NOT (NOT (active AND NOT (funded OR NOT (score > 50)))));";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_4_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT participant, score \
    FROM test_table_1 \
    WHERE score >= 9223372036854775807 OR grant_val <= -9223372036854775808;";

    test_query_on_tables(sql, tables)
}

#[test]
#[should_panic]
fn test_5_data_1() -> () {
    let tables = load_tables("tests/test_data_1");

    // The negative number is out of range for an i64
    let sql = "SELECT participant, score \
    FROM test_table_1 \
    WHERE score >= 9223372036854775807 OR grant_val <= -9223372036854775809;";

    test_query_on_tables(sql, tables).unwrap()
}

#[test]
fn test_6_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT DISTINCT participant, score \
    FROM test_table_1 \
    WHERE NOT ((score > 000050 AND score = 000000000000) AND NOT (participant BETWEEN 'Dr. A' AND 'Dr. Z')) \
    OR ((research_area = 'Astrophysics' OR research_area = 'Quantum Mechanics') AND (grant_val BETWEEN -10000 AND 500000) AND active) \
    AND NOT (rating IN (1, 2, 4, 5));";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_7_data_1() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_1");

    let sql = "SELECT DISTINCT *, id, funded \
    FROM test_table_1 \
    WHERE (participant NOT IN ('Dr. Alpha', 'Dr. Gamma') AND score NOT BETWEEN 55 AND 18446744073709551615) \
    OR (NOT (rating > 3 AND rating < 5) AND (grant_val > 1000 OR grant_val < -500) AND NOT (research_area IN ('Microbiology', 'Cryptography')));";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_1_data_2() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_2");

    let sql = "SELECT DISTINCT favorite_game \
    FROM streamers_fav_games \
    WHERE nickname NOT IN ('Ibai', 'ElXokas', 'illojuan');";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_2_data_2() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_2");

    let sql = "SELECT DISTINCT age \
    FROM streamers \
    WHERE lives_in_andorra AND age BETWEEN 25 AND 35;";

    test_query_on_tables(sql, tables)
}

#[test]
fn test_3_data_2() -> duckdb::Result<()> {
    let tables = load_tables("tests/test_data_2");

    let sql = "SELECT DISTINCT content_type, platform \
    FROM streamers_content \
    WHERE (content_type = 'Gameplay' OR content_type = 'Comedy/Gameplay') OR NOT nickname != 'Invicthor';";

    test_query_on_tables(sql, tables)
}
