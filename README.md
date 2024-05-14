# Sql_fhe

Implementation of an encrypted SQL `SELECT` query, executed in FHE over a clear database.

The client encrypts the query, and the server, which has access to the clear database, executes `run_fhe_query` on it. The encrypted result is then decrypted by the client and compared against the `duckdb` SQL backend result.

## Usage

To run the program you will need to specify a path to the database directory, with each table as a csv file, and the path to a file containing the SQL query.

```
cargo run --release -- --input-db path/to/db_dir --query-file path/to/query.txt
```

The supported table types are bools, 8-bit, 16-bit, 32-bit and 64-bit signed and unsigned integers, as well as short strings (up to 32 ASCII characters). The csv files must contain column headers with the following format:

```
column_1_name:int64,column_2_name:uint64,column_3_name:string,column_4_name:bool
```

Tests can simply be run with `cargo test --release`, although this will be very slow.

## Supported SQL Operators
- `=` and `!=` for all types. For boolean columns, you can use the column name without an operator to check if it is `true` (e.g. `is_employed` is equivalent to `is_employed = true`).
- `>`, `<`, `>=`, `<=`, `BETWEEN`, `NOT BETWEEN`, `IN` and `NOT IN` for all types except bools.
- `AND`, `OR` and `NOT` to combine conditions. Nested `NOT`s are properly reduced before encryption.
- The `DISTINCT` flag.

## Encrypted Query Format

Our encrypted query contains an encrypted bool vector signaling which columns are selected, the encrypted selected table name (`FROM`), a perfect Abstract Syntax Tree with encrypted node operators and leaves (the `WHERE` conditions) and the encrypted `DISTINCT` boolean flag.

The selected columns vector is set to the maximum column length across all tables to prevent the server from inferring information about the selected table.

Additionally, the `WHERE` AST is filled with (encrypted) NoOp leaves to conceal the exact tree structure. Leaves contain arguments for comparison operators, which require a single encrypted value, and for `BETWEEN` and `IN` operators, which can contain two or more values. We pad the leaves to a constant size to prevent the server from inferring the leaf operator. The minimum leaf size is 2, as the `BETWEEN` operator requires two values (lower and upper bounds).

Finally, all leaf values must be encrypted with the same bit length to prevent the server from deducing the column type. For example, `SELECT ... WHERE enc_col enc_op 64_bit_enc_value` would reveal information about the column type being compared.

## Optimizations

### Homomorphic Table Selection

The server needs to perform the `WHERE` and `DISTINCT` computations on the selected table. If there's only one table in the database, server doesn't need to perform any table selection in FHE. That table **is** the selected one as the client cannot select a non-existing table.

However, if there are two or more tables in the database, the server will compute the union of all tables. In this union, only overlapping values between two or more tables are selected using FHE. Values from a table that do not overlap with others at the same position are kept in the clear.

### Leaf Operations

To optimize leaf operations we "recycle" computations in the following way (note that the boolean operators here refer to the FHE boolean methods):
- `!=` is computed as `NOT =`.
- `>` is computed as `NOT = AND NOT <`.
- `>=` is computed as `NOT <`.
- `<=` is computed as `NOT >`.
- The lower bound comparison of `BETWEEN` is the `>=` result.
- The first equality comparison of `IN` is the `=` result.

Technically, our leaf evaluation functions are not aware of the `!=`, `>=`, and `<=` operations, as these operators are rewritten before encryption as a negated `=`, `<`, and `>`, respectively.

### Compact ASCII Representation

Another potential optimization would be to use 7 bits (rather than 8) for each ASCII character. Since all the leaf values are stored with the maximum bit length, we could reduce this length by 12.5%. While this optimization is straightforward, it is not particularly interesting, so we are currently using 8 bits.
