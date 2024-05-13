use super::leaf_operations::{encrypt_str, EncCells};
use crate::sql::{LeafOp, SqlExpr, SqlSelect};
use crate::ColumnDef;
use tfhe::integer::{BooleanBlock, ClientKey, RadixCiphertext};

pub enum EncSqlExpr {
    EncNode {
        left: Box<EncSqlExpr>,
        // false means AND, true means OR
        op: BooleanBlock,
        right: Box<EncSqlExpr>,
        negated: BooleanBlock,
    },
    EncLeaf {
        left: RadixCiphertext,
        op: RadixCiphertext,
        right: EncCells,
        negated: BooleanBlock,
    },
}

// Encrypted SQL Select type with an AST as where_clause
pub struct EncSqlSelect {
    selected_columns: Vec<BooleanBlock>,
    from: RadixCiphertext,
    where_clause: Option<EncSqlExpr>,
    distinct: BooleanBlock,
}

fn encrypt_perfect_ast(expr: &SqlExpr, leaf_size: usize, ck: &ClientKey) -> EncSqlExpr {
    let target_depth = calculate_max_depth(expr);
    let enc_expr = encrypt_expr(expr, leaf_size, ck);

    balance_tree(enc_expr, leaf_size, 1, target_depth, ck)
}

// The AND operator uses an encrypted flag with value 0 while OR with value 1
fn encrypt_expr(expr: &SqlExpr, leaf_size: usize, ck: &ClientKey) -> EncSqlExpr {
    match expr {
        SqlExpr::And { left, right, negated } => EncSqlExpr::EncNode {
            // False means AND
            op: ck.encrypt_bool(false),
            left: Box::new(encrypt_expr(left, leaf_size, ck)),
            right: Box::new(encrypt_expr(right, leaf_size, ck)),
            negated: ck.encrypt_bool(*negated),
        },
        SqlExpr::Or { left, right, negated } => EncSqlExpr::EncNode {
            // True means OR
            op: ck.encrypt_bool(true),
            left: Box::new(encrypt_expr(left, leaf_size, ck)),
            right: Box::new(encrypt_expr(right, leaf_size, ck)),
            negated: ck.encrypt_bool(*negated),
        },
        SqlExpr::Leaf {
            left,
            op,
            right,
            negated,
        } => {
            let (new_negated, enc_op) = match op {
                // We use these flags to represent each operator
                LeafOp::Eq => (*negated, ck.encrypt_radix(0u8, 2)),
                LeafOp::Lt => (*negated, ck.encrypt_radix(1u8, 2)),
                LeafOp::Gt => (*negated, ck.encrypt_radix(2u8, 2)),
                LeafOp::Bt => (*negated, ck.encrypt_radix(3u8, 2)),
                LeafOp::In => (*negated, ck.encrypt_radix(4u8, 2)),
                // Write the Ne operator as a negated Eq (if it was already negated the two NOTs
                // cancel out, and we end up with just an Eq)
                LeafOp::Ne => (!negated, ck.encrypt_radix(0u8, 2)),
                // Write the Ge operator as a negated Lt
                LeafOp::Ge => (!negated, ck.encrypt_radix(1u8, 2)),
                // Write the Le operator as a negated Gt
                LeafOp::Le => (!negated, ck.encrypt_radix(2u8, 2)),
            };

            EncSqlExpr::EncLeaf {
                left: encrypt_str(left, ck),
                op: enc_op,
                right: EncCells::new(right, leaf_size, ck),
                negated: ck.encrypt_bool(new_negated),
            }
        }
    }
}

// Balances an EncSqlExpr tree to make it a perfect tree
fn balance_tree(
    expr: EncSqlExpr,
    leaf_size: usize,
    current_depth: usize,
    target_depth: usize,
    ck: &ClientKey,
) -> EncSqlExpr {
    if current_depth == target_depth {
        return expr;
    }
    match expr {
        // If we are in a leaf, and not in the target depth, recursively replace the leaf with an
        // OR node that includes the leaf and a NoOp leaf, until the target depth is reached.
        // The OR will simply propagate the results from any non-NoOp leaf.
        //
        // I.e. OR(AND(leaf1, leaf2), leaf3) = OR(AND(leaf1, leaf2), OR_PAD(leaf3, noop_leaf))
        EncSqlExpr::EncLeaf { .. } => {
            let pad_leaf = noop_leaf(leaf_size, ck);
            let or = ck.encrypt_bool(true);

            EncSqlExpr::EncNode {
                left: Box::new(balance_tree(expr, leaf_size, current_depth + 1, target_depth, ck)),
                right: Box::new(balance_tree(pad_leaf, leaf_size, current_depth + 1, target_depth, ck)),
                op: or,
                negated: ck.encrypt_bool(false),
            }
        }
        EncSqlExpr::EncNode {
            left,
            right,
            op,
            negated,
        } => EncSqlExpr::EncNode {
            left: Box::new(balance_tree(*left, leaf_size, current_depth + 1, target_depth, ck)),
            right: Box::new(balance_tree(*right, leaf_size, current_depth + 1, target_depth, ck)),
            op,
            negated,
        },
    }
}

/// Calculates the maximum depth of an SqlExpr
fn calculate_max_depth(expr: &SqlExpr) -> usize {
    match expr {
        SqlExpr::And { left, right, .. } | SqlExpr::Or { left, right, .. } => {
            1 + std::cmp::max(calculate_max_depth(left), calculate_max_depth(right))
        }
        SqlExpr::Leaf { .. } => 1, // Leaf nodes are at depth 1
    }
}

/// Represents a no-operation leaf node used for padding in the AST. The flag uses the value 5.
fn noop_leaf(leaf_size: usize, ck: &ClientKey) -> EncSqlExpr {
    EncSqlExpr::EncLeaf {
        left: encrypt_str(&"".into(), ck),
        op: ck.encrypt_radix(5u8, 2),
        right: EncCells::new(&[0u64.into()], leaf_size, ck),
        negated: ck.encrypt_bool(false),
    }
}

fn assert_leaf_depths(expr: &EncSqlExpr, current_depth: usize, target_depth: usize) {
    match expr {
        EncSqlExpr::EncNode { left, right, .. } => {
            // Recursively check the depth for both the left and right subtrees
            assert_leaf_depths(left, current_depth + 1, target_depth);
            assert_leaf_depths(right, current_depth + 1, target_depth);
        }
        EncSqlExpr::EncLeaf { .. } => {
            // Assert that the current depth equals the target depth for leaf nodes
            assert_eq!(
                current_depth, target_depth,
                "Leaf at depth {} but target depth is {}",
                current_depth, target_depth
            );
        }
    }
}

impl EncSqlSelect {
    // Encrypts our SqlSelect type, given the optional leaf size and column headers in order to
    // provide the selected columns as a BooleanBlock vector
    pub fn new(
        clear: &SqlSelect,
        leaf_size: Option<usize>,
        column_headers: &[ColumnDef],
        max_col_len: usize,
        ck: &ClientKey,
    ) -> Self {
        let where_clause = clear.where_clause().as_ref().map(|expr| {
            let max_leaf_size = expr
                .leaves()
                .map(|leaf| leaf.2.len())
                .max()
                .expect("If there's a SqlExpr then there are leaves");

            // If None, always use at least a leaf size of two
            let final_leaf_size = leaf_size.unwrap_or_else(|| max_leaf_size.max(2));

            let enc_ast = encrypt_perfect_ast(expr, final_leaf_size, ck);
            let target_depth = calculate_max_depth(expr);
            assert_leaf_depths(&enc_ast, 1, target_depth);

            enc_ast
        });

        let mut selected_columns = Vec::new();
        let wildcard = clear.columns().contains(&"*".into());
        for col in column_headers {
            // Current column in the headers is selected if it appears in the query or query is "*"
            let is_selected = clear.columns().contains(col.name()) | wildcard;
            selected_columns.push(ck.encrypt_bool(is_selected));
        }

        // Check if padding is needed and apply
        if selected_columns.len() < max_col_len {
            selected_columns.resize(max_col_len, ck.encrypt_bool(false));
        }

        let from = encrypt_str(clear.from(), ck);
        let distinct = ck.encrypt_bool(clear.distinct());

        EncSqlSelect {
            selected_columns,
            from,
            where_clause,
            distinct,
        }
    }

    pub fn select_columns(&self) -> &[BooleanBlock] {
        &self.selected_columns
    }

    pub fn from(&self) -> &RadixCiphertext {
        &self.from
    }

    pub fn where_clause(&self) -> Option<&EncSqlExpr> {
        self.where_clause.as_ref()
    }

    pub fn distinct(&self) -> &BooleanBlock {
        &self.distinct
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt_query, gen_keys, parse_sql_select, CellTypeId, ColumnDef};
    use sqlparser::dialect::GenericDialect;

    // TODO maybe remove
    fn dec_ast(ast: &EncSqlExpr, ck: &ClientKey) -> String {
        match ast {
            EncSqlExpr::EncNode {
                op,
                left,
                right,
                negated,
            } => {
                let lhs = dec_ast(left, ck);
                let rhs = dec_ast(right, ck);
                let re = if ck.decrypt_bool(op) {
                    format!("OR({}, {})", lhs, rhs)
                } else {
                    format!("AND({}, {})", lhs, rhs)
                };
                if ck.decrypt_bool(negated) {
                    format!("NOT {}", re)
                } else {
                    re
                }
            }
            EncSqlExpr::EncLeaf { op, negated, .. } => {
                let re = if ck.decrypt_radix::<u8>(op) == 5u8 {
                    "NOOP LEAF".to_string()
                } else {
                    "LEAF".to_string()
                };
                if ck.decrypt_bool(negated) {
                    format!("NOT {}", re)
                } else {
                    re
                }
            }
        }
    }

    fn example_column_headers() -> Vec<ColumnDef> {
        vec![
            ColumnDef {
                name: "id".into(),
                type_def: CellTypeId::UInt,
            },
            ColumnDef {
                name: "name".into(),
                type_def: CellTypeId::Str,
            },
            ColumnDef {
                name: "age".into(),
                type_def: CellTypeId::UInt,
            },
            ColumnDef {
                name: "net_worth".into(),
                type_def: CellTypeId::Int,
            },
        ]
    }

    #[test]
    fn test_calculate_depth() {
        let column_headers = example_column_headers();

        // This condition tree has a max depth of 5 (Leaves -> AND -> NOT OR -> OR -> AND)
        let sql = "SELECT * FROM users WHERE \
        (NOT((id != 0 AND name NOT IN ('Carol', 'Jaime', 'Moises')) OR age BETWEEN 18 AND 35) \
        OR name = 'Pepelu') \
        AND name > 'AA'";
        let sql_select = parse_sql_select(&GenericDialect, sql);
        let clear = SqlSelect::from_sqlparser_ast(sql_select, &column_headers);
        let clear_ast = clear.where_clause().as_ref().unwrap();

        assert_eq!(calculate_max_depth(clear_ast), 5);
    }

    #[test]
    fn test_balanced_ast() {
        let column_headers = example_column_headers();

        let sql = "SELECT id, name FROM users WHERE \
        (((id != 0 AND name NOT IN ('Carol', 'Jaime', 'Moises')) AND (age BETWEEN 18 AND 35 OR age > 70)) OR net_worth < 0) \
        OR id > 600";
        let sql_select = parse_sql_select(&GenericDialect, sql);

        let (ck, _) = gen_keys();

        let clear = SqlSelect::from_sqlparser_ast(sql_select.clone(), &column_headers);
        let clear_ast = clear.where_clause().as_ref().unwrap();

        let enc = encrypt_query(sql_select, &column_headers, column_headers.len(), None, &ck);
        let enc_ast = enc.where_clause.as_ref().unwrap();
        println!("{}", dec_ast(enc_ast, &ck));

        assert_leaf_depths(enc_ast, 1, calculate_max_depth(clear_ast));
    }
}
