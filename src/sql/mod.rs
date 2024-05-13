use crate::{AsciiStr, Cell};
use duckdb::ToSql;

mod parser;
pub mod sql_backend;

// Operator used to compare the cells of a column with a given value
#[derive(Debug, Clone, Copy)]
pub enum LeafOp {
    Eq, // ==
    Ne, // !=
    Gt, // >
    Lt, // <
    Ge, // >=
    Le, // <=
    In, // IN
    Bt, // BETWEEN
}

// The WHERE condition tree
#[derive(Debug, Clone)]
pub enum SqlExpr {
    // Logically joins two conditions with And / Or
    And {
        left: Box<SqlExpr>,
        right: Box<SqlExpr>,
        negated: bool, // if set, this node is NOT AND
    },
    Or {
        left: Box<SqlExpr>,
        right: Box<SqlExpr>,
        negated: bool, // if set, this node is NOT OR
    },
    // A leaf condition, which ends recursion. Left holds the name of the column and right
    // holds the cells used in the comparison (variable number of cells for the IN operator)
    Leaf {
        left: AsciiStr,
        op: LeafOp,
        right: Vec<Cell>,
        negated: bool,
    },
}

impl SqlExpr {
    // Returns an iterator over the leaves, ignoring any NOTs
    pub fn leaves(&self) -> Box<dyn Iterator<Item = (&AsciiStr, &LeafOp, &Vec<Cell>)> + '_> {
        match self {
            SqlExpr::And { left, right, .. } | SqlExpr::Or { left, right, .. } => {
                Box::new(left.leaves().chain(right.leaves()))
            }
            SqlExpr::Leaf { left, op, right, .. } => Box::new(std::iter::once((left, op, right))),
        }
    }

    // Convert the WHERE expr into the format used in duckdb. The sql string uses '?' placeholders
    // and the respective values are ToSql trait objects
    fn to_sql(&self) -> (String, Vec<Box<dyn ToSql>>) {
        let mut values: Vec<Box<dyn ToSql>> = Vec::new();

        let sql = match self {
            SqlExpr::And { left, right, negated } => {
                let (left_sql, mut left_values) = left.to_sql();
                let (right_sql, mut right_values) = right.to_sql();
                values.append(&mut left_values);
                values.append(&mut right_values);
                let and_sql = format!("({}) AND ({})", left_sql, right_sql);
                if *negated {
                    format!("NOT({})", and_sql)
                } else {
                    and_sql
                }
            }
            SqlExpr::Or { left, right, negated } => {
                let (left_sql, mut left_values) = left.to_sql();
                let (right_sql, mut right_values) = right.to_sql();
                values.append(&mut left_values);
                values.append(&mut right_values);
                let or_sql = format!("({}) OR ({})", left_sql, right_sql);
                if *negated {
                    format!("NOT({})", or_sql)
                } else {
                    or_sql
                }
            }
            SqlExpr::Leaf {
                left,
                op,
                right,
                negated,
            } => {
                let operator = match op {
                    LeafOp::Eq => "=",
                    LeafOp::Ne => "!=",
                    LeafOp::Gt => ">",
                    LeafOp::Lt => "<",
                    LeafOp::Ge => ">=",
                    LeafOp::Le => "<=",
                    LeafOp::In => "IN",
                    LeafOp::Bt => "BETWEEN",
                };
                // Collect the parameters
                right.iter().for_each(|cell| values.push(cell.into()));
                // Get the SQL string where '?' is a placeholder for the actual cell value
                let leaf_sql = match operator {
                    "IN" => {
                        let placeholders = std::iter::repeat("?").take(right.len()).collect::<Vec<_>>().join(", ");
                        format!("{} IN ({})", left.inner(), placeholders)
                    }
                    "BETWEEN" => {
                        assert_eq!(right.len(), 2, "BETWEEN operator expects two values");
                        format!("{} BETWEEN ? AND ?", left.inner())
                    }
                    _ => format!("{} {} ?", left.inner(), operator),
                };

                if *negated {
                    format!("NOT({})", leaf_sql)
                } else {
                    leaf_sql
                }
            }
        };

        (sql, values)
    }
}

impl From<&Cell> for Box<dyn ToSql> {
    fn from(value: &Cell) -> Self {
        match value {
            Cell::Bool(b) => Box::new(*b),
            Cell::Int(int) => Box::new(*int),
            Cell::UInt(uint) => Box::new(*uint),
            Cell::Str(str) => Box::new(str.inner().to_string()),
        }
    }
}

// Clear SQL Select type with an AST as where_clause. This is the type that we use for encryption (internally).
#[derive(Debug, Clone)]
pub struct SqlSelect {
    columns: Vec<AsciiStr>,
    from: AsciiStr,
    where_clause: Option<SqlExpr>,
    distinct: bool,
}

impl SqlSelect {
    pub fn columns(&self) -> &[AsciiStr] {
        &self.columns
    }

    pub fn from(&self) -> &AsciiStr {
        &self.from
    }

    pub fn where_clause(&self) -> &Option<SqlExpr> {
        &self.where_clause
    }

    pub fn distinct(&self) -> bool {
        self.distinct
    }
}

// Clear SQL Select type used for the duckdb backend
pub struct DuckDBSelect {
    sql: String,
    params: Vec<Box<dyn ToSql>>,
}

impl DuckDBSelect {
    pub fn sql(&self) -> &str {
        &self.sql
    }

    pub fn params(&self) -> impl Iterator<Item = &Box<dyn ToSql>> {
        self.params.iter()
    }
}

impl From<SqlSelect> for DuckDBSelect {
    fn from(value: SqlSelect) -> Self {
        let select = if value.columns.iter().any(|s| s.inner() == "*") {
            // If any of the columns to select is "*", just use "*" to avoid duplicate selections
            "*".to_string()
        } else {
            // Use each different column only once to avoid duplicate selections
            let mut ordered_columns = Vec::new();
            for col in value.columns.iter().map(|s| s.inner()) {
                if !ordered_columns.contains(&col) {
                    ordered_columns.push(col);
                }
            }

            ordered_columns.join(", ")
        };

        let distinct = if value.distinct { "DISTINCT " } else { "" };
        let mut sql = format!("SELECT {}{} FROM {}", distinct, select, value.from.inner());
        let mut params = Vec::new();

        if let Some(expr) = value.where_clause {
            let (sql_expr, mut values) = expr.to_sql();

            sql.push_str(&format!(" WHERE {}", sql_expr));
            params.append(&mut values);
        }

        DuckDBSelect { sql, params }
    }
}
