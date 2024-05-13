use crate::sql::{LeafOp, SqlExpr, SqlSelect};
use crate::{AsciiStr, Cell, CellTypeId, ColumnDef};
use sqlparser::ast::{BinaryOperator, Distinct, Expr, Ident, SelectItem, UnaryOperator, Value};

impl SqlSelect {
    fn builder_check(
        from: String,
        column_headers: &[ColumnDef],
        select_columns: Vec<&str>,
        where_clause: Option<SqlExpr>,
        distinct: bool,
    ) -> Self {
        assert!(!select_columns.is_empty(), "At least a column to select");
        assert!(
            select_columns.len() <= column_headers.len(),
            "We can not select more columns than there are in the table",
        );

        // Try converting the columns to select into AsciiStr and check if they exist
        let select_columns: Vec<_> = select_columns
            .into_iter()
            .map(|str| AsciiStr::new(str.to_owned()))
            .collect();

        for column in &select_columns {
            let found = column_headers.iter().find(|def| column == def.name());
            assert!(
                found.is_some() || column.inner() == "*",
                "No such column: {}",
                column.inner()
            );
        }

        // Also check if the columns in the WHERE conditions exist, and that we compare their cells
        // with values of the same type
        if let Some(clause) = &where_clause {
            let leaves = clause.leaves();

            for (where_column, op, values) in leaves {
                let found = column_headers.iter().find(|def| where_column == def.name());
                assert!(found.is_some(), "No such column: {}", where_column.inner());

                let column_type = column_headers
                    .iter()
                    .find(|def| def.name() == where_column)
                    .expect("At this point we know a column with that name exists")
                    .type_def();

                assert!(!values.is_empty(), "At least a value for the WHERE condition");

                // Validate the BETWEEN values
                if let LeafOp::Bt = op {
                    assert_eq!(values.len(), 2, "BETWEEN operator expects two values");
                    assert!(values[0] <= values[1], "First BETWEEN value must be <= than second one");
                }

                // Unsupported operators for boolean types
                if let CellTypeId::Bool = column_type {
                    match op {
                        LeafOp::Bt | LeafOp::In | LeafOp::Ge | LeafOp::Le | LeafOp::Gt | LeafOp::Lt => {
                            panic!("Operator {:?} not supported for boolean types", op)
                        }
                        _ => (),
                    }
                }

                for cell in values {
                    let cell_type = cell.data_type();

                    assert_eq!(
                        cell_type, column_type,
                        "Cannot compare a {:?} with a column of type {:?}",
                        cell_type, column_type,
                    );
                }
            }
        }

        SqlSelect {
            columns: select_columns,
            from: AsciiStr::new(from),
            where_clause,
            distinct,
        }
    }

    // Using the sqlparser input
    pub fn from_sqlparser_ast(select: sqlparser::ast::Select, column_headers: &[ColumnDef]) -> Self {
        let from = if let Some(table) = select.from.first() {
            table.relation.to_string()
        } else {
            panic!("No FROM clause found");
        };

        let distinct = match select.distinct {
            Some(Distinct::Distinct) => true,
            None => false,
            Some(Distinct::On(_)) => panic!("DISTINCT ON not supported"),
        };

        let columns = select
            .projection
            .iter()
            .map(|item| match item {
                // Direct column name
                SelectItem::UnnamedExpr(Expr::Identifier(Ident { value, .. })) => value.as_str(),
                // Handle the "*" wildcard, which selects all columns
                SelectItem::Wildcard(_) => "*",
                _ => panic!("Unsupported or complex SELECT item"),
            })
            .collect::<Vec<&str>>();

        let where_clause = select.selection.map(|expr| parse_expr(expr, false, column_headers));

        SqlSelect::builder_check(from, column_headers, columns, where_clause, distinct)
    }
}

// From sqlparser::ast::Expr to our custom SqlExpr tree. Uses the column definitions to properly
// parse leaf values (and validate their type)
fn parse_expr(expr: Expr, negate_expr: bool, column_headers: &[ColumnDef]) -> SqlExpr {
    match expr {
        // If 'expr' is an identifier, this is expected to be a boolean_column leaf, which just
        // selects the rows that have a true (e.g. SELECT * FROM table WHERE boolean_column)
        Expr::Identifier(ident) => {
            let column = AsciiStr::new(ident.value);
            let column_type = column_headers
                .iter()
                .find(|def| column == *def.name())
                .unwrap_or_else(|| {
                    panic!(
                        "The column {:?} used in the SQL query does not appear in the headers",
                        column
                    )
                })
                .type_def();

            assert_eq!(
                column_type,
                CellTypeId::Bool,
                "Trying to use a single column name as leaf but it's not boolean",
            );
            // We are checking if column_values are true
            SqlExpr::Leaf {
                left: column,
                op: LeafOp::Eq,
                right: vec![true.into()],
                // If we have a NOT node that precedes this leaf, we take it into account
                negated: negate_expr,
            }
        }
        // Logical NOT: Only parse the inner expr as negated if it's not preceded by another NOT
        // For instance 'NOT(NOT(expr))' should cancel out to just 'expr'
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => parse_expr(*expr, !negate_expr, column_headers),
        // Expr inside parenthesis: Propagate the negate flag
        Expr::Nested(expr) => parse_expr(*expr, negate_expr, column_headers),
        // Logical AND
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => SqlExpr::And {
            left: Box::new(parse_expr(*left, false, column_headers)),
            right: Box::new(parse_expr(*right, false, column_headers)),
            negated: negate_expr,
        },
        // Logical OR
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => SqlExpr::Or {
            left: Box::new(parse_expr(*left, false, column_headers)),
            right: Box::new(parse_expr(*right, false, column_headers)),
            negated: negate_expr,
        },
        // Handling IN by ensuring 'expr' is a column name and 'list' contains the values
        Expr::InList { expr, list, negated } => {
            let column = extract_column_name(*expr);
            let column_type = column_headers
                .iter()
                .find(|def| column == *def.name())
                .unwrap_or_else(|| {
                    panic!(
                        "The column {:?} used in the SQL query does not appear in the headers",
                        column
                    )
                })
                .type_def();

            SqlExpr::Leaf {
                left: column,
                op: LeafOp::In,
                right: list.into_iter().map(|value| parse_cell(value, column_type)).collect(),
                // If this is a 'NOT column_x NOT IN', the NOTs cancel out
                negated: negated ^ negate_expr,
            }
        }
        // Handling BETWEEN
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => {
            let column = extract_column_name(*expr);
            let column_type = column_headers
                .iter()
                .find(|def| column == *def.name())
                .unwrap_or_else(|| {
                    panic!(
                        "The column {:?} used in the SQL query does not appear in the headers",
                        column
                    )
                })
                .type_def();

            SqlExpr::Leaf {
                left: column,
                op: LeafOp::Bt,
                right: vec![parse_cell(*low, column_type), parse_cell(*high, column_type)],
                // If this is a 'NOT column_x NOT BETWEEN', the NOTs cancel out
                negated: negated ^ negate_expr,
            }
        }
        // Handling leaves with comparison operators
        Expr::BinaryOp { left, op, right } => {
            let operator = match op {
                BinaryOperator::Eq => LeafOp::Eq,
                BinaryOperator::NotEq => LeafOp::Ne,
                BinaryOperator::Gt => LeafOp::Gt,
                BinaryOperator::Lt => LeafOp::Lt,
                BinaryOperator::GtEq => LeafOp::Ge,
                BinaryOperator::LtEq => LeafOp::Le,
                _ => panic!("Unsupported operator"),
            };
            let column = extract_column_name(*left);
            let column_type = column_headers
                .iter()
                .find(|def| column == *def.name())
                .unwrap_or_else(|| {
                    panic!(
                        "The column {:?} used in the SQL query does not appear in the headers",
                        column
                    )
                })
                .type_def();

            SqlExpr::Leaf {
                left: column,
                op: operator,
                right: vec![parse_cell(*right, column_type)],
                negated: negate_expr,
            }
        }
        _ => panic!("Unsupported expression type"),
    }
}

// Helper function to extract the column name from an Expr, which is expected to be an identifier
fn extract_column_name(expr: Expr) -> AsciiStr {
    if let Expr::Identifier(ident) = expr {
        AsciiStr::new(ident.value)
    } else {
        panic!("Expected a column name");
    }
}

fn parse_cell(expr: Expr, data_type: CellTypeId) -> Cell {
    match expr {
        Expr::Value(Value::Number(n, _)) => match data_type {
            CellTypeId::Int => n.parse::<i64>().map(Cell::Int).expect("Failed to parse i64"),
            CellTypeId::UInt => n.parse::<u64>().map(Cell::UInt).expect("Failed to parse u64"),
            _ => panic!("Number provided but expected data type was {:?}", data_type),
        },
        // Handle a possible negative number
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => {
            if let Expr::Value(Value::Number(n, _)) = *expr {
                if data_type == CellTypeId::Int {
                    // We have to parse as i128 because the absolute value of i64::MIN will
                    // overflow in i64
                    let abs = n.parse::<i128>().expect("Failed to parse i64");
                    Cell::Int((-abs).try_into().expect("Failed to parse i64"))
                } else {
                    panic!("Negative number used to compare a column which is not Int")
                }
            } else {
                panic!("Negative sign was found in the query without a number")
            }
        }
        Expr::Value(Value::SingleQuotedString(s)) => match data_type {
            CellTypeId::Str => Cell::Str(AsciiStr::new(s)),
            _ => panic!("String provided but expected data type was {:?}", data_type),
        },
        Expr::Value(Value::Boolean(b)) => match data_type {
            CellTypeId::Bool => Cell::Bool(b),
            _ => panic!("Boolean provided but expected data type was {:?}", data_type),
        },
        _ => panic!(
            "Unsupported or unhandled expression type for Cell conversion: {:?}",
            expr
        ),
    }
}
