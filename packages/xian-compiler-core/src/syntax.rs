use std::fmt::Write;

use rustpython_parser::ast::{self, Constant, Ranged};
use rustpython_parser::source_code::RandomLocator;
use rustpython_parser::text_size::TextRange;
use serde::{Deserialize, Serialize};

use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::frontend::{parse_source, ParsedModule};
use crate::source::SourceUnit;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxModule {
    pub module_name: String,
    pub source_sha256: String,
    pub body: Vec<SyntaxStatement>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum SyntaxStatement {
    FunctionDef {
        span: SourceRange,
        name: String,
        decorators: Vec<SyntaxExpression>,
        parameters: Vec<SyntaxParameter>,
        returns: Option<SyntaxExpression>,
        body: Vec<SyntaxStatement>,
    },
    Return {
        span: SourceRange,
        value: Option<SyntaxExpression>,
    },
    Assign {
        span: SourceRange,
        targets: Vec<SyntaxExpression>,
        value: SyntaxExpression,
    },
    AugAssign {
        span: SourceRange,
        target: SyntaxExpression,
        operator: SyntaxBinaryOperator,
        value: SyntaxExpression,
    },
    For {
        span: SourceRange,
        target: SyntaxExpression,
        iter: SyntaxExpression,
        body: Vec<SyntaxStatement>,
        orelse: Vec<SyntaxStatement>,
    },
    While {
        span: SourceRange,
        test: SyntaxExpression,
        body: Vec<SyntaxStatement>,
        orelse: Vec<SyntaxStatement>,
    },
    If {
        span: SourceRange,
        test: SyntaxExpression,
        body: Vec<SyntaxStatement>,
        orelse: Vec<SyntaxStatement>,
    },
    Assert {
        span: SourceRange,
        test: SyntaxExpression,
        message: Option<SyntaxExpression>,
    },
    Raise {
        span: SourceRange,
        exception: Option<SyntaxExpression>,
        cause: Option<SyntaxExpression>,
    },
    Import {
        span: SourceRange,
        names: Vec<SyntaxImportAlias>,
    },
    Expr {
        span: SourceRange,
        value: SyntaxExpression,
    },
    Pass {
        span: SourceRange,
    },
    Break {
        span: SourceRange,
    },
    Continue {
        span: SourceRange,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum SyntaxExpression {
    Name {
        span: SourceRange,
        id: String,
        context: SyntaxExpressionContext,
    },
    Constant {
        span: SourceRange,
        value: SyntaxConstant,
    },
    List {
        span: SourceRange,
        elements: Vec<SyntaxExpression>,
        context: SyntaxExpressionContext,
    },
    ListComp {
        span: SourceRange,
        element: Box<SyntaxExpression>,
        generators: Vec<SyntaxComprehension>,
    },
    DictComp {
        span: SourceRange,
        key: Box<SyntaxExpression>,
        value: Box<SyntaxExpression>,
        generators: Vec<SyntaxComprehension>,
    },
    Tuple {
        span: SourceRange,
        elements: Vec<SyntaxExpression>,
        context: SyntaxExpressionContext,
    },
    Dict {
        span: SourceRange,
        entries: Vec<SyntaxDictEntry>,
    },
    Attribute {
        span: SourceRange,
        value: Box<SyntaxExpression>,
        attr: String,
        context: SyntaxExpressionContext,
    },
    Subscript {
        span: SourceRange,
        value: Box<SyntaxExpression>,
        slice: Box<SyntaxExpression>,
        context: SyntaxExpressionContext,
    },
    Slice {
        span: SourceRange,
        lower: Option<Box<SyntaxExpression>>,
        upper: Option<Box<SyntaxExpression>>,
        step: Option<Box<SyntaxExpression>>,
    },
    Call {
        span: SourceRange,
        func: Box<SyntaxExpression>,
        args: Vec<SyntaxExpression>,
        keywords: Vec<SyntaxKeyword>,
    },
    Compare {
        span: SourceRange,
        left: Box<SyntaxExpression>,
        operators: Vec<SyntaxCompareOperator>,
        comparators: Vec<SyntaxExpression>,
    },
    BoolOp {
        span: SourceRange,
        operator: SyntaxBoolOperator,
        values: Vec<SyntaxExpression>,
    },
    BinOp {
        span: SourceRange,
        operator: SyntaxBinaryOperator,
        left: Box<SyntaxExpression>,
        right: Box<SyntaxExpression>,
    },
    UnaryOp {
        span: SourceRange,
        operator: SyntaxUnaryOperator,
        operand: Box<SyntaxExpression>,
    },
    IfExpr {
        span: SourceRange,
        test: Box<SyntaxExpression>,
        body: Box<SyntaxExpression>,
        orelse: Box<SyntaxExpression>,
    },
    FString {
        span: SourceRange,
        values: Vec<SyntaxExpression>,
    },
    FormattedValue {
        span: SourceRange,
        value: Box<SyntaxExpression>,
        conversion: Option<char>,
        format_spec: Option<Box<SyntaxExpression>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxParameter {
    pub span: SourceRange,
    pub name: String,
    pub kind: SyntaxParameterKind,
    pub annotation: Option<SyntaxExpression>,
    pub default: Option<SyntaxExpression>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxParameterKind {
    PositionalOnly,
    PositionalOrKeyword,
    Vararg,
    KeywordOnly,
    Kwarg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxImportAlias {
    pub span: SourceRange,
    pub name: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxKeyword {
    pub span: SourceRange,
    pub arg: Option<String>,
    pub value: SyntaxExpression,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxDictEntry {
    pub key: Option<SyntaxExpression>,
    pub value: SyntaxExpression,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntaxComprehension {
    pub span: SourceRange,
    pub target: SyntaxExpression,
    pub iter: SyntaxExpression,
    pub ifs: Vec<SyntaxExpression>,
    pub is_async: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum SyntaxConstant {
    None,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    Bytes(String),
    Tuple(Vec<SyntaxConstant>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxExpressionContext {
    Load,
    Store,
    Del,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxBoolOperator {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxBinaryOperator {
    Add,
    Sub,
    Mult,
    Div,
    FloorDiv,
    Mod,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    LShift,
    RShift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxUnaryOperator {
    Not,
    Neg,
    Pos,
    Invert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxCompareOperator {
    Eq,
    NotEq,
    Gt,
    GtE,
    Lt,
    LtE,
    In,
    NotIn,
    Is,
    IsNot,
}

pub fn parse_to_syntax(unit: &SourceUnit) -> Result<SyntaxModule, Vec<CompilerDiagnostic>> {
    let parsed = parse_source(unit)?;
    build_syntax_tree(&parsed)
}

pub fn build_syntax_tree(parsed: &ParsedModule) -> Result<SyntaxModule, Vec<CompilerDiagnostic>> {
    SyntaxBuilder::new(parsed).build()
}

struct SyntaxBuilder<'a> {
    parsed: &'a ParsedModule,
    locator: RandomLocator<'a>,
    diagnostics: Vec<CompilerDiagnostic>,
}

impl<'a> SyntaxBuilder<'a> {
    fn new(parsed: &'a ParsedModule) -> Self {
        Self {
            parsed,
            locator: RandomLocator::new(parsed.source()),
            diagnostics: Vec::new(),
        }
    }

    fn build(mut self) -> Result<SyntaxModule, Vec<CompilerDiagnostic>> {
        let body = self.convert_statements(parsed_suite(self.parsed));
        if !self.diagnostics.is_empty() {
            return Err(self.diagnostics);
        }

        Ok(SyntaxModule {
            module_name: self.parsed.module_name().to_string(),
            source_sha256: self.parsed.source_unit().source_sha256(),
            body,
        })
    }

    fn convert_statements(&mut self, statements: &[ast::Stmt]) -> Vec<SyntaxStatement> {
        statements
            .iter()
            .filter_map(|statement| self.convert_statement(statement))
            .collect()
    }

    fn convert_statement(&mut self, statement: &ast::Stmt) -> Option<SyntaxStatement> {
        match statement {
            ast::Stmt::FunctionDef(node) => {
                let decorators = self.convert_expressions(&node.decorator_list)?;
                let parameters = self.convert_parameters(&node.args)?;
                let returns = self.convert_optional_expr(node.returns.as_deref())?;
                let body = self.convert_statements(&node.body);
                Some(SyntaxStatement::FunctionDef {
                    span: self.span(node.range),
                    name: node.name.to_string(),
                    decorators,
                    parameters,
                    returns,
                    body,
                })
            }
            ast::Stmt::Return(node) => Some(SyntaxStatement::Return {
                span: self.span(node.range),
                value: self.convert_optional_expr(node.value.as_deref())?,
            }),
            ast::Stmt::Assign(node) => Some(SyntaxStatement::Assign {
                span: self.span(node.range),
                targets: self.convert_expressions(&node.targets)?,
                value: self.convert_expr(&node.value)?,
            }),
            ast::Stmt::AugAssign(node) => Some(SyntaxStatement::AugAssign {
                span: self.span(node.range),
                target: self.convert_expr(&node.target)?,
                operator: self.convert_binary_operator(node.op, node.range)?,
                value: self.convert_expr(&node.value)?,
            }),
            ast::Stmt::For(node) => Some(SyntaxStatement::For {
                span: self.span(node.range),
                target: self.convert_expr(&node.target)?,
                iter: self.convert_expr(&node.iter)?,
                body: self.convert_statements(&node.body),
                orelse: self.convert_statements(&node.orelse),
            }),
            ast::Stmt::While(node) => Some(SyntaxStatement::While {
                span: self.span(node.range),
                test: self.convert_expr(&node.test)?,
                body: self.convert_statements(&node.body),
                orelse: self.convert_statements(&node.orelse),
            }),
            ast::Stmt::If(node) => Some(SyntaxStatement::If {
                span: self.span(node.range),
                test: self.convert_expr(&node.test)?,
                body: self.convert_statements(&node.body),
                orelse: self.convert_statements(&node.orelse),
            }),
            ast::Stmt::Assert(node) => Some(SyntaxStatement::Assert {
                span: self.span(node.range),
                test: self.convert_expr(&node.test)?,
                message: self.convert_optional_expr(node.msg.as_deref())?,
            }),
            ast::Stmt::Raise(node) => Some(SyntaxStatement::Raise {
                span: self.span(node.range),
                exception: self.convert_optional_expr(node.exc.as_deref())?,
                cause: self.convert_optional_expr(node.cause.as_deref())?,
            }),
            ast::Stmt::Import(node) => Some(SyntaxStatement::Import {
                span: self.span(node.range),
                names: node
                    .names
                    .iter()
                    .map(|alias| SyntaxImportAlias {
                        span: self.span(alias.range),
                        name: alias.name.to_string(),
                        alias: alias.asname.as_ref().map(ToString::to_string),
                    })
                    .collect(),
            }),
            ast::Stmt::Expr(node) => Some(SyntaxStatement::Expr {
                span: self.span(node.range),
                value: self.convert_expr(&node.value)?,
            }),
            ast::Stmt::Pass(node) => Some(SyntaxStatement::Pass {
                span: self.span(node.range),
            }),
            ast::Stmt::Break(node) => Some(SyntaxStatement::Break {
                span: self.span(node.range),
            }),
            ast::Stmt::Continue(node) => Some(SyntaxStatement::Continue {
                span: self.span(node.range),
            }),
            ast::Stmt::AsyncFunctionDef(_) => self.unsupported_statement(
                statement.range(),
                "async_function_def",
                "async functions are not supported",
            ),
            ast::Stmt::ClassDef(_) => self.unsupported_statement(
                statement.range(),
                "class_def",
                "class definitions are not supported",
            ),
            ast::Stmt::Delete(_) => self.unsupported_statement(
                statement.range(),
                "delete",
                "delete statements are not supported",
            ),
            ast::Stmt::TypeAlias(_) => self.unsupported_statement(
                statement.range(),
                "type_alias",
                "type aliases are not supported",
            ),
            ast::Stmt::AnnAssign(_) => self.unsupported_statement(
                statement.range(),
                "ann_assign",
                "annotated assignments are not supported",
            ),
            ast::Stmt::AsyncFor(_) => self.unsupported_statement(
                statement.range(),
                "async_for",
                "async for loops are not supported",
            ),
            ast::Stmt::With(_) | ast::Stmt::AsyncWith(_) => self.unsupported_statement(
                statement.range(),
                "with",
                "with statements are not supported",
            ),
            ast::Stmt::Match(_) => self.unsupported_statement(
                statement.range(),
                "match",
                "match statements are not supported",
            ),
            ast::Stmt::Try(_) | ast::Stmt::TryStar(_) => self.unsupported_statement(
                statement.range(),
                "try",
                "try statements are not supported",
            ),
            ast::Stmt::ImportFrom(_) => self.unsupported_statement(
                statement.range(),
                "import_from",
                "from-import statements are not supported",
            ),
            ast::Stmt::Global(_) => self.unsupported_statement(
                statement.range(),
                "global",
                "global statements are not supported",
            ),
            ast::Stmt::Nonlocal(_) => self.unsupported_statement(
                statement.range(),
                "nonlocal",
                "nonlocal statements are not supported",
            ),
        }
    }

    fn convert_expr(&mut self, expression: &ast::Expr) -> Option<SyntaxExpression> {
        match expression {
            ast::Expr::Name(node) => Some(SyntaxExpression::Name {
                span: self.span(node.range),
                id: node.id.to_string(),
                context: convert_context(node.ctx),
            }),
            ast::Expr::Constant(node) => Some(SyntaxExpression::Constant {
                span: self.span(node.range),
                value: self.convert_constant(&node.value, node.range)?,
            }),
            ast::Expr::List(node) => Some(SyntaxExpression::List {
                span: self.span(node.range),
                elements: self.convert_expressions(&node.elts)?,
                context: convert_context(node.ctx),
            }),
            ast::Expr::ListComp(node) => Some(SyntaxExpression::ListComp {
                span: self.span(node.range),
                element: Box::new(self.convert_expr(&node.elt)?),
                generators: self.convert_comprehensions(&node.generators, node.range)?,
            }),
            ast::Expr::DictComp(node) => Some(SyntaxExpression::DictComp {
                span: self.span(node.range),
                key: Box::new(self.convert_expr(&node.key)?),
                value: Box::new(self.convert_expr(&node.value)?),
                generators: self.convert_comprehensions(&node.generators, node.range)?,
            }),
            ast::Expr::Tuple(node) => Some(SyntaxExpression::Tuple {
                span: self.span(node.range),
                elements: self.convert_expressions(&node.elts)?,
                context: convert_context(node.ctx),
            }),
            ast::Expr::Dict(node) => {
                let entries = node
                    .keys
                    .iter()
                    .zip(node.values.iter())
                    .map(|(key, value)| {
                        Some(SyntaxDictEntry {
                            key: self.convert_optional_expr(key.as_ref())?,
                            value: self.convert_expr(value)?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(SyntaxExpression::Dict {
                    span: self.span(node.range),
                    entries,
                })
            }
            ast::Expr::Attribute(node) => Some(SyntaxExpression::Attribute {
                span: self.span(node.range),
                value: Box::new(self.convert_expr(&node.value)?),
                attr: node.attr.to_string(),
                context: convert_context(node.ctx),
            }),
            ast::Expr::Subscript(node) => Some(SyntaxExpression::Subscript {
                span: self.span(node.range),
                value: Box::new(self.convert_expr(&node.value)?),
                slice: Box::new(self.convert_expr(&node.slice)?),
                context: convert_context(node.ctx),
            }),
            ast::Expr::Slice(node) => Some(SyntaxExpression::Slice {
                span: self.span(node.range),
                lower: self
                    .convert_optional_expr(node.lower.as_deref())?
                    .map(Box::new),
                upper: self
                    .convert_optional_expr(node.upper.as_deref())?
                    .map(Box::new),
                step: self
                    .convert_optional_expr(node.step.as_deref())?
                    .map(Box::new),
            }),
            ast::Expr::Call(node) => Some(SyntaxExpression::Call {
                span: self.span(node.range),
                func: Box::new(self.convert_expr(&node.func)?),
                args: self.convert_expressions(&node.args)?,
                keywords: node
                    .keywords
                    .iter()
                    .map(|keyword| {
                        Some(SyntaxKeyword {
                            span: self.span(keyword.range),
                            arg: keyword.arg.as_ref().map(ToString::to_string),
                            value: self.convert_expr(&keyword.value)?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            }),
            ast::Expr::Compare(node) => Some(SyntaxExpression::Compare {
                span: self.span(node.range),
                left: Box::new(self.convert_expr(&node.left)?),
                operators: node
                    .ops
                    .iter()
                    .copied()
                    .map(convert_compare_operator)
                    .collect(),
                comparators: self.convert_expressions(&node.comparators)?,
            }),
            ast::Expr::BoolOp(node) => Some(SyntaxExpression::BoolOp {
                span: self.span(node.range),
                operator: convert_bool_operator(node.op),
                values: self.convert_expressions(&node.values)?,
            }),
            ast::Expr::BinOp(node) => Some(SyntaxExpression::BinOp {
                span: self.span(node.range),
                operator: self.convert_binary_operator(node.op, node.range)?,
                left: Box::new(self.convert_expr(&node.left)?),
                right: Box::new(self.convert_expr(&node.right)?),
            }),
            ast::Expr::UnaryOp(node) => Some(SyntaxExpression::UnaryOp {
                span: self.span(node.range),
                operator: convert_unary_operator(node.op),
                operand: Box::new(self.convert_expr(&node.operand)?),
            }),
            ast::Expr::IfExp(node) => Some(SyntaxExpression::IfExpr {
                span: self.span(node.range),
                test: Box::new(self.convert_expr(&node.test)?),
                body: Box::new(self.convert_expr(&node.body)?),
                orelse: Box::new(self.convert_expr(&node.orelse)?),
            }),
            ast::Expr::JoinedStr(node) => {
                let span = self.span(node.range);
                Some(SyntaxExpression::FString {
                    span,
                    values: self.convert_fstring_values(span, &node.values)?,
                })
            }
            ast::Expr::FormattedValue(node) => Some(SyntaxExpression::FormattedValue {
                span: self.span(node.range),
                value: Box::new(self.convert_expr(&node.value)?),
                conversion: node.conversion.to_char(),
                format_spec: self
                    .convert_optional_expr(node.format_spec.as_deref())?
                    .map(Box::new),
            }),
            ast::Expr::NamedExpr(_) => self.unsupported_expression(
                expression.range(),
                "named_expr",
                "assignment expressions are not supported",
            ),
            ast::Expr::Lambda(_) => self.unsupported_expression(
                expression.range(),
                "lambda",
                "lambda expressions are not supported",
            ),
            ast::Expr::Set(_) => self.unsupported_expression(
                expression.range(),
                "set",
                "set literals are not supported",
            ),
            ast::Expr::SetComp(_) => self.unsupported_expression(
                expression.range(),
                "set_comp",
                "set comprehensions are not supported",
            ),
            ast::Expr::GeneratorExp(_) => self.unsupported_expression(
                expression.range(),
                "generator_exp",
                "generator expressions are not supported",
            ),
            ast::Expr::Await(_) => self.unsupported_expression(
                expression.range(),
                "await",
                "await expressions are not supported",
            ),
            ast::Expr::Yield(_) | ast::Expr::YieldFrom(_) => self.unsupported_expression(
                expression.range(),
                "yield",
                "yield expressions are not supported",
            ),
            ast::Expr::Starred(_) => self.unsupported_expression(
                expression.range(),
                "starred",
                "starred expressions are not supported",
            ),
        }
    }

    fn convert_expressions(&mut self, expressions: &[ast::Expr]) -> Option<Vec<SyntaxExpression>> {
        expressions
            .iter()
            .map(|expression| self.convert_expr(expression))
            .collect()
    }

    fn convert_fstring_values(
        &mut self,
        fstring_span: SourceRange,
        values: &[ast::Expr],
    ) -> Option<Vec<SyntaxExpression>> {
        let mut converted = self.convert_expressions(values)?;
        self.refine_fstring_value_spans(fstring_span, &mut converted);
        Some(converted)
    }

    fn refine_fstring_value_spans(
        &self,
        fstring_span: SourceRange,
        values: &mut [SyntaxExpression],
    ) {
        if fstring_span.start_line != fstring_span.end_line {
            return;
        }
        let Some(line) = self
            .parsed
            .source()
            .lines()
            .nth(fstring_span.start_line.saturating_sub(1) as usize)
        else {
            return;
        };
        let Some((content_start, content_end)) = fstring_content_bounds(
            line,
            fstring_span.start_column as usize,
            fstring_span.end_column as usize,
        ) else {
            return;
        };

        let mut cursor = content_start;
        for value in values {
            match value {
                SyntaxExpression::Constant {
                    value: SyntaxConstant::Str(_),
                    ..
                } => {
                    let end = find_next_fstring_expression(line, cursor, content_end)
                        .unwrap_or(content_end);
                    set_expression_span(
                        value,
                        SourceRange {
                            start_line: fstring_span.start_line,
                            start_column: cursor as u32,
                            end_line: fstring_span.start_line,
                            end_column: end as u32,
                        },
                    );
                    cursor = end;
                }
                SyntaxExpression::FormattedValue { .. } => {
                    let Some(start) = find_next_fstring_expression(line, cursor, content_end)
                    else {
                        return;
                    };
                    let Some(end) = find_fstring_expression_end(line, start, content_end) else {
                        return;
                    };
                    set_expression_span(
                        value,
                        SourceRange {
                            start_line: fstring_span.start_line,
                            start_column: start as u32,
                            end_line: fstring_span.start_line,
                            end_column: end as u32,
                        },
                    );
                    cursor = end;
                }
                _ => {}
            }
        }
    }

    fn convert_optional_expr(
        &mut self,
        expression: Option<&ast::Expr>,
    ) -> Option<Option<SyntaxExpression>> {
        match expression {
            Some(expression) => self.convert_expr(expression).map(Some),
            None => Some(None),
        }
    }

    fn convert_parameters(&mut self, arguments: &ast::Arguments) -> Option<Vec<SyntaxParameter>> {
        let mut parameters = Vec::new();
        for arg in &arguments.posonlyargs {
            parameters
                .push(self.convert_arg_with_default(arg, SyntaxParameterKind::PositionalOnly)?);
        }
        for arg in &arguments.args {
            parameters.push(
                self.convert_arg_with_default(arg, SyntaxParameterKind::PositionalOrKeyword)?,
            );
        }
        if let Some(arg) = &arguments.vararg {
            parameters.push(self.convert_arg(arg, SyntaxParameterKind::Vararg, None)?);
        }
        for arg in &arguments.kwonlyargs {
            parameters.push(self.convert_arg_with_default(arg, SyntaxParameterKind::KeywordOnly)?);
        }
        if let Some(arg) = &arguments.kwarg {
            parameters.push(self.convert_arg(arg, SyntaxParameterKind::Kwarg, None)?);
        }
        Some(parameters)
    }

    fn convert_arg_with_default(
        &mut self,
        arg: &ast::ArgWithDefault,
        kind: SyntaxParameterKind,
    ) -> Option<SyntaxParameter> {
        self.convert_arg(&arg.def, kind, arg.default.as_deref())
    }

    fn convert_arg(
        &mut self,
        arg: &ast::Arg,
        kind: SyntaxParameterKind,
        default: Option<&ast::Expr>,
    ) -> Option<SyntaxParameter> {
        Some(SyntaxParameter {
            span: self.span(arg.range),
            name: arg.arg.to_string(),
            kind,
            annotation: self.convert_optional_expr(arg.annotation.as_deref())?,
            default: self.convert_optional_expr(default)?,
        })
    }

    fn convert_comprehensions(
        &mut self,
        comprehensions: &[ast::Comprehension],
        fallback_range: TextRange,
    ) -> Option<Vec<SyntaxComprehension>> {
        comprehensions
            .iter()
            .map(|comprehension| {
                Some(SyntaxComprehension {
                    span: self.span(fallback_range),
                    target: self.convert_expr(&comprehension.target)?,
                    iter: self.convert_expr(&comprehension.iter)?,
                    ifs: self.convert_expressions(&comprehension.ifs)?,
                    is_async: comprehension.is_async,
                })
            })
            .collect()
    }

    fn convert_constant(
        &mut self,
        constant: &Constant,
        range: TextRange,
    ) -> Option<SyntaxConstant> {
        match constant {
            Constant::None => Some(SyntaxConstant::None),
            Constant::Bool(value) => Some(SyntaxConstant::Bool(*value)),
            Constant::Int(value) => Some(SyntaxConstant::Int(value.to_string())),
            Constant::Float(value) => Some(SyntaxConstant::Float(*value)),
            Constant::Str(value) => Some(SyntaxConstant::Str(value.clone())),
            Constant::Bytes(value) => Some(SyntaxConstant::Bytes(hex_bytes(value))),
            Constant::Tuple(values) => values
                .iter()
                .map(|value| self.convert_constant(value, range))
                .collect::<Option<Vec<_>>>()
                .map(SyntaxConstant::Tuple),
            Constant::Complex { .. } => {
                self.unsupported_constant(range, "complex", "complex constants are not supported")
            }
            Constant::Ellipsis => {
                self.unsupported_constant(range, "ellipsis", "ellipsis constants are not supported")
            }
        }
    }

    fn convert_binary_operator(
        &mut self,
        operator: ast::Operator,
        range: TextRange,
    ) -> Option<SyntaxBinaryOperator> {
        match operator {
            ast::Operator::Add => Some(SyntaxBinaryOperator::Add),
            ast::Operator::Sub => Some(SyntaxBinaryOperator::Sub),
            ast::Operator::Mult => Some(SyntaxBinaryOperator::Mult),
            ast::Operator::Div => Some(SyntaxBinaryOperator::Div),
            ast::Operator::FloorDiv => Some(SyntaxBinaryOperator::FloorDiv),
            ast::Operator::Mod => Some(SyntaxBinaryOperator::Mod),
            ast::Operator::Pow => Some(SyntaxBinaryOperator::Pow),
            ast::Operator::BitAnd => Some(SyntaxBinaryOperator::BitAnd),
            ast::Operator::BitOr => Some(SyntaxBinaryOperator::BitOr),
            ast::Operator::BitXor => Some(SyntaxBinaryOperator::BitXor),
            ast::Operator::LShift => Some(SyntaxBinaryOperator::LShift),
            ast::Operator::RShift => Some(SyntaxBinaryOperator::RShift),
            ast::Operator::MatMult => self.unsupported_operator(
                range,
                "mat_mult",
                "matrix multiplication is not supported",
            ),
        }
    }

    fn unsupported_statement(
        &mut self,
        range: TextRange,
        code: &str,
        message: &str,
    ) -> Option<SyntaxStatement> {
        self.push_unsupported("statement", range, code, message);
        None
    }

    fn unsupported_expression(
        &mut self,
        range: TextRange,
        code: &str,
        message: &str,
    ) -> Option<SyntaxExpression> {
        self.push_unsupported("expression", range, code, message);
        None
    }

    fn unsupported_constant(
        &mut self,
        range: TextRange,
        code: &str,
        message: &str,
    ) -> Option<SyntaxConstant> {
        self.push_unsupported("constant", range, code, message);
        None
    }

    fn unsupported_operator(
        &mut self,
        range: TextRange,
        code: &str,
        message: &str,
    ) -> Option<SyntaxBinaryOperator> {
        self.push_unsupported("operator", range, code, message);
        None
    }

    fn push_unsupported(&mut self, category: &str, range: TextRange, code: &str, message: &str) {
        let span = self.span(range);
        self.diagnostics.push(
            CompilerDiagnostic::error(
                format!("xian.syntax.unsupported_{category}.{code}"),
                message,
            )
            .with_range(span),
        );
    }

    fn span(&mut self, range: TextRange) -> SourceRange {
        let start = self.locator.locate(range.start());
        let end = self.locator.locate(range.end());
        SourceRange {
            start_line: start.row.get(),
            start_column: start.column.to_zero_indexed(),
            end_line: end.row.get(),
            end_column: end.column.to_zero_indexed(),
        }
    }
}

fn parsed_suite(parsed: &ParsedModule) -> &[ast::Stmt] {
    parsed.suite()
}

fn fstring_content_bounds(
    line: &str,
    start_column: usize,
    end_column: usize,
) -> Option<(usize, usize)> {
    let bounded_end = end_column.min(line.len());
    let mut quote_start = None;
    for (offset, character) in line.get(start_column..bounded_end)?.char_indices() {
        if character == '\'' || character == '"' {
            quote_start = Some(start_column + offset + character.len_utf8());
            break;
        }
    }
    let content_start = quote_start?;
    let content_end = bounded_end.checked_sub(1)?;
    if content_start <= content_end {
        Some((content_start, content_end))
    } else {
        None
    }
}

fn find_next_fstring_expression(line: &str, start: usize, end: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor < end {
        let rest = line.get(cursor..end)?;
        if rest.starts_with("{{") {
            cursor += 2;
            continue;
        }
        if rest.starts_with('{') {
            return Some(cursor);
        }
        let character = rest.chars().next()?;
        cursor += character.len_utf8();
    }
    None
}

fn find_fstring_expression_end(line: &str, start: usize, end: usize) -> Option<usize> {
    let mut cursor = start;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    while cursor < end {
        let rest = line.get(cursor..end)?;
        let character = rest.chars().next()?;
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            cursor += character.len_utf8();
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                cursor += character.len_utf8();
                if depth == 0 {
                    return Some(cursor);
                }
                continue;
            }
            _ => {}
        }
        cursor += character.len_utf8();
    }
    None
}

fn set_expression_span(expression: &mut SyntaxExpression, next_span: SourceRange) {
    match expression {
        SyntaxExpression::Name { span, .. }
        | SyntaxExpression::Constant { span, .. }
        | SyntaxExpression::List { span, .. }
        | SyntaxExpression::ListComp { span, .. }
        | SyntaxExpression::DictComp { span, .. }
        | SyntaxExpression::Tuple { span, .. }
        | SyntaxExpression::Dict { span, .. }
        | SyntaxExpression::Attribute { span, .. }
        | SyntaxExpression::Subscript { span, .. }
        | SyntaxExpression::Slice { span, .. }
        | SyntaxExpression::Call { span, .. }
        | SyntaxExpression::Compare { span, .. }
        | SyntaxExpression::BoolOp { span, .. }
        | SyntaxExpression::BinOp { span, .. }
        | SyntaxExpression::UnaryOp { span, .. }
        | SyntaxExpression::IfExpr { span, .. }
        | SyntaxExpression::FString { span, .. }
        | SyntaxExpression::FormattedValue { span, .. } => *span = next_span,
    }
}

fn convert_context(context: ast::ExprContext) -> SyntaxExpressionContext {
    match context {
        ast::ExprContext::Load => SyntaxExpressionContext::Load,
        ast::ExprContext::Store => SyntaxExpressionContext::Store,
        ast::ExprContext::Del => SyntaxExpressionContext::Del,
    }
}

fn convert_bool_operator(operator: ast::BoolOp) -> SyntaxBoolOperator {
    match operator {
        ast::BoolOp::And => SyntaxBoolOperator::And,
        ast::BoolOp::Or => SyntaxBoolOperator::Or,
    }
}

fn convert_unary_operator(operator: ast::UnaryOp) -> SyntaxUnaryOperator {
    match operator {
        ast::UnaryOp::Not => SyntaxUnaryOperator::Not,
        ast::UnaryOp::USub => SyntaxUnaryOperator::Neg,
        ast::UnaryOp::UAdd => SyntaxUnaryOperator::Pos,
        ast::UnaryOp::Invert => SyntaxUnaryOperator::Invert,
    }
}

fn convert_compare_operator(operator: ast::CmpOp) -> SyntaxCompareOperator {
    match operator {
        ast::CmpOp::Eq => SyntaxCompareOperator::Eq,
        ast::CmpOp::NotEq => SyntaxCompareOperator::NotEq,
        ast::CmpOp::Gt => SyntaxCompareOperator::Gt,
        ast::CmpOp::GtE => SyntaxCompareOperator::GtE,
        ast::CmpOp::Lt => SyntaxCompareOperator::Lt,
        ast::CmpOp::LtE => SyntaxCompareOperator::LtE,
        ast::CmpOp::In => SyntaxCompareOperator::In,
        ast::CmpOp::NotIn => SyntaxCompareOperator::NotIn,
        ast::CmpOp::Is => SyntaxCompareOperator::Is,
        ast::CmpOp::IsNot => SyntaxCompareOperator::IsNot,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String should not fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::source::SourceUnit;
    use crate::syntax::{
        parse_to_syntax, SyntaxExpression, SyntaxStatement, SyntaxStatement::FunctionDef,
    };

    #[test]
    fn parse_to_syntax_captures_contract_shape() {
        let source =
            "counter = Variable()\n\n@export\ndef get() -> int:\n    return counter.get()\n";
        let unit = SourceUnit::new("con_counter", source).expect("source unit should build");

        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        assert_eq!(syntax.module_name, "con_counter");
        assert_eq!(syntax.body.len(), 2);
        assert!(matches!(
            syntax.body.first(),
            Some(SyntaxStatement::Assign { .. })
        ));
        match &syntax.body[1] {
            FunctionDef {
                name,
                decorators,
                parameters,
                returns,
                body,
                ..
            } => {
                assert_eq!(name, "get");
                assert_eq!(decorators.len(), 1);
                assert!(parameters.is_empty());
                assert!(returns.is_some());
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected function, got {other:?}"),
        }
    }

    #[test]
    fn parse_to_syntax_preserves_calls_and_attributes() {
        let source = "counter = Variable()\n\n@export\ndef get():\n    return counter.get()\n";
        let unit = SourceUnit::new("con_counter", source).expect("source unit should build");

        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        let FunctionDef { body, .. } = &syntax.body[1] else {
            panic!("expected function");
        };
        let SyntaxStatement::Return {
            value: Some(value), ..
        } = &body[0]
        else {
            panic!("expected return value");
        };
        let SyntaxExpression::Call { func, args, .. } = value else {
            panic!("expected call expression");
        };
        assert!(args.is_empty());
        assert!(matches!(func.as_ref(), SyntaxExpression::Attribute { attr, .. } if attr == "get"));
    }

    #[test]
    fn parse_to_syntax_reports_unsupported_nodes() {
        let unit =
            SourceUnit::new("con_bad", "class Bad:\n    pass\n").expect("source unit should build");

        let diagnostics = parse_to_syntax(&unit).expect_err("class should be unsupported");

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            "xian.syntax.unsupported_statement.class_def"
        );
        assert_eq!(
            diagnostics[0].range.as_ref().map(|range| range.start_line),
            Some(1)
        );
    }
}
