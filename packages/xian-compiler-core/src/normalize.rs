use crate::compiler::CompileOptions;
use crate::diagnostic::CompilerDiagnostic;
use crate::frontend::parse_source;
use crate::lint::lint_syntax;
use crate::source::SourceUnit;
use crate::syntax::{
    build_syntax_tree, SyntaxBinaryOperator, SyntaxBoolOperator, SyntaxCompareOperator,
    SyntaxComprehension, SyntaxConstant, SyntaxDictEntry, SyntaxExpression, SyntaxKeyword,
    SyntaxModule, SyntaxParameter, SyntaxParameterKind, SyntaxStatement, SyntaxUnaryOperator,
};

const INDENT: &str = "    ";

pub fn normalize_source(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<String, Vec<CompilerDiagnostic>> {
    let unit = match SourceUnit::with_profile(module_name, source, &options.vm_profile) {
        Ok(unit) => unit,
        Err(error) => {
            return Err(vec![CompilerDiagnostic::error(
                "xian.source.invalid",
                error.to_string(),
            )]);
        }
    };
    let parsed = parse_source(&unit)?;
    let syntax = build_syntax_tree(&parsed)?;
    if options.lint {
        let diagnostics = lint_syntax(&syntax);
        if !diagnostics.is_empty() {
            return Err(diagnostics);
        }
    }
    Ok(normalize_syntax(&syntax))
}

pub fn normalize_syntax(module: &SyntaxModule) -> String {
    format_statements(&module.body, 0, true)
}

fn format_statements(statements: &[SyntaxStatement], indent: usize, top_level: bool) -> String {
    let mut output = String::new();
    for (index, statement) in statements.iter().enumerate() {
        if index > 0 {
            if top_level && needs_top_level_blank_line(&statements[index - 1], statement) {
                output.push_str("\n\n");
            } else {
                output.push('\n');
            }
        }
        output.push_str(&format_statement(statement, indent));
    }
    output
}

fn needs_top_level_blank_line(previous: &SyntaxStatement, current: &SyntaxStatement) -> bool {
    let _ = previous;
    matches!(current, SyntaxStatement::FunctionDef { .. })
}

fn format_statement(statement: &SyntaxStatement, indent: usize) -> String {
    let prefix = INDENT.repeat(indent);
    match statement {
        SyntaxStatement::FunctionDef {
            name,
            decorators,
            parameters,
            returns,
            body,
            ..
        } => {
            let mut lines = Vec::new();
            for decorator in decorators {
                lines.push(format!("{prefix}@{}", format_expression(decorator)));
            }
            let mut header = format!("{prefix}def {name}({})", format_parameters(parameters));
            if let Some(returns) = returns {
                header.push_str(" -> ");
                header.push_str(&format_expression(returns));
            }
            header.push(':');
            lines.push(header);
            lines.push(format_block(body, indent + 1));
            lines.join("\n")
        }
        SyntaxStatement::Return { value, .. } => match value {
            Some(value) => format!("{prefix}return {}", format_expression(value)),
            None => format!("{prefix}return"),
        },
        SyntaxStatement::Assign { targets, value, .. } => {
            let targets = targets
                .iter()
                .map(format_assignment_target)
                .collect::<Vec<_>>()
                .join(" = ");
            format!("{prefix}{targets} = {}", format_expression(value))
        }
        SyntaxStatement::AugAssign {
            target,
            operator,
            value,
            ..
        } => format!(
            "{prefix}{} {}= {}",
            format_expression(target),
            binary_operator_symbol(*operator),
            format_expression(value)
        ),
        SyntaxStatement::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => {
            let mut output = format!(
                "{prefix}for {} in {}:\n{}",
                format_assignment_target(target),
                format_expression(iter),
                format_block(body, indent + 1)
            );
            if !orelse.is_empty() {
                output.push('\n');
                output.push_str(&format!(
                    "{prefix}else:\n{}",
                    format_block(orelse, indent + 1)
                ));
            }
            output
        }
        SyntaxStatement::While {
            test, body, orelse, ..
        } => {
            let mut output = format!(
                "{prefix}while {}:\n{}",
                format_expression(test),
                format_block(body, indent + 1)
            );
            if !orelse.is_empty() {
                output.push('\n');
                output.push_str(&format!(
                    "{prefix}else:\n{}",
                    format_block(orelse, indent + 1)
                ));
            }
            output
        }
        SyntaxStatement::If {
            test, body, orelse, ..
        } => format_conditional_chain("if", test, body, orelse, indent),
        SyntaxStatement::Assert { test, message, .. } => match message {
            Some(message) => format!(
                "{prefix}assert {}, {}",
                format_expression(test),
                format_expression(message)
            ),
            None => format!("{prefix}assert {}", format_expression(test)),
        },
        SyntaxStatement::Raise {
            exception, cause, ..
        } => match (exception, cause) {
            (Some(exception), Some(cause)) => format!(
                "{prefix}raise {} from {}",
                format_expression(exception),
                format_expression(cause)
            ),
            (Some(exception), None) => format!("{prefix}raise {}", format_expression(exception)),
            (None, _) => format!("{prefix}raise"),
        },
        SyntaxStatement::Import { names, .. } => {
            let names = names
                .iter()
                .map(|alias| match &alias.alias {
                    Some(alias_name) => format!("{} as {alias_name}", alias.name),
                    None => alias.name.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{prefix}import {names}")
        }
        SyntaxStatement::Expr { value, .. } => match value {
            SyntaxExpression::Constant {
                value: SyntaxConstant::Str(value),
                ..
            } if value.contains('\n') => format!("{prefix}{}", quote_triple_string(value)),
            _ => format!("{prefix}{}", format_expression(value)),
        },
        SyntaxStatement::Pass { .. } => format!("{prefix}pass"),
        SyntaxStatement::Break { .. } => format!("{prefix}break"),
        SyntaxStatement::Continue { .. } => format!("{prefix}continue"),
    }
}

fn format_block(statements: &[SyntaxStatement], indent: usize) -> String {
    if statements.is_empty() {
        format!("{}pass", INDENT.repeat(indent))
    } else {
        format_statements(statements, indent, false)
    }
}

fn format_conditional_chain(
    keyword: &str,
    test: &SyntaxExpression,
    body: &[SyntaxStatement],
    orelse: &[SyntaxStatement],
    indent: usize,
) -> String {
    let prefix = INDENT.repeat(indent);
    let mut output = format!(
        "{prefix}{keyword} {}:\n{}",
        format_expression(test),
        format_block(body, indent + 1)
    );
    if let [SyntaxStatement::If {
        test, body, orelse, ..
    }] = orelse
    {
        output.push('\n');
        output.push_str(&format_conditional_chain(
            "elif", test, body, orelse, indent,
        ));
    } else if !orelse.is_empty() {
        output.push('\n');
        output.push_str(&format!(
            "{prefix}else:\n{}",
            format_block(orelse, indent + 1)
        ));
    }
    output
}

fn format_parameters(parameters: &[SyntaxParameter]) -> String {
    let mut parts = Vec::new();
    let mut saw_vararg = false;
    let has_positional_only = parameters
        .iter()
        .any(|parameter| parameter.kind == SyntaxParameterKind::PositionalOnly);
    let mut inserted_positional_only_separator = false;
    let mut inserted_keyword_only_separator = false;

    for (index, parameter) in parameters.iter().enumerate() {
        if has_positional_only
            && !inserted_positional_only_separator
            && parameter.kind != SyntaxParameterKind::PositionalOnly
        {
            parts.push("/".to_string());
            inserted_positional_only_separator = true;
        }
        if parameter.kind == SyntaxParameterKind::KeywordOnly
            && !saw_vararg
            && !inserted_keyword_only_separator
        {
            parts.push("*".to_string());
            inserted_keyword_only_separator = true;
        }

        parts.push(format_parameter(parameter));
        if parameter.kind == SyntaxParameterKind::Vararg {
            saw_vararg = true;
        }

        if has_positional_only
            && index + 1 == parameters.len()
            && !inserted_positional_only_separator
        {
            parts.push("/".to_string());
        }
    }

    parts.join(", ")
}

fn format_parameter(parameter: &SyntaxParameter) -> String {
    let mut output = match parameter.kind {
        SyntaxParameterKind::Vararg => format!("*{}", parameter.name),
        SyntaxParameterKind::Kwarg => format!("**{}", parameter.name),
        SyntaxParameterKind::PositionalOnly
        | SyntaxParameterKind::PositionalOrKeyword
        | SyntaxParameterKind::KeywordOnly => parameter.name.clone(),
    };
    if let Some(annotation) = &parameter.annotation {
        output.push_str(": ");
        output.push_str(&format_expression(annotation));
    }
    if let Some(default) = &parameter.default {
        output.push('=');
        output.push_str(&format_expression(default));
    }
    output
}

fn format_assignment_target(expression: &SyntaxExpression) -> String {
    match expression {
        SyntaxExpression::Tuple { elements, .. } => format_bare_tuple(elements),
        other => format_expression(other),
    }
}

pub(crate) fn format_expression(expression: &SyntaxExpression) -> String {
    format_expression_with_precedence(expression, 0)
}

fn format_expression_with_precedence(
    expression: &SyntaxExpression,
    parent_precedence: u8,
) -> String {
    let precedence = expression_precedence(expression);
    let raw = match expression {
        SyntaxExpression::Name { id, .. } => id.clone(),
        SyntaxExpression::Constant { value, .. } => format_constant(value),
        SyntaxExpression::List { elements, .. } => {
            format!("[{}]", format_expression_list(elements))
        }
        SyntaxExpression::ListComp {
            element,
            generators,
            ..
        } => format!(
            "[{} {}]",
            format_expression(element),
            format_comprehensions(generators)
        ),
        SyntaxExpression::DictComp {
            key,
            value,
            generators,
            ..
        } => format!(
            "{{{}: {} {}}}",
            format_expression(key),
            format_expression(value),
            format_comprehensions(generators)
        ),
        SyntaxExpression::Tuple { elements, .. } => format_tuple(elements),
        SyntaxExpression::Dict { entries, .. } => format_dict(entries),
        SyntaxExpression::Attribute { value, attr, .. } => format!(
            "{}.{attr}",
            format_expression_with_precedence(value, PRECEDENCE_POSTFIX)
        ),
        SyntaxExpression::Subscript { value, slice, .. } => format!(
            "{}[{}]",
            format_expression_with_precedence(value, PRECEDENCE_POSTFIX),
            format_subscript_slice(slice)
        ),
        SyntaxExpression::Slice {
            lower, upper, step, ..
        } => format_slice(lower.as_deref(), upper.as_deref(), step.as_deref()),
        SyntaxExpression::Call {
            func,
            args,
            keywords,
            ..
        } => format!(
            "{}({})",
            format_expression_with_precedence(func, PRECEDENCE_POSTFIX),
            format_call_args(args, keywords)
        ),
        SyntaxExpression::Compare {
            left,
            operators,
            comparators,
            ..
        } => format_compare(left, operators, comparators),
        SyntaxExpression::BoolOp {
            operator, values, ..
        } => format_bool_op(*operator, values),
        SyntaxExpression::BinOp {
            operator,
            left,
            right,
            ..
        } => {
            let left_precedence = if *operator == SyntaxBinaryOperator::Pow {
                precedence + 1
            } else {
                precedence
            };
            let right_precedence = if *operator == SyntaxBinaryOperator::Pow {
                precedence
            } else {
                precedence + 1
            };
            format!(
                "{} {} {}",
                format_expression_with_precedence(left, left_precedence),
                binary_operator_symbol(*operator),
                format_expression_with_precedence(right, right_precedence)
            )
        }
        SyntaxExpression::UnaryOp {
            operator, operand, ..
        } => match operator {
            SyntaxUnaryOperator::Not => format!(
                "not {}",
                format_expression_with_precedence(operand, precedence)
            ),
            SyntaxUnaryOperator::Neg => format!(
                "-{}",
                format_expression_with_precedence(operand, precedence)
            ),
            SyntaxUnaryOperator::Pos => format!(
                "+{}",
                format_expression_with_precedence(operand, precedence)
            ),
            SyntaxUnaryOperator::Invert => format!(
                "~{}",
                format_expression_with_precedence(operand, precedence)
            ),
        },
        SyntaxExpression::IfExpr {
            test, body, orelse, ..
        } => format!(
            "{} if {} else {}",
            format_expression_with_precedence(body, precedence + 1),
            format_expression_with_precedence(test, precedence + 1),
            format_expression_with_precedence(orelse, precedence + 1)
        ),
        SyntaxExpression::FString { values, .. } => format_fstring(values),
        SyntaxExpression::FormattedValue { .. } => {
            format!("{{{}}}", format_fstring_part(expression))
        }
    };

    if precedence < parent_precedence {
        format!("({raw})")
    } else {
        raw
    }
}

const PRECEDENCE_IF_EXPR: u8 = 10;
const PRECEDENCE_OR: u8 = 20;
const PRECEDENCE_AND: u8 = 30;
const PRECEDENCE_NOT: u8 = 35;
const PRECEDENCE_COMPARE: u8 = 40;
const PRECEDENCE_BIT_OR: u8 = 48;
const PRECEDENCE_BIT_XOR: u8 = 49;
const PRECEDENCE_BIT_AND: u8 = 50;
const PRECEDENCE_SHIFT: u8 = 55;
const PRECEDENCE_ADD: u8 = 60;
const PRECEDENCE_MULT: u8 = 70;
const PRECEDENCE_UNARY: u8 = 80;
const PRECEDENCE_POWER: u8 = 90;
const PRECEDENCE_POSTFIX: u8 = 100;
const PRECEDENCE_ATOM: u8 = 110;

fn expression_precedence(expression: &SyntaxExpression) -> u8 {
    match expression {
        SyntaxExpression::IfExpr { .. } => PRECEDENCE_IF_EXPR,
        SyntaxExpression::BoolOp {
            operator: SyntaxBoolOperator::Or,
            ..
        } => PRECEDENCE_OR,
        SyntaxExpression::BoolOp {
            operator: SyntaxBoolOperator::And,
            ..
        } => PRECEDENCE_AND,
        SyntaxExpression::UnaryOp {
            operator: SyntaxUnaryOperator::Not,
            ..
        } => PRECEDENCE_NOT,
        SyntaxExpression::Compare { .. } => PRECEDENCE_COMPARE,
        SyntaxExpression::BinOp { operator, .. } => binary_operator_precedence(*operator),
        SyntaxExpression::UnaryOp { .. } => PRECEDENCE_UNARY,
        SyntaxExpression::Attribute { .. }
        | SyntaxExpression::Subscript { .. }
        | SyntaxExpression::Call { .. } => PRECEDENCE_POSTFIX,
        SyntaxExpression::Name { .. }
        | SyntaxExpression::Constant { .. }
        | SyntaxExpression::List { .. }
        | SyntaxExpression::ListComp { .. }
        | SyntaxExpression::DictComp { .. }
        | SyntaxExpression::Tuple { .. }
        | SyntaxExpression::Dict { .. }
        | SyntaxExpression::Slice { .. }
        | SyntaxExpression::FString { .. }
        | SyntaxExpression::FormattedValue { .. } => PRECEDENCE_ATOM,
    }
}

fn binary_operator_precedence(operator: SyntaxBinaryOperator) -> u8 {
    match operator {
        SyntaxBinaryOperator::Pow => PRECEDENCE_POWER,
        SyntaxBinaryOperator::Mult
        | SyntaxBinaryOperator::Div
        | SyntaxBinaryOperator::FloorDiv
        | SyntaxBinaryOperator::Mod => PRECEDENCE_MULT,
        SyntaxBinaryOperator::Add | SyntaxBinaryOperator::Sub => PRECEDENCE_ADD,
        SyntaxBinaryOperator::LShift | SyntaxBinaryOperator::RShift => PRECEDENCE_SHIFT,
        SyntaxBinaryOperator::BitAnd => PRECEDENCE_BIT_AND,
        SyntaxBinaryOperator::BitXor => PRECEDENCE_BIT_XOR,
        SyntaxBinaryOperator::BitOr => PRECEDENCE_BIT_OR,
    }
}

fn format_expression_list(expressions: &[SyntaxExpression]) -> String {
    expressions
        .iter()
        .map(format_expression)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_tuple(elements: &[SyntaxExpression]) -> String {
    match elements {
        [] => "()".to_string(),
        [single] => format!("({},)", format_expression(single)),
        _ => format!("({})", format_expression_list(elements)),
    }
}

fn format_bare_tuple(elements: &[SyntaxExpression]) -> String {
    match elements {
        [] => "()".to_string(),
        [single] => format!("{},", format_expression(single)),
        _ => format_expression_list(elements),
    }
}

fn format_bool_op(operator: SyntaxBoolOperator, values: &[SyntaxExpression]) -> String {
    let separator = format!(" {} ", bool_operator_symbol(operator));
    let mut child_context_precedence = match operator {
        SyntaxBoolOperator::Or => CPYTHON_PRECEDENCE_OR,
        SyntaxBoolOperator::And => CPYTHON_PRECEDENCE_AND,
    };
    values
        .iter()
        .map(|value| {
            child_context_precedence = (child_context_precedence + 1).min(CPYTHON_PRECEDENCE_ATOM);
            let rendered = format_expression(value);
            if child_context_precedence > cpython_expression_precedence(value) {
                format!("({rendered})")
            } else {
                rendered
            }
        })
        .collect::<Vec<_>>()
        .join(&separator)
}

const CPYTHON_PRECEDENCE_TEST: u8 = 4;
const CPYTHON_PRECEDENCE_OR: u8 = 5;
const CPYTHON_PRECEDENCE_AND: u8 = 6;
const CPYTHON_PRECEDENCE_NOT: u8 = 7;
const CPYTHON_PRECEDENCE_COMPARE: u8 = 8;
const CPYTHON_PRECEDENCE_EXPR: u8 = 9;
const CPYTHON_PRECEDENCE_BXOR: u8 = 10;
const CPYTHON_PRECEDENCE_BAND: u8 = 11;
const CPYTHON_PRECEDENCE_SHIFT: u8 = 12;
const CPYTHON_PRECEDENCE_ARITH: u8 = 13;
const CPYTHON_PRECEDENCE_TERM: u8 = 14;
const CPYTHON_PRECEDENCE_FACTOR: u8 = 15;
const CPYTHON_PRECEDENCE_POWER: u8 = 16;
const CPYTHON_PRECEDENCE_ATOM: u8 = 18;

fn cpython_expression_precedence(expression: &SyntaxExpression) -> u8 {
    match expression {
        SyntaxExpression::IfExpr { .. } => CPYTHON_PRECEDENCE_TEST,
        SyntaxExpression::BoolOp {
            operator: SyntaxBoolOperator::Or,
            ..
        } => CPYTHON_PRECEDENCE_OR,
        SyntaxExpression::BoolOp {
            operator: SyntaxBoolOperator::And,
            ..
        } => CPYTHON_PRECEDENCE_AND,
        SyntaxExpression::UnaryOp {
            operator: SyntaxUnaryOperator::Not,
            ..
        } => CPYTHON_PRECEDENCE_NOT,
        SyntaxExpression::Compare { .. } => CPYTHON_PRECEDENCE_COMPARE,
        SyntaxExpression::BinOp { operator, .. } => match operator {
            SyntaxBinaryOperator::BitOr => CPYTHON_PRECEDENCE_EXPR,
            SyntaxBinaryOperator::BitXor => CPYTHON_PRECEDENCE_BXOR,
            SyntaxBinaryOperator::BitAnd => CPYTHON_PRECEDENCE_BAND,
            SyntaxBinaryOperator::LShift | SyntaxBinaryOperator::RShift => CPYTHON_PRECEDENCE_SHIFT,
            SyntaxBinaryOperator::Add | SyntaxBinaryOperator::Sub => CPYTHON_PRECEDENCE_ARITH,
            SyntaxBinaryOperator::Mult
            | SyntaxBinaryOperator::Div
            | SyntaxBinaryOperator::FloorDiv
            | SyntaxBinaryOperator::Mod => CPYTHON_PRECEDENCE_TERM,
            SyntaxBinaryOperator::Pow => CPYTHON_PRECEDENCE_POWER,
        },
        SyntaxExpression::UnaryOp { .. } => CPYTHON_PRECEDENCE_FACTOR,
        _ => CPYTHON_PRECEDENCE_ATOM,
    }
}

fn format_dict(entries: &[SyntaxDictEntry]) -> String {
    let entries = entries
        .iter()
        .map(|entry| match &entry.key {
            Some(key) => format!(
                "{}: {}",
                format_expression(key),
                format_expression(&entry.value)
            ),
            None => format!("**{}", format_expression(&entry.value)),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{entries}}}")
}

fn format_slice(
    lower: Option<&SyntaxExpression>,
    upper: Option<&SyntaxExpression>,
    step: Option<&SyntaxExpression>,
) -> String {
    let lower = lower.map(format_expression).unwrap_or_default();
    let upper = upper.map(format_expression).unwrap_or_default();
    match step {
        Some(step) => format!("{lower}:{upper}:{}", format_expression(step)),
        None => format!("{lower}:{upper}"),
    }
}

fn format_subscript_slice(slice: &SyntaxExpression) -> String {
    match slice {
        SyntaxExpression::Slice {
            lower, upper, step, ..
        } => format_slice(lower.as_deref(), upper.as_deref(), step.as_deref()),
        SyntaxExpression::Tuple { elements, .. } => format_bare_tuple(elements),
        _ => format_expression(slice),
    }
}

fn format_call_args(args: &[SyntaxExpression], keywords: &[SyntaxKeyword]) -> String {
    let mut parts = args.iter().map(format_expression).collect::<Vec<_>>();
    parts.extend(keywords.iter().map(|keyword| match &keyword.arg {
        Some(arg) => format!("{arg}={}", format_expression(&keyword.value)),
        None => format!("**{}", format_expression(&keyword.value)),
    }));
    parts.join(", ")
}

fn format_compare(
    left: &SyntaxExpression,
    operators: &[SyntaxCompareOperator],
    comparators: &[SyntaxExpression],
) -> String {
    let mut output = format_expression_with_precedence(left, PRECEDENCE_COMPARE + 1);
    for (operator, comparator) in operators.iter().zip(comparators.iter()) {
        output.push(' ');
        output.push_str(compare_operator_symbol(*operator));
        output.push(' ');
        output.push_str(&format_expression_with_precedence(
            comparator,
            PRECEDENCE_COMPARE + 1,
        ));
    }
    output
}

fn format_comprehensions(comprehensions: &[SyntaxComprehension]) -> String {
    comprehensions
        .iter()
        .map(|comprehension| {
            let mut output = String::new();
            if comprehension.is_async {
                output.push_str("async ");
            }
            output.push_str("for ");
            output.push_str(&format_expression(&comprehension.target));
            output.push_str(" in ");
            output.push_str(&format_expression(&comprehension.iter));
            for condition in &comprehension.ifs {
                output.push_str(" if ");
                output.push_str(&format_expression(condition));
            }
            output
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_fstring(values: &[SyntaxExpression]) -> String {
    let content = values.iter().map(format_fstring_part).collect::<String>();
    format!("f'{}'", content.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn format_fstring_part(expression: &SyntaxExpression) -> String {
    match expression {
        SyntaxExpression::Constant {
            value: SyntaxConstant::Str(value),
            ..
        } => value.replace('{', "{{").replace('}', "}}"),
        SyntaxExpression::FormattedValue {
            value,
            conversion,
            format_spec,
            ..
        } => {
            let mut output = format_expression(value);
            if let Some(conversion) = conversion {
                output.push('!');
                output.push(*conversion);
            }
            if let Some(format_spec) = format_spec {
                output.push(':');
                output.push_str(&match format_spec.as_ref() {
                    SyntaxExpression::FString { values, .. } => {
                        values.iter().map(format_fstring_part).collect::<String>()
                    }
                    other => format_expression(other),
                });
            }
            format!("{{{output}}}")
        }
        other => format_expression(other),
    }
}

fn format_constant(constant: &SyntaxConstant) -> String {
    match constant {
        SyntaxConstant::None => "None".to_string(),
        SyntaxConstant::Bool(value) => {
            if *value {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        SyntaxConstant::Int(value) => value.clone(),
        SyntaxConstant::Float(value) => format_float(*value),
        SyntaxConstant::Str(value) => quote_string(value),
        SyntaxConstant::Bytes(value) => quote_bytes(value),
        SyntaxConstant::Tuple(values) => match values.as_slice() {
            [] => "()".to_string(),
            [single] => format!("({},)", format_constant(single)),
            _ => format!(
                "({})",
                values
                    .iter()
                    .map(format_constant)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        },
    }
}

fn quote_string(value: &str) -> String {
    if value.contains('\'') && !value.contains('"') {
        return quote_string_with_delimiter(value, '"');
    }
    quote_string_with_delimiter(value, '\'')
}

fn quote_triple_string(value: &str) -> String {
    format!("\"\"\"{}\"\"\"", value.replace("\"\"\"", "\\\"\"\""))
}

fn quote_string_with_delimiter(value: &str, delimiter: char) -> String {
    let mut output = String::new();
    output.push(delimiter);
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\'' if delimiter == '\'' => output.push_str("\\'"),
            '"' if delimiter == '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format_python_unicode_escape(character));
            }
            character => output.push(character),
        }
    }
    output.push(delimiter);
    output
}

fn format_python_unicode_escape(character: char) -> String {
    let codepoint = character as u32;
    if codepoint <= 0xffff {
        format!("\\u{codepoint:04x}")
    } else {
        format!("\\U{codepoint:08x}")
    }
}

fn quote_bytes(hex: &str) -> String {
    let mut output = String::from("b'");
    for chunk in hex.as_bytes().chunks(2) {
        output.push_str("\\x");
        output.push_str(std::str::from_utf8(chunk).unwrap_or("00"));
    }
    output.push('\'');
    output
}

pub(crate) fn format_float(value: f64) -> String {
    if value != 0.0 && value.abs() < 0.0001 {
        return format_scientific_float(value);
    }
    let rendered = value.to_string();
    if rendered.contains('.') || rendered.contains('e') || rendered.contains('E') {
        rendered
    } else {
        format!("{rendered}.0")
    }
}

fn format_scientific_float(value: f64) -> String {
    let rendered = format!("{value:e}");
    let Some((mantissa, exponent)) = rendered.split_once('e') else {
        return rendered;
    };
    let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
    let exponent_value = exponent.parse::<i32>().unwrap_or(0);
    let sign = if exponent_value < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exponent_value.abs())
}

fn bool_operator_symbol(operator: SyntaxBoolOperator) -> &'static str {
    match operator {
        SyntaxBoolOperator::And => "and",
        SyntaxBoolOperator::Or => "or",
    }
}

fn binary_operator_symbol(operator: SyntaxBinaryOperator) -> &'static str {
    match operator {
        SyntaxBinaryOperator::Add => "+",
        SyntaxBinaryOperator::Sub => "-",
        SyntaxBinaryOperator::Mult => "*",
        SyntaxBinaryOperator::Div => "/",
        SyntaxBinaryOperator::FloorDiv => "//",
        SyntaxBinaryOperator::Mod => "%",
        SyntaxBinaryOperator::Pow => "**",
        SyntaxBinaryOperator::BitAnd => "&",
        SyntaxBinaryOperator::BitOr => "|",
        SyntaxBinaryOperator::BitXor => "^",
        SyntaxBinaryOperator::LShift => "<<",
        SyntaxBinaryOperator::RShift => ">>",
    }
}

fn compare_operator_symbol(operator: SyntaxCompareOperator) -> &'static str {
    match operator {
        SyntaxCompareOperator::Eq => "==",
        SyntaxCompareOperator::NotEq => "!=",
        SyntaxCompareOperator::Gt => ">",
        SyntaxCompareOperator::GtE => ">=",
        SyntaxCompareOperator::Lt => "<",
        SyntaxCompareOperator::LtE => "<=",
        SyntaxCompareOperator::In => "in",
        SyntaxCompareOperator::NotIn => "not in",
        SyntaxCompareOperator::Is => "is",
        SyntaxCompareOperator::IsNot => "is not",
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::CompileOptions;
    use crate::normalize::{normalize_source, normalize_syntax};
    use crate::source::SourceUnit;
    use crate::syntax::parse_to_syntax;

    #[test]
    fn normalize_syntax_matches_counter_fixture_style() {
        let source = "counter = Variable()\n\n\n@construct\ndef seed():\n    counter.set(0)\n\n\n@export\ndef get():\n    return counter.get()\n\n\n@export\ndef increment():\n    counter.set(counter.get() + 1)\n    return counter.get()\n";
        let unit = SourceUnit::new("con_counter", source).expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        assert_eq!(
            normalize_syntax(&syntax),
            "counter = Variable()\n\n@construct\ndef seed():\n    counter.set(0)\n\n@export\ndef get():\n    return counter.get()\n\n@export\ndef increment():\n    counter.set(counter.get() + 1)\n    return counter.get()"
        );
    }

    #[test]
    fn normalize_source_runs_lint_by_default() {
        let error = normalize_source(
            "con_bad",
            "def helper():\n    return 1\n",
            &CompileOptions::default(),
        )
        .expect_err("lint should reject missing export");

        assert_eq!(error[0].code, "xian.lint.E013");
    }

    #[test]
    fn normalize_source_can_skip_lint() {
        let normalized = normalize_source(
            "con_helper",
            "a=1\nb=2\n\ndef helper():\n return a+b\n",
            &CompileOptions {
                lint: false,
                ..CompileOptions::default()
            },
        )
        .expect("source should normalize");

        assert_eq!(
            normalized,
            "a = 1\nb = 2\n\ndef helper():\n    return a + b"
        );
    }

    #[test]
    fn normalize_syntax_formats_control_flow_and_annotations() {
        let source = "@export(typecheck=False)\ndef select(value: int = 1) -> int:\n    if value > 0:\n        return value\n    else:\n        return -value\n";
        let unit = SourceUnit::new("con_select", source).expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        assert_eq!(
            normalize_syntax(&syntax),
            "@export(typecheck=False)\ndef select(value: int=1) -> int:\n    if value > 0:\n        return value\n    else:\n        return -value"
        );
    }

    #[test]
    fn normalize_syntax_preserves_power_associativity() {
        let source = "@export\ndef calc(a: int, b: int, c: int):\n    return (a ** b) ** c\n";
        let unit = SourceUnit::new("con_power", source).expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        assert_eq!(
            normalize_syntax(&syntax),
            "@export\ndef calc(a: int, b: int, c: int):\n    return (a ** b) ** c"
        );
    }
}
