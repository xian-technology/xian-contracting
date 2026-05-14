use std::collections::HashSet;

use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::syntax::{
    SyntaxBinaryOperator, SyntaxConstant, SyntaxDictEntry, SyntaxExpression, SyntaxImportAlias,
    SyntaxModule, SyntaxParameter, SyntaxStatement,
};

const EXPORT_DECORATOR: &str = "export";
const CONSTRUCT_DECORATOR: &str = "construct";
const ORM_CLASS_NAMES: &[&str] = &[
    "Variable",
    "Hash",
    "ForeignVariable",
    "ForeignHash",
    "LogEvent",
];
const AUTO_NAMED_ORM_CLASS_NAMES: &[&str] = &["Variable", "Hash", "LogEvent"];
const ALLOWED_ANNOTATION_TYPES: &[&str] = &[
    "Any",
    "bool",
    "bytearray",
    "bytes",
    "datetime.datetime",
    "datetime.timedelta",
    "dict",
    "float",
    "frozenset",
    "int",
    "list",
    "set",
    "str",
];

const DISALLOWED_BUILTIN_CALLS: &[&str] = &[
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BaseExceptionGroup",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "EncodingWarning",
    "EnvironmentError",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
    "__build_class__",
    "__import__",
    "aiter",
    "anext",
    "breakpoint",
    "callable",
    "classmethod",
    "compile",
    "delattr",
    "dir",
    "enumerate",
    "eval",
    "exec",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "id",
    "input",
    "iter",
    "locals",
    "memoryview",
    "next",
    "object",
    "open",
    "print",
    "property",
    "repr",
    "setattr",
    "slice",
    "staticmethod",
    "super",
    "type",
];

const DISALLOWED_STDLIB_IMPORTS: &[&str] = &[
    "abc",
    "argparse",
    "asyncio",
    "base64",
    "collections",
    "contextlib",
    "copy",
    "csv",
    "datetime",
    "decimal",
    "functools",
    "hashlib",
    "heapq",
    "importlib",
    "inspect",
    "io",
    "itertools",
    "json",
    "math",
    "os",
    "pathlib",
    "random",
    "re",
    "statistics",
    "string",
    "sys",
    "time",
    "typing",
    "uuid",
];

#[derive(Debug, Default)]
pub struct SyntaxLinter {
    diagnostics: Vec<CompilerDiagnostic>,
    orm_names: HashSet<String>,
    export_args: Vec<(String, SourceRange)>,
    arg_annotations: Vec<(Option<String>, SourceRange)>,
    return_annotations: Vec<(Option<String>, SourceRange)>,
    has_export: bool,
    has_construct: bool,
    first_function_span: Option<SourceRange>,
}

pub fn lint_syntax(module: &SyntaxModule) -> Vec<CompilerDiagnostic> {
    SyntaxLinter::default().lint(module)
}

impl SyntaxLinter {
    pub fn lint(mut self, module: &SyntaxModule) -> Vec<CompilerDiagnostic> {
        self.visit_statements(&module.body, 0);
        self.run_final_checks();
        self.diagnostics
            .sort_by(|left, right| diagnostic_sort_key(left).cmp(&diagnostic_sort_key(right)));
        self.diagnostics
    }

    fn visit_statements(&mut self, statements: &[SyntaxStatement], function_depth: usize) {
        for statement in statements {
            self.visit_statement(statement, function_depth);
        }
    }

    fn visit_statement(&mut self, statement: &SyntaxStatement, function_depth: usize) {
        match statement {
            SyntaxStatement::FunctionDef {
                span,
                decorators,
                parameters,
                returns,
                body,
                ..
            } => {
                if self.first_function_span.is_none() {
                    self.first_function_span = Some(span.clone());
                }
                if function_depth > 0 {
                    self.push("E019", "Nested function definitions are not allowed", span);
                    return;
                }
                self.check_function_decorators(*span, decorators, parameters, returns);
                self.check_single_line_body(*span, body);
                for decorator in decorators {
                    self.visit_expression(decorator);
                }
                if let Some(returns) = returns {
                    self.visit_expression(returns);
                }
                for parameter in parameters {
                    if let Some(annotation) = &parameter.annotation {
                        self.visit_expression(annotation);
                    }
                    if let Some(default) = &parameter.default {
                        self.visit_expression(default);
                    }
                }
                self.visit_statements(body, function_depth + 1);
            }
            SyntaxStatement::Return { value, .. } => {
                if let Some(value) = value {
                    self.visit_expression(value);
                }
            }
            SyntaxStatement::Assign {
                span,
                targets,
                value,
            } => {
                self.check_orm_assignment(*span, targets, value);
                for target in targets {
                    self.visit_expression(target);
                }
                self.visit_expression(value);
            }
            SyntaxStatement::AugAssign {
                span,
                target,
                operator,
                value,
            } => {
                if *operator == SyntaxBinaryOperator::Mult {
                    self.push(
                        "E001",
                        "Illegal syntax: Augmented multiplication is not allowed; use x = x * y",
                        span,
                    );
                }
                self.visit_expression(target);
                self.visit_expression(value);
            }
            SyntaxStatement::For {
                span,
                target,
                iter,
                body,
                orelse,
            } => {
                self.check_single_line_body(*span, body);
                self.check_single_line_body(*span, orelse);
                self.visit_expression(target);
                self.visit_expression(iter);
                self.visit_statements(body, function_depth);
                self.visit_statements(orelse, function_depth);
            }
            SyntaxStatement::While {
                span,
                test,
                body,
                orelse,
            }
            | SyntaxStatement::If {
                span,
                test,
                body,
                orelse,
            } => {
                self.check_single_line_body(*span, body);
                self.check_single_line_body(*span, orelse);
                self.visit_expression(test);
                self.visit_statements(body, function_depth);
                self.visit_statements(orelse, function_depth);
            }
            SyntaxStatement::Assert { test, message, .. } => {
                self.visit_expression(test);
                if let Some(message) = message {
                    self.visit_expression(message);
                }
            }
            SyntaxStatement::Raise {
                exception, cause, ..
            } => {
                if let Some(exception) = exception {
                    self.visit_expression(exception);
                }
                if let Some(cause) = cause {
                    self.visit_expression(cause);
                }
            }
            SyntaxStatement::Import { span, names } => {
                if function_depth > 0 {
                    self.push("E003", "Imports are not allowed inside functions", span);
                    return;
                }
                for alias in names {
                    self.check_import_alias(alias, span);
                }
            }
            SyntaxStatement::Expr { value, .. } => self.visit_expression(value),
            SyntaxStatement::Pass { .. }
            | SyntaxStatement::Break { .. }
            | SyntaxStatement::Continue { .. } => {}
        }
    }

    fn check_function_decorators(
        &mut self,
        function_span: SourceRange,
        decorators: &[SyntaxExpression],
        parameters: &[SyntaxParameter],
        returns: &Option<SyntaxExpression>,
    ) {
        if decorators.len() > 1 {
            self.push(
                "E010",
                "Functions may have at most one decorator",
                &function_span,
            );
        }

        let mut selected_decorator_name = None;
        if let Some(decorator) = decorators.first() {
            selected_decorator_name = decorator_name(decorator);
            match selected_decorator_name {
                Some(EXPORT_DECORATOR | CONSTRUCT_DECORATOR) => {
                    self.check_decorator_args(decorator, selected_decorator_name.unwrap());
                }
                Some(name) => self.push(
                    "E008",
                    format!("Invalid decorator '{name}'; must be 'export' or 'construct'"),
                    span_of_expression(decorator),
                ),
                None => self.push(
                    "E008",
                    "Invalid decorator '<complex>'; must be 'export' or 'construct'",
                    span_of_expression(decorator),
                ),
            }
        }

        if selected_decorator_name == Some(CONSTRUCT_DECORATOR) {
            if self.has_construct {
                self.push(
                    "E009",
                    "Multiple @construct decorators found; only one allowed",
                    &function_span,
                );
            }
            self.has_construct = true;
        }

        if selected_decorator_name == Some(EXPORT_DECORATOR) {
            self.has_export = true;
            self.record_export_annotations(parameters, returns, &function_span);
        }
    }

    fn check_decorator_args(&mut self, decorator: &SyntaxExpression, decorator_name: &str) {
        let SyntaxExpression::Call {
            span,
            args,
            keywords,
            ..
        } = decorator
        else {
            return;
        };

        if decorator_name == CONSTRUCT_DECORATOR {
            if !args.is_empty() || !keywords.is_empty() {
                self.push(
                    "E021",
                    "Invalid decorator arguments for 'construct': @construct does not accept arguments",
                    span,
                );
            }
            return;
        }

        if !args.is_empty() {
            self.push(
                "E021",
                "Invalid decorator arguments for 'export': @export accepts keyword arguments only",
                span,
            );
        }
        for keyword in keywords {
            if keyword.arg.as_deref() != Some("typecheck") {
                self.push(
                    "E021",
                    "Invalid decorator arguments for 'export': only 'typecheck' is supported",
                    &keyword.span,
                );
                continue;
            }
            if !matches!(
                keyword.value,
                SyntaxExpression::Constant {
                    value: SyntaxConstant::Bool(_),
                    ..
                }
            ) {
                self.push(
                    "E021",
                    "Invalid decorator arguments for 'export': 'typecheck' must be True or False",
                    span_of_expression(&keyword.value),
                );
            }
        }
    }

    fn record_export_annotations(
        &mut self,
        parameters: &[SyntaxParameter],
        returns: &Option<SyntaxExpression>,
        function_span: &SourceRange,
    ) {
        for parameter in parameters {
            self.export_args
                .push((parameter.name.clone(), parameter.span.clone()));
            self.arg_annotations.push((
                parameter.annotation.as_ref().and_then(annotation_name),
                parameter.span.clone(),
            ));
        }
        if let Some(returns) = returns {
            self.return_annotations
                .push((annotation_name(returns), function_span.clone()));
        }
    }

    fn check_single_line_body(&mut self, parent: SourceRange, body: &[SyntaxStatement]) {
        if let Some(first) = body.first() {
            let first_span = span_of_statement(first);
            if first_span.start_line == parent.start_line {
                self.push(
                    "E001",
                    "Illegal syntax: Single-line compound statements are not allowed",
                    first_span,
                );
            }
        }
    }

    fn check_orm_assignment(
        &mut self,
        span: SourceRange,
        targets: &[SyntaxExpression],
        value: &SyntaxExpression,
    ) {
        if let Some(orm_name) = call_name(value) {
            if ORM_CLASS_NAMES.contains(&orm_name) {
                for target in targets {
                    if matches!(target, SyntaxExpression::Tuple { .. }) {
                        self.push(
                            "E012",
                            "Tuple unpacking on ORM assignment is not allowed",
                            &span,
                        );
                        return;
                    }
                }
                if AUTO_NAMED_ORM_CLASS_NAMES.contains(&orm_name) {
                    if let SyntaxExpression::Call { keywords, .. } = value {
                        for keyword in keywords {
                            if matches!(keyword.arg.as_deref(), Some("contract" | "name")) {
                                self.push(
                                    "E011",
                                    format!(
                                        "Cannot pass '{}' to {orm_name}; it is set automatically",
                                        keyword.arg.as_deref().unwrap_or("")
                                    ),
                                    &keyword.span,
                                );
                            }
                        }
                    }
                }
                if let Some(first_target) = targets.first() {
                    if let Some(name) = name_expr(first_target) {
                        self.orm_names.insert(name.to_string());
                    }
                }
            }
            return;
        }

        if let Some(name) = name_expr(value) {
            if ORM_CLASS_NAMES.contains(&name) {
                self.push(
                    "E014",
                    format!("'{name}' is not allowed in smart contracts"),
                    &span,
                );
            }
        }
    }

    fn check_import_alias(&mut self, alias: &SyntaxImportAlias, statement_span: &SourceRange) {
        let root = alias.name.split('.').next().unwrap_or(alias.name.as_str());
        if DISALLOWED_STDLIB_IMPORTS.contains(&root) {
            self.push(
                "E005",
                format!("Cannot import stdlib module '{}'", alias.name),
                statement_span,
            );
        }
    }

    fn visit_expression(&mut self, expression: &SyntaxExpression) {
        match expression {
            SyntaxExpression::Name { span, id, .. } => self.check_name(id, span),
            SyntaxExpression::Constant { .. } => {}
            SyntaxExpression::List { elements, .. } | SyntaxExpression::Tuple { elements, .. } => {
                for element in elements {
                    self.visit_expression(element);
                }
            }
            SyntaxExpression::ListComp {
                element,
                generators,
                ..
            } => {
                self.visit_expression(element);
                self.visit_comprehensions(generators);
            }
            SyntaxExpression::DictComp {
                key,
                value,
                generators,
                ..
            } => {
                self.visit_expression(key);
                self.visit_expression(value);
                self.visit_comprehensions(generators);
            }
            SyntaxExpression::Dict { entries, .. } => {
                for SyntaxDictEntry { key, value } in entries {
                    if let Some(key) = key {
                        self.visit_expression(key);
                    }
                    self.visit_expression(value);
                }
            }
            SyntaxExpression::Attribute {
                span, value, attr, ..
            } => {
                self.check_name(attr, span);
                self.visit_expression(value);
            }
            SyntaxExpression::Subscript { value, slice, .. } => {
                self.visit_expression(value);
                self.visit_expression(slice);
            }
            SyntaxExpression::Slice {
                lower, upper, step, ..
            } => {
                for expression in [lower.as_deref(), upper.as_deref(), step.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    self.visit_expression(expression);
                }
            }
            SyntaxExpression::Call {
                span,
                func,
                args,
                keywords,
            } => {
                if let Some(name) = name_expr(func) {
                    if DISALLOWED_BUILTIN_CALLS.contains(&name) {
                        self.push(
                            "E014",
                            format!("'{name}' is not allowed in smart contracts"),
                            span,
                        );
                    }
                }
                self.visit_expression(func);
                for arg in args {
                    self.visit_expression(arg);
                }
                for keyword in keywords {
                    self.visit_expression(&keyword.value);
                }
            }
            SyntaxExpression::Compare {
                left, comparators, ..
            } => {
                self.visit_expression(left);
                for comparator in comparators {
                    self.visit_expression(comparator);
                }
            }
            SyntaxExpression::BoolOp { values, .. } | SyntaxExpression::FString { values, .. } => {
                for value in values {
                    self.visit_expression(value);
                }
            }
            SyntaxExpression::BinOp { left, right, .. } => {
                self.visit_expression(left);
                self.visit_expression(right);
            }
            SyntaxExpression::UnaryOp { operand, .. } => self.visit_expression(operand),
            SyntaxExpression::IfExpr {
                test, body, orelse, ..
            } => {
                self.visit_expression(test);
                self.visit_expression(body);
                self.visit_expression(orelse);
            }
            SyntaxExpression::FormattedValue {
                value, format_spec, ..
            } => {
                self.visit_expression(value);
                if let Some(format_spec) = format_spec {
                    self.visit_expression(format_spec);
                }
            }
        }
    }

    fn visit_comprehensions(&mut self, comprehensions: &[crate::syntax::SyntaxComprehension]) {
        for comprehension in comprehensions {
            self.visit_expression(&comprehension.target);
            self.visit_expression(&comprehension.iter);
            for condition in &comprehension.ifs {
                self.visit_expression(condition);
            }
        }
    }

    fn check_name(&mut self, name: &str, span: &SourceRange) {
        if name == "rt" {
            self.push("E014", "'rt' is not allowed in smart contracts", span);
        } else if name.starts_with('_') || name.ends_with('_') {
            self.push(
                "E002",
                format!("Name '{name}' must not start or end with underscore"),
                span,
            );
        }
    }

    fn run_final_checks(&mut self) {
        if !self.has_export {
            let span = self.first_function_span.unwrap_or_else(default_span);
            self.push(
                "E013",
                "Contract must have at least one @export function",
                &span,
            );
        }

        let export_args = self.export_args.clone();
        for (name, span) in export_args {
            if self.orm_names.contains(&name) {
                self.push(
                    "E015",
                    format!("Argument '{name}' shadows ORM variable defined at module level"),
                    &span,
                );
            }
        }

        let allowed = allowed_annotations_message();
        let arg_annotations = self.arg_annotations.clone();
        for (annotation, span) in arg_annotations {
            match annotation {
                None => self.push(
                    "E017",
                    "All @export function arguments must have type annotations",
                    &span,
                ),
                Some(annotation) if !annotation_allowed(&annotation) => self.push(
                    "E016",
                    format!("Type annotation '{annotation}' is not allowed; use one of: {allowed}"),
                    &span,
                ),
                Some(_) => {}
            }
        }

        let return_annotations = self.return_annotations.clone();
        for (annotation, span) in return_annotations {
            if let Some(annotation) = annotation {
                if !annotation_allowed(&annotation) {
                    self.push(
                        "E018",
                        format!(
                            "Return type annotation '{annotation}' is not allowed; use one of: {allowed}"
                        ),
                        &span,
                    );
                }
            }
        }
    }

    fn push(&mut self, code: impl AsRef<str>, message: impl Into<String>, span: &SourceRange) {
        self.diagnostics.push(
            CompilerDiagnostic::error(format!("xian.lint.{}", code.as_ref()), message.into())
                .with_range(span.clone()),
        );
    }
}

fn decorator_name(expression: &SyntaxExpression) -> Option<&str> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id),
        SyntaxExpression::Call { func, .. } => name_expr(func),
        _ => None,
    }
}

fn call_name(expression: &SyntaxExpression) -> Option<&str> {
    match expression {
        SyntaxExpression::Call { func, .. } => name_expr(func),
        _ => None,
    }
}

fn name_expr(expression: &SyntaxExpression) -> Option<&str> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id),
        _ => None,
    }
}

fn annotation_name(expression: &SyntaxExpression) -> Option<String> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id.clone()),
        SyntaxExpression::Attribute { value, attr, .. } => {
            dotted_name(value).map(|prefix| format!("{prefix}.{attr}"))
        }
        SyntaxExpression::Subscript { value, slice, .. } => {
            annotation_name(value).map(|base| format!("{base}[{}]", compact_expression(slice)))
        }
        SyntaxExpression::Constant {
            value: SyntaxConstant::Str(value),
            ..
        } => Some(value.clone()),
        _ => None,
    }
}

fn dotted_name(expression: &SyntaxExpression) -> Option<String> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id.clone()),
        SyntaxExpression::Attribute { value, attr, .. } => {
            dotted_name(value).map(|prefix| format!("{prefix}.{attr}"))
        }
        _ => None,
    }
}

fn compact_expression(expression: &SyntaxExpression) -> String {
    match expression {
        SyntaxExpression::Name { id, .. } => id.clone(),
        SyntaxExpression::Attribute { value, attr, .. } => {
            format!("{}.{}", compact_expression(value), attr)
        }
        SyntaxExpression::Subscript { value, slice, .. } => {
            format!(
                "{}[{}]",
                compact_expression(value),
                compact_expression(slice)
            )
        }
        SyntaxExpression::Tuple { elements, .. } => elements
            .iter()
            .map(compact_expression)
            .collect::<Vec<_>>()
            .join(","),
        SyntaxExpression::Constant { value, .. } => compact_constant(value),
        _ => "<complex>".to_string(),
    }
}

fn compact_constant(constant: &SyntaxConstant) -> String {
    match constant {
        SyntaxConstant::None => "None".to_string(),
        SyntaxConstant::Bool(value) => {
            if *value {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        SyntaxConstant::Int(value) | SyntaxConstant::Str(value) | SyntaxConstant::Bytes(value) => {
            value.clone()
        }
        SyntaxConstant::Float(value) => value.to_string(),
        SyntaxConstant::Tuple(values) => values
            .iter()
            .map(compact_constant)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn annotation_allowed(annotation: &str) -> bool {
    let base = annotation
        .split_once('[')
        .map_or(annotation, |(base, _)| base);
    ALLOWED_ANNOTATION_TYPES.contains(&base)
}

fn allowed_annotations_message() -> String {
    let mut allowed = ALLOWED_ANNOTATION_TYPES.to_vec();
    allowed.sort_unstable();
    allowed.join(", ")
}

fn span_of_statement(statement: &SyntaxStatement) -> &SourceRange {
    match statement {
        SyntaxStatement::FunctionDef { span, .. }
        | SyntaxStatement::Return { span, .. }
        | SyntaxStatement::Assign { span, .. }
        | SyntaxStatement::AugAssign { span, .. }
        | SyntaxStatement::For { span, .. }
        | SyntaxStatement::While { span, .. }
        | SyntaxStatement::If { span, .. }
        | SyntaxStatement::Assert { span, .. }
        | SyntaxStatement::Raise { span, .. }
        | SyntaxStatement::Import { span, .. }
        | SyntaxStatement::Expr { span, .. }
        | SyntaxStatement::Pass { span }
        | SyntaxStatement::Break { span }
        | SyntaxStatement::Continue { span } => span,
    }
}

fn span_of_expression(expression: &SyntaxExpression) -> &SourceRange {
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
        | SyntaxExpression::FormattedValue { span, .. } => span,
    }
}

fn default_span() -> SourceRange {
    SourceRange {
        start_line: 1,
        start_column: 0,
        end_line: 1,
        end_column: 0,
    }
}

fn diagnostic_sort_key(diagnostic: &CompilerDiagnostic) -> (u32, u32, String) {
    let (line, column) = diagnostic
        .range
        .as_ref()
        .map(|range| (range.start_line, range.start_column))
        .unwrap_or((0, 0));
    (line, column, diagnostic.code.clone())
}

#[cfg(test)]
mod tests {
    use crate::compiler::{diagnose_contract, CompileOptions};
    use crate::lint::lint_syntax;
    use crate::source::SourceUnit;
    use crate::syntax::parse_to_syntax;

    fn lint_source(source: &str) -> Vec<String> {
        let unit = SourceUnit::new("con_lint", source).expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");
        lint_syntax(&syntax)
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn lint_accepts_minimal_export() {
        let diagnostics = lint_source("@export\ndef ping() -> int:\n    return 1\n");

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn lint_requires_export() {
        let diagnostics = lint_source("def helper():\n    return 1\n");

        assert_eq!(diagnostics, vec!["xian.lint.E013"]);
    }

    #[test]
    fn lint_checks_export_argument_annotations() {
        let diagnostics = lint_source("@export\ndef ping(value):\n    return value\n");

        assert_eq!(diagnostics, vec!["xian.lint.E017"]);
    }

    #[test]
    fn lint_rejects_invalid_decorator_and_multiple_constructs() {
        let diagnostics = lint_source(
            "@construct\ndef seed():\n    pass\n\n@construct\ndef seed_again():\n    pass\n\n@bad\ndef ping() -> int:\n    return 1\n",
        );

        assert!(diagnostics.contains(&"xian.lint.E008".to_string()));
        assert!(diagnostics.contains(&"xian.lint.E009".to_string()));
        assert!(diagnostics.contains(&"xian.lint.E013".to_string()));
    }

    #[test]
    fn lint_checks_orm_assignment_rules() {
        let diagnostics = lint_source(
            "counter = Variable(name='counter')\n\n@export\ndef ping(counter: int) -> int:\n    return counter\n",
        );

        assert!(diagnostics.contains(&"xian.lint.E011".to_string()));
        assert!(diagnostics.contains(&"xian.lint.E015".to_string()));
    }

    #[test]
    fn diagnose_contract_honors_lint_option() {
        let source = "def helper():\n    return 1\n";

        let linted = diagnose_contract("con_lint", source, &CompileOptions::default());
        let unlinted = diagnose_contract(
            "con_lint",
            source,
            &CompileOptions {
                lint: false,
                ..CompileOptions::default()
            },
        );

        assert_eq!(linted[0].code, "xian.lint.E013");
        assert!(unlinted.is_empty());
    }
}
