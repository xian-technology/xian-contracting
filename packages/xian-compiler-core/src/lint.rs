use std::collections::HashSet;

use crate::constants::{MAX_CONTRACT_NAME_BYTES, MAX_STORAGE_KEY_BYTES};
use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::syntax::{
    SyntaxBinaryOperator, SyntaxConstant, SyntaxDictEntry, SyntaxExpression, SyntaxImportAlias,
    SyntaxKeyword, SyntaxModule, SyntaxParameter, SyntaxStatement,
};
use crate::XIAN_VM_V2_PROFILE;

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
const FOREIGN_STORAGE_CLASS_NAMES: &[&str] = &["ForeignVariable", "ForeignHash"];
const FOREIGN_STORAGE_KEYWORDS: &[&str] = &["foreign_contract", "foreign_name"];
const ALLOWED_ANNOTATION_TYPES: &[&str] = &[
    "Any",
    "bool",
    "bytearray",
    "bytes",
    "datetime.datetime",
    "datetime.timedelta",
    "dict",
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
    // Set for xian_vm_v2, which also enables the V2-only admission rules.
    exact_numbers: bool,
    diagnostics: Vec<CompilerDiagnostic>,
    orm_names: HashSet<String>,
    module_function_names: HashSet<String>,
    // The ORM call that is the whole value of the module declaration being visited.
    declaration_call: Option<*const SyntaxExpression>,
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
        self.exact_numbers = module.vm_profile == XIAN_VM_V2_PROFILE;
        self.module_function_names = module
            .body
            .iter()
            .filter_map(|statement| match statement {
                SyntaxStatement::FunctionDef { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
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
                if function_depth == 0 && targets.len() == 1 && name_expr(&targets[0]).is_some() {
                    self.declaration_call = Some(value as *const SyntaxExpression);
                }
                self.visit_expression(value);
                self.declaration_call = None;
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
                if !self.exact_numbers {
                    self.check_v1_declaration_keywords(orm_name, value);
                }
                if let Some(first_target) = targets.first() {
                    if let Some(name) = name_expr(first_target) {
                        if self.exact_numbers && AUTO_NAMED_ORM_CLASS_NAMES.contains(&orm_name) {
                            self.check_storage_key_room(orm_name, name, &span);
                        }
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

    // Archival V1 admission keeps its original declaration rule.
    fn check_v1_declaration_keywords(&mut self, orm_name: &str, value: &SyntaxExpression) {
        let SyntaxExpression::Call { keywords, .. } = value else {
            return;
        };
        if !AUTO_NAMED_ORM_CLASS_NAMES.contains(&orm_name) {
            return;
        }
        for keyword in keywords {
            if let Some(arg @ ("contract" | "name")) = keyword.arg.as_deref() {
                self.push(
                    "E011",
                    format!("Cannot pass '{arg}' to {orm_name}; it is set automatically"),
                    &keyword.span,
                );
            }
        }
    }

    fn check_storage_call(
        &mut self,
        name: &str,
        span: &SourceRange,
        args: &[SyntaxExpression],
        keywords: &[SyntaxKeyword],
        is_declaration: bool,
    ) {
        let foreign = FOREIGN_STORAGE_CLASS_NAMES.contains(&name);
        if !foreign && !is_declaration {
            self.push(
                "E022",
                format!("{name} must be declared at module level as 'name = {name}(...)'"),
                span,
            );
        }
        for keyword in keywords {
            self.check_storage_keyword(name, foreign, keyword);
        }
        // LogEvent takes its event name and params positionally; storage does not.
        if name != "LogEvent" && !args.is_empty() {
            self.push(
                "E023",
                format!("Invalid {name} arguments: use keyword arguments only"),
                span,
            );
        }
        if foreign {
            self.check_foreign_storage_target(name, span, keywords);
        }
    }

    // The shortest key a declaration can use is `contract.binding`, plus ':'
    // and an empty hash key for a hash; it must fit under the longest name.
    fn check_storage_key_room(&mut self, kind: &str, binding: &str, span: &SourceRange) {
        let separators = if kind.ends_with("Hash") { 2 } else { 1 };
        let max_binding = MAX_STORAGE_KEY_BYTES - MAX_CONTRACT_NAME_BYTES - separators;
        if binding.len() > max_binding {
            self.push(
                "E024",
                format!(
                    "{kind} name is too long ({} bytes): its storage key could exceed \
                     {MAX_STORAGE_KEY_BYTES} bytes. Max is {max_binding}.",
                    binding.len()
                ),
                span,
            );
        }
    }

    fn check_storage_keyword(&mut self, name: &str, foreign: bool, keyword: &SyntaxKeyword) {
        let message = match keyword.arg.as_deref() {
            Some(arg @ ("contract" | "name")) if !foreign => {
                self.push(
                    "E011",
                    format!("Cannot pass '{arg}' to {name}; it is set automatically"),
                    &keyword.span,
                );
                return;
            }
            Some(arg @ ("contract" | "name")) => format!("'{arg}' is not accepted"),
            None => "'**' unpacking is not allowed".to_string(),
            Some(_) => return,
        };
        self.push(
            "E023",
            format!("Invalid {name} arguments: {message}"),
            &keyword.span,
        );
    }

    fn check_foreign_storage_target(
        &mut self,
        name: &str,
        span: &SourceRange,
        keywords: &[SyntaxKeyword],
    ) {
        for keyword in keywords {
            if let (
                Some("foreign_name"),
                SyntaxExpression::Constant {
                    value: SyntaxConstant::Str(foreign_name),
                    ..
                },
            ) = (keyword.arg.as_deref(), &keyword.value)
            {
                self.check_storage_key_room(name, foreign_name, &keyword.span);
            }
        }
        for required in FOREIGN_STORAGE_KEYWORDS {
            if !keywords
                .iter()
                .any(|keyword| keyword.arg.as_deref() == Some(*required))
            {
                self.push(
                    "E023",
                    format!("Invalid {name} arguments: '{required}' is required"),
                    span,
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
            SyntaxExpression::Name { span, id, .. } => {
                if self.exact_numbers && matches!(id.as_str(), "float" | "round") {
                    self.push(
                        "E014",
                        format!("'{id}' is unavailable in {XIAN_VM_V2_PROFILE}"),
                        span,
                    );
                }
                self.check_name(id, span);
            }
            SyntaxExpression::Constant { .. } => {}
            SyntaxExpression::Starred { value, .. } => self.visit_expression(value),
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
                if self.exact_numbers && attr == "Decimal" && name_expr(value) == Some("decimal") {
                    self.push("E014", "use decimal(value) for fixed-point values", span);
                }
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
                    if self.exact_numbers
                        && ORM_CLASS_NAMES.contains(&name)
                        && !self.module_function_names.contains(name)
                    {
                        let is_declaration = self
                            .declaration_call
                            .is_some_and(|call| std::ptr::eq(call, expression));
                        self.check_storage_call(name, span, args, keywords, is_declaration);
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

        let numeric_type = if self.exact_numbers {
            "decimal"
        } else {
            "float"
        };
        let allowed = allowed_annotations_message(numeric_type);
        let arg_annotations = self.arg_annotations.clone();
        for (annotation, span) in arg_annotations {
            match annotation {
                None => self.push(
                    "E017",
                    "All @export function arguments must have type annotations",
                    &span,
                ),
                Some(annotation) if !annotation_allowed(&annotation, numeric_type) => self.push(
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
                if !annotation_allowed(&annotation, numeric_type) {
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
        SyntaxConstant::Decimal(value)
        | SyntaxConstant::Int(value)
        | SyntaxConstant::Str(value)
        | SyntaxConstant::Bytes(value) => value.clone(),
        SyntaxConstant::Float(value) => value.to_string(),
        SyntaxConstant::Tuple(values) => values
            .iter()
            .map(compact_constant)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn annotation_allowed(annotation: &str, numeric_type: &str) -> bool {
    if numeric_type == "decimal"
        && annotation
            .split(['[', ']', ','])
            .any(|name| matches!(name.trim(), "float" | "Decimal" | "decimal.Decimal"))
    {
        return false;
    }
    let base = annotation
        .split_once('[')
        .map_or(annotation, |(base, _)| base);
    base == numeric_type || ALLOWED_ANNOTATION_TYPES.contains(&base)
}

fn allowed_annotations_message(numeric_type: &str) -> String {
    let mut allowed = ALLOWED_ANNOTATION_TYPES.to_vec();
    allowed.push(numeric_type);
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
        | SyntaxExpression::Starred { span, .. }
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
    fn lint_rejects_storage_declarations_that_cannot_run() {
        for (source, code) in [
            ("v = Variable(**{'name': 'x'})\n", "xian.lint.E023"),
            ("h = Hash(**{'default_value': 0})\n", "xian.lint.E023"),
            ("v = Variable('con_other', 'value')\n", "xian.lint.E023"),
            ("args = ['con_other', 'balances']\nh = Hash(*args)\n", "xian.lint.E023"),
            ("x = [Hash()]\n", "xian.lint.E022"),
            ("Hash()\n", "xian.lint.E022"),
            ("def g():\n    v = Variable()\n", "xian.lint.E022"),
            ("def g():\n    e = LogEvent('E', {'a': {'type': str}})\n", "xian.lint.E022"),
            ("f = ForeignHash(foreign_contract='con_other')\n", "xian.lint.E023"),
            (
                "f = ForeignHash(foreign_contract='con_other', foreign_name='h', name='x')\n",
                "xian.lint.E023",
            ),
            (
                "def g(t: str):\n    return ForeignHash(**{'foreign_contract': t, 'foreign_name': 'h'})\n",
                "xian.lint.E023",
            ),
        ] {
            let source = format!("{source}\n@export\ndef ping() -> int:\n    return 1\n");
            let diagnostics = lint_source(&source);

            assert!(diagnostics.contains(&code.to_string()), "{source}: {diagnostics:?}");
        }
    }

    #[test]
    fn lint_keeps_archival_v1_storage_rules() {
        let unit = SourceUnit::with_profile(
            "con_lint",
            "x = [Hash()]\nh = Hash(**{'default_value': 0})\n\n@export\ndef ping() -> int:\n    return 1\n",
            crate::XIAN_VM_V1_PROFILE,
        )
        .expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");

        assert!(lint_syntax(&syntax).is_empty());
    }

    fn lint_v1_source(source: &str) -> Vec<String> {
        let source = format!("{source}\n@export\ndef ping() -> int:\n    return 1\n");
        let unit = SourceUnit::with_profile("con_lint", &source, crate::XIAN_VM_V1_PROFILE)
            .expect("source unit should build");
        let syntax = parse_to_syntax(&unit).expect("syntax should build");
        lint_syntax(&syntax)
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn lint_keeps_archival_v1_declaration_keywords() {
        for source in [
            "h = Hash(contract='con_other')\n",
            "v = Variable(name='other')\n",
            "e = LogEvent('E', {'a': {'type': str}}, name='other')\n",
        ] {
            assert_eq!(lint_v1_source(source), vec!["xian.lint.E011"], "{source}");
        }
        // Foreign storage names its target; V1 never set those automatically.
        assert!(lint_v1_source(
            "f = ForeignHash(foreign_contract='con_other', foreign_name='h', contract='x')\n"
        )
        .is_empty());
        assert!(lint_v1_source("h = Hash(default_value=0)\n").is_empty());
    }

    #[test]
    fn lint_rejects_tuple_unpacking_of_storage_in_every_profile() {
        let source = "a, b = Hash()\n";
        assert!(lint_v1_source(source).contains(&"xian.lint.E012".to_string()));
        let v2 = lint_source(&format!(
            "{source}\n@export\ndef ping() -> int:\n    return 1\n"
        ));
        assert!(v2.contains(&"xian.lint.E012".to_string()), "{v2:?}");
    }

    #[test]
    fn lint_rejects_storage_whose_key_cannot_fit_whatever_the_contract_name() {
        // A 64-byte contract name, '.', the binding and, for a hash, ':' must
        // fit LMDB's 511-byte storage key, so a variable binding may have 446
        // bytes and a hash binding 445.
        let fits = |code: &str| {
            let diagnostics = lint_source(&format!(
                "{code}\n@export\ndef ping(token: str) -> Any:\n    return 1\n"
            ));
            let too_long = diagnostics.contains(&"xian.lint.E024".to_string());
            assert!(
                diagnostics.iter().all(|code| code == "xian.lint.E024"),
                "{diagnostics:?}"
            );
            !too_long
        };
        let name = |len: usize| "n".repeat(len);
        assert!(fits(&format!("{} = Variable()", name(446))));
        assert!(!fits(&format!("{} = Variable()", name(447))));
        assert!(fits(&format!("{} = Hash()", name(445))));
        assert!(!fits(&format!("{} = Hash()", name(446))));
        let foreign = |kind: &str, len: usize| {
            format!(
                "f = {kind}(foreign_contract='con_other', foreign_name='{}')",
                name(len)
            )
        };
        assert!(fits(&foreign("ForeignVariable", 446)));
        assert!(!fits(&foreign("ForeignVariable", 447)));
        assert!(fits(&foreign("ForeignHash", 445)));
        assert!(!fits(&foreign("ForeignHash", 446)));
        // Text counts by its UTF-8 bytes.
        assert!(!fits(&format!(
            "f = ForeignHash(foreign_contract='con_other', foreign_name='{}')",
            "\u{e9}".repeat(223)
        )));
        // A function-local foreign target is checked the same way.
        assert!(!fits(&format!(
            "def g(t: str):\n    return ForeignVariable(foreign_contract=t, foreign_name='{}')",
            name(447)
        )));
        // Archival V1 admission is unchanged.
        assert!(lint_v1_source(&format!("{} = Hash()\n", name(600))).is_empty());
    }

    #[test]
    fn lint_accepts_runnable_storage_declarations() {
        let diagnostics = lint_source(
            "v = Variable(default_value=0, t=int)\nh = Hash(default_value=0)\nE = LogEvent('E', {'a': {'type': str}})\nf = ForeignHash(foreign_contract='con_other', foreign_name='h')\n\ndef Hash2():\n    return 1\n\ndef Variable():\n    return 1\n\n@export\ndef ping(token: str) -> Any:\n    balances = ForeignHash(foreign_contract=token, foreign_name='balances')\n    owner = ForeignVariable(foreign_contract=token, foreign_name='owner')\n    return balances['a'], owner.get(), Variable()\n",
        );

        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn diagnose_contract_enforces_profile_checks_when_lint_disabled() {
        let source = "@export\ndef ping(value):\n    return value\n";

        let linted = diagnose_contract("con_lint", source, &CompileOptions::default());
        let unlinted = diagnose_contract(
            "con_lint",
            source,
            &CompileOptions {
                lint: false,
                ..CompileOptions::default()
            },
        );

        assert_eq!(linted[0].code, "xian.lint.E017");
        assert_eq!(unlinted[0].code, "xian.lint.E017");
    }
}
