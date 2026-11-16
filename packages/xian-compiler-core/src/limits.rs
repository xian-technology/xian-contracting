use rustpython_parser::ast;
use rustpython_parser::lexer::lex;
use rustpython_parser::{Mode, StringKind, Tok};
use serde::{Deserialize, Serialize};

use crate::diagnostic::CompilerDiagnostic;

pub const MAX_SOURCE_BYTES: usize = 128 * 1024;
pub const MAX_SYNTAX_NODES: usize = 50_000;
pub const MAX_SYNTAX_DEPTH: usize = 64;
pub const MAX_TOKENS: usize = 100_000;
pub const MAX_LOGICAL_LINE_TOKENS: usize = 4_096;
pub const MAX_IR_JSON_BYTES: usize = 1_048_576;
pub const MAX_CONTRACT_HANDLE_INFERENCE_PASSES: usize = 512;
/// The work units one compilation may spend on its whole-program analyses
/// (module aliases, contract-handle inference, local handle bindings): one
/// unit per input, settled fact, followed edge or queued binding. That work
/// is linear in the program (a few units per syntax node; the largest
/// pathological contracts that compile spend under 60,000), so no admissible
/// source comes near this ceiling; it stops any superlinear work a future
/// analysis could add. Counted, not timed: the same on every platform and in
/// the native and WebAssembly builds.
pub const MAX_COMPILE_WORK: usize = 20 * MAX_SYNTAX_NODES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct CompilerLimits {
    pub max_source_bytes: usize,
    pub max_syntax_nodes: usize,
    pub max_syntax_depth: usize,
    pub max_tokens: usize,
    pub max_logical_line_tokens: usize,
    pub max_ir_json_bytes: usize,
    pub max_contract_handle_inference_passes: usize,
    pub max_compile_work: usize,
}

pub const fn compiler_limits() -> CompilerLimits {
    CompilerLimits {
        max_source_bytes: MAX_SOURCE_BYTES,
        max_syntax_nodes: MAX_SYNTAX_NODES,
        max_syntax_depth: MAX_SYNTAX_DEPTH,
        max_tokens: MAX_TOKENS,
        max_logical_line_tokens: MAX_LOGICAL_LINE_TOKENS,
        max_ir_json_bytes: MAX_IR_JSON_BYTES,
        max_contract_handle_inference_passes: MAX_CONTRACT_HANDLE_INFERENCE_PASSES,
        max_compile_work: MAX_COMPILE_WORK,
    }
}

pub(crate) fn validate_source_limits(source: &str) -> Result<(), CompilerDiagnostic> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(limit_error(
            "xian.limit.source_bytes",
            format!("contract source exceeds the maximum of {MAX_SOURCE_BYTES} UTF-8 bytes"),
        ));
    }
    let mut budget = LexicalBudget::default();
    for token in lex(source, Mode::Module) {
        let Ok((token, _)) = token else {
            break;
        };
        if token != Tok::EndOfFile {
            budget.observe(&token)?;
        }
    }
    Ok(())
}

/// The token counts and nesting depths of the source read so far.
#[derive(Default)]
struct LexicalBudget {
    total_tokens: usize,
    logical_line_tokens: usize,
    delimiter_depth: usize,
    indentation_depth: usize,
}

impl LexicalBudget {
    fn observe(&mut self, token: &Tok) -> Result<(), CompilerDiagnostic> {
        self.total_tokens = self.total_tokens.saturating_add(1);
        if self.total_tokens > MAX_TOKENS {
            return Err(limit_error(
                "xian.limit.tokens",
                format!("contract source exceeds the maximum of {MAX_TOKENS} lexical tokens"),
            ));
        }
        self.logical_line_tokens = self
            .logical_line_tokens
            .saturating_add(logical_line_weight(token));
        if self.logical_line_tokens > MAX_LOGICAL_LINE_TOKENS {
            return Err(limit_error(
                "xian.limit.logical_line_tokens",
                format!(
                    "contract source exceeds the maximum of {MAX_LOGICAL_LINE_TOKENS} tokens on one logical line"
                ),
            ));
        }
        self.track_nesting(token)
    }

    fn track_nesting(&mut self, token: &Tok) -> Result<(), CompilerDiagnostic> {
        let depth = match token {
            Tok::Lpar | Tok::Lsqb | Tok::Lbrace => deeper(&mut self.delimiter_depth),
            Tok::Indent => deeper(&mut self.indentation_depth),
            Tok::Rpar | Tok::Rsqb | Tok::Rbrace => shallower(&mut self.delimiter_depth),
            Tok::Dedent => shallower(&mut self.indentation_depth),
            Tok::Newline => {
                self.logical_line_tokens = 0;
                0
            }
            _ => 0,
        };
        if depth > MAX_SYNTAX_DEPTH {
            return Err(syntax_depth_error());
        }
        Ok(())
    }
}

fn deeper(depth: &mut usize) -> usize {
    *depth = depth.saturating_add(1);
    *depth
}

fn shallower(depth: &mut usize) -> usize {
    *depth = depth.saturating_sub(1);
    0
}

/// The tokens a lexical token stands for on its logical line. The parser
/// reads the expressions inside an f-string from its one string token, so an
/// f-string counts one token per character: that bounds the tokens, and with
/// them the nesting depth, of those expressions like any other code.
fn logical_line_weight(token: &Tok) -> usize {
    match token {
        Tok::String {
            value,
            kind: StringKind::FString | StringKind::RawFString,
            ..
        } => value.chars().count().max(1),
        _ => 1,
    }
}

pub(crate) fn validate_syntax_limits(suite: &[ast::Stmt]) -> Result<(), CompilerDiagnostic> {
    let mut budget = SyntaxBudget::default();
    for statement in suite {
        budget.visit_stmt(statement);
        if budget.exceeded.is_some() {
            break;
        }
    }

    match budget.exceeded {
        Some(LimitExceeded::Nodes) => Err(limit_error(
            "xian.limit.syntax_nodes",
            format!("contract syntax tree exceeds the maximum of {MAX_SYNTAX_NODES} syntax nodes"),
        )),
        Some(LimitExceeded::Depth) => Err(syntax_depth_error()),
        None => Ok(()),
    }
}

pub(crate) fn validate_ir_json_limits(payload: &str) -> Result<(), CompilerDiagnostic> {
    if payload.len() > MAX_IR_JSON_BYTES {
        return Err(limit_error(IR_JSON_BYTES_CODE, ir_json_bytes_message()));
    }
    Ok(())
}

pub(crate) const IR_JSON_BYTES_CODE: &str = "xian.limit.ir_json_bytes";

pub(crate) fn ir_json_bytes_message() -> String {
    format!("contract IR exceeds the maximum of {MAX_IR_JSON_BYTES} UTF-8 bytes")
}

pub(crate) const COMPILE_WORK_CODE: &str = "xian.limit.compile_work";

pub(crate) fn compile_work_message() -> String {
    format!("contract compilation exceeds the maximum of {MAX_COMPILE_WORK} work units")
}

/// The work units a compilation has left.
#[derive(Debug)]
pub(crate) struct WorkBudget {
    remaining: usize,
}

/// A compilation ran out of work units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkExceeded;

impl Default for WorkBudget {
    fn default() -> Self {
        Self::with_limit(MAX_COMPILE_WORK)
    }
}

impl WorkBudget {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self { remaining: limit }
    }

    #[cfg(test)]
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }

    pub(crate) fn spend(&mut self, units: usize) -> Result<(), WorkExceeded> {
        self.remaining = self.remaining.checked_sub(units).ok_or(WorkExceeded)?;
        Ok(())
    }
}

fn syntax_depth_error() -> CompilerDiagnostic {
    limit_error(
        "xian.limit.syntax_depth",
        format!("contract syntax nesting exceeds the maximum depth of {MAX_SYNTAX_DEPTH}"),
    )
}

fn limit_error(code: &str, message: String) -> CompilerDiagnostic {
    CompilerDiagnostic::error(code, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitExceeded {
    Nodes,
    Depth,
}

#[derive(Default)]
struct SyntaxBudget {
    nodes: usize,
    depth: usize,
    exceeded: Option<LimitExceeded>,
}

impl SyntaxBudget {
    fn enter_node(&mut self) -> bool {
        if self.exceeded.is_some() {
            return false;
        }
        self.nodes = self.nodes.saturating_add(1);
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_SYNTAX_DEPTH {
            self.exceeded = Some(LimitExceeded::Depth);
            self.depth = self.depth.saturating_sub(1);
            return false;
        }
        if self.nodes > MAX_SYNTAX_NODES {
            self.exceeded = Some(LimitExceeded::Nodes);
            self.depth = self.depth.saturating_sub(1);
            return false;
        }
        true
    }

    fn leave_node(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

impl SyntaxBudget {
    // Borrow before checking depth: cloning an untrusted parser tree can
    // overflow a native/WASM stack before this budget gets to reject it.
    fn visit_stmt(&mut self, node: &ast::Stmt) {
        if !self.enter_node() {
            return;
        }
        self.walk_stmt(node);
        self.leave_node();
    }

    fn visit_expr(&mut self, node: &ast::Expr) {
        if !self.enter_node() {
            return;
        }
        self.walk_expr(node);
        self.leave_node();
    }

    fn visit_arguments(&mut self, node: &ast::Arguments) {
        if !self.enter_node() {
            return;
        }
        for argument in node.posonlyargs.iter().chain(&node.args) {
            self.visit_arg(&argument.def);
            if let Some(default) = &argument.default {
                self.visit_expr(default);
            }
        }
        if let Some(argument) = &node.vararg {
            self.visit_arg(argument);
        }
        for argument in &node.kwonlyargs {
            self.visit_arg(&argument.def);
            if let Some(default) = &argument.default {
                self.visit_expr(default);
            }
        }
        if let Some(argument) = &node.kwarg {
            self.visit_arg(argument);
        }
        self.leave_node();
    }

    fn visit_arg(&mut self, node: &ast::Arg) {
        if !self.enter_node() {
            return;
        }
        self.visit_optional_expr(node.annotation.as_deref());
        self.leave_node();
    }

    fn visit_keyword(&mut self, node: &ast::Keyword) {
        self.visit_counted_expressions(std::iter::once(&node.value));
    }

    fn visit_comprehension(&mut self, node: &ast::Comprehension) {
        self.visit_counted_expressions(
            std::iter::once(&node.target)
                .chain(std::iter::once(&node.iter))
                .chain(&node.ifs),
        );
    }

    fn visit_counted_expressions<'a>(&mut self, nodes: impl IntoIterator<Item = &'a ast::Expr>) {
        if !self.enter_node() {
            return;
        }
        for node in nodes {
            self.visit_expr(node);
        }
        self.leave_node();
    }

    fn visit_alias(&mut self, _node: &ast::Alias) {
        if self.enter_node() {
            self.leave_node();
        }
    }

    fn visit_statements(&mut self, nodes: &[ast::Stmt]) {
        nodes.iter().for_each(|node| self.visit_stmt(node));
    }

    fn visit_expressions(&mut self, nodes: &[ast::Expr]) {
        nodes.iter().for_each(|node| self.visit_expr(node));
    }

    fn visit_optional_expr(&mut self, node: Option<&ast::Expr>) {
        if let Some(node) = node {
            self.visit_expr(node);
        }
    }

    fn visit_keywords(&mut self, nodes: &[ast::Keyword]) {
        nodes.iter().for_each(|node| self.visit_keyword(node));
    }

    fn visit_aliases(&mut self, nodes: &[ast::Alias]) {
        nodes.iter().for_each(|node| self.visit_alias(node));
    }

    fn visit_comprehensions(&mut self, nodes: &[ast::Comprehension]) {
        nodes.iter().for_each(|node| self.visit_comprehension(node));
    }

    fn visit_type_params(&mut self, nodes: &[ast::TypeParam]) {
        for node in nodes {
            if let ast::TypeParam::TypeVar(node) = node {
                self.visit_optional_expr(node.bound.as_deref());
            }
        }
    }

    fn visit_try(
        &mut self,
        body: &[ast::Stmt],
        handlers: &[ast::ExceptHandler],
        otherwise: &[ast::Stmt],
        finalbody: &[ast::Stmt],
    ) {
        self.visit_statements(body);
        for ast::ExceptHandler::ExceptHandler(handler) in handlers {
            self.visit_optional_expr(handler.type_.as_deref());
            self.visit_statements(&handler.body);
        }
        self.visit_statements(otherwise);
        self.visit_statements(finalbody);
    }

    /// Same field order and counted node kinds as RustPython's consuming
    /// Visitor plus the argument/comprehension overrides above.
    fn walk_stmt(&mut self, node: &ast::Stmt) {
        match node {
            ast::Stmt::FunctionDef(node) => {
                self.visit_arguments(&node.args);
                self.visit_statements(&node.body);
                self.visit_expressions(&node.decorator_list);
                self.visit_optional_expr(node.returns.as_deref());
                self.visit_type_params(&node.type_params);
            }
            ast::Stmt::AsyncFunctionDef(node) => {
                self.visit_arguments(&node.args);
                self.visit_statements(&node.body);
                self.visit_expressions(&node.decorator_list);
                self.visit_optional_expr(node.returns.as_deref());
                self.visit_type_params(&node.type_params);
            }
            ast::Stmt::ClassDef(node) => {
                self.visit_expressions(&node.bases);
                self.visit_keywords(&node.keywords);
                self.visit_statements(&node.body);
                self.visit_expressions(&node.decorator_list);
                self.visit_type_params(&node.type_params);
            }
            ast::Stmt::Return(node) => self.visit_optional_expr(node.value.as_deref()),
            ast::Stmt::Delete(node) => self.visit_expressions(&node.targets),
            ast::Stmt::Assign(node) => {
                self.visit_expressions(&node.targets);
                self.visit_expr(&node.value);
            }
            ast::Stmt::TypeAlias(node) => {
                self.visit_expr(&node.name);
                self.visit_type_params(&node.type_params);
                self.visit_expr(&node.value);
            }
            ast::Stmt::AugAssign(node) => {
                self.visit_expr(&node.target);
                self.visit_expr(&node.value);
            }
            ast::Stmt::AnnAssign(node) => {
                self.visit_expr(&node.target);
                self.visit_expr(&node.annotation);
                self.visit_optional_expr(node.value.as_deref());
            }
            ast::Stmt::For(node) => {
                self.visit_expr(&node.target);
                self.visit_expr(&node.iter);
                self.visit_statements(&node.body);
                self.visit_statements(&node.orelse);
            }
            ast::Stmt::AsyncFor(node) => {
                self.visit_expr(&node.target);
                self.visit_expr(&node.iter);
                self.visit_statements(&node.body);
                self.visit_statements(&node.orelse);
            }
            ast::Stmt::While(node) => {
                self.visit_expr(&node.test);
                self.visit_statements(&node.body);
                self.visit_statements(&node.orelse);
            }
            ast::Stmt::If(node) => {
                self.visit_expr(&node.test);
                self.visit_statements(&node.body);
                self.visit_statements(&node.orelse);
            }
            // The upstream Visitor does not walk WithItem or MatchCase.
            // Both statement forms are rejected by syntax conversion.
            ast::Stmt::With(node) => self.visit_statements(&node.body),
            ast::Stmt::AsyncWith(node) => self.visit_statements(&node.body),
            ast::Stmt::Match(node) => self.visit_expr(&node.subject),
            ast::Stmt::Raise(node) => {
                self.visit_optional_expr(node.exc.as_deref());
                self.visit_optional_expr(node.cause.as_deref());
            }
            ast::Stmt::Try(node) => {
                self.visit_try(&node.body, &node.handlers, &node.orelse, &node.finalbody);
            }
            ast::Stmt::TryStar(node) => {
                self.visit_try(&node.body, &node.handlers, &node.orelse, &node.finalbody);
            }
            ast::Stmt::Assert(node) => {
                self.visit_expr(&node.test);
                self.visit_optional_expr(node.msg.as_deref());
            }
            ast::Stmt::Import(node) => self.visit_aliases(&node.names),
            ast::Stmt::ImportFrom(node) => self.visit_aliases(&node.names),
            ast::Stmt::Expr(node) => self.visit_expr(&node.value),
            ast::Stmt::Global(_)
            | ast::Stmt::Nonlocal(_)
            | ast::Stmt::Pass(_)
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue(_) => {}
        }
    }

    fn walk_expr(&mut self, node: &ast::Expr) {
        match node {
            ast::Expr::BoolOp(node) => self.visit_expressions(&node.values),
            ast::Expr::NamedExpr(node) => {
                self.visit_expr(&node.target);
                self.visit_expr(&node.value);
            }
            ast::Expr::BinOp(node) => {
                self.visit_expr(&node.left);
                self.visit_expr(&node.right);
            }
            ast::Expr::UnaryOp(node) => self.visit_expr(&node.operand),
            ast::Expr::Lambda(node) => {
                self.visit_arguments(&node.args);
                self.visit_expr(&node.body);
            }
            ast::Expr::IfExp(node) => {
                self.visit_expr(&node.test);
                self.visit_expr(&node.body);
                self.visit_expr(&node.orelse);
            }
            ast::Expr::Dict(node) => {
                for key in node.keys.iter().flatten() {
                    self.visit_expr(key);
                }
                self.visit_expressions(&node.values);
            }
            ast::Expr::Set(node) => self.visit_expressions(&node.elts),
            ast::Expr::ListComp(node) => {
                self.visit_expr(&node.elt);
                self.visit_comprehensions(&node.generators);
            }
            ast::Expr::SetComp(node) => {
                self.visit_expr(&node.elt);
                self.visit_comprehensions(&node.generators);
            }
            ast::Expr::DictComp(node) => {
                self.visit_expr(&node.key);
                self.visit_expr(&node.value);
                self.visit_comprehensions(&node.generators);
            }
            ast::Expr::GeneratorExp(node) => {
                self.visit_expr(&node.elt);
                self.visit_comprehensions(&node.generators);
            }
            ast::Expr::Await(node) => self.visit_expr(&node.value),
            ast::Expr::Yield(node) => self.visit_optional_expr(node.value.as_deref()),
            ast::Expr::YieldFrom(node) => self.visit_expr(&node.value),
            ast::Expr::Compare(node) => {
                self.visit_expr(&node.left);
                self.visit_expressions(&node.comparators);
            }
            ast::Expr::Call(node) => {
                self.visit_expr(&node.func);
                self.visit_expressions(&node.args);
                self.visit_keywords(&node.keywords);
            }
            ast::Expr::FormattedValue(node) => {
                self.visit_expr(&node.value);
                self.visit_optional_expr(node.format_spec.as_deref());
            }
            ast::Expr::JoinedStr(node) => self.visit_expressions(&node.values),
            ast::Expr::Attribute(node) => self.visit_expr(&node.value),
            ast::Expr::Subscript(node) => {
                self.visit_expr(&node.value);
                self.visit_expr(&node.slice);
            }
            ast::Expr::Starred(node) => self.visit_expr(&node.value),
            ast::Expr::List(node) => self.visit_expressions(&node.elts),
            ast::Expr::Tuple(node) => self.visit_expressions(&node.elts),
            ast::Expr::Slice(node) => {
                self.visit_optional_expr(node.lower.as_deref());
                self.visit_optional_expr(node.upper.as_deref());
                self.visit_optional_expr(node.step.as_deref());
            }
            ast::Expr::Constant(_) | ast::Expr::Name(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LimitExceeded;
    use crate::frontend::parse_source;
    use crate::source::SourceUnit;
    use rustpython_parser::ast::{self, Visitor};

    use super::{
        validate_ir_json_limits, validate_source_limits, WorkBudget, WorkExceeded,
        MAX_COMPILE_WORK, MAX_IR_JSON_BYTES, MAX_LOGICAL_LINE_TOKENS, MAX_SOURCE_BYTES,
        MAX_SYNTAX_DEPTH, MAX_SYNTAX_NODES, MAX_TOKENS,
    };

    fn diagnostic_code(source: &str) -> String {
        let unit = SourceUnit::new("con_limit", source).expect("source unit should build");
        parse_source(&unit).expect_err("source should exceed an admission limit")[0]
            .code
            .clone()
    }

    #[test]
    fn source_byte_limit_is_stable() {
        assert!(validate_source_limits(&"a".repeat(MAX_SOURCE_BYTES)).is_ok());
        let source = "a".repeat(MAX_SOURCE_BYTES + 1);
        assert_eq!(diagnostic_code(&source), "xian.limit.source_bytes");
    }

    #[test]
    fn total_token_limit_is_stable() {
        assert!(validate_source_limits(&"a=0\n".repeat(MAX_TOKENS / 4)).is_ok());
        let source = "a=0\n".repeat((MAX_TOKENS / 4) + 1);
        assert_eq!(diagnostic_code(&source), "xian.limit.tokens");
    }

    #[test]
    fn logical_line_token_limit_is_stable() {
        let maximum = format!("{}True\n", "not ".repeat(MAX_LOGICAL_LINE_TOKENS - 2));
        assert!(validate_source_limits(&maximum).is_ok());
        let source = format!("value = {}True\n", "not ".repeat(MAX_LOGICAL_LINE_TOKENS));
        assert_eq!(diagnostic_code(&source), "xian.limit.logical_line_tokens");
    }

    #[test]
    fn fstring_expressions_count_toward_the_logical_line_tokens() {
        // The expressions inside an f-string reach the parser as one string
        // token; their characters bound their tokens.
        let fits = format!("value = f\"{{{}1}}\"\n", "1+".repeat(2_000));
        assert!(validate_source_limits(&fits).is_ok());
        let source = format!(
            "value = f\"{{{}1}}\"\n",
            "1+".repeat(MAX_LOGICAL_LINE_TOKENS / 2)
        );
        assert_eq!(diagnostic_code(&source), "xian.limit.logical_line_tokens");
    }

    #[test]
    fn a_deeply_nested_fstring_expression_is_refused_before_parsing() {
        // Parsed, this expression is a syntax tree 60k levels deep: dropping
        // or cloning it overflows the stack and aborts the node.
        let depth = (MAX_SOURCE_BYTES - 64) / 2;
        let source = format!("x = f\"{{{}1{}}}\"\n", "[".repeat(depth), "]".repeat(depth));
        assert!(source.len() <= MAX_SOURCE_BYTES);
        assert_eq!(diagnostic_code(&source), "xian.limit.logical_line_tokens");
    }

    #[test]
    fn a_deep_unary_tree_is_refused_without_cloning_it() {
        let source = format!(
            "@export\ndef f():\n    return {}True\n",
            "not ".repeat(4090)
        );
        assert!(validate_source_limits(&source).is_ok());
        assert_eq!(diagnostic_code(&source), "xian.limit.syntax_depth");
    }

    #[test]
    fn syntax_node_limit_is_stable() {
        let maximum = format!("{}a\n", "a=0\n".repeat((MAX_SYNTAX_NODES - 2) / 3));
        let unit = SourceUnit::new("con_limit", maximum).expect("source unit should build");
        parse_source(&unit).expect("the maximum syntax node count should be accepted");
        let source = "a=0\n".repeat((MAX_SYNTAX_NODES / 3) + 1);
        assert_eq!(diagnostic_code(&source), "xian.limit.syntax_nodes");
    }

    #[test]
    fn syntax_depth_limit_is_stable() {
        let maximum = format!(
            "@export\ndef value():\n    return {}True\n",
            "not ".repeat(MAX_SYNTAX_DEPTH - 3)
        );
        let unit = SourceUnit::new("con_limit", maximum).expect("source unit should build");
        parse_source(&unit).expect("the maximum syntax depth should be accepted");
        let source = format!(
            "@export\ndef value():\n    return {}True\n",
            "not ".repeat(MAX_SYNTAX_DEPTH)
        );
        assert_eq!(diagnostic_code(&source), "xian.limit.syntax_depth");
    }

    #[test]
    fn ir_json_byte_limit_is_stable() {
        assert!(validate_ir_json_limits(&"x".repeat(MAX_IR_JSON_BYTES)).is_ok());
        let error = validate_ir_json_limits(&"x".repeat(MAX_IR_JSON_BYTES + 1))
            .expect_err("oversized IR JSON should fail");
        assert_eq!(error.code, "xian.limit.ir_json_bytes");
    }

    #[test]
    fn work_budget_refuses_the_unit_past_its_limit() {
        let mut work = WorkBudget::default();
        assert_eq!(work.spend(MAX_COMPILE_WORK - 1), Ok(()));
        assert_eq!(work.spend(1), Ok(()));
        assert_eq!(work.spend(1), Err(WorkExceeded));
        assert_eq!(WorkBudget::with_limit(3).spend(4), Err(WorkExceeded));
    }

    #[test]
    fn a_refused_syntax_budget_cannot_visit_any_later_node() {
        let mut budget = super::SyntaxBudget::default();
        for _ in 0..MAX_SYNTAX_DEPTH {
            assert!(budget.enter_node());
        }
        assert!(!budget.enter_node());
        let previous = (budget.nodes, budget.depth);
        assert!(!budget.enter_node());
        assert_eq!((budget.nodes, budget.depth), previous);
    }

    // Independent reference: the previous consuming RustPython Visitor.
    #[derive(Default)]
    struct ConsumingBudget {
        nodes: usize,
        depth: usize,
        exceeded: Option<LimitExceeded>,
    }

    impl ConsumingBudget {
        fn enter_node(&mut self) -> bool {
            if self.exceeded.is_some() {
                return false;
            }
            self.nodes = self.nodes.saturating_add(1);
            self.depth = self.depth.saturating_add(1);
            if self.depth > MAX_SYNTAX_DEPTH {
                self.exceeded = Some(LimitExceeded::Depth);
                self.depth = self.depth.saturating_sub(1);
                return false;
            }
            if self.nodes > MAX_SYNTAX_NODES {
                self.exceeded = Some(LimitExceeded::Nodes);
                self.depth = self.depth.saturating_sub(1);
                return false;
            }
            true
        }

        fn leave_node(&mut self) {
            self.depth = self.depth.saturating_sub(1);
        }
    }

    impl Visitor for ConsumingBudget {
        fn visit_stmt(&mut self, node: ast::Stmt) {
            if !self.enter_node() {
                return;
            }
            self.generic_visit_stmt(node);
            self.leave_node();
        }

        fn visit_expr(&mut self, node: ast::Expr) {
            if !self.enter_node() {
                return;
            }
            self.generic_visit_expr(node);
            self.leave_node();
        }

        fn visit_arguments(&mut self, node: ast::Arguments) {
            if !self.enter_node() {
                return;
            }
            for argument in node.posonlyargs.into_iter().chain(node.args) {
                self.visit_arg(argument.def);
                if let Some(default) = argument.default {
                    self.visit_expr(*default);
                }
            }
            if let Some(argument) = node.vararg {
                self.visit_arg(*argument);
            }
            for argument in node.kwonlyargs {
                self.visit_arg(argument.def);
                if let Some(default) = argument.default {
                    self.visit_expr(*default);
                }
            }
            if let Some(argument) = node.kwarg {
                self.visit_arg(*argument);
            }
            self.leave_node();
        }

        fn visit_arg(&mut self, node: ast::Arg) {
            if !self.enter_node() {
                return;
            }
            if let Some(annotation) = node.annotation {
                self.visit_expr(*annotation);
            }
            self.leave_node();
        }

        fn visit_keyword(&mut self, node: ast::Keyword) {
            if !self.enter_node() {
                return;
            }
            self.visit_expr(node.value);
            self.leave_node();
        }

        fn visit_comprehension(&mut self, node: ast::Comprehension) {
            if !self.enter_node() {
                return;
            }
            self.visit_expr(node.target);
            self.visit_expr(node.iter);
            for condition in node.ifs {
                self.visit_expr(condition);
            }
            self.leave_node();
        }

        fn visit_alias(&mut self, _node: ast::Alias) {
            if self.enter_node() {
                self.leave_node();
            }
        }
    }

    #[test]
    fn borrowed_budget_preserves_all_parser_field_counts_and_depths() {
        let sources = [
            "@decorate(key=1)\ndef f[T: Bound](a: int = 1, /, b=2, *args, c: str='x', **kw) -> int:\n    return a\n",
            "@decorate\nasync def f(x):\n    async for i in x:\n        await i\n    else:\n        pass\n    async with x as y:\n        pass\n",
            "@decorate\nclass C[T: Bound](Base, option=1):\n    x: int = 2\n    def f(self):\n        return self.x\n",
            "type A[T: Bound] = list[T]\n",
            "x = (y := 1)\nx += 2\ndel x\nx: int\nassert x, 'bad'\nraise ValueError('x') from cause\n",
            "for x in items:\n    if x:\n        break\n    else:\n        continue\nelse:\n    pass\nwhile x:\n    x -= 1\n",
            "try:\n    x = f()\nexcept Error as e:\n    raise e\nelse:\n    x = 1\nfinally:\n    x = 2\n",
            "try:\n    x = f()\nexcept* Error:\n    pass\n",
            "import a, b as c\nfrom d import e, f as g\nglobal x\nnonlocal y\n",
            "with f(x) as y:\n    pass\nmatch x:\n    case 1:\n        pass\n",
            "x = [a for a in b if a]\ny = {a for a in b}\nz = {a: b for a in c}\nw = (a for a in b)\n",
            "x = (lambda a=1, *b, **c: a)(2, x=3)\ny = a and b or not c\nz = a if b else c\n",
            "x = a.b[1:2:3]\ny = [*x, 1]\nz = (x, y)\na = {'k': x, **y}\nb = {1, 2}\nc = f'{x!r:>10}'\n",
            "def f():\n    yield 1\n    yield from values\n    return\n",
        ];
        for source in sources {
            compare_budget_walks(source);
        }
        compare_budget_walks(&format!("x = {}True\n", "not ".repeat(70)));
        compare_budget_walks(&"x = 1\n".repeat(17_000));
    }

    fn compare_budget_walks(source: &str) {
        use rustpython_parser::Parse;
        let suite = ast::Suite::parse(source, "con_budget").expect("test input parses");
        let mut borrowed = super::SyntaxBudget::default();
        let mut consuming = ConsumingBudget::default();
        for statement in &suite {
            borrowed.visit_stmt(statement);
            consuming.visit_stmt(statement.clone());
        }
        assert_eq!(borrowed.nodes, consuming.nodes, "node count: {source}");
        assert_eq!(borrowed.depth, consuming.depth, "depth: {source}");
        assert_eq!(borrowed.exceeded, consuming.exceeded, "admission: {source}");
    }
}
