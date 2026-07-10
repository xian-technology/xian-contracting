use rustpython_parser::ast::{self, Visitor};
use rustpython_parser::lexer::lex;
use rustpython_parser::{Mode, Tok};
use serde::{Deserialize, Serialize};

use crate::diagnostic::CompilerDiagnostic;

pub const MAX_SOURCE_BYTES: usize = 128 * 1024;
pub const MAX_SYNTAX_NODES: usize = 50_000;
pub const MAX_SYNTAX_DEPTH: usize = 64;
pub const MAX_TOKENS: usize = 100_000;
pub const MAX_LOGICAL_LINE_TOKENS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct CompilerLimits {
    pub max_source_bytes: usize,
    pub max_syntax_nodes: usize,
    pub max_syntax_depth: usize,
    pub max_tokens: usize,
    pub max_logical_line_tokens: usize,
}

pub const fn compiler_limits() -> CompilerLimits {
    CompilerLimits {
        max_source_bytes: MAX_SOURCE_BYTES,
        max_syntax_nodes: MAX_SYNTAX_NODES,
        max_syntax_depth: MAX_SYNTAX_DEPTH,
        max_tokens: MAX_TOKENS,
        max_logical_line_tokens: MAX_LOGICAL_LINE_TOKENS,
    }
}

pub(crate) fn validate_source_limits(source: &str) -> Result<(), CompilerDiagnostic> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(limit_error(
            "xian.limit.source_bytes",
            format!("contract source exceeds the maximum of {MAX_SOURCE_BYTES} UTF-8 bytes"),
        ));
    }

    let mut total_tokens = 0usize;
    let mut logical_line_tokens = 0usize;
    let mut delimiter_depth = 0usize;
    let mut indentation_depth = 0usize;

    for token in lex(source, Mode::Module) {
        let (token, _) = match token {
            Ok(token) => token,
            Err(_) => break,
        };
        if token == Tok::EndOfFile {
            continue;
        }

        total_tokens = total_tokens.saturating_add(1);
        if total_tokens > MAX_TOKENS {
            return Err(limit_error(
                "xian.limit.tokens",
                format!("contract source exceeds the maximum of {MAX_TOKENS} lexical tokens"),
            ));
        }

        logical_line_tokens = logical_line_tokens.saturating_add(1);
        if logical_line_tokens > MAX_LOGICAL_LINE_TOKENS {
            return Err(limit_error(
                "xian.limit.logical_line_tokens",
                format!(
                    "contract source exceeds the maximum of {MAX_LOGICAL_LINE_TOKENS} tokens on one logical line"
                ),
            ));
        }

        match token {
            Tok::Lpar | Tok::Lsqb | Tok::Lbrace => {
                delimiter_depth = delimiter_depth.saturating_add(1);
                if delimiter_depth > MAX_SYNTAX_DEPTH {
                    return Err(syntax_depth_error());
                }
            }
            Tok::Rpar | Tok::Rsqb | Tok::Rbrace => {
                delimiter_depth = delimiter_depth.saturating_sub(1);
            }
            Tok::Indent => {
                indentation_depth = indentation_depth.saturating_add(1);
                if indentation_depth > MAX_SYNTAX_DEPTH {
                    return Err(syntax_depth_error());
                }
            }
            Tok::Dedent => {
                indentation_depth = indentation_depth.saturating_sub(1);
            }
            Tok::Newline => logical_line_tokens = 0,
            _ => {}
        }
    }

    Ok(())
}

pub(crate) fn validate_syntax_limits(suite: &[ast::Stmt]) -> Result<(), CompilerDiagnostic> {
    let mut budget = SyntaxBudget::default();
    for statement in suite.iter().cloned() {
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

impl Visitor for SyntaxBudget {
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

#[cfg(test)]
mod tests {
    use crate::frontend::parse_source;
    use crate::source::SourceUnit;

    use super::{
        validate_source_limits, MAX_LOGICAL_LINE_TOKENS, MAX_SOURCE_BYTES, MAX_SYNTAX_DEPTH,
        MAX_SYNTAX_NODES, MAX_TOKENS,
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
}
