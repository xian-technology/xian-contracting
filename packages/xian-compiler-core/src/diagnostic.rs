use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct SourceRange {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CompilerDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<SourceRange>,
}

impl CompilerDiagnostic {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            code: code.into(),
            message: message.into(),
            range: None,
        }
    }

    pub fn with_range(mut self, range: SourceRange) -> Self {
        self.range = Some(range);
        self
    }
}

/// The text of the compiler's `CompilerError` for `diagnostics`: the first
/// diagnostic's code and message, then every diagnostic as JSON. A host that
/// runs the compiler reports a failed compilation with exactly this text.
pub fn compiler_error_message(diagnostics: &[CompilerDiagnostic]) -> String {
    let message = diagnostics
        .first()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .unwrap_or_else(|| "compiler failed".to_string());
    let payload = serde_json::to_string(diagnostics).unwrap_or_else(|_| message.clone());
    format!("{message}\n{payload}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_error_message_names_the_first_diagnostic_and_lists_them_all() {
        let diagnostics = [
            CompilerDiagnostic::error("xian.a", "first"),
            CompilerDiagnostic::error("xian.b", "second").with_range(SourceRange {
                start_line: 1,
                start_column: 2,
                end_line: 3,
                end_column: 4,
            }),
        ];
        assert_eq!(
            compiler_error_message(&diagnostics),
            "xian.a: first\n[{\"severity\":\"error\",\"code\":\"xian.a\",\"message\":\"first\"},\
             {\"severity\":\"error\",\"code\":\"xian.b\",\"message\":\"second\",\
             \"range\":{\"start_line\":1,\"start_column\":2,\"end_line\":3,\"end_column\":4}}]"
        );
        assert_eq!(compiler_error_message(&[]), "compiler failed\n[]");
    }
}
