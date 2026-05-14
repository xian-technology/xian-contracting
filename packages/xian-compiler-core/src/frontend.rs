use rustpython_parser::source_code::LinearLocator;
use rustpython_parser::{ast, Parse, ParseError};

use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::source::SourceUnit;

#[derive(Debug, Clone)]
pub struct ParsedModule {
    source: SourceUnit,
    suite: ast::Suite,
}

impl ParsedModule {
    pub fn module_name(&self) -> &str {
        self.source.module_name()
    }

    pub fn source(&self) -> &str {
        self.source.source()
    }

    pub fn statement_count(&self) -> usize {
        self.suite.len()
    }

    pub(crate) fn source_unit(&self) -> &SourceUnit {
        &self.source
    }

    pub(crate) fn suite(&self) -> &ast::Suite {
        &self.suite
    }
}

pub fn parse_source(unit: &SourceUnit) -> Result<ParsedModule, Vec<CompilerDiagnostic>> {
    match ast::Suite::parse(unit.source(), unit.module_name()) {
        Ok(suite) => Ok(ParsedModule {
            source: unit.clone(),
            suite,
        }),
        Err(error) => Err(vec![parse_error_to_diagnostic(unit.source(), error)]),
    }
}

pub fn parse_diagnostics(unit: &SourceUnit) -> Vec<CompilerDiagnostic> {
    parse_source(unit).err().unwrap_or_default()
}

fn parse_error_to_diagnostic(source: &str, error: ParseError) -> CompilerDiagnostic {
    let mut locator = LinearLocator::new(source);
    let location = locator.locate(error.offset);
    let line = location.row.get();
    let column = location.column.to_zero_indexed();
    CompilerDiagnostic::error("xian.syntax.parse_error", error.error.to_string()).with_range(
        SourceRange {
            start_line: line,
            start_column: column,
            end_line: line,
            end_column: column.saturating_add(1),
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::frontend::{parse_diagnostics, parse_source};
    use crate::source::SourceUnit;

    #[test]
    fn parse_source_accepts_valid_python_module() {
        let unit = SourceUnit::new(
            "con_counter",
            "counter = Variable()\n\n@export\ndef get():\n    return 1\n",
        )
        .expect("source unit should build");

        let parsed = parse_source(&unit).expect("source should parse");

        assert_eq!(parsed.module_name(), "con_counter");
        assert_eq!(parsed.statement_count(), 2);
    }

    #[test]
    fn parse_diagnostics_reports_parse_error_range() {
        let unit = SourceUnit::new("con_bad", "def broken(:\n").expect("source unit should build");

        let diagnostics = parse_diagnostics(&unit);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "xian.syntax.parse_error");
        assert_eq!(
            diagnostics[0].range.as_ref().map(|range| range.start_line),
            Some(1)
        );
    }
}
