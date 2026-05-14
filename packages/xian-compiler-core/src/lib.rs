pub mod artifact;
pub mod compiler;
pub mod constants;
pub mod diagnostic;
pub mod error;
pub mod fixture;
pub mod frontend;
pub mod hashing;
pub mod ir;
pub mod lint;
pub mod normalize;
#[cfg(feature = "python-extension")]
mod python_bindings;
pub mod source;
pub mod syntax;
#[cfg(feature = "wasm")]
pub mod wasm_bindings;

pub use artifact::{
    build_contract_artifact, validate_contract_artifact, ArtifactHashes, ContractArtifact,
    ValidatedArtifact,
};
pub use compiler::{compiler_version, diagnose_contract, CompileOptions, CompilerVersion};
pub use constants::{
    COMPILER_FIXTURE_SCHEMA_V1, CONTRACT_ARTIFACT_FORMAT_V1, XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1,
    XIAN_VM_V1_PROFILE,
};
pub use diagnostic::{CompilerDiagnostic, DiagnosticSeverity, SourceRange};
pub use error::ValidationError;
pub use fixture::{
    parse_compiler_fixture_json, CompilerFixture, FixtureExpectation, FixtureGenerator,
};
pub use frontend::{parse_diagnostics, parse_source, ParsedModule};
pub use ir::{
    compile_contract_artifact, describe_vm_host_surface, lower_source_to_ir,
    lower_source_to_ir_json, lower_syntax_to_ir, HostBinding, IrLoweringError, HOST_BINDINGS,
};
pub use lint::{lint_syntax, SyntaxLinter};
pub use normalize::{normalize_source, normalize_syntax};
pub use source::SourceUnit;
pub use syntax::{
    build_syntax_tree, parse_to_syntax, SyntaxExpression, SyntaxModule, SyntaxStatement,
};
