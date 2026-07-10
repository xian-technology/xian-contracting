use std::fs;
use std::path::Path;
use xian_compiler_core::{
    compile_contract_artifact, diagnose_contract, parse_compiler_fixture_json, CompileOptions,
};

#[test]
fn checked_in_compiler_fixtures_are_structurally_valid() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut checked = 0;

    for entry in fs::read_dir(&fixture_dir).expect("fixture directory should exist") {
        let entry = entry.expect("fixture entry should be readable");
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        let raw = fs::read_to_string(&path).expect("fixture should be readable");
        let fixture = parse_compiler_fixture_json(&raw)
            .unwrap_or_else(|error| panic!("{} failed to parse: {error}", path.display()));
        fixture
            .validate_basic()
            .unwrap_or_else(|error| panic!("{} invalid: {error}", path.display()));

        let options = CompileOptions {
            vm_profile: fixture.vm_profile.clone(),
            lint: true,
        };
        let diagnostics = diagnose_contract(&fixture.module_name, &fixture.input_source, &options);
        if fixture.expected.accepted {
            assert_eq!(
                diagnostics,
                fixture.diagnostics,
                "{} diagnostics",
                path.display()
            );
            let artifact =
                compile_contract_artifact(&fixture.module_name, &fixture.input_source, &options)
                    .unwrap_or_else(|errors| {
                        panic!("{} failed to compile: {errors:?}", path.display())
                    });
            assert_eq!(
                Some(&artifact),
                fixture.artifact.as_ref(),
                "{} artifact",
                path.display()
            );
        } else {
            assert_eq!(
                diagnostics,
                fixture.diagnostics,
                "{} diagnostics",
                path.display()
            );
            let compile_diagnostics =
                compile_contract_artifact(&fixture.module_name, &fixture.input_source, &options)
                    .expect_err("rejected fixture must not compile");
            assert_eq!(
                compile_diagnostics,
                fixture.diagnostics,
                "{} compile diagnostics",
                path.display()
            );
        }
        checked += 1;
    }

    assert!(checked > 0, "expected at least one compiler fixture");
}
