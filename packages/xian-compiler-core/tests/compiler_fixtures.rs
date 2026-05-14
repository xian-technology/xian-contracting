use std::fs;
use std::path::Path;
use xian_compiler_core::parse_compiler_fixture_json;

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
        checked += 1;
    }

    assert!(checked > 0, "expected at least one compiler fixture");
}
