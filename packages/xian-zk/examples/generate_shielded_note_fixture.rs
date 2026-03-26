use _native::build_shielded_note_fixture;

fn main() {
    let fixture = build_shielded_note_fixture().expect("shielded note fixture should build");
    println!(
        "{}",
        serde_json::to_string_pretty(&fixture).expect("fixture should serialize")
    );
}
