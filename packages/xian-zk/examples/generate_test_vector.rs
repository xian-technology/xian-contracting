use _native::build_demo_vector;

fn main() {
    let vector = build_demo_vector().expect("demo vector should build");
    println!(
        "{}",
        serde_json::to_string_pretty(&vector).expect("demo vector should serialize")
    );
}
