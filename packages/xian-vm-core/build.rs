#[cfg(feature = "lmdb")]
fn build_lmdb() {
    use std::path::Path;

    let vendor = Path::new("vendor/lmdb");
    cc::Build::new()
        .include(vendor)
        .file(vendor.join("mdb.c"))
        .file(vendor.join("midl.c"))
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-pthread")
        .warnings(false)
        .compile("xian_lmdb");
    println!("cargo:rerun-if-changed=vendor/lmdb");
}

fn main() {
    #[cfg(feature = "lmdb")]
    build_lmdb();
    #[cfg(feature = "python-extension")]
    pyo3_build_config::add_extension_module_link_args();
}
