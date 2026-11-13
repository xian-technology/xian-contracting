use std::path::Path;

fn build_decimal_backend() {
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref(),
        Ok("64"),
        "the consensus Decimal backend requires a 64-bit target"
    );
    let vendor = Path::new("vendor/mpdecimal");
    let units = [
        "basearith",
        "context",
        "constants",
        "convolute",
        "crt",
        "mpdecimal",
        "mpsignal",
        "difradix2",
        "fnt",
        "fourstep",
        "io",
        "mpalloc",
        "numbertheory",
        "sixstep",
        "transpose",
    ];
    let mut build = cc::Build::new();
    // MSVC exposes C11/C17 switches, but no /std:c99. The portable ANSI
    // arithmetic path is identical; only the compiler language flag differs.
    let c_standard = if build.get_compiler().is_like_msvc() {
        "c11"
    } else {
        "c99"
    };
    build
        .include(vendor)
        .define("CONFIG_64", None)
        .define("ANSI", None)
        .std(c_standard)
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fno-fast-math");
    for unit in units {
        build.file(vendor.join(format!("{unit}.c")));
    }
    build.file("src/decimal_shim.c").compile("xian_decimal");
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("unix") {
        println!("cargo:rustc-link-lib=m");
    }
    println!("cargo:rerun-if-changed=vendor/mpdecimal");
    println!("cargo:rerun-if-changed=src/decimal_shim.c");
}

fn build_lmdb() {
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
    build_decimal_backend();
    build_lmdb();
    #[cfg(feature = "python-extension")]
    pyo3_build_config::add_extension_module_link_args();
}
