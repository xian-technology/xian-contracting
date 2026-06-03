fn main() {
    #[cfg(feature = "python-extension")]
    pyo3_build_config::add_extension_module_link_args();
}
