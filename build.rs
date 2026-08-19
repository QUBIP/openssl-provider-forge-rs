#[cfg(feature = "regen")]
fn env_flag(name: &str) -> bool {
    println!("cargo:rerun-if-env-changed={name}");
    let Some(raw) = std::env::var_os(name) else {
        // we default to false if the env var is not set
        return false;
    };
    match raw.to_string_lossy().trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => false,
        "1" | "true" | "yes" | "on" => true,
        other => panic!("{name} must be a boolean, got {other:?}"),
    }
}

#[cfg(feature = "regen")]
fn generate_bindings() {
    use std::env;
    use std::path::PathBuf;

    if env_flag("OSSL_PROVIDER_FORGE_REGENERATE_BINDINGS") == false {
        // We regenerate the bindings only if the above env var is set to true
        return;
    }

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=include/wrapper.h");

    // This might require to correctly setup the PKG_CONFIG_PATH env variable
    // e.g., export PKG_CONFIG_PATH="<my_custom_ossl_path>/lib/pkgconfig:$PKG_CONFIG_PATH"
    let openssl = pkg_config::probe_library("openssl").unwrap();

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_args(
            openssl
                .include_paths
                .iter()
                .map(|path| format!("-isystem{}", path.to_string_lossy())),
        )
        // The input header we would like to generate
        // bindings for.
        .header("include/wrapper.h")
        // Filter only headers from OpenSSL
        .allowlist_file(".*/openssl/.*\\.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Generate string constants as Cstrs instead of u8 arrays
        .generate_cstr(true)
        // Use C tpes from the libc crate
        .ctypes_prefix("libc")
        // filter out system typedefs like __off_t, size_t families
        .blocklist_type("__?[a-z0-9_]+_t")
        // filter out both _intmax_t and intmax_t, signed + unsigned
        .blocklist_type("_?u?intmax_t")
        // include required definitions for u?intmax_t from the libc crate
        .raw_line("use libc::{intmax_t, uintmax_t};")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");
    bindings
        .write_to_file(out_path.join("bindings").join("generated_bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    //println!("cargo:rustc-link-search=/path/to/lib");

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    //println!("cargo:rustc-link-lib=bz2");

    #[cfg(feature = "regen")]
    generate_bindings()
}
