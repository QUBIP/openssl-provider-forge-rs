use std::env;
use std::path::PathBuf;

fn generate_bindings() {
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
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Generate string constants as Cstrs instead of u8 arrays
        .generate_cstr(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    //println!("cargo:rustc-link-search=/path/to/lib");

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    //println!("cargo:rustc-link-lib=bz2");

    generate_bindings()
}
