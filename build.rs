use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_path = PathBuf::from(manifest_dir).join("lib");

    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=dylib=qingming");
    println!("cargo:rustc-link-arg=-Wl,-rpath={}", lib_path.display());
    println!("cargo:rerun-if-changed=lib/libqingming.so");
}
