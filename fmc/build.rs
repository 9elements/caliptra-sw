// Licensed under the Apache-2.0 license

fn main() {
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=build.rs");
}
