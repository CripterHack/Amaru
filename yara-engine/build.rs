fn main() {
    // Tell cargo to look for YARA libraries in standard locations
    println!("cargo:rustc-link-lib=yara");
    
    // If YARA is installed in a non-standard location, uncomment and modify the following line
    // println!("cargo:rustc-link-search=C:/Program Files/YARA/lib");
    
    // If any source files changes, rerun this build script
    println!("cargo:rerun-if-changed=src/lib.rs");
    
    // If we had C files to compile, we would use the cc crate here
    // let mut build = cc::Build::new();
    // build.include("include").file("src/wrapper.c").compile("wrapper");
} 