fn main() {
    if std::env::var_os("CARGO_FEATURE_NATIVE_RANDOMX").is_none() {
        return;
    }
    let lib_dir = std::env::var("RANDOMX_LIB_DIR")
        .expect("native-randomx requires RANDOMX_LIB_DIR pointing to the built RandomX library");
    let include_dir = std::env::var("RANDOMX_INCLUDE_DIR")
        .expect("native-randomx requires RANDOMX_INCLUDE_DIR pointing to randomx.h");
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=static=randomx");
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=dylib=advapi32");
    }
    println!("cargo:rerun-if-env-changed=RANDOMX_LIB_DIR");
    println!("cargo:rerun-if-env-changed=RANDOMX_INCLUDE_DIR");
    println!("cargo:rerun-if-changed={include_dir}/randomx.h");
}
