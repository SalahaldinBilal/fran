fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // vendored OpenSSL ships without its ossl_static.pdb
        println!("cargo::rustc-link-arg-bins=/IGNORE:4099");
    }
}
