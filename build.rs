//! Workaround for a bug in `include_dir` 0.7.4: its `nightly` feature, which makes the compiler
//! track the files included by `include_dir!`, no longer compiles on nightly Rust.
//! See https://github.com/Michael-F-Bryan/include_dir/issues/118.
//! Once fixed, enable `include_dir`'s `nightly` feature again and remove this build script.

fn main() {
    println!("cargo::rerun-if-changed=assets");
}
