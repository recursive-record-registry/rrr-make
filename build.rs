//! Rebuilds the crate when the assets embedded by `include_dir!` change.
//! `include_dir` can only track them itself with its `nightly` feature, which requires nightly Rust.

fn main() {
    println!("cargo::rerun-if-changed=assets");
}
