# rrr-make
A basic command-line tool for the creation of Recursive Record Registries.

## Compiling the executable binary
1. Install Rust via [rustup.rs](https://rustup.rs/)
2. Clone this repository using Git or download it as an archive
3. Open the repository in your shell, and compile the executable binary by running:
    ```sh
    cargo build --release --bin rrr-make --features cmd
    ```
4. If the compilation was successful, the executable binary is now located in the `target/release` directory.
Launch it by running the following:
    ```sh
    # On Windows
    target\release\rrr-make.exe
    # On Unix
    target/release/rrr-make
    ```
