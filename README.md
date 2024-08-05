<img src="https://raw.githubusercontent.com/recursive-record-registry/rrr-assets/1b1ca5e008fb990e35de10a1a4ecdd4a5f94e2be/logo/logo_framed_white.svg" width="64px" align="right" />

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

## TODO
* [ ] Better error reporting for incomplete record parameters
* [ ] Output registry staging
    * [ ] Checking whether the stored record is identical to the to-be-written one
        * [x] Record equality
        * [ ] Fragment equality
    * [ ] `published` directory
    * [ ] `revisions` directory
