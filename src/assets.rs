use include_dir::{include_dir, Dir};

pub const SOURCE_DIRECTORY_TEMPLATE: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/assets/source-directory-template");
