use std::path::Path;

use futures::{future::BoxFuture, FutureExt};
use include_dir::{include_dir, Dir, DirEntry};

pub const SOURCE_DIRECTORY_TEMPLATE: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/assets/source-directory-template");

pub(crate) fn extract<'a>(
    dir: &'a Dir<'_>,
    base_path: impl AsRef<Path> + Send + Sync + 'a,
) -> BoxFuture<'a, std::io::Result<()>> {
    async move {
        let base_path = base_path.as_ref();

        for entry in dir.entries() {
            let path = base_path.join(entry.path());

            match entry {
                DirEntry::Dir(d) => {
                    tokio::fs::create_dir_all(&path).await?;
                    extract(d, base_path).await?;
                }
                DirEntry::File(f) => {
                    tokio::fs::write(path, f.contents()).await?;
                }
            }
        }

        Ok(())
    }
    .boxed()
}
