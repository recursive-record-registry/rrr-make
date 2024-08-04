use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use futures::{future::BoxFuture, FutureExt};
use include_dir::{include_dir, Dir, DirEntry};
use rrr::utils::fd_lock::{FileLock, WriteLock};
use tokio::io::AsyncWriteExt;

pub const SOURCE_DIRECTORY_TEMPLATE: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/assets/source-directory-template");

pub(crate) fn extract_with_locks<'a>(
    dir: &'a Dir<'_>,
    base_path: impl AsRef<Path> + Send + Sync + 'a,
    lock_map: &'a mut HashMap<PathBuf, &mut WriteLock>,
) -> BoxFuture<'a, std::io::Result<()>> {
    async move {
        let base_path = base_path.as_ref();

        for entry in dir.entries() {
            let path = base_path.join(entry.path());

            match entry {
                DirEntry::Dir(d) => {
                    tokio::fs::create_dir_all(&path).await?;
                    extract_with_locks(d, base_path, lock_map).await?;
                }
                DirEntry::File(f) => {
                    if let Some(lock) = lock_map.get_mut(entry.path()) {
                        lock.file_mut().write_all(f.contents()).await?;
                    } else {
                        tokio::fs::write(path, f.contents()).await?;
                    }
                }
            }
        }

        Ok(())
    }
    .boxed()
}
