use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Duplicate successive record {name:?} of parent {parent:?}")]
    DuplicateSuccessiveRecord { parent: PathBuf, name: Vec<u8> },
    #[error("Registry already exists at path {path:?}")]
    RegistryAlreadyExists { path: PathBuf },
}
