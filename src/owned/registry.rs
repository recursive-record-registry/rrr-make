use color_eyre::Result;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, spki::der::pem::LineEnding};
use itertools::Itertools;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rrr::crypto::signature::{SigningKey, SigningKeyEd25519};
use rrr::record::RecordKey;
use rrr::registry::{RegistryConfig, RegistryConfigHash, RegistryConfigKdf};
use rrr::utils::fd_lock::{FileLock, ReadLock, WriteLock};
use rrr::utils::fs::replace_file;
use rrr::utils::serde::Secret;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};
use toml_edit::DocumentMut;

use crate::assets;
use crate::error::Error;
use crate::record::OwnedRecordConfigParametersUnresolved;

use super::record::OwnedRecord;

/// Represents a registry with cryptographic credentials for editing.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRegistryConfig {
    pub hash: RegistryConfigHash,
    pub kdf: RegistryConfigKdf,
    /// Whether record's parameters should be inherited from (combined with) the parent record, rather
    /// than the default record parameters (`default_record_parameters`) in the registry config.
    pub inherit_record_parameters_from_parent: bool,
    pub default_record_parameters: OwnedRecordConfigParametersUnresolved,
    pub root_record_path: PathBuf,
    /// This is where the resulting registry is generated, every time the `make` subcommand is executed.
    pub staging_directory_path: PathBuf,
    /// This directory contains all of the published record fragments, separated to directories according
    /// to the revision they were published in.
    pub revisions_directory_path: PathBuf,
    /// Path to a directory where the accumulation of all published revisions is stored.
    /// This directory contains all the published data of the registry, and can be browsed.
    pub published_directory_path: PathBuf,
    /// Paths to files with signing keys.
    /// These paths are relative to the directory containing the registry config.
    pub signing_key_paths: Vec<PathBuf>,
}

impl OwnedRegistryConfig {
    pub fn get_root_record_key(&self) -> RecordKey {
        RecordKey {
            record_name: Default::default(),
            predecessor_nonce: self.kdf.get_root_record_predecessor_nonce().clone(),
        }
    }
}

#[derive(Debug, Eq)]
pub struct OwnedRegistry<L: FileLock> {
    pub directory_path: PathBuf,
    pub config: OwnedRegistryConfig,
    /// Keys loaded from files at `config.signing_key_paths`, in the same order.
    pub signing_keys: Vec<SigningKey>,
    /// A lock on the registry lock file, held for as long as the registry is loaded.
    /// Readers hold a shared lock, and writers an exclusive one, so that readers block writers.
    _file_lock: L,
}

impl<L: FileLock> OwnedRegistry<L> {
    const FILE_NAME_CONFIG: &str = "registry.toml";
    /// The lock file that synchronizes access to the registry. See [`rrr::utils::fd_lock`].
    const FILE_NAME_LOCK: &str = "registry.lock";

    pub async fn load(directory_path: impl Into<PathBuf>) -> Result<Self> {
        let directory_path = directory_path.into();
        let config_path = Self::get_config_path_from_registry_directory_path(&directory_path);

        // Check that this is a registry, before creating a lock file in it.
        let file_lock = L::lock_if_exists(
            Self::get_lock_path_from_registry_directory_path(&directory_path),
            &config_path,
        )
        .await?;
        let config_string = tokio::fs::read_to_string(&config_path).await?;
        let config = toml::from_str::<OwnedRegistryConfig>(&config_string)?;
        let signing_keys = {
            let mut signing_keys = Vec::new();

            for key_path in &config.signing_key_paths {
                let key_path =
                    Self::get_key_path_from_record_directory_path(&directory_path, key_path);
                let mut file = File::open(&key_path).await?;
                let mut key_bytes = Default::default();

                file.read_to_string(&mut key_bytes).await?;

                let key = SigningKey::from_pkcs8_pem(&key_bytes).unwrap();

                signing_keys.push(key);
            }

            signing_keys
        };

        Ok(Self {
            config,
            directory_path,
            signing_keys,
            _file_lock: file_lock,
        })
    }

    /// Releases the lock, and loads the registry again with a lock of type `L2`.
    /// The config and signing keys are reloaded, because another writer may have changed them
    /// while no lock was held.
    async fn relock<L2: FileLock>(self) -> Result<OwnedRegistry<L2>> {
        let directory_path = self.directory_path.clone();

        drop(self);

        OwnedRegistry::load(directory_path).await
    }

    fn get_config_path_from_registry_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join(Self::FILE_NAME_CONFIG)
    }

    fn get_lock_path_from_registry_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join(Self::FILE_NAME_LOCK)
    }

    fn get_key_path_from_record_directory_path(
        directory_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> PathBuf {
        directory_path.as_ref().join(key_path)
    }

    fn get_key_path(&self, key_path: impl AsRef<Path>) -> PathBuf {
        Self::get_key_path_from_record_directory_path(&self.directory_path, key_path)
    }

    pub fn get_staging_directory_path(&self) -> PathBuf {
        self.directory_path.join(&self.staging_directory_path)
    }

    pub fn get_revisions_directory_path(&self) -> PathBuf {
        self.directory_path.join(&self.revisions_directory_path)
    }

    pub fn get_published_directory_path(&self) -> PathBuf {
        self.directory_path.join(&self.published_directory_path)
    }

    fn get_root_record_path(&self) -> PathBuf {
        self.directory_path.join(&self.root_record_path)
    }

    pub async fn load_root_record(&self) -> Result<OwnedRecord> {
        OwnedRecord::load_from_directory(&self.config, None, self.get_root_record_path()).await
    }
}

impl OwnedRegistry<ReadLock> {
    /// Acquires an exclusive lock on the registry.
    /// The config and signing keys are reloaded, discarding any changes made to them.
    pub async fn lock_write(self) -> Result<OwnedRegistry<WriteLock>> {
        self.relock().await
    }
}

impl OwnedRegistry<WriteLock> {
    /// Creates a new registry with generated cryptographic keys, and the provided root record.
    /// The root record is signed but **not encrypted**, it is the record displayed to the user
    /// upon opening the registry.
    pub async fn generate(directory_path: impl Into<PathBuf>, overwrite: bool) -> Result<Self> {
        let directory_path = directory_path.into();

        // Ensure the registry directory exists.
        match tokio::fs::metadata(&directory_path).await {
            Ok(directory_metadata) if directory_metadata.is_dir() => {
                if !overwrite {
                    let mut dir_entries = tokio::fs::read_dir(&directory_path).await?;

                    if dir_entries.next_entry().await?.is_some() {
                        return Err(Error::RegistryAlreadyExists {
                            path: directory_path,
                        }
                        .into());
                    }
                }
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Not a directory: {:?}", directory_path),
                )
                .into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir_all(&directory_path).await?
            }
            Err(error) => return Err(error.into()),
        }

        let config_path = Self::get_config_path_from_registry_directory_path(&directory_path);

        tokio::fs::create_dir_all(&directory_path).await?;
        let file_lock = WriteLock::lock(Self::get_lock_path_from_registry_directory_path(
            &directory_path,
        ))
        .await?;

        assets::extract(&assets::SOURCE_DIRECTORY_TEMPLATE, &directory_path).await?;

        let mut csprng = UnwrapErr(SysRng);

        // Patch registry config.
        let config = {
            let config_string = tokio::fs::read_to_string(&config_path).await?;
            let mut config_doc = config_string.parse::<DocumentMut>()?;
            let root_predecessor_nonce =
                RegistryConfigKdf::generate_random_root_predecessor_nonce(csprng, None);
            let root_predecessor_nonce_string =
                format!("{:02x}", root_predecessor_nonce.iter().format(""));
            config_doc["kdf"]["root_predecessor_nonce"] =
                toml_edit::value(root_predecessor_nonce_string);
            let config_string = config_doc.to_string();

            // Parse patched config
            let config = toml::from_str::<OwnedRegistryConfig>(&config_string)?;

            // Store patched config
            Self::write_config_string(&directory_path, &config_string).await?;

            config
        };

        // Generate signing keys.
        let signing_keys = {
            let signing_key = SigningKey::Ed25519(Secret(SigningKeyEd25519(
                ed25519_dalek::SigningKey::generate(&mut csprng),
            )));
            let signing_keys_directory_relative = PathBuf::from("keys");
            let signing_keys_directory_absolute =
                directory_path.join(&signing_keys_directory_relative);

            tokio::fs::create_dir_all(signing_keys_directory_absolute).await?;

            let signing_key_path_relative = signing_keys_directory_relative
                .join(format!("key_{}.pem", signing_key.key_type_name()));
            let signing_key_path_absolute = directory_path.join(&signing_key_path_relative);
            let pem = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();
            let mut file = File::create_new(&signing_key_path_absolute).await?;

            file.write_all(pem.as_bytes()).await?;

            vec![signing_key]
        };

        let registry = Self {
            directory_path,
            config,
            signing_keys,
            _file_lock: file_lock,
        };

        Ok(registry)
    }

    /// Atomically replaces the config file with one containing [`Self::config`].
    pub async fn save_config(&mut self) -> Result<()> {
        let config_string = toml::to_string_pretty(&self.config)?;

        Self::write_config_string(&self.directory_path, &config_string).await
    }

    /// Atomically replaces the config file with one containing `config_string`.
    /// The caller must hold the write lock.
    async fn write_config_string(directory_path: &Path, config_string: &str) -> Result<()> {
        replace_file(
            Self::get_config_path_from_registry_directory_path(directory_path),
            async |file| Ok(file.write_all(config_string.as_bytes()).await?),
        )
        .await?;

        Ok(())
    }

    /// Downgrades to a shared lock on the registry.
    /// The config and signing keys are reloaded, discarding any unsaved changes made to them.
    pub async fn lock_read(self) -> Result<OwnedRegistry<ReadLock>> {
        self.relock().await
    }
}

impl<L: FileLock> Deref for OwnedRegistry<L> {
    type Target = OwnedRegistryConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<L: FileLock> DerefMut for OwnedRegistry<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl<L: FileLock> PartialEq for OwnedRegistry<L> {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            directory_path: self_directory_path,
            config: self_config,
            signing_keys: self_signing_keys,
            _file_lock: _,
        } = self;
        let Self {
            directory_path: other_directory_path,
            config: other_config,
            signing_keys: other_signing_keys,
            _file_lock: _,
        } = other;
        self_directory_path == other_directory_path
            && self_config == other_config
            && self_signing_keys == other_signing_keys
    }
}

impl<L: FileLock> From<&OwnedRegistry<L>> for RegistryConfig {
    fn from(owned: &OwnedRegistry<L>) -> Self {
        Self {
            hash: owned.config.hash.clone(),
            kdf: owned.config.kdf.clone(),
            verifying_keys: owned.signing_keys.iter().map(Into::into).collect(),
        }
    }
}
