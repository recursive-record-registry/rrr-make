use aes_gcm::aead::OsRng;
use color_eyre::Result;
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey};
use rrr::crypto::kdf::hkdf::HkdfParams;
use rrr::crypto::kdf::KdfAlgorithm;
use rrr::crypto::password_hash::{argon2::Argon2Params, PasswordHashAlgorithm};
use rrr::crypto::signature::{SigningKey, SigningKeyEd25519};
use rrr::registry::{RegistryConfig, RegistryConfigHash, RegistryConfigKdf};
use rrr::utils::fd_lock::{FileLock, FileLockType, ReadLock, WriteLock};
use rrr::utils::serde::Secret;
use rrr::{crypto::encryption::EncryptionAlgorithm, record::RecordKey};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
};
use tokio::fs::OpenOptions;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::assets;
use crate::error::Error;
use crate::record::{
    OwnedRecordConfigEncryption, OwnedRecordConfigParameters, OwnedRecordConfigParametersUnresolved,
};

use super::record::{OwnedRecord, SplittingStrategy};

/// Represents a registry with cryptographic credentials for editing.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRegistryConfig {
    pub hash: RegistryConfigHash,
    pub kdf: RegistryConfigKdf,
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
    file_lock: L,
}

impl<L: FileLock> OwnedRegistry<L> {
    pub async fn load(directory_path: impl Into<PathBuf>) -> Result<Self> {
        let directory_path = directory_path.into();
        let config_path = Self::get_config_path_from_registry_directory_path(&directory_path);
        let open_options = {
            let mut open_options = OpenOptions::new();
            open_options.read(true);
            open_options.write(L::TYPE == FileLockType::Write);
            open_options
        };
        let mut file_lock = L::lock(&config_path, &open_options).await?;
        let config_string = {
            let mut config_string = String::new();
            file_lock
                .file_mut()
                .read_to_string(&mut config_string)
                .await?;
            config_string
        };
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
            file_lock,
        })
    }

    pub async fn save_config(&mut self) -> Result<()> {
        let config_string = toml::to_string_pretty(&self.config)?;

        self.file_lock
            .file_mut()
            .write_all(config_string.as_bytes())
            .await?;

        Ok(())
    }

    fn get_config_path_from_registry_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join("registry.toml")
    }

    fn get_config_path(&self) -> PathBuf {
        Self::get_config_path_from_registry_directory_path(&self.directory_path)
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
        OwnedRecord::load_from_directory(&self.config, self.get_root_record_path()).await
    }
}

impl OwnedRegistry<ReadLock> {
    pub async fn lock_write(self) -> Result<OwnedRegistry<WriteLock>> {
        let config_path = self.get_config_path();
        let open_options = {
            let mut open_options = File::options();
            open_options.read(true);
            open_options.write(true);
            open_options.truncate(true);
            open_options
        };

        drop(self.file_lock);

        Ok(OwnedRegistry {
            file_lock: WriteLock::lock(&config_path, &open_options).await?,
            directory_path: self.directory_path,
            config: self.config,
            signing_keys: self.signing_keys,
        })
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
                .into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir_all(&directory_path).await?
            }
            Err(error) => return Err(error.into()),
        }

        let signing_keys_directory_relative = PathBuf::from("keys");
        let signing_keys_directory_absolute = directory_path.join(&signing_keys_directory_relative);
        let config_path = Self::get_config_path_from_registry_directory_path(&directory_path);

        // TODO: Unify with save_config
        tokio::fs::create_dir_all(&directory_path).await?;
        let file_lock = {
            let open_options = {
                let mut open_options = OpenOptions::new();
                open_options.read(true);
                open_options.write(true);
                open_options.truncate(true);
                open_options.create(overwrite);
                open_options.create_new(!overwrite);
                open_options
            };
            WriteLock::lock(&config_path, &open_options).await?
        };
        tokio::task::spawn_blocking({
            let directory_path = directory_path.clone();
            move || assets::SOURCE_DIRECTORY_TEMPLATE.extract(directory_path)
        })
        .await??;
        tokio::fs::create_dir(&signing_keys_directory_absolute).await?;

        let mut csprng = OsRng;
        let signing_keys = vec![SigningKey::Ed25519(Secret(SigningKeyEd25519(
            ed25519_dalek::SigningKey::generate(&mut csprng),
        )))];
        let signing_key_paths = {
            let mut signing_key_paths = Vec::new();

            for signing_key in &signing_keys {
                let signing_key_path_relative = signing_keys_directory_relative
                    .join(format!("key_{}.pem", signing_key.key_type_name()));
                let signing_key_path_absolute = directory_path.join(&signing_key_path_relative);
                let pem = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();
                let mut file = File::create_new(&signing_key_path_absolute).await?;

                file.write_all(pem.as_bytes()).await?;
                signing_key_paths.push(signing_key_path_relative);
            }

            signing_key_paths
        };

        let config = OwnedRegistryConfig {
            hash: RegistryConfigHash {
                algorithm: PasswordHashAlgorithm::Argon2(Argon2Params::default()),
                output_length_in_bytes: Default::default(),
            },
            kdf: RegistryConfigKdf::builder()
                .with_algorithm(KdfAlgorithm::Hkdf(HkdfParams::default()))
                .build_with_random_root_predecessor_nonce(csprng)?,
            default_record_parameters: OwnedRecordConfigParameters {
                splitting_strategy: SplittingStrategy::Fill {},
                encryption: Some(OwnedRecordConfigEncryption {
                    algorithm: EncryptionAlgorithm::Aes256Gcm,
                    segment_padding_to_bytes: 1024, // 1 KiB
                }),
            }
            .into(),
            staging_directory_path: PathBuf::from("target/staging"),
            revisions_directory_path: PathBuf::from("target/revisions"),
            published_directory_path: PathBuf::from("target/published"),
            root_record_path: PathBuf::from("root"),
            signing_key_paths,
        };

        let mut registry = Self {
            directory_path,
            config,
            signing_keys,
            file_lock,
        };

        registry.save_config().await?;

        Ok(registry)
    }

    pub async fn lock_read(self) -> Result<OwnedRegistry<ReadLock>> {
        let config_path = self.get_config_path();
        let open_options = {
            let mut open_options = File::options();
            open_options.read(true);
            open_options
        };

        drop(self.file_lock);

        Ok(OwnedRegistry {
            file_lock: ReadLock::lock(&config_path, &open_options).await?,
            directory_path: self.directory_path,
            config: self.config,
            signing_keys: self.signing_keys,
        })
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
            file_lock: _,
        } = self;
        let Self {
            directory_path: other_directory_path,
            config: other_config,
            signing_keys: other_signing_keys,
            file_lock: _,
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
