use chrono::{DateTime, Utc};
use color_eyre::{
    eyre::{bail, eyre, OptionExt},
    Result,
};
use futures::future::{BoxFuture, FutureExt};
use rrr::{crypto::encryption::EncryptionAlgorithm, record::segment::SegmentEncryption};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::{
    collections::HashSet,
    ffi::OsString,
    fmt::Debug,
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::{error::Error, registry::OwnedRegistryConfig, util::serde::DoubleOption};

pub trait Unresolved: Sized + Default + From<Self::Resolved> {
    type Resolved: Sized;

    fn or(self, fallback: Self) -> Self;
    fn resolve(self) -> Result<Self::Resolved, Self>;
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRecordConfigEncryptionUnresolved {
    pub algorithm: Option<EncryptionAlgorithm>,
    pub segment_padding_to_bytes: Option<u64>,
}

impl Unresolved for OwnedRecordConfigEncryptionUnresolved {
    type Resolved = OwnedRecordConfigEncryption;

    fn or(self, fallback: Self) -> Self {
        Self {
            algorithm: self.algorithm.or(fallback.algorithm),
            segment_padding_to_bytes: self
                .segment_padding_to_bytes
                .or(fallback.segment_padding_to_bytes),
        }
    }

    fn resolve(self) -> Result<Self::Resolved, Self> {
        if let Self {
            algorithm: Some(algorithm),
            segment_padding_to_bytes: Some(segment_padding_to_bytes),
        } = self
        {
            Ok(Self::Resolved {
                algorithm,
                segment_padding_to_bytes,
            })
        } else {
            Err(self)
        }
    }
}

impl From<OwnedRecordConfigEncryption> for OwnedRecordConfigEncryptionUnresolved {
    fn from(value: OwnedRecordConfigEncryption) -> Self {
        Self {
            algorithm: Some(value.algorithm),
            segment_padding_to_bytes: Some(value.segment_padding_to_bytes),
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRecordConfigParametersUnresolved {
    pub encryption: DoubleOption<OwnedRecordConfigEncryptionUnresolved>,
}

impl Unresolved for OwnedRecordConfigParametersUnresolved {
    type Resolved = OwnedRecordConfigParameters;

    fn or(self, fallback: Self) -> Self {
        Self {
            encryption: self.encryption.or(fallback.encryption),
        }
    }

    fn resolve(self) -> Result<Self::Resolved, Self> {
        if let Self {
            encryption: Some(encryption),
        } = self
        {
            match Option::from(encryption)
                .map(Unresolved::resolve)
                .transpose()
            {
                Ok(resolved) => Ok(Self::Resolved {
                    encryption: resolved,
                }),
                Err(unresolved) => Err(Self {
                    encryption: Some(Some(unresolved).into()),
                }),
            }
        } else {
            Err(self)
        }
    }
}

impl From<OwnedRecordConfigParameters> for OwnedRecordConfigParametersUnresolved {
    fn from(value: OwnedRecordConfigParameters) -> Self {
        Self {
            encryption: Some(
                value
                    .encryption
                    .map(OwnedRecordConfigEncryptionUnresolved::from)
                    .into(),
            ),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRecordConfigUnresolved {
    pub name: ByteBuf,
    pub metadata: OwnedRecordMetadata,
    #[serde(flatten)]
    pub parameters: OwnedRecordConfigParametersUnresolved,
}

impl OwnedRecordConfigUnresolved {
    pub fn try_resolve_with(
        self,
        parameters: OwnedRecordConfigParametersUnresolved,
    ) -> Result<OwnedRecordConfig, OwnedRecordConfigUnresolved> {
        match self.parameters.or(parameters).resolve() {
            Ok(resolved) => Ok(OwnedRecordConfig {
                name: self.name,
                metadata: self.metadata,
                parameters: resolved,
            }),
            Err(unresolved) => Err(Self {
                name: self.name,
                metadata: self.metadata,
                parameters: unresolved,
            }),
        }
    }
}

impl From<OwnedRecordConfig> for OwnedRecordConfigUnresolved {
    fn from(value: OwnedRecordConfig) -> Self {
        Self {
            name: value.name,
            metadata: value.metadata,
            parameters: value.parameters.into(),
        }
    }
}

impl From<&OwnedRecordConfigEncryption> for SegmentEncryption {
    fn from(value: &OwnedRecordConfigEncryption) -> Self {
        Self {
            algorithm: value.algorithm,
            padding_to_bytes: value.segment_padding_to_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRecordMetadata {
    pub created_at: Option<toml::value::Datetime>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRecordConfigEncryption {
    pub algorithm: EncryptionAlgorithm,
    pub segment_padding_to_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedRecordConfigParameters {
    pub encryption: Option<OwnedRecordConfigEncryption>,
}

#[derive(Clone, Debug)]
pub struct OwnedRecordConfig {
    pub name: ByteBuf,
    pub metadata: OwnedRecordMetadata,
    pub parameters: OwnedRecordConfigParameters,
}

#[derive(Debug)]
pub struct OwnedRecord {
    pub directory_path: PathBuf,
    pub config: OwnedRecordConfig,
    pub successive_records: Vec<OwnedRecord>,
}

impl OwnedRecord {
    pub fn load_from_directory<'a>(
        registry_config: &'a OwnedRegistryConfig,
        directory_path: impl AsRef<Path> + Send + Sync + 'a,
    ) -> BoxFuture<'a, Result<Self>> {
        async move {
            let config_unresolved = Self::load_config(&directory_path).await?;
            let config = config_unresolved
                .try_resolve_with(registry_config.default_record_parameters.clone() /* TODO: cloning seems excessive */)
                .map_err(|_| eyre!("incomplete record parameters"))?;
            dbg!(&config);
            let mut successive_records_stream = tokio::fs::read_dir(&directory_path).await?;
            let mut successive_records = Vec::new();
            let mut successive_record_names = HashSet::new();

            while let Some(entry) = successive_records_stream.next_entry().await? {
                if entry.metadata().await?.is_dir() {
                    let successive_record_directory = entry.path();
                    let successive_record = OwnedRecord::load_from_directory(
                        registry_config,
                        &successive_record_directory,
                    )
                    .await?;
                    let successive_record_name_unique =
                        successive_record_names.insert(successive_record.config.name.clone());

                    if successive_record_name_unique {
                        successive_records.push(successive_record);
                    } else {
                        return Err(Error::DuplicateSuccessiveRecord {
                            parent: directory_path.as_ref().to_owned(),
                            name: successive_record.config.name.to_vec(),
                        }
                        .into());
                    }
                }
            }

            Ok(Self {
                directory_path: directory_path.as_ref().to_owned(),
                config,
                successive_records,
            })
        }
        .boxed()
    }

    pub async fn save(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.directory_path).await?;

        let config_string =
            toml::to_string_pretty(&OwnedRecordConfigUnresolved::from(self.config.clone()))?;
        let mut config_file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&self.get_config_path())
            .await?;

        config_file.write_all(config_string.as_bytes()).await?;

        Ok(())
    }

    pub async fn load_config(
        directory_path: impl AsRef<Path>,
    ) -> Result<OwnedRecordConfigUnresolved> {
        match tokio::fs::read_to_string(Self::get_config_path_from_record_directory_path(
            &directory_path,
        ))
        .await
        {
            Ok(config_string) => {
                toml::from_str::<OwnedRecordConfigUnresolved>(&config_string).map_err(Into::into)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let file_name = directory_path.as_ref().file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "The record in directory {:?} lacks a name.",
                            directory_path.as_ref()
                        ),
                    )
                })?;
                let file_name_utf8 = file_name.to_str().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Cannot derive a record name from the path segment {file_name:?}, as it is not a valid UTF-8 string.")
                    )
                })?;
                let created_at_system = tokio::fs::metadata(&directory_path).await?.created()?;
                let created_at_chrono = DateTime::<Utc>::from(created_at_system);
                let created_at =
                    toml::value::Datetime::from_str(&created_at_chrono.to_rfc3339()).unwrap();
                Ok(OwnedRecordConfigUnresolved {
                    name: ByteBuf::from(file_name_utf8.as_bytes()),
                    metadata: OwnedRecordMetadata {
                        created_at: Some(created_at),
                    },
                    parameters: Default::default(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn read(&self) -> Result<Option<impl AsyncRead>> {
        match tokio::fs::OpenOptions::new()
            .read(true)
            .open(self.get_data_path().await?)
            .await
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn get_config_path_from_record_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join("record.toml")
    }

    pub fn get_config_path(&self) -> PathBuf {
        Self::get_config_path_from_record_directory_path(&self.directory_path)
    }

    pub async fn get_data_path(&self) -> Result<PathBuf> {
        const FILE_STEM_DATA: &str = "data";

        let mut read_dir = tokio::fs::read_dir(&self.directory_path).await?;
        let mut candidate = None;

        while let Some(dir_entry) = read_dir.next_entry().await? {
            if dir_entry.file_type().await?.is_file() {
                let path = dir_entry.path();

                if path.file_stem() == Some(&OsString::from(FILE_STEM_DATA)) {
                    if candidate.is_none() {
                        candidate = Some(path);
                    } else {
                        bail!("Multiple data files available, but only one may exist");
                    }
                }
            }
        }

        candidate.ok_or_eyre("No data file found")
    }
}
