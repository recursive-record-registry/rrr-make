
use chrono::DateTime;
use color_eyre::eyre::OptionExt;
use futures::{future::BoxFuture, FutureExt};
use record::OwnedRecord;
use registry::OwnedRegistry;
use rrr::{
    record::{
        segment::{RecordVersion, SegmentEncryption},
        HashedRecordKey, ListRecordVersionsOptions, Record, RecordKey, RecordMetadata, RecordName,
        RecordPath, SaveRecordOptions, SuccessionNonce,
    },
    registry::Registry,
    utils::{
        fd_lock::{FileLock, WriteLock},
        serde::BytesOrAscii,
    },
};
use tokio::io::AsyncReadExt;

pub mod assets;
pub mod error;
pub mod owned;
pub mod util;

#[cfg(feature = "cmd")]
pub mod cmd;

pub use owned::*;
use tracing::{debug, info};

#[derive(Default)]
pub struct MakeRecursiveStatistics {
    pub records_created: usize,
    pub records_updated: usize,
    pub records_unchanged: usize,
}

/// What [`save_record_versioned`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveRecordVersionedOutcome {
    /// No version of the record was found, so the record was saved as version 0.
    Created,
    /// The latest version, `previous`, differed from the record, so the record was saved as the
    /// next version, `current`.
    Updated {
        previous: RecordVersion,
        current: RecordVersion,
    },
    /// The latest version, `version`, was equal to the record, so nothing was saved.
    Unchanged { version: RecordVersion },
}

/// If `record` differs from the latest version of the record at `hashed_key` in the `registry`,
/// saves `record` as a new version.
///
/// Existing versions are searched with `max_version_lookahead`, and with the
/// [`SaveRecordOptions::max_collision_resolution_attempts`] of `options`.
pub async fn save_record_versioned(
    registry: &mut Registry<WriteLock>,
    hashed_key: &HashedRecordKey,
    record: &Record,
    max_version_lookahead: u64,
    options: SaveRecordOptions<'_>,
) -> color_eyre::Result<SaveRecordVersionedOutcome> {
    let existing_versions = registry
        .list_record_versions(
            hashed_key,
            ListRecordVersionsOptions {
                max_version_lookahead,
                max_collision_resolution_attempts: options.max_collision_resolution_attempts,
            },
        )
        .await?;

    let Some(latest_existing_version) = existing_versions.last() else {
        // This is the first version of the record, as no other versions have been found.
        registry
            .save_record(hashed_key, record, RecordVersion(0), options)
            .await?;

        return Ok(SaveRecordVersionedOutcome::Created);
    };
    let latest_existing_version_record = Record::read_version_with_collision_index(
        registry,
        hashed_key,
        latest_existing_version.record_version,
        latest_existing_version.collision_index,
    )
    .await?
    .ok_or_eyre("Failed to load the latest version of a record.")?;

    if &latest_existing_version_record.record == record {
        return Ok(SaveRecordVersionedOutcome::Unchanged {
            version: latest_existing_version.record_version,
        });
    }

    let new_version = RecordVersion(latest_existing_version.record_version.0 + 1);

    registry
        .save_record(hashed_key, record, new_version, options)
        .await?;

    Ok(SaveRecordVersionedOutcome::Updated {
        previous: latest_existing_version.record_version,
        current: new_version,
    })
}

pub fn make_recursive<'a, L: FileLock>(
    output_registry: &'a mut Registry<WriteLock>,
    input_registry: &'a OwnedRegistry<L>,
    input_record: &'a OwnedRecord,
    predecessor_nonce: &'a SuccessionNonce,
    options: ListRecordVersionsOptions,
    // Record path excluding the `input_record`.
    path_to_parent_record: &'a mut Vec<RecordName>,
    stats: &'a mut MakeRecursiveStatistics,
) -> BoxFuture<'a, color_eyre::Result<()>> {
    async move {
        let mut read_result = input_record.read().await?.expect("Data not found.");
        let data = {
            let mut data = Vec::new();
            read_result.read.read_to_end(&mut data).await?;
            data
        };

        let output_record = Record {
            metadata: {
                let mut metadata = RecordMetadata::default();

                if let Some(created_at) = input_record.config.metadata.created_at.as_ref() {
                    let created_at_chrono = DateTime::parse_from_rfc3339(&created_at.to_string())?;

                    metadata.insert_created_at(created_at_chrono);
                }

                metadata
            },
            data: BytesOrAscii(data),
        };
        let key = RecordKey {
            record_name: RecordName::from(input_record.config.name.to_vec()),
            predecessor_nonce: predecessor_nonce.clone(),
        };
        let hashed_key = key.hash(&input_registry.hash).await?;
        let record_path = {
            let mut record_path = path_to_parent_record.clone();
            record_path.push(key.record_name.clone());
            RecordPath::try_from(record_path).unwrap()
        };

        let encryption = input_record
            .config
            .parameters
            .encryption
            .as_ref()
            .map(SegmentEncryption::from);
        let outcome = save_record_versioned(
            output_registry,
            &hashed_key,
            &output_record,
            options.max_version_lookahead,
            SaveRecordOptions {
                // TODO: Handle `SplittingStrategy::Fill`
                split_at: read_result.split_at.as_deref().unwrap_or_default(),
                max_collision_resolution_attempts: options.max_collision_resolution_attempts,
                ..SaveRecordOptions::new(&input_registry.signing_keys, encryption.as_ref())
            },
        )
        .await?;

        match outcome {
            SaveRecordVersionedOutcome::Created => {
                stats.records_created += 1;
                info!(%record_path, "New record created.");
            }
            SaveRecordVersionedOutcome::Updated { previous, current } => {
                stats.records_updated += 1;
                info!(
                    version_previous = previous.0,
                    version_current = current.0,
                    %record_path,
                    "New version of record created."
                );
            }
            SaveRecordVersionedOutcome::Unchanged { version } => {
                stats.records_unchanged += 1;
                debug!(version = version.0, %record_path, "Record unchanged, skipping.");
            }
        }

        let succession_nonce = hashed_key
            .derive_succession_nonce(&input_registry.config.kdf)
            .await?;

        {
            path_to_parent_record.push(key.record_name.clone());

            for successive_record in &input_record.successive_records {
                make_recursive(
                    output_registry,
                    input_registry,
                    successive_record,
                    &succession_nonce,
                    options,
                    path_to_parent_record,
                    stats,
                )
                .await?;
            }

            path_to_parent_record.pop();
        }

        Ok(())
    }
    .boxed()
}
