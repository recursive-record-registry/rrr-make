use chrono::DateTime;
use color_eyre::eyre::OptionExt;
use futures::{future::BoxFuture, FutureExt};
use record::OwnedRecord;
use registry::OwnedRegistry;
use rrr::{
    record::{
        segment::{RecordVersion, SegmentEncryption},
        HashedRecordKey, Record, RecordKey, RecordMetadata, RecordName, RecordPath,
        SuccessionNonce,
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

/// If `output_record` differs from the latest version of the record in the `output_registry`, saves
/// the `output_record` as a new version.
pub async fn save_record_versioned<L: FileLock>(
    output_registry: &mut Registry<WriteLock>,
    input_registry: &OwnedRegistry<L>,
    input_record: &OwnedRecord,
    max_version_lookahead: u64,
    max_collision_resolution_attempts: u64,
    record_path: &RecordPath,
    output_record: &Record,
    hashed_key: &HashedRecordKey,
    stats: &mut MakeRecursiveStatistics,
) -> color_eyre::Result<()> {
    let existing_versions = output_registry
        .list_record_versions(
            hashed_key,
            max_version_lookahead,
            max_collision_resolution_attempts,
        )
        .await?;
    let encryption = input_record
        .config
        .parameters
        .encryption
        .as_ref()
        .map(SegmentEncryption::from);

    if let Some(latest_existing_version) = existing_versions.last() {
        let latest_existing_version_record = Record::read_version_with_nonce(
            output_registry,
            hashed_key,
            latest_existing_version.record_version,
            latest_existing_version.record_nonce,
        )
        .await?
        .ok_or_eyre("Failed to load the latest version of a record.")?;

        if &latest_existing_version_record.record == output_record {
            debug!(version = %latest_existing_version.record_version.0, %record_path, "Record unchanged, skipping.");
            stats.records_unchanged += 1;
        } else {
            let new_version = RecordVersion(latest_existing_version.record_version.0 + 1);

            debug!(
                version_previous = latest_existing_version.record_version.0,
                version_current = new_version.0,
                %record_path,
                "Record changed, writing new version."
            );
            output_registry
                .save_record(
                    &input_registry.signing_keys,
                    hashed_key,
                    output_record,
                    new_version,
                    max_collision_resolution_attempts,
                    &[], // TODO
                    encryption.as_ref(),
                    false,
                )
                .await?;
            stats.records_updated += 1;

            info!(
                version_previous = latest_existing_version.record_version.0,
                version_current = new_version.0,
                %record_path,
                "New version of record created."
            );
        }
    } else {
        output_registry
            .save_record(
                &input_registry.signing_keys,
                hashed_key,
                output_record,
                0.into(), // This is the first version of the record, as no other versions have been found.
                max_collision_resolution_attempts,
                &[], // TODO
                encryption.as_ref(),
                false,
            )
            .await?;
        stats.records_created += 1;

        info!(%record_path, "New record created.");
    }

    Ok(())
}

pub fn make_recursive<'a, L: FileLock>(
    output_registry: &'a mut Registry<WriteLock>,
    input_registry: &'a OwnedRegistry<L>,
    input_record: &'a OwnedRecord,
    predecessor_nonce: &'a SuccessionNonce,
    max_version_lookahead: u64,
    max_collision_resolution_attempts: u64,
    // Record path excluding the `input_record`.
    path_to_parent_record: &'a mut Vec<RecordName>,
    stats: &'a mut MakeRecursiveStatistics,
) -> BoxFuture<'a, color_eyre::Result<()>> {
    async move {
        let mut data = Vec::new();

        input_record
            .read()
            .await?
            .expect("Data not found.")
            .read_to_end(&mut data)
            .await?;

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

        save_record_versioned(
            output_registry,
            input_registry,
            input_record,
            max_version_lookahead,
            max_collision_resolution_attempts,
            &record_path,
            &output_record,
            &hashed_key,
            stats,
        )
        .await?;

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
                    max_version_lookahead,
                    max_collision_resolution_attempts,
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
