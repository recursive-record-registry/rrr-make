use chrono::DateTime;
use futures::{future::BoxFuture, FutureExt};
use record::OwnedRecord;
use registry::OwnedRegistry;
use rrr::{
    record::{
        segment::SegmentEncryption, Record, RecordKey, RecordMetadata, RecordName, SuccessionNonce,
    },
    registry::{Registry, WriteLock},
    utils::serde::BytesOrAscii,
};
use tokio::io::AsyncReadExt;

pub mod assets;
pub mod error;
pub mod owned;
pub mod util;

#[cfg(feature = "cmd")]
pub mod cmd;

pub use owned::*;

pub fn make_recursive<'a>(
    output_registry: &'a mut Registry<WriteLock>,
    input_registry: &'a OwnedRegistry,
    input_record: &'a OwnedRecord,
    predecessor_nonce: &'a SuccessionNonce,
    force: bool,
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

        output_registry
            .save_record(
                &input_registry.signing_keys,
                &hashed_key,
                &output_record,
                0.into(), // TODO
                0,        // TODO
                &[],      // TODO
                input_record
                    .config
                    .parameters
                    .encryption
                    .as_ref()
                    .map(SegmentEncryption::from)
                    .as_ref(),
                force,
            )
            .await?;

        let succession_nonce = hashed_key
            .derive_succession_nonce(&input_registry.config.kdf)
            .await?;

        for successive_record in &input_record.successive_records {
            make_recursive(
                output_registry,
                input_registry,
                successive_record,
                &succession_nonce,
                force,
            )
            .await?;
        }

        Ok(())
    }
    .boxed()
}
