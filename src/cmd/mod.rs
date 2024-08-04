use std::path::PathBuf;

use crate::{make_recursive, registry::OwnedRegistry, MakeRecursiveStatistics};
use clap::Parser;
use color_eyre::eyre::Result;
use rrr::{
    registry::{Registry, RegistryConfig},
    utils::fd_lock::WriteLock,
};
use tracing::info;

#[derive(Parser)]
#[command(version, about)]
pub enum Command {
    /// Creates a new source directory.
    New {
        /// The directory in which to create a new source directory.
        directory: PathBuf,
        /// Force existing files to be overwritten.
        #[arg(short, long, default_value = "false")]
        force: bool,
    },
    /// Compiles a source directory into an RRR registry.
    Make {
        /// Path to a source directory.
        #[arg(short, long, default_value = ".")]
        input_directory: PathBuf,
        /// Force existing files to be overwritten.
        #[arg(short, long, default_value = "false")]
        force: bool,
        /// Whether a new revision should be created in the published directory.
        #[arg(long, default_value = "false")]
        publish: bool,
    },
}

impl Command {
    pub async fn process(self) -> Result<()> {
        match self {
            Command::New { directory, force } => {
                OwnedRegistry::generate(&directory, force).await.unwrap();
                println!("New registry successfully generated in {directory:?}.");
            }
            Command::Make {
                input_directory,
                force,
                publish,
            } => {
                let input_registry = OwnedRegistry::<WriteLock>::load(input_directory).await?;
                let input_root_record = input_registry.load_root_record().await?;
                let mut output_registry = Registry::create(
                    input_registry.get_staging_directory_path(),
                    RegistryConfig::from(&input_registry),
                    force,
                )
                .await?;
                let root_predecessor_nonce = output_registry
                    .config
                    .kdf
                    .get_root_record_predecessor_nonce()
                    .clone();

                // TODO: Verify target registry keys
                let mut stats = MakeRecursiveStatistics::default();

                make_recursive(
                    &mut output_registry,
                    &input_registry,
                    &input_root_record,
                    &root_predecessor_nonce,
                    0, // TODO
                    0, // TODO
                    &mut Vec::new(),
                    &mut stats,
                )
                .await?;

                if stats.records_created == 0 && stats.records_updated == 0 {
                    info! {
                        "Target registry unchanged. Checked {} records in total.",
                        stats.records_created + stats.records_updated + stats.records_unchanged,
                    };
                } else {
                    info! {
                        "Target registry updated. Checked {} records in total. {} new records created, {} existing records updated, {} existing records unchanged.",
                        stats.records_created + stats.records_updated + stats.records_unchanged,
                        stats.records_created,
                        stats.records_updated,
                        stats.records_unchanged,
                    };
                }
            }
        }

        Ok(())
    }
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Command::command().debug_assert();
}
