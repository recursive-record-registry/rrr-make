use std::path::PathBuf;

use crate::{make_recursive, registry::OwnedRegistry};
use clap::Parser;
use color_eyre::eyre::Result;
use rrr::registry::{Registry, RegistryConfig};

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
        /// Path to a directory in which to put the RRR registry.
        #[arg(short, long, default_value = "target")]
        output_directory: PathBuf,
        /// Force existing files to be overwritten.
        #[arg(short, long, default_value = "false")]
        force: bool,
    },
}

impl Command {
    pub async fn process(self) -> Result<()> {
        match Command::parse() {
            Command::New { directory, force } => {
                OwnedRegistry::generate(&directory, force).await.unwrap();
                println!("New registry successfully generated in {directory:?}.");
            }
            Command::Make {
                input_directory,
                output_directory,
                force,
            } => {
                let input_registry = OwnedRegistry::load(input_directory).await?;
                let input_root_record = input_registry.load_root_record().await?;
                let mut output_registry = Registry::create(
                    output_directory,
                    RegistryConfig::from(&input_registry),
                    force,
                )
                .await?;
                let root_predecessor_nonce = output_registry
                    .config
                    .kdf
                    .get_root_record_predecessor_nonce();

                // TODO: Verify target registry keys

                make_recursive(
                    &mut output_registry,
                    &input_registry,
                    &input_root_record,
                    &root_predecessor_nonce,
                    force,
                )
                .await?;
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
