use clap::Parser;
use color_eyre::eyre::Result;
use rrr_make::cmd::Command;
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

async fn setup_tracing() -> Result<()> {
    let log_directives = std::env::var("RUST_LOG")
        .ok()
        .unwrap_or_else(|| format!("{}=info", env!("CARGO_CRATE_NAME")));

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .with(EnvFilter::builder().parse_lossy(log_directives))
        .try_init()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing().await?;
    Command::parse().process().await?;

    Ok(())
}
