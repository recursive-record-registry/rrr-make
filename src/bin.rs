use clap::Parser;
use color_eyre::eyre::Result;
use rrr_make::cmd::Command;
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

async fn setup_tracing() -> Result<()> {
    // Enable logging by default.
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", format!("{}=info", env!("CARGO_CRATE_NAME")));
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing().await?;
    Command::parse().process().await?;

    Ok(())
}
