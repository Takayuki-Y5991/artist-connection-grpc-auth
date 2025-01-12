mod auth;
mod config;
mod generated;

use crate::config::Settings;
use crate::auth::adapters::grpc::start_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    tracing_subscriber::fmt::init();

    let config = Settings::new().expect("Failed to load config");

    start_server(&config).await?;

    Ok(())
}