use std::error::Error;
use tonic::transport::Server;
use tracing::{info, error, Level};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

mod auth;
mod config;
mod generated;

use auth::adapters::{
    auth0::Auth0Client,
    keycloak::KeycloakClient,
    grpc::GrpcAuthServer
};
use auth::AuthenticationPort;
use generated::auth::auth_service_server::AuthServiceServer;
use config::{Settings, ProviderType};
use auth::domain::AuthError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    info!("Starting authentication server...");

    // Load configuration
    let settings = Settings::new().map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Initialize authentication provider
    let auth_provider: Box<dyn AuthenticationPort + Send + Sync> = match settings.auth.provider_type {
        ProviderType::Auth0 => {
            let config = settings.auth.auth0.ok_or_else(|| {
                AuthError::ConfigError("Auth0 configuration is missing".to_string())
            })?;
            Box::new(Auth0Client::new(config)?)
        }
        ProviderType::Keycloak => {
            let config = settings.auth.keycloak.ok_or_else(|| {
                AuthError::ConfigError("Keycloak configuration is missing".to_string())
            })?;
            Box::new(KeycloakClient::new(config)?)
        }
    };

    // Create gRPC server
    let addr = format!("{}:{}", settings.server.host, settings.server.port)
        .parse()?;
    let grpc_service = GrpcAuthServer::new(auth_provider);

    info!("Starting gRPC server on {}", addr);

    tokio::select! {
        res = Server::builder()
            .add_service(AuthServiceServer::new(grpc_service))
            .serve(addr) => {
            if let Err(e) = res {
                error!("Server error: {}", e);
                return Err(e.into());
            }
        }
        _ = shutdown_signal() => {
            info!("Shutting down server...");
        }
    }

    Ok(())
}

// Signal handling for graceful shutdown
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
    info!("Received shutdown signal");
}