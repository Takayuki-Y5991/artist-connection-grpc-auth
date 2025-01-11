use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    pub provider_type: ProviderType,
    pub auth0: Option<Auth0Config>,
    pub keycloak: Option<KeycloakConfig>,
}

#[derive(Debug, Deserialize)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
}

#[derive(Debug, Deserialize)]
pub struct KeycloakConfig {
    pub realm: String,
    pub auth_server_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Auth0,
    Keycloak,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(Environment::with_prefix("AUTH_SERVICE"))
            .build()?;

        config.try_deserialize()
    }
}