use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub provider_type: ProviderType,
    pub auth0: Option<Auth0Config>,
    pub keycloak: Option<KeycloakConfig>,
}
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub force_https: Option<bool>,
}
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct KeycloakConfig {
    pub realm: String,
    pub auth_server_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Auth0,
    Keycloak,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        Self::new_with_config("config/default")
    }

    pub fn new_with_config(config_path: &str) -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name(config_path))
            .add_source(Environment::with_prefix("AUTH_SERVICE"))
            .build()?;

        config.try_deserialize()
    }
}
