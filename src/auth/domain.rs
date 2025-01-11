use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub scope: String,
    pub client_id: String,
    pub sub: String,
    pub username: String,
    pub token_type: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub aud: String,
    pub iss: String,
    pub jti: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid grant")]
    InvalidGrant,

    #[error("invalid token")]
    InvalidToken,

    #[error("invalid client")]
    InvalidClient,

    #[error("provider error: {0}")]
    ProviderError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("internal error: {0}")]
    InternalError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;