use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub sub: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
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

    #[error("Redirect URI error: {0}")]
    RedirectUriError(#[source] oauth2::url::ParseError),
}

pub type AuthResult<T> = Result<T, AuthError>;
