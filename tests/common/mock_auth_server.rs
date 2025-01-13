use async_trait::async_trait;
use grpc_auth::auth::domain::{AuthError, AuthResult, TokenInfo, TokenResponse};
use grpc_auth::auth::ports::AuthenticationPort;
use std::sync::Mutex;

pub struct MockAuthServer {
    pub exchange_token_response: Mutex<Option<TokenResponse>>,
    pub introspect_token_response: Mutex<Option<TokenInfo>>,
}

impl MockAuthServer {
    pub fn new() -> Self {
        Self {
            exchange_token_response: Mutex::new(None),
            introspect_token_response: Mutex::new(None),
        }
    }

    pub fn set_exchange_token_response(&self, response: TokenResponse) {
        *self.exchange_token_response.lock().unwrap() = Some(response);
    }

    pub fn set_introspect_token_response(&self, response: TokenInfo) {
        *self.introspect_token_response.lock().unwrap() = Some(response);
    }
}

#[async_trait]
impl AuthenticationPort for MockAuthServer {
    async fn exchange_token(
        &self,
        _grant_type: &str,
        _code: Option<&str>,
        _refresh_token: Option<&str>,
        _redirect_uri: Option<&str>,
        _code_verifier: Option<&str>,
    ) -> AuthResult<TokenResponse> {
        self.exchange_token_response
            .lock()
            .unwrap()
            .clone()
            .ok_or(AuthError::ProviderError("No mock response set".to_string()))
    }

    async fn introspect_token(
        &self,
        _token: &str,
        _token_type_hint: Option<&str>,
    ) -> AuthResult<TokenInfo> {
        self.introspect_token_response
            .lock()
            .unwrap()
            .clone()
            .ok_or(AuthError::ProviderError("No mock response set".to_string()))
    }
}
