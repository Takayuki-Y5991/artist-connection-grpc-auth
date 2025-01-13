use async_trait::async_trait;
use grpc_auth::auth::domain::{AuthError, AuthResult, TokenInfo, TokenResponse};
use grpc_auth::auth::ports::{AuthProviderFactory, AuthenticationPort};
use grpc_auth::config::Auth0Config;
use std::sync::Mutex;

pub struct MockAuth0Client {
    exchange_token_response: Mutex<Option<Result<TokenResponse, AuthError>>>,
    introspect_token_response: Mutex<Option<Result<TokenInfo, AuthError>>>,
}

impl MockAuth0Client {
    pub fn new() -> Self {
        Self {
            exchange_token_response: Mutex::new(None),
            introspect_token_response: Mutex::new(None),
        }
    }

    pub fn set_exchange_token_response(&self, response: Result<TokenResponse, AuthError>) {
        *self.exchange_token_response.lock().unwrap() = Some(response);
    }

    pub fn set_introspect_token_response(&self, response: Result<TokenInfo, AuthError>) {
        *self.introspect_token_response.lock().unwrap() = Some(response);
    }
}

#[async_trait]
impl AuthenticationPort for MockAuth0Client {
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
            .unwrap_or(Err(AuthError::ProviderError(
                "No mock response set".to_string(),
            )))
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
            .unwrap_or(Err(AuthError::ProviderError(
                "No mock response set".to_string(),
            )))
    }
}

pub struct Auth0ProviderFactory {
    config: Auth0Config,
}

impl Auth0ProviderFactory {
    pub fn new(config: Auth0Config) -> Self {
        Self { config }
    }
}

#[async_trait]
impl AuthProviderFactory for Auth0ProviderFactory {
    type Provider = MockAuth0Client;

    async fn create_provider(&self) -> AuthResult<Self::Provider> {
        Ok(MockAuth0Client::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exchange_token_authorization_code_success() {
        let mock_client = MockAuth0Client::new();

        let expected_response = TokenResponse {
            access_token: "access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_token".to_string()),
            id_token: None,
        };

        mock_client.set_exchange_token_response(Ok(expected_response.clone()));

        let result = mock_client
            .exchange_token(
                "authorization_code",
                Some("auth_code"),
                None,
                Some("redirect_uri"),
                Some("code_verifier"),
            )
            .await;

        assert_eq!(result, Ok(expected_response));
    }

    #[tokio::test]
    async fn test_exchange_token_refresh_token_success() {
        let mock_client = MockAuth0Client::new();

        let expected_response = TokenResponse {
            access_token: "new_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("new_refresh_token".to_string()),
            id_token: None,
        };

        mock_client.set_exchange_token_response(Ok(expected_response.clone()));

        let result = mock_client
            .exchange_token("refresh_token", None, Some("refresh_token"), None, None)
            .await;

        assert_eq!(result, Ok(expected_response));
    }

    #[tokio::test]
    async fn test_exchange_token_invalid_grant_type() {
        let mock_client = MockAuth0Client::new();
        mock_client.set_exchange_token_response(Err(AuthError::InvalidGrant));

        let result = mock_client
            .exchange_token("invalid_grant", None, None, None, None)
            .await;

        assert_eq!(result, Err(AuthError::InvalidGrant));
    }

    #[tokio::test]
    async fn test_introspect_token_success() {
        let mock_client = MockAuth0Client::new();

        let expected_info = TokenInfo {
            active: true,
            scope: Some("openid profile".to_string()),
            client_id: Some("client_id".to_string()),
            username: Some("user".to_string()),
            exp: Some(1678886400),
            iat: Some(1678882800),
            sub: Some("sub".to_string()),
            aud: Some("aud".to_string()),
            iss: Some("iss".to_string()),
            token_type: Some("Bearer".to_string()),
            nbf: Some(1678882800),
            jti: Some("jti".to_string()),
        };

        mock_client.set_introspect_token_response(Ok(expected_info.clone()));

        let result = mock_client.introspect_token("access_token", None).await;

        assert_eq!(result, Ok(expected_info));
    }
}
