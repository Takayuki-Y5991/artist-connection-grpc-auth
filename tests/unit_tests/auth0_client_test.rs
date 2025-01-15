use async_trait::async_trait;
use grpc_auth::auth::domain::{AuthError, AuthResult, TokenInfo, TokenResponse};
use grpc_auth::auth::ports::{AuthProviderFactory, AuthenticationPort};
use grpc_auth::config::Auth0Config;
use parking_lot::RwLock;
use std::sync::Arc;

pub struct MockAuth0Client {
    exchange_token_response: Arc<RwLock<Option<Result<TokenResponse, AuthError>>>>,
    introspect_token_response: Arc<RwLock<Option<Result<TokenInfo, AuthError>>>>,
}

impl MockAuth0Client {
    pub fn new() -> Self {
        Self {
            exchange_token_response: Arc::new(RwLock::new(None)),
            introspect_token_response: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_exchange_token_response(&self, response: Result<TokenResponse, AuthError>) {
        *self.exchange_token_response.write() = Some(response);
    }

    pub fn set_introspect_token_response(&self, response: Result<TokenInfo, AuthError>) {
        *self.introspect_token_response.write() = Some(response);
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
            .read()
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
            .read()
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
    use std::time::Duration;
    use tokio::time::sleep;

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

    #[tokio::test]
    async fn test_introspect_token_invalid_token() {
        let mock_client = MockAuth0Client::new();
        mock_client.set_introspect_token_response(Err(AuthError::InvalidToken));

        let result = mock_client.introspect_token("invalid_token", None).await;
        assert_eq!(result, Err(AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn test_default_error_when_no_response_set() {
        let mock_client = MockAuth0Client::new();

        let exchange_result = mock_client
            .exchange_token("authorization_code", None, None, None, None)
            .await;
        assert!(matches!(
            exchange_result,
            Err(AuthError::ProviderError(msg)) if msg == "No mock response set"
        ));

        let introspect_result = mock_client.introspect_token("token", None).await;
        assert!(matches!(
            introspect_result,
            Err(AuthError::ProviderError(msg)) if msg == "No mock response set"
        ));
    }

    #[tokio::test]
    async fn test_factory_creates_new_instance() {
        let config = Auth0Config {
            domain: "test.auth0.com".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            audience: "test_audience".to_string(),
            force_https: Some(false),
        };

        let factory = Auth0ProviderFactory::new(config);
        let provider = factory.create_provider().await;

        assert!(provider.is_ok());
    }
    #[tokio::test]
    async fn test_concurrent_access() {
        let mock_client = Arc::new(MockAuth0Client::new());
        let mock_client_clone = mock_client.clone();

        let expected_response = Arc::new(TokenResponse {
            access_token: "test_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
            id_token: None,
        });
        let expected_response_clone1 = expected_response.clone();
        let expected_response_clone2 = expected_response.clone();

        // スレッド1: レスポンスを設定
        let handle1 = tokio::spawn(async move {
            mock_client.set_exchange_token_response(Ok((*expected_response_clone1).clone()));
            sleep(Duration::from_millis(100)).await;
            mock_client
                .exchange_token("authorization_code", None, None, None, None)
                .await
        });

        // スレッド2: 同じクライアントでレスポンスを取得
        let handle2 = tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            mock_client_clone
                .exchange_token("authorization_code", None, None, None, None)
                .await
        });

        let (result1, result2) = tokio::join!(handle1, handle2);
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), Ok((*expected_response_clone2).clone()));
        assert_eq!(result2.unwrap(), Ok((*expected_response).clone()));
    }
}
