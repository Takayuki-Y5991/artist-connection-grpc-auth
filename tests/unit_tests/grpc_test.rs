#[cfg(test)]
mod tests {
    use grpc_auth::auth::adapters::grpc::GrpcAuthService;
    use grpc_auth::auth::domain::{AuthError, TokenInfo, TokenResponse};
    use grpc_auth::auth::ports::AuthenticationPort;
    use grpc_auth::generated::auth::auth_service_server::AuthService;
    use grpc_auth::generated::auth::{GetTokenRequest, IntrospectTokenRequest};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tonic::{Request, Status};

    struct MockAuthService {
        exchange_token_response: Arc<Mutex<Option<Result<TokenResponse, AuthError>>>>,
        introspect_token_response: Arc<Mutex<Option<Result<TokenInfo, AuthError>>>>,
    }

    impl MockAuthService {
        fn new() -> Self {
            Self {
                exchange_token_response: Arc::new(Mutex::new(None)),
                introspect_token_response: Arc::new(Mutex::new(None)),
            }
        }

        async fn set_exchange_token_response(&self, response: Result<TokenResponse, AuthError>) {
            *self.exchange_token_response.lock().await = Some(response);
        }

        async fn set_introspect_token_response(&self, response: Result<TokenInfo, AuthError>) {
            *self.introspect_token_response.lock().await = Some(response);
        }
    }

    #[tonic::async_trait]
    impl AuthenticationPort for MockAuthService {
        async fn exchange_token(
            &self,
            _grant_type: &str,
            _code: Option<&str>,
            _refresh_token: Option<&str>,
            _redirect_uri: Option<&str>,
            _code_verifier: Option<&str>,
        ) -> Result<TokenResponse, AuthError> {
            self.exchange_token_response
                .lock()
                .await
                .clone()
                .unwrap_or(Err(AuthError::ProviderError("No response set".to_string())))
        }

        async fn introspect_token(
            &self,
            _token: &str,
            _token_type_hint: Option<&str>,
        ) -> Result<TokenInfo, AuthError> {
            self.introspect_token_response
                .lock()
                .await
                .clone()
                .unwrap_or(Err(AuthError::ProviderError("No response set".to_string())))
        }
    }

    #[tokio::test]
    async fn test_get_token_success() {
        let mock_service = Arc::new(MockAuthService::new());
        let grpc_service = GrpcAuthService::new(mock_service.clone());

        let expected_response = TokenResponse {
            access_token: "access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_token".to_string()),
            id_token: Some("id_token".to_string()),
        };

        mock_service
            .set_exchange_token_response(Ok(expected_response.clone()))
            .await;

        let request = Request::new(GetTokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
            code: "auth_code".to_string(),
            refresh_token: "refresh_token".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            code_verifier: "code_verifier".to_string(),
        });

        let response = grpc_service.get_token(request).await.unwrap();
        let response = response.into_inner();

        assert_eq!(response.access_token, expected_response.access_token);
        assert_eq!(response.token_type, expected_response.token_type);
        assert_eq!(response.expires_in, expected_response.expires_in);
        assert_eq!(
            response.refresh_token,
            expected_response.refresh_token.unwrap_or_default()
        );
        assert_eq!(
            response.id_token,
            expected_response.id_token.unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_get_token_error() {
        let mock_service = Arc::new(MockAuthService::new());
        let grpc_service = GrpcAuthService::new(mock_service.clone());

        mock_service
            .set_exchange_token_response(Err(AuthError::InvalidGrant))
            .await;

        let request = Request::new(GetTokenRequest {
            grant_type: "invalid_grant".to_string(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
            code: "".to_string(),
            refresh_token: "".to_string(),
            redirect_uri: "".to_string(),
            code_verifier: "".to_string(),
        });

        let result = grpc_service.get_token(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_introspect_token_success() {
        let mock_service = Arc::new(MockAuthService::new());
        let grpc_service = GrpcAuthService::new(mock_service.clone());

        let expected_info = TokenInfo {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("client123".to_string()),
            username: Some("user@example.com".to_string()),
            exp: Some(1678886400),
            iat: Some(1678882800),
            sub: Some("user123".to_string()),
            aud: Some("api".to_string()),
            iss: Some("https://auth.example.com".to_string()),
            token_type: Some("Bearer".to_string()),
            nbf: Some(1678882800),
            jti: Some("token123".to_string()),
        };

        mock_service
            .set_introspect_token_response(Ok(expected_info.clone()))
            .await;

        let request = Request::new(IntrospectTokenRequest {
            token: "valid_token".to_string(),
            token_type_hint: "".to_string(),
        });

        let response = grpc_service.introspect_token(request).await.unwrap();
        let response = response.into_inner();

        assert_eq!(response.active, expected_info.active);
        assert_eq!(response.scope, expected_info.scope.unwrap_or_default());
        assert_eq!(
            response.client_id,
            expected_info.client_id.unwrap_or_default()
        );
        assert_eq!(
            response.username,
            expected_info.username.unwrap_or_default()
        );
        assert_eq!(response.exp, expected_info.exp.unwrap_or_default());
        assert_eq!(response.iat, expected_info.iat.unwrap_or_default());
    }

    #[tokio::test]
    async fn test_introspect_token_error() {
        let mock_service = Arc::new(MockAuthService::new());
        let grpc_service = GrpcAuthService::new(mock_service.clone());

        mock_service
            .set_introspect_token_response(Err(AuthError::InvalidToken))
            .await;

        let request = Request::new(IntrospectTokenRequest {
            token: "invalid_token".to_string(),
            token_type_hint: "".to_string(),
        });

        let result = grpc_service.introspect_token(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_auth_error_to_status_conversion() {
        // 各種エラーの変換をテスト
        assert_eq!(
            Status::from(AuthError::InvalidGrant).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            Status::from(AuthError::InvalidToken).code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Status::from(AuthError::InvalidClient).code(),
            tonic::Code::Unauthenticated
        );

        // ProviderErrorの変換をテスト
        let provider_error = AuthError::ProviderError("test error".to_string());
        assert_eq!(Status::from(provider_error).code(), tonic::Code::Internal);
    }
}
