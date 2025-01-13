use crate::common::mock_auth_server::MockAuthServer;
use grpc_auth::auth::adapters::grpc::GrpcAuthService;
use grpc_auth::auth::domain::TokenResponse;
use grpc_auth::generated::auth::auth_service_server::AuthService;
use grpc_auth::generated::auth::GetTokenRequest;
use std::sync::Arc;
use tonic::Request;

#[tokio::test]
async fn test_grpc_service_get_token() {
    let mock_server = Arc::new(MockAuthServer::new());

    // モックレスポンスを設定
    mock_server.set_exchange_token_response(TokenResponse {
        access_token: "test_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: None,
        id_token: None,
    });

    let service = GrpcAuthService::new(mock_server);

    let request = Request::new(GetTokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: "".to_string(),
        client_secret: "".to_string(),
        code: "test_code".to_string(),
        redirect_uri: "http://localhost/callback".to_string(),
        code_verifier: "test_verifier".to_string(),
        refresh_token: String::new(),
    });

    let response = service.get_token(request).await;
    assert!(response.is_ok());
}
