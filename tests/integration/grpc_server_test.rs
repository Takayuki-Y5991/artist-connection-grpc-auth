use std::sync::Arc;
use tonic::transport::Server;
use grpc_auth::auth::adapters::auth0::Auth0Client;
use grpc_auth::auth::adapters::grpc::GrpcAuthService;
use grpc_auth::config::Settings;
use grpc_auth::generated::auth::auth_service_server::AuthServiceServer;
use grpc_auth::generated::auth::auth_service_client::AuthServiceClient;
use grpc_auth::generated::auth::{GetTokenRequest};

#[tokio::test]
async fn test_grpc_server_integration() -> Result<(), Box<dyn std::error::Error>> {
    // テスト用の設定を読み込み（OAuth2モックサーバーの設定を含む）
    let config = Settings::new_with_config("config/test")
        .expect("Failed to load test config");

    // 実際のAuth0クライアントを作成
    let auth_client = Auth0Client::new(config.auth.auth0.clone().unwrap())?;
    let service = GrpcAuthService::new(Arc::new(auth_client));

    let addr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let server = Server::builder()
        .add_service(AuthServiceServer::new(service))
        .serve(addr);

    let server_handle = tokio::spawn(server);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let channel = tonic::transport::Channel::from_shared(
        format!("http://{}:{}", config.server.host, config.server.port)
    )?
        .connect()
        .await?;

    let mut client = AuthServiceClient::new(channel);

    let response = client
        .get_token(GetTokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: config.auth.auth0.as_ref()
                .map(|c| c.client_id.clone())
                .unwrap_or_default(),
            client_secret: config.auth.auth0.as_ref()
                .map(|c| c.client_secret.clone())
                .unwrap_or_default(),
            code: "test_code".to_string(),  // モックサーバーが受け付ける認可コード
            redirect_uri: "http://localhost/callback".to_string(),
            code_verifier: "test_verifier".to_string(),
            refresh_token: String::new(),
        })
        .await;

    assert!(response.is_ok());

    server_handle.abort();
    Ok(())
}