use std::sync::Arc;
use tonic::transport::Server;
use grpc_auth::auth::adapters::auth0::Auth0Client;
use grpc_auth::auth::adapters::grpc::GrpcAuthService;
use grpc_auth::config::Settings;
use grpc_auth::generated::auth::auth_service_server::AuthServiceServer;
use grpc_auth::generated::auth::auth_service_client::AuthServiceClient;
use grpc_auth::generated::auth::{GetTokenRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Sha256, Digest};
use reqwest;

fn generate_code_verifier() -> String {
    let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(&random_bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

// setup_mock_oauth_serverの修正
async fn setup_mock_oauth_server(
    config: &Settings,
    code_verifier: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // リダイレクトを無効化
        .build()?;
    let mock_server_url = format!("http://{}", config.auth.auth0.as_ref().unwrap().domain);

    // モックサーバーの準備待機
    for _ in 0..30 {
        match client.get(format!("{}/default/.well-known/openid-configuration", mock_server_url)).send().await {
            Ok(response) => {
                println!("Mock server status: {}", response.status());
                if response.status().is_success() {
                    println!("Mock server is ready");
                    break;
                }
            }
            Err(e) => {
                println!("Failed to connect to mock server: {}", e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    let auth0_config = config.auth.auth0.as_ref().unwrap();

    // まず認証フォームを送信
    let auth_form = [
        ("username", "test_user"),
        ("claims", r#"{"sub": "test_user", "scope": "openid profile offline_access"}"#),
    ];

    let code_challenge = generate_code_challenge(code_verifier);
    let auth_params = [
        ("client_id", auth0_config.client_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", "http://localhost/callback"),
        ("scope", "openid profile offline_access"),
        ("state", "test-state"),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
    ];

    let auth_response = client
        .post(format!("{}/default/authorize", mock_server_url))
        .form(&auth_form)
        .query(&auth_params)
        .send()
        .await?;

    // リダイレクトURLからcodeを取得
    let location = auth_response
        .headers()
        .get("location")
        .ok_or("No location header")?
        .to_str()?;

    let code = url::Url::parse(location)?
        .query_pairs()
        .find(|(key, _)| key == "code")
        .ok_or("No code in redirect URL")?
        .1
        .into_owned();

    // ここで認可コードのみを返す（トークン取得は行わない）
    Ok((code, auth0_config.client_id.clone()))
}

#[tokio::test]
async fn test_grpc_server_integration() -> Result<(), Box<dyn std::error::Error>> {
    let config = Settings::new_with_config("config/test")
        .expect("Failed to load test config");

    // PKCE用のcode_verifier生成
    let code_verifier = generate_code_verifier();

    // モックサーバーのセットアップ（認可コードを取得）
    let (auth_code, _) = setup_mock_oauth_server(&config, &code_verifier).await?;

    let auth_client = Auth0Client::new(config.auth.auth0.clone().unwrap())?;
    let service = GrpcAuthService::new(Arc::new(auth_client));

    let addr = format!("{}:{}", config.server.host, config.server.port).parse()?;

    let server = Server::builder()
        .add_service(AuthServiceServer::new(service))
        .serve(addr);

    let server_handle = tokio::spawn(server);

    // サーバーの起動を待機
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let channel = tonic::transport::Channel::from_shared(
        format!("http://{}:{}", config.server.host, config.server.port)
    )?
        .connect()
        .await?;

    let mut client = AuthServiceClient::new(channel);

    // 認可コードからトークンを取得
    let auth_response = client
        .get_token(GetTokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: config.auth.auth0.as_ref().unwrap().client_id.clone(),
            client_secret: config.auth.auth0.as_ref().unwrap().client_secret.clone(),
            code: auth_code,  // 取得した認可コードを使用
            redirect_uri: "http://localhost/callback".to_string(),
            code_verifier,
            refresh_token: String::new(),
        })
        .await?;

    let token_response = auth_response.into_inner();
    assert!(!token_response.access_token.is_empty(), "Access token should not be empty");
    assert!(!token_response.refresh_token.is_empty(), "Refresh token should not be empty");
    assert_eq!(token_response.token_type, "Bearer");

    // クリーンアップ
    server_handle.abort();
    Ok(())
}