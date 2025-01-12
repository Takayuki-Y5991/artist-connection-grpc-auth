use std::sync::Arc;
use config::ConfigError;
use tonic::{Request, Response, Status};
use tonic::transport::Server;
use tracing::{error};

use crate::auth::adapters::auth0::Auth0ProviderFactory;
use crate::auth::domain::AuthError;
use crate::auth::ports::AuthProviderFactory;
use crate::auth::ports::AuthenticationPort;
use crate::config::{ProviderType, Settings};
use crate::generated::auth::auth_service_server::AuthServiceServer;
use crate::generated::auth::{
    auth_service_server::AuthService, GetTokenRequest, GetTokenResponse, IntrospectTokenRequest,
    IntrospectTokenResponse,
};

pub struct GrpcAuthService<T: AuthenticationPort> {
    auth_service: Arc<T>,
}
impl From<AuthError> for tonic::Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidGrant => Status::invalid_argument("Invalid grant"), // メッセージを固定化
            AuthError::ProviderError(msg) => Status::internal(msg),
            AuthError::ConfigError(msg) => Status::internal(msg),
            AuthError::RedirectUriError(e) => {
                Status::invalid_argument(format!("Redirect URI error: {}", e))
            }
            AuthError::InvalidToken => Status::unauthenticated("Invalid token"),
            AuthError::InvalidClient => Status::unauthenticated("Invalid client"),
            // 他のエラーバリアントもここに追加
            _ => {
                error!("Internal error during token exchange: {:?}", err);
                Status::internal("Internal server error")
            }
        }
    }
}

impl<T: AuthenticationPort> GrpcAuthService<T> {
    pub fn new(auth_service: Arc<T>) -> Self {
        Self { auth_service }
    }
}

#[tonic::async_trait]
impl<T: AuthenticationPort + Send + Sync + 'static> AuthService for GrpcAuthService<T> {
    async fn get_token(
        &self,
        request: Request<GetTokenRequest>,
    ) -> Result<Response<GetTokenResponse>, Status> {
        let req = request.into_inner();

        let token_response = self
            .auth_service
            .exchange_token(
                &req.grant_type,
                Some(&req.code),
                Some(&req.refresh_token),
                Some(&req.redirect_uri),
                Some(&req.code_verifier),
            )
            .await
            .map_err(tonic::Status::from)?;

        Ok(Response::new(GetTokenResponse {
            access_token: token_response.access_token,
            id_token: token_response.id_token.unwrap_or_default(),
            refresh_token: token_response.refresh_token.unwrap_or_default(),
            expires_in: token_response.expires_in,
            token_type: token_response.token_type,
        }))
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        let req = request.into_inner();

        let token_info = self
            .auth_service
            .introspect_token(&req.token, None)
            .await
            .map_err(tonic::Status::from)?;

        Ok(Response::new(IntrospectTokenResponse {
            active: token_info.active,
            scope: token_info.scope.unwrap_or_default(),
            client_id: token_info.client_id.unwrap_or_default(),
            sub: token_info.sub.unwrap_or_default(),
            username: token_info.username.unwrap_or_default(),
            token_type: token_info.token_type.unwrap_or_default(),
            exp: token_info.exp.unwrap_or_default(),
            iat: token_info.iat.unwrap_or_default(),
            nbf: token_info.nbf.unwrap_or_default(),
            aud: token_info.aud.unwrap_or_default(),
            iss: token_info.iss.unwrap_or_default(),
            jti: token_info.jti.unwrap_or_default(),
        }))
    }
}

pub async fn start_server(config: &Settings) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("Starting gRPC server at {}", addr);

    // 設定に基づいて適切なファクトリーを作成
    let auth_client = match config.auth.provider_type {
        ProviderType::Auth0 => {
            let auth0_config = config.auth.auth0.clone()
                .ok_or_else(|| Box::new(ConfigError::NotFound("Auth0 configuration not found".into())))?;
            let factory = Auth0ProviderFactory::new(auth0_config);
            factory.create_provider().await?
        },
        ProviderType::Keycloak => {
            // Keycloak用のファクトリーとプロバイダーの実装が必要
            todo!("Keycloak provider not implemented yet")
        }
    };

    // GrpcAuthServiceの初期化
    let auth_service = GrpcAuthService::new(Arc::new(auth_client));

    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(AuthServiceServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
