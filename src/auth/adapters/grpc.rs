use tonic::{Request, Response, Status};
use tracing::{info, error};

use crate::auth::ports::AuthenticationPort;
use crate::auth::domain::AuthError;

// protoから生成されるコードをインポート
tonic::include_proto!("auth");

// 生成されたトレイトをインポート
use auth_service_server::AuthService;

pub struct GrpcAuthServer<T: AuthenticationPort> {
    auth_service: T,
}

impl<T: AuthenticationPort> GrpcAuthServer<T> {
    pub fn new(auth_service: T) -> Self {
        Self { auth_service }
    }
}

#[tonic::async_trait]
impl<T: AuthenticationPort + Send + Sync + 'static> AuthService for GrpcAuthServer<T> {
    async fn get_token(
        &self,
        request: Request<GetTokenRequest>,
    ) -> Result<Response<GetTokenResponse>, Status> {
        let req = request.into_inner();
        info!("Received token request with grant_type: {}", req.grant_type);

        let result = self.auth_service
            .exchange_token(
                &req.grant_type,
                req.code.as_ref().map(|s| s.as_str()),
                req.refresh_token.as_ref().map(|s| s.as_str()),
                req.redirect_uri.as_ref().map(|s| s.as_str()),
                req.code_verifier.as_ref().map(|s| s.as_str()),
            )
            .await
            .map_err(|e| match e {
                AuthError::InvalidGrant => Status::invalid_argument("Invalid grant"),
                AuthError::InvalidClient => Status::unauthenticated("Invalid client"),
                _ => {
                    error!("Internal error during token exchange: {:?}", e);
                    Status::internal("Internal server error")
                }
            })?;

        Ok(Response::new(GetTokenResponse {
            access_token: result.access_token,
            id_token: result.id_token.unwrap_or_default(),
            refresh_token: result.refresh_token.unwrap_or_default(),
            expires_in: result.expires_in,
            token_type: result.token_type,
        }))
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        let req = request.into_inner();
        info!("Received introspection request");

        let result = self.auth_service
            .introspect_token(
                &req.token,
                req.token_type_hint.as_ref().map(|s| s.as_str()),
            )
            .await
            .map_err(|e| match e {
                AuthError::InvalidToken => Status::invalid_argument("Invalid token"),
                _ => {
                    error!("Internal error during token introspection: {:?}", e);
                    Status::internal("Internal server error")
                }
            })?;

        Ok(Response::new(IntrospectTokenResponse {
            active: result.active,
            scope: result.scope,
            client_id: result.client_id,
            sub: result.sub,
            username: result.username,
            token_type: result.token_type,
            exp: result.exp,
            iat: result.iat,
            nbf: result.nbf,
            aud: result.aud,
            iss: result.iss,
            jti: result.jti,
        }))
    }
}