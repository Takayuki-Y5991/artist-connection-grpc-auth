use async_trait::async_trait;
use oauth2::basic::{BasicTokenIntrospectionResponse, BasicTokenType};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, EmptyExtraTokenFields, RedirectUrl, RefreshToken,
    StandardTokenResponse, TokenIntrospectionResponse, TokenResponse as OAuth2TokenResponse,
    TokenUrl,
};
use tracing::{error, info};

use crate::auth::domain::{AuthError, AuthResult, TokenInfo, TokenResponse};
use crate::auth::ports::{AuthProviderFactory, AuthenticationPort};
use crate::config::Auth0Config;

#[allow(dead_code)]
pub struct Auth0Client {
    oauth_client: BasicClient,
    config: Auth0Config,
}

impl Auth0Client {
    pub fn new(config: Auth0Config) -> AuthResult<Self> {
        let use_https = config.force_https.unwrap_or(false);
        let scheme = if use_https { "https" } else { "http" };

        let auth_url = format!("{}://{}/default/authorize", scheme, config.domain);
        let token_url = format!("{}://{}/default/oauth/token", scheme, config.domain);

        let oauth_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(auth_url).map_err(|e| AuthError::ConfigError(e.to_string()))?,
            Some(TokenUrl::new(token_url).map_err(|e| AuthError::ConfigError(e.to_string()))?),
        );

        Ok(Self {
            oauth_client,
            config,
        })
    }
    fn convert_token_response(
        token_result: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> TokenResponse {
        TokenResponse {
            access_token: token_result.access_token().secret().to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_result
                .expires_in()
                .map(|d| d.as_secs() as i32)
                .unwrap_or(3600),
            refresh_token: token_result.refresh_token().map(|t| t.secret().to_string()),
            id_token: None,
        }
    }
    fn convert_token_type(token_type: &BasicTokenType) -> String {
        match token_type {
            BasicTokenType::Bearer => "Bearer".to_string(),
            BasicTokenType::Mac => "Mac".to_string(),
            // panic の代わりに、未知のトークンタイプの場合はBearerとして扱う
            _ => "Bearer".to_string(),
        }
    }

    fn convert_introspection_response(response: BasicTokenIntrospectionResponse) -> TokenInfo {
        TokenInfo {
            active: response.active(),
            scope: response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            client_id: response.client_id().map(|c| c.to_string()),
            username: response.username().map(|s| s.to_string()),
            exp: response.exp().map(|t| t.timestamp()),
            iat: response.iat().map(|t| t.timestamp()),
            sub: response.sub().map(|s| s.to_string()),
            aud: response
                .aud()
                .and_then(|v| v.first())
                .map(|s| s.to_string()),
            iss: response.iss().map(|s| s.to_string()),
            token_type: response.token_type().map(Self::convert_token_type),
            nbf: response.nbf().map(|t| t.timestamp()),
            jti: response.jti().map(|s| s.to_string()),
        }
    }

    async fn exchange_authentication_token(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> AuthResult<TokenResponse> {
        info!("Exchanging authorization code for token");

        let mut token_request = self
            .oauth_client
            .exchange_code(AuthorizationCode::new(code.to_string()));

        // Setting RedirectUrl
        token_request = token_request.set_redirect_uri(std::borrow::Cow::Owned(
            RedirectUrl::new(redirect_uri.to_string()).map_err(AuthError::RedirectUriError)?,
        ));

        // Add PKCE if code_verifier is provided
        if let Some(verifier) = code_verifier {
            token_request = token_request
                .set_pkce_verifier(oauth2::PkceCodeVerifier::new(verifier.to_string()));
        }

        let token_result = token_request
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::ProviderError(e.to_string()))?;

        Ok(Self::convert_token_response(&token_result))
    }
    async fn exchange_refresh_token(&self, refresh_token: &str) -> AuthResult<TokenResponse> {
        info!("Refreshing token");

        let token_result = self
            .oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::ProviderError(e.to_string()))?;

        Ok(Self::convert_token_response(&token_result))
    }
    async fn introspect_token_internal(&self, token: &str) -> AuthResult<TokenInfo> {
        let access_token = AccessToken::new(token.to_string());

        let introspection_request = self
            .oauth_client
            .introspect(&access_token)
            .map_err(|e| {
                AuthError::ProviderError(format!("Failed to create introspection request: {}", e))
            })?
            .add_extra_param("token_type_hint", "access_token");

        let introspection_result = introspection_request.request_async(async_http_client).await;

        match introspection_result {
            Ok(response) => Ok(Self::convert_introspection_response(response)),
            Err(err) => {
                error!("Token introspection failed: {:?}", err);
                Err(AuthError::ProviderError(err.to_string()))
            }
        }
    }
}
#[async_trait]
impl AuthenticationPort for Auth0Client {
    async fn exchange_token(
        &self,
        grant_type: &str,
        code: Option<&str>,
        refresh_token: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
    ) -> AuthResult<TokenResponse> {

        match grant_type {
            "authorization_code" => {
                let code = code.ok_or(AuthError::InvalidGrant)?;
                let redirect_uri = redirect_uri.ok_or(AuthError::InvalidGrant)?;
                self.exchange_authentication_token(code, redirect_uri, code_verifier)
                    .await
            }
            "refresh_token" => {
                let refresh_token = refresh_token.ok_or(AuthError::InvalidGrant)?;
                self.exchange_refresh_token(refresh_token).await
            }
            _ => Err(AuthError::InvalidGrant),
        }
    }
    async fn introspect_token(
        &self,
        token: &str,
        _token_type_hint: Option<&str>,
    ) -> AuthResult<TokenInfo> {
        self.introspect_token_internal(token).await
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
    type Provider = Auth0Client;

    async fn create_provider(&self) -> AuthResult<Self::Provider> {
        Auth0Client::new(self.config.clone())
    }
}
