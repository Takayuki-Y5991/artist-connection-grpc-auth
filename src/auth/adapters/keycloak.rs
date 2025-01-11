use std::borrow::Cow;
use async_trait::async_trait;
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthUrl, ClientId, ClientSecret, TokenUrl, RedirectUrl,
    AuthorizationCode, RefreshToken,
    TokenResponse as OAuth2TokenResponse,
    StandardTokenResponse, EmptyExtraTokenFields,
};
use reqwest::Client as HttpClient;
use tracing::{info, error};

use crate::auth::domain::{AuthError, AuthResult, TokenResponse, TokenInfo};
use crate::auth::ports::AuthenticationPort;
use crate::config::KeycloakConfig;

pub struct KeycloakClient {
    oauth_client: BasicClient,
    http_client: HttpClient,
    config: KeycloakConfig,
}

impl KeycloakClient {
    pub fn new(config: KeycloakConfig) -> AuthResult<Self> {
        let auth_url = format!("{}/realms/{}/protocol/openid-connect/auth",
                               config.auth_server_url, config.realm);
        let token_url = format!("{}/realms/{}/protocol/openid-connect/token",
                                config.auth_server_url, config.realm);

        let oauth_client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(auth_url).map_err(|e| AuthError::ConfigError(e.to_string()))?,
            Some(TokenUrl::new(token_url).map_err(|e| AuthError::ConfigError(e.to_string()))?),
        );

        Ok(Self {
            oauth_client,
            http_client: HttpClient::new(),
            config,
        })
    }

    fn convert_token_response(
        token_result: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>
    ) -> TokenResponse {
        TokenResponse {
            access_token: token_result.access_token().secret().to_string(),
            token_type: token_result.token_type().to_string(),
            expires_in: token_result.expires_in()
                .map(|d| d.as_secs() as i32)
                .unwrap_or(3600),
            refresh_token: token_result.refresh_token()
                .map(|t| t.secret().to_string()),
            id_token: None,
        }
    }

    async fn handle_token_request(
        &self,
        request_fn: impl FnOnce(&BasicClient) -> std::pin::Pin<Box<
            dyn std::future::Future<Output = Result<
                StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
                oauth2::reqwest::Error<reqwest::Error>
            >> + Send
        >>,
        error_context: &str,
    ) -> AuthResult<TokenResponse> {
        let token_result = request_fn(&self.oauth_client)
            .await
            .map_err(|e| {
                error!("{}: {:?}", error_context, e);
                AuthError::ProviderError(e.to_string())
            })?;

        Ok(Self::convert_token_response(&token_result))
    }

    fn setup_token_request(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<impl FnOnce(&BasicClient) -> _, AuthError> {
        let redirect = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| AuthError::InvalidGrant)?;

        let code = AuthorizationCode::new(code.to_string());
        let code_verifier = code_verifier.map(|v| oauth2::PkceCodeVerifier::new(v.to_string()));

        Ok(move |client: &BasicClient| {
            let mut request = client.exchange_code(code);
            request = request.set_redirect_uri(Cow::Owned(redirect));

            if let Some(verifier) = code_verifier {
                request = request.set_pkce_verifier(verifier);
            }

            request.request_async(async_http_client)
        })
    }

    async fn introspect_token_internal(&self, token: &str) -> AuthResult<TokenInfo> {
        let introspect_url = format!(
            "{}/realms/{}/protocol/openid-connect/token/introspect",
            self.config.auth_server_url,
            self.config.realm
        );

        let response = self.http_client
            .post(&introspect_url)
            .form(&[
                ("token", token),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await
            .map_err(|e| AuthError::ProviderError(e.to_string()))?;

        if !response.status().is_success() {
            error!("Introspection failed: {:?}", response.status());
            return Err(AuthError::InvalidToken);
        }

        response.json().await
            .map_err(|e| AuthError::ProviderError(e.to_string()))
    }
}

#[async_trait]
impl AuthenticationPort for KeycloakClient {
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
                let code = code.ok_or_else(|| AuthError::InvalidGrant)?;
                let redirect_uri = redirect_uri.ok_or_else(|| AuthError::InvalidGrant)?;

                info!("Exchanging authorization code for token");

                let request = self.setup_token_request(code, redirect_uri, code_verifier)?;
                self.handle_token_request(request, "Failed to exchange authorization code").await
            }
            "refresh_token" => {
                let refresh_token = refresh_token.ok_or_else(|| AuthError::InvalidGrant)?;

                info!("Refreshing token");

                let request = |client: &BasicClient| {
                    client.exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
                        .request_async(async_http_client)
                };

                self.handle_token_request(request, "Failed to refresh token").await
            }
            _ => Err(AuthError::InvalidGrant),
        }
    }

    async fn introspect_token(
        &self,
        token: &str,
        _token_type_hint: Option<&str>,
    ) -> AuthResult<TokenInfo> {
        info!("Introspecting token");
        self.introspect_token_internal(token).await
    }
}