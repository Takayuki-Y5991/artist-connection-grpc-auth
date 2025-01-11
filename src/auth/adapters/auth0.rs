use async_trait::async_trait;
use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl, ClientId, ClientSecret, TokenUrl, RedirectUrl,
    AuthorizationCode, RefreshToken, AccessToken,
    TokenResponse as OAuth2TokenResponse,
};
use reqwest::Client as HttpClient;
use tracing::{info, error};

use crate::auth::domain::{AuthError, AuthResult, TokenResponse, TokenInfo};
use crate::auth::ports::AuthenticationPort;
use crate::config::Auth0Config;

pub struct Auth0Client {
    oauth_client: BasicClient,
    http_client: HttpClient,
    config: Auth0Config,
}

impl Auth0Client {
    pub fn new(config: Auth0Config) -> AuthResult<Self> {
        let auth_url = format!("https://{}/authorize", config.domain);
        let token_url = format!("https://{}/oauth/token", config.domain);

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

    fn convert_token_response<RT>(
        token_result: &impl OAuth2TokenResponse<RT>
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

    async fn introspect_token_internal(&self, token: &str) -> AuthResult<TokenInfo> {
        let introspect_url = format!("https://{}/oauth/introspect", self.config.domain);

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

        let info: TokenInfo = response
            .json()
            .await
            .map_err(|e| AuthError::ProviderError(e.to_string()))?;

        Ok(info)
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
                let code = code.ok_or_else(|| AuthError::InvalidGrant)?;
                let redirect_uri = redirect_uri.ok_or_else(|| AuthError::InvalidGrant)?;

                info!("Exchanging authorization code for token");

                let mut token_request = self.oauth_client
                    .exchange_code(AuthorizationCode::new(code.to_string()));

                // RedirectUrlを設定
                if let Ok(redirect) = RedirectUrl::new(redirect_uri.to_string()) {
                    token_request = token_request.set_redirect_uri(std::borrow::Cow::Owned(redirect));
                }

                // Add PKCE if code_verifier is provided
                if let Some(verifier) = code_verifier {
                    token_request = token_request.set_pkce_verifier(
                        oauth2::PkceCodeVerifier::new(verifier.to_string())
                    );
                }

                let token_result = token_request
                    .request(async_http_client)
                    .await
                    .map_err(|e| AuthError::ProviderError(e.to_string()))?;

                Ok(Self::convert_token_response(&token_result))
            }
            "refresh_token" => {
                let refresh_token = refresh_token.ok_or_else(|| AuthError::InvalidGrant)?;

                info!("Refreshing token");

                let token_result = self.oauth_client
                    .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
                    .request(async_http_client)
                    .await
                    .map_err(|e| AuthError::ProviderError(e.to_string()))?;

                Ok(Self::convert_token_response(&token_result))
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