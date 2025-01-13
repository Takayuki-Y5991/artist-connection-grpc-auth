use crate::auth::domain::{AuthResult, TokenInfo, TokenResponse};
use async_trait::async_trait;

#[async_trait]
pub trait AuthenticationPort: Send + Sync {
    /// 認可コードをトークンと交換
    async fn exchange_token(
        &self,
        grant_type: &str,
        code: Option<&str>,
        refresh_token: Option<&str>,
        redirect_uri: Option<&str>,
        code_verifier: Option<&str>,
    ) -> AuthResult<TokenResponse>;
    /// トークンの検証（イントロスペクション）
    async fn introspect_token(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> AuthResult<TokenInfo>;
}

#[async_trait]
pub trait AuthProviderFactory {
    type Provider: AuthenticationPort;

    async fn create_provider(&self) -> AuthResult<Self::Provider>;
}
