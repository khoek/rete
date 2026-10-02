use crate::{
    JwtIssuer, RefreshTokenValidation, ScopeSet, Subject, oauth,
    oauth::{PkceCodeChallengeMethod, is_valid_pkce_code_challenge, is_valid_pkce_code_verifier},
    random_urlsafe_string,
};
use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    extract::{
        Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, future::Future, sync::Arc};
use time::OffsetDateTime;
use url::Url;

#[derive(Clone)]
pub struct AuthorizationCodeOAuthEndpoint<S, P, A> {
    store: S,
    provider: P,
    policy: A,
    issuer: Arc<JwtIssuer>,
    config: AuthorizationCodeOAuthConfig,
}

impl<S, P, A> AuthorizationCodeOAuthEndpoint<S, P, A> {
    pub fn new(
        store: S,
        provider: P,
        policy: A,
        issuer: Arc<JwtIssuer>,
        config: AuthorizationCodeOAuthConfig,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self {
            store,
            provider,
            policy,
            issuer,
            config,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationCodeOAuthConfig {
    pub public_client_id: String,
    pub login_session_ttl_seconds: u64,
    pub authorization_code_ttl_seconds: u64,
    pub state_max_len: usize,
}

impl AuthorizationCodeOAuthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.public_client_id.trim().is_empty() {
            anyhow::bail!("OAuth public_client_id must not be empty");
        }
        if self.login_session_ttl_seconds == 0 {
            anyhow::bail!("OAuth login_session_ttl_seconds must be > 0");
        }
        if self.authorization_code_ttl_seconds == 0 {
            anyhow::bail!("OAuth authorization_code_ttl_seconds must be > 0");
        }
        i64::try_from(self.login_session_ttl_seconds)
            .map_err(|_| anyhow::anyhow!("OAuth login_session_ttl_seconds exceeds i64"))?;
        i64::try_from(self.authorization_code_ttl_seconds)
            .map_err(|_| anyhow::anyhow!("OAuth authorization_code_ttl_seconds exceeds i64"))?;
        if self.state_max_len == 0 {
            anyhow::bail!("OAuth state_max_len must be > 0");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthLoginSession {
    pub client_id: String,
    pub state: String,
    pub pkce_challenge: String,
    pub pkce_challenge_method: PkceCodeChallengeMethod,
    pub provider_session_state: String,
    pub redirect_uri: String,
    pub created_unix: i64,
    pub expires_unix: i64,
}

impl OAuthLoginSession {
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_unix
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthAuthorizationCode {
    pub token_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub provider_sub: String,
    pub principal: String,
    pub pkce_challenge: String,
    pub pkce_challenge_method: PkceCodeChallengeMethod,
    pub created_unix: i64,
    pub expires_unix: i64,
}

impl OAuthAuthorizationCode {
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_unix
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthAuthorizationCodeExchange {
    pub provider_sub: String,
    pub principal: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthAuthorizationCodeExchangeRequest<'a> {
    pub code_id: &'a str,
    pub expected_token_verifier: &'a str,
    pub expected_client_id: &'a str,
    pub expected_redirect_uri: &'a str,
    pub expected_pkce_challenge: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthRefreshTokenIssueRequest<'a> {
    pub client_id: &'a str,
    pub provider_sub: &'a str,
    pub principal: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthRefreshTokenRotation {
    pub sid: String,
    pub provider_sub: String,
    pub principal: String,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthVerifiedIdentity {
    pub provider_sub: String,
    pub principal: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthProviderAuthorizationRequest {
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthProviderAuthorization {
    pub url: String,
    pub session_state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthProviderCodeExchangeRequest {
    pub code: String,
    pub session_state: String,
}

#[derive(Clone, Debug)]
pub struct OAuthAccessGrant<E> {
    pub subject: Subject,
    pub client_id: String,
    pub audience: Vec<String>,
    pub scope: ScopeSet,
    pub extra: E,
}

#[derive(Debug)]
pub enum OAuthAccessGrantError {
    AccessDenied(anyhow::Error),
    Internal(anyhow::Error),
}

impl OAuthAccessGrantError {
    pub fn access_denied(error: anyhow::Error) -> Self {
        Self::AccessDenied(error)
    }

    pub fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl From<anyhow::Error> for OAuthAccessGrantError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthAuthorizationCodeIssueRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub provider_sub: &'a str,
    pub principal: &'a str,
    pub pkce_challenge: &'a str,
    pub pkce_challenge_method: PkceCodeChallengeMethod,
    pub now_unix: i64,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthIssuedAuthorizationCode {
    pub code: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthAuthorizationCodeGrantRequest<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthRefreshTokenGrantRequest<'a> {
    pub refresh_token: &'a str,
    pub client_id: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug)]
pub struct OAuthCommittedRefreshTokenGrant<E> {
    pub access_grant: OAuthAccessGrant<E>,
    pub sid: String,
    pub refresh_token: String,
    pub refresh_expires_unix: i64,
}

#[derive(Debug)]
pub enum OAuthGrantError {
    AccessDenied(anyhow::Error),
    Internal(anyhow::Error),
}

impl OAuthGrantError {
    pub fn access_denied(error: anyhow::Error) -> Self {
        Self::AccessDenied(error)
    }

    pub fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

#[async_trait]
pub trait AuthorizationCodeOAuthStore: Clone + Send + Sync + 'static {
    async fn put_login_session(&self, sid: &str, session: OAuthLoginSession) -> anyhow::Result<()>;

    async fn take_login_session(&self, sid: &str) -> anyhow::Result<Option<OAuthLoginSession>>;

    async fn prune_expired_login_sessions(&self, now_unix: i64) -> anyhow::Result<usize>;

    async fn issue_authorization_code(
        &self,
        request: OAuthAuthorizationCodeIssueRequest<'_>,
    ) -> anyhow::Result<OAuthIssuedAuthorizationCode>;

    async fn exchange_authorization_code<E, F, Fut>(
        &self,
        request: OAuthAuthorizationCodeGrantRequest<'_>,
        authorize: F,
    ) -> Result<Option<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: FnOnce(OAuthVerifiedIdentity) -> Fut + Send,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send;

    async fn exchange_refresh_token<E, F, Fut>(
        &self,
        request: OAuthRefreshTokenGrantRequest<'_>,
        authorize: F,
    ) -> Result<RefreshTokenValidation<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: Fn(OAuthVerifiedIdentity) -> Fut + Clone + Send + Sync,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send;
}

#[async_trait]
pub trait AuthorizationCodeOAuthProvider: Clone + Send + Sync + 'static {
    fn authorization_url(
        &self,
        request: OAuthProviderAuthorizationRequest,
    ) -> anyhow::Result<OAuthProviderAuthorization>;

    async fn exchange_code(
        &self,
        request: OAuthProviderCodeExchangeRequest,
    ) -> anyhow::Result<OAuthVerifiedIdentity>;
}

#[async_trait]
pub trait AuthorizationCodeOAuthPolicy: Clone + Send + Sync + 'static {
    type Extra: Serialize + Send + Sync + 'static;

    fn validate_redirect_uri(&self, redirect_uri: &Url) -> anyhow::Result<()>;

    async fn access_grant(
        &self,
        identity: &OAuthVerifiedIdentity,
    ) -> Result<OAuthAccessGrant<Self::Extra>, OAuthAccessGrantError>;
}

#[derive(Debug, Deserialize)]
pub struct OAuthAuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: PkceCodeChallengeMethod,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthTokenFormRequest {
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug)]
enum OAuthTokenGrantRequest {
    AuthorizationCode {
        client_id: String,
        code: String,
        redirect_uri: String,
        code_verifier: String,
    },
    RefreshToken {
        client_id: String,
        refresh_token: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct OAuthTokenSuccess<E> {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<u64>,
    #[serde(flatten)]
    pub extra: E,
}

#[derive(Debug)]
pub struct OAuthEndpointError {
    status: StatusCode,
    error: &'static str,
    description: Option<String>,
}

impl OAuthEndpointError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: Some(message.into()),
        }
    }

    fn unauthorized_client(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "unauthorized_client",
            description: Some(message.into()),
        }
    }

    fn invalid_grant(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: Some(message.into()),
        }
    }

    fn unsupported_grant_type(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "unsupported_grant_type",
            description: Some(message.into()),
        }
    }

    fn access_denied(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: "access_denied",
            description: Some(message.into()),
        }
    }

    fn server_error(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: Some(message.into()),
        }
    }
}

#[derive(Debug, Serialize)]
struct OAuthEndpointErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl IntoResponse for OAuthEndpointError {
    fn into_response(self) -> Response {
        (
            self.status,
            [
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (PRAGMA, HeaderValue::from_static("no-cache")),
            ],
            Json(OAuthEndpointErrorBody {
                error: self.error,
                error_description: self.description,
            }),
        )
            .into_response()
    }
}

pub fn authorization_code_oauth_router<S, P, A>(
    authorize_path: &'static str,
    callback_path: &'static str,
    token_path: &'static str,
    endpoint: AuthorizationCodeOAuthEndpoint<S, P, A>,
) -> Router
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    Router::new()
        .route(authorize_path, get(get_authorize::<S, P, A>))
        .route(callback_path, get(get_callback::<S, P, A>))
        .route(token_path, post(post_token::<S, P, A>))
        .with_state(endpoint)
}

pub fn authorization_code_oauth_router_without_callback<S, P, A>(
    authorize_path: &'static str,
    token_path: &'static str,
    endpoint: AuthorizationCodeOAuthEndpoint<S, P, A>,
) -> Router
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    Router::new()
        .route(authorize_path, get(get_authorize::<S, P, A>))
        .route(token_path, post(post_token::<S, P, A>))
        .with_state(endpoint)
}

async fn get_authorize<S, P, A>(
    State(state): State<AuthorizationCodeOAuthEndpoint<S, P, A>>,
    query: Result<Query<OAuthAuthorizeQuery>, QueryRejection>,
) -> Result<Redirect, OAuthEndpointError>
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    let Query(query) =
        query.map_err(|error| OAuthEndpointError::invalid_request(error.body_text()))?;
    validate_authorize_query(&state.config, &state.policy, &query)?;

    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let sid = random_urlsafe_string(32);
    let provider_authorization = state
        .provider
        .authorization_url(OAuthProviderAuthorizationRequest { state: sid.clone() })
        .map_err(|error| OAuthEndpointError::server_error(error.to_string()))?;
    state
        .store
        .put_login_session(
            &sid,
            OAuthLoginSession {
                client_id: query.client_id,
                state: query.state,
                pkce_challenge: query.code_challenge,
                pkce_challenge_method: query.code_challenge_method,
                provider_session_state: provider_authorization.session_state,
                redirect_uri: query.redirect_uri,
                created_unix: now_unix,
                expires_unix: expires_unix(
                    now_unix,
                    state.config.login_session_ttl_seconds,
                    "OAuth login session",
                )?,
            },
        )
        .await
        .map_err(|error| OAuthEndpointError::server_error(error.to_string()))?;
    if let Err(error) = state.store.prune_expired_login_sessions(now_unix).await {
        tracing::warn!(error = ?error, "failed to prune expired OAuth login sessions");
    }

    Ok(Redirect::to(&provider_authorization.url))
}

async fn get_callback<S, P, A>(
    State(state): State<AuthorizationCodeOAuthEndpoint<S, P, A>>,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Redirect, OAuthEndpointError>
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    let Query(query) =
        query.map_err(|error| OAuthEndpointError::invalid_request(error.body_text()))?;
    state.callback(query).await
}

impl<S, P, A> AuthorizationCodeOAuthEndpoint<S, P, A>
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    pub async fn callback(
        &self,
        query: OAuthCallbackQuery,
    ) -> Result<Redirect, OAuthEndpointError> {
        let session = self
            .store
            .take_login_session(&query.state)
            .await
            .map_err(|error| OAuthEndpointError::server_error(error.to_string()))?
            .ok_or_else(|| OAuthEndpointError::invalid_request("invalid state"))?;
        let now_unix = OffsetDateTime::now_utc().unix_timestamp();
        if session.is_expired_at(now_unix) {
            return Err(OAuthEndpointError::invalid_request(format!(
                "expired state (max age {} seconds)",
                self.config.login_session_ttl_seconds
            )));
        }

        if let Some(error) = query.error.as_deref() {
            return Ok(Redirect::to(
                build_redirect_with_error(
                    &session.redirect_uri,
                    &session.state,
                    error,
                    query.error_description.as_deref(),
                )?
                .as_str(),
            ));
        }

        let identity = self
            .provider
            .exchange_code(OAuthProviderCodeExchangeRequest {
                code: query
                    .code
                    .ok_or_else(|| OAuthEndpointError::invalid_request("missing code"))?,
                session_state: session.provider_session_state.clone(),
            })
            .await
            .map_err(|error| OAuthEndpointError::invalid_grant(error.to_string()))?;

        let issued_code = self
            .store
            .issue_authorization_code(OAuthAuthorizationCodeIssueRequest {
                client_id: &session.client_id,
                redirect_uri: &session.redirect_uri,
                provider_sub: &identity.provider_sub,
                principal: &identity.principal,
                pkce_challenge: &session.pkce_challenge,
                pkce_challenge_method: session.pkce_challenge_method,
                now_unix,
                expires_unix: expires_unix(
                    now_unix,
                    self.config.authorization_code_ttl_seconds,
                    "OAuth authorization code",
                )?,
            })
            .await
            .map_err(|error| OAuthEndpointError::server_error(error.to_string()))?;

        Ok(Redirect::to(
            build_redirect_with_code(&session.redirect_uri, &session.state, &issued_code.code)?
                .as_str(),
        ))
    }
}

async fn post_token<S, P, A>(
    State(state): State<AuthorizationCodeOAuthEndpoint<S, P, A>>,
    form: Result<Form<OAuthTokenFormRequest>, FormRejection>,
) -> Result<Response, OAuthEndpointError>
where
    S: AuthorizationCodeOAuthStore,
    P: AuthorizationCodeOAuthProvider,
    A: AuthorizationCodeOAuthPolicy,
{
    let Form(req) = form.map_err(|error| OAuthEndpointError::invalid_request(error.body_text()))?;
    match parse_token_grant(req, &state.config.public_client_id)? {
        OAuthTokenGrantRequest::AuthorizationCode {
            client_id,
            code,
            redirect_uri,
            code_verifier,
        } => {
            let now_unix = OffsetDateTime::now_utc().unix_timestamp();
            let policy = state.policy.clone();
            let grant = state
                .store
                .exchange_authorization_code(
                    OAuthAuthorizationCodeGrantRequest {
                        code: &code,
                        client_id: &client_id,
                        redirect_uri: &redirect_uri,
                        code_verifier: &code_verifier,
                        now_unix,
                    },
                    |identity| async move { policy.access_grant(&identity).await },
                )
                .await
                .map_err(map_oauth_grant_error)?
                .ok_or_else(|| {
                    OAuthEndpointError::invalid_grant(
                        "invalid, expired, or already-used authorization code",
                    )
                })?;
            let signed = sign_oauth_access(&state.issuer, grant.access_grant, &grant.sid)?;
            token_success_response(
                &state.issuer,
                signed,
                Some(&grant.refresh_token),
                Some(grant.refresh_expires_unix),
                now_unix,
            )
        }
        OAuthTokenGrantRequest::RefreshToken {
            client_id,
            refresh_token,
        } => {
            let now_unix = OffsetDateTime::now_utc().unix_timestamp();
            let policy = state.policy.clone();
            let grant = match state
                .store
                .exchange_refresh_token(
                    OAuthRefreshTokenGrantRequest {
                        refresh_token: &refresh_token,
                        client_id: &client_id,
                        now_unix,
                    },
                    move |identity| {
                        let policy = policy.clone();
                        async move { policy.access_grant(&identity).await }
                    },
                )
                .await
                .map_err(map_oauth_grant_error)?
            {
                RefreshTokenValidation::Valid(grant) => grant,
                RefreshTokenValidation::Invalid => {
                    return Err(OAuthEndpointError::invalid_grant(
                        "invalid, expired, or already-used refresh token",
                    ));
                }
            };
            let signed = sign_oauth_access(&state.issuer, grant.access_grant, &grant.sid)?;
            token_success_response(
                &state.issuer,
                signed,
                Some(&grant.refresh_token),
                Some(grant.refresh_expires_unix),
                now_unix,
            )
        }
    }
}

fn map_oauth_grant_error(error: OAuthGrantError) -> OAuthEndpointError {
    match error {
        OAuthGrantError::AccessDenied(error) => {
            OAuthEndpointError::access_denied(error.to_string())
        }
        OAuthGrantError::Internal(error) => OAuthEndpointError::server_error(error.to_string()),
    }
}

fn validate_authorize_query<A>(
    config: &AuthorizationCodeOAuthConfig,
    policy: &A,
    query: &OAuthAuthorizeQuery,
) -> Result<(), OAuthEndpointError>
where
    A: AuthorizationCodeOAuthPolicy,
{
    if query.response_type != oauth::RESPONSE_TYPE_CODE {
        return Err(OAuthEndpointError::invalid_request(
            "response_type must be code",
        ));
    }
    if query.client_id != config.public_client_id {
        return Err(OAuthEndpointError::unauthorized_client(
            "unknown oauth client_id",
        ));
    }
    let redirect_uri = Url::parse(&query.redirect_uri)
        .map_err(|_| OAuthEndpointError::invalid_request("redirect_uri must be a valid URL"))?;
    policy
        .validate_redirect_uri(&redirect_uri)
        .map_err(|error| OAuthEndpointError::invalid_request(error.to_string()))?;
    validate_state(&query.state, config.state_max_len)?;
    if query.code_challenge_method != PkceCodeChallengeMethod::S256 {
        return Err(OAuthEndpointError::invalid_request(
            "code_challenge_method must be S256",
        ));
    }
    if !is_valid_pkce_code_challenge(&query.code_challenge) {
        return Err(OAuthEndpointError::invalid_request(
            "invalid code_challenge",
        ));
    }
    Ok(())
}

fn validate_state(state: &str, max_len: usize) -> Result<(), OAuthEndpointError> {
    if state.is_empty() || state.len() > max_len {
        return Err(OAuthEndpointError::invalid_request(format!(
            "state must be 1-{max_len} characters"
        )));
    }
    if state.chars().any(char::is_control) {
        return Err(OAuthEndpointError::invalid_request(
            "state contains control characters",
        ));
    }
    Ok(())
}

fn parse_token_grant(
    req: OAuthTokenFormRequest,
    expected_client_id: &str,
) -> Result<OAuthTokenGrantRequest, OAuthEndpointError> {
    match req.grant_type.as_deref() {
        Some(oauth::GRANT_TYPE_AUTHORIZATION_CODE) => {
            if req.refresh_token.is_some() {
                return Err(OAuthEndpointError::invalid_request(
                    "refresh_token is not valid for authorization_code",
                ));
            }
            let client_id = require_client_id(req.client_id, expected_client_id)?;
            let code = require_nonempty_field(req.code, "code")?;
            let redirect_uri = require_nonempty_field(req.redirect_uri, "redirect_uri")?;
            let code_verifier = require_nonempty_field(req.code_verifier, "code_verifier")?;
            if !is_valid_pkce_code_verifier(&code_verifier) {
                return Err(OAuthEndpointError::invalid_request("invalid code_verifier"));
            }
            Ok(OAuthTokenGrantRequest::AuthorizationCode {
                client_id,
                code,
                redirect_uri,
                code_verifier,
            })
        }
        Some(oauth::GRANT_TYPE_REFRESH_TOKEN) => {
            if req.code.is_some() || req.code_verifier.is_some() || req.redirect_uri.is_some() {
                return Err(OAuthEndpointError::invalid_request(
                    "code, code_verifier, and redirect_uri are not valid for refresh_token",
                ));
            }
            Ok(OAuthTokenGrantRequest::RefreshToken {
                client_id: require_client_id(req.client_id, expected_client_id)?,
                refresh_token: require_nonempty_field(req.refresh_token, "refresh_token")?,
            })
        }
        Some(other) => Err(OAuthEndpointError::unsupported_grant_type(format!(
            "unsupported grant_type `{other}`"
        ))),
        None => Err(OAuthEndpointError::invalid_request(
            "grant_type is required",
        )),
    }
}

fn require_client_id(
    client_id: Option<String>,
    expected_client_id: &str,
) -> Result<String, OAuthEndpointError> {
    let client_id = client_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| OAuthEndpointError::invalid_request("client_id is required"))?;
    if client_id == expected_client_id {
        Ok(client_id)
    } else {
        Err(OAuthEndpointError::unauthorized_client(
            "unknown oauth client_id",
        ))
    }
}

fn require_nonempty_field(
    value: Option<String>,
    name: &'static str,
) -> Result<String, OAuthEndpointError> {
    value
        .filter(|candidate| !candidate.trim().is_empty())
        .ok_or_else(|| OAuthEndpointError::invalid_request(format!("{name} is required")))
}

fn token_success_response<E>(
    issuer: &JwtIssuer,
    signed: SignedOAuthAccess<E>,
    refresh_token: Option<&str>,
    refresh_expires_unix: Option<i64>,
    now_unix: i64,
) -> Result<Response, OAuthEndpointError>
where
    E: Serialize + Send + Sync + 'static,
{
    Ok((
        StatusCode::OK,
        [
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (PRAGMA, HeaderValue::from_static("no-cache")),
        ],
        Json(OAuthTokenSuccess {
            access_token: signed.access_token,
            token_type: oauth::TOKEN_TYPE_BEARER.to_string(),
            expires_in: issuer.access_token_ttl_seconds(),
            refresh_token: refresh_token.map(str::to_string),
            refresh_expires_in: refresh_expires_unix
                .map(|expires_unix| expires_unix.saturating_sub(now_unix).max(0) as u64),
            extra: signed.extra,
        }),
    )
        .into_response())
}

struct SignedOAuthAccess<E> {
    access_token: String,
    extra: E,
}

fn sign_oauth_access<E>(
    issuer: &JwtIssuer,
    grant: OAuthAccessGrant<E>,
    sid: &str,
) -> Result<SignedOAuthAccess<E>, OAuthEndpointError>
where
    E: Serialize + Send + Sync + 'static,
{
    Ok(SignedOAuthAccess {
        access_token: issuer
            .sign_access(
                grant.subject,
                &grant.client_id,
                grant.audience,
                grant.scope,
                Some(sid.to_string()),
            )
            .map_err(|error| OAuthEndpointError::server_error(error.to_string()))?,
        extra: grant.extra,
    })
}

fn build_redirect_with_code(
    redirect_uri: &str,
    state: &str,
    code: &str,
) -> Result<Url, OAuthEndpointError> {
    let mut dest = Url::parse(redirect_uri)
        .map_err(|_| OAuthEndpointError::invalid_request("invalid stored redirect_uri"))?;
    {
        let mut qp = dest.query_pairs_mut();
        qp.append_pair("code", code);
        qp.append_pair("state", state);
    }
    Ok(dest)
}

fn build_redirect_with_error(
    redirect_uri: &str,
    state: &str,
    error: &str,
    error_description: Option<&str>,
) -> Result<Url, OAuthEndpointError> {
    let mut dest = Url::parse(redirect_uri)
        .map_err(|_| OAuthEndpointError::invalid_request("invalid stored redirect_uri"))?;
    {
        let mut qp = dest.query_pairs_mut();
        qp.append_pair("error", error);
        qp.append_pair("state", state);
        if let Some(description) = error_description.filter(|value| !value.is_empty()) {
            qp.append_pair("error_description", description);
        }
    }
    Ok(dest)
}

fn expires_unix(now_unix: i64, ttl_seconds: u64, label: &str) -> Result<i64, OAuthEndpointError> {
    let ttl_seconds = i64::try_from(ttl_seconds)
        .map_err(|_| OAuthEndpointError::server_error(format!("{label} TTL exceeds i64")))?;
    now_unix
        .checked_add(ttl_seconds)
        .ok_or_else(|| OAuthEndpointError::server_error(format!("{label} expiry exceeds i64")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_CLIENT_ID: &str = "test-tool";

    #[derive(Clone)]
    struct TestPolicy;

    #[async_trait]
    impl AuthorizationCodeOAuthPolicy for TestPolicy {
        type Extra = serde_json::Value;

        fn validate_redirect_uri(&self, redirect_uri: &Url) -> anyhow::Result<()> {
            if redirect_uri.scheme() == "http" && redirect_uri.host_str() == Some("127.0.0.1") {
                Ok(())
            } else {
                anyhow::bail!("redirect_uri must be loopback http")
            }
        }

        async fn access_grant(
            &self,
            _identity: &OAuthVerifiedIdentity,
        ) -> Result<OAuthAccessGrant<Self::Extra>, OAuthAccessGrantError> {
            unreachable!("not used by these tests")
        }
    }

    fn test_config() -> AuthorizationCodeOAuthConfig {
        AuthorizationCodeOAuthConfig {
            public_client_id: TEST_PUBLIC_CLIENT_ID.to_string(),
            login_session_ttl_seconds: 600,
            authorization_code_ttl_seconds: 120,
            state_max_len: 512,
        }
    }

    #[test]
    fn endpoint_config_rejects_invalid_invariants() {
        let mut config = test_config();
        config.public_client_id.clear();
        config
            .validate()
            .expect_err("empty client id should be rejected");

        let mut config = test_config();
        config.login_session_ttl_seconds = 0;
        config
            .validate()
            .expect_err("zero login session TTL should be rejected");

        let mut config = test_config();
        config.authorization_code_ttl_seconds = 0;
        config
            .validate()
            .expect_err("zero authorization-code TTL should be rejected");

        let mut config = test_config();
        config.state_max_len = 0;
        config
            .validate()
            .expect_err("zero state max length should be rejected");
    }

    #[test]
    fn validates_authorize_query_policy_and_pkce() {
        validate_authorize_query(
            &test_config(),
            &TestPolicy,
            &OAuthAuthorizeQuery {
                response_type: oauth::RESPONSE_TYPE_CODE.to_string(),
                client_id: TEST_PUBLIC_CLIENT_ID.to_string(),
                redirect_uri: "http://127.0.0.1:7777/callback".to_string(),
                state: "client-state".to_string(),
                code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789-._~"
                    .to_string(),
                code_challenge_method: PkceCodeChallengeMethod::S256,
            },
        )
        .expect("valid query should pass");
    }

    #[test]
    fn parse_token_grant_rejects_invalid_refresh_request_shape() {
        let error = parse_token_grant(
            OAuthTokenFormRequest {
                grant_type: Some(oauth::GRANT_TYPE_REFRESH_TOKEN.to_string()),
                client_id: Some(TEST_PUBLIC_CLIENT_ID.to_string()),
                code: Some("ac.one.two".to_string()),
                redirect_uri: None,
                code_verifier: None,
                refresh_token: Some("rt.one.two".to_string()),
            },
            TEST_PUBLIC_CLIENT_ID,
        )
        .expect_err("refresh request with code should fail");
        assert_eq!("invalid_request", error.error);
    }

    #[test]
    fn redirect_builders_preserve_oauth_state() {
        let with_code = build_redirect_with_code(
            "http://127.0.0.1:7777/callback",
            "client-state",
            "ac.123.secret",
        )
        .expect("redirect should build");
        assert_eq!(
            Some("ac.123.secret"),
            with_code
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.into_owned())
                .as_deref()
        );

        let with_error = build_redirect_with_error(
            "http://127.0.0.1:7777/callback",
            "client-state",
            "access_denied",
            Some("provider canceled"),
        )
        .expect("redirect should build");
        assert_eq!(
            Some("access_denied"),
            with_error
                .query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned())
                .as_deref()
        );
    }
}
