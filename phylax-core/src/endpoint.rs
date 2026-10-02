use crate::{JwtIssuer, ScopeSet, Subject, oauth};
use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    extract::{
        State,
        rejection::{FormRejection, JsonRejection},
    },
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA},
    },
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone)]
pub struct JsonRefreshTokenEndpoint<G> {
    grant: G,
}

impl<G> JsonRefreshTokenEndpoint<G> {
    pub fn new(grant: G) -> Self {
        Self { grant }
    }
}

#[derive(Clone)]
pub struct FormRevokeTokenEndpoint<G> {
    grant: G,
}

impl<G> FormRevokeTokenEndpoint<G> {
    pub fn new(grant: G) -> Self {
        Self { grant }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRefreshTokenRequest {
    pub grant_type: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FormRevokeTokenRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRefreshTokenResponse<E> {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_expires_in: u64,
    #[serde(flatten)]
    pub extra: E,
}

#[derive(Clone, Copy, Debug)]
pub struct RefreshTokenValidationRequest<'a> {
    pub token_id: &'a str,
    pub expected_token_verifier: &'a str,
    pub expected_client_id: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshTokenValidation<T> {
    Valid(T),
    Invalid,
}

#[derive(Clone, Debug)]
pub struct RefreshTokenRotationRequest<'a> {
    pub token_id: &'a str,
    pub expected_token_verifier: &'a str,
    pub expected_client_id: &'a str,
    pub next_token_id: &'a str,
    pub next_token_verifier: &'a str,
    pub next_expires_unix: i64,
    pub now_unix: i64,
}

#[derive(Clone, Debug)]
pub struct AccessTokenGrant<E> {
    pub subject: Subject,
    pub client_id: String,
    pub audience: Vec<String>,
    pub scope: ScopeSet,
    pub sid: Option<String>,
    pub refresh_expires_unix: i64,
    pub extra: E,
}

#[derive(Clone, Copy, Debug)]
pub struct JsonRefreshTokenGrantRequest<'a> {
    pub refresh_token: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug)]
pub struct JsonRefreshTokenExchange<E> {
    pub access_grant: AccessTokenGrant<E>,
    pub refresh_token: String,
}

#[async_trait]
pub trait JsonRefreshTokenGrant: Clone + Send + Sync + 'static {
    type Extra: Serialize + Send + Sync + 'static;

    fn issuer(&self) -> Arc<JwtIssuer>;

    async fn exchange_refresh_token(
        &self,
        request: JsonRefreshTokenGrantRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<JsonRefreshTokenExchange<Self::Extra>>>;
}

#[async_trait]
pub trait FormRevokeTokenGrant: Clone + Send + Sync + 'static {
    async fn revoke_refresh_token(&self, token: &str) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub struct TokenEndpointError {
    status: StatusCode,
    error: &'static str,
    description: Option<String>,
}

impl TokenEndpointError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: Some(message.into()),
        }
    }

    fn invalid_grant(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_grant",
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

    fn unsupported_token_type(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "unsupported_token_type",
            description: Some(message.into()),
        }
    }
}

#[derive(Debug, Serialize)]
struct TokenEndpointErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl IntoResponse for TokenEndpointError {
    fn into_response(self) -> Response {
        (
            self.status,
            [
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (PRAGMA, HeaderValue::from_static("no-cache")),
            ],
            Json(TokenEndpointErrorBody {
                error: self.error,
                error_description: self.description,
            }),
        )
            .into_response()
    }
}

pub fn json_refresh_token_router<G>(path: &'static str, grant: G) -> Router
where
    G: JsonRefreshTokenGrant,
{
    Router::new()
        .route(path, post(post_json_refresh_token::<G>))
        .with_state(JsonRefreshTokenEndpoint::new(grant))
}

pub fn form_revoke_token_router<G>(path: &'static str, grant: G) -> Router
where
    G: FormRevokeTokenGrant,
{
    Router::new()
        .route(path, post(post_form_revoke_token::<G>))
        .with_state(FormRevokeTokenEndpoint::new(grant))
}

async fn post_json_refresh_token<G>(
    State(state): State<JsonRefreshTokenEndpoint<G>>,
    json: Result<Json<JsonRefreshTokenRequest>, JsonRejection>,
) -> Result<Response, TokenEndpointError>
where
    G: JsonRefreshTokenGrant,
{
    let Json(req) = json.map_err(|error| TokenEndpointError::invalid_request(error.body_text()))?;
    if req.grant_type != oauth::GRANT_TYPE_REFRESH_TOKEN {
        return Err(TokenEndpointError::invalid_request(
            "grant_type must be refresh_token",
        ));
    }
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let exchange = match state
        .grant
        .exchange_refresh_token(JsonRefreshTokenGrantRequest {
            refresh_token: &req.refresh_token,
            now_unix,
        })
        .await
        .map_err(|error| TokenEndpointError::server_error(error.to_string()))?
    {
        RefreshTokenValidation::Valid(exchange) => exchange,
        RefreshTokenValidation::Invalid => {
            return Err(TokenEndpointError::invalid_grant("invalid refresh token"));
        }
    };

    let issuer = state.grant.issuer();
    let grant = exchange.access_grant;
    let access_token = issuer
        .sign_access(
            grant.subject,
            &grant.client_id,
            grant.audience,
            grant.scope,
            grant.sid,
        )
        .map_err(|error| TokenEndpointError::server_error(error.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (PRAGMA, HeaderValue::from_static("no-cache")),
        ],
        Json(JsonRefreshTokenResponse {
            access_token,
            token_type: oauth::TOKEN_TYPE_BEARER.to_string(),
            expires_in: issuer.access_token_ttl_seconds(),
            refresh_token: exchange.refresh_token,
            refresh_expires_in: grant.refresh_expires_unix.saturating_sub(now_unix).max(0) as u64,
            extra: grant.extra,
        }),
    )
        .into_response())
}

async fn post_form_revoke_token<G>(
    State(state): State<FormRevokeTokenEndpoint<G>>,
    form: Result<Form<FormRevokeTokenRequest>, FormRejection>,
) -> Result<Response, TokenEndpointError>
where
    G: FormRevokeTokenGrant,
{
    let Form(req) = form.map_err(|error| TokenEndpointError::invalid_request(error.body_text()))?;
    if let Some(hint) = req.token_type_hint.as_deref()
        && !matches!(hint, "refresh_token" | "access_token")
    {
        return Err(TokenEndpointError::unsupported_token_type(format!(
            "unsupported token_type_hint `{hint}`"
        )));
    }
    state
        .grant
        .revoke_refresh_token(&req.token)
        .await
        .map_err(|error| TokenEndpointError::server_error(error.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (PRAGMA, HeaderValue::from_static("no-cache")),
        ],
    )
        .into_response())
}
