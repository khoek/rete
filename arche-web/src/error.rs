#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}
use axum::{Json, http::StatusCode, response::IntoResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Unavailable(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })).into_response()
            }
            ApiError::Conflict(msg) => {
                (StatusCode::CONFLICT, Json(ErrorResponse { error: msg })).into_response()
            }
            ApiError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, Json(ErrorResponse { error: msg })).into_response()
            }
            ApiError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: msg })).into_response()
            }
            ApiError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, Json(ErrorResponse { error: msg })).into_response()
            }
            ApiError::Unavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse { error: msg }),
            )
                .into_response(),
            ApiError::Internal(e) => {
                tracing::error!(error = ?e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "internal error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}
