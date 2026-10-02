//! Small HTTP service runtime shared by independently deployed services.
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, time::Duration};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct ServiceOptions {
    pub listen: SocketAddr,
    pub request_timeout: Duration,
}
impl Default for ServiceOptions {
    fn default() -> Self {
        Self {
            listen: ([0, 0, 0, 0], 8080).into(),
            request_timeout: Duration::from_secs(240),
        }
    }
}
pub struct ServiceConfig {
    options: ServiceOptions,
}
impl ServiceOptions {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut options = Self::default();
        if let Ok(port) = std::env::var("PORT") {
            options.listen.set_port(port.parse()?);
        }
        Ok(options)
    }
    pub fn validate(self) -> anyhow::Result<ServiceConfig> {
        anyhow::ensure!(
            !self.request_timeout.is_zero(),
            "request timeout must be positive"
        );
        Ok(ServiceConfig { options: self })
    }
}
pub fn initialize() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS provider is already installed"))?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()?;
    Ok(())
}
pub fn response_headers(app: Router) -> Router {
    app.layer(SetResponseHeaderLayer::overriding(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    ))
}
async fn deadline(State(timeout): State<Duration>, request: Request, next: Next) -> Response {
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "request deadline exceeded").into_response(),
    }
}
pub async fn serve(config: ServiceConfig, app: Router) -> anyhow::Result<()> {
    let app = response_headers(
        app.layer(middleware::from_fn_with_state(config.options.request_timeout, deadline))
            .layer(TraceLayer::new_for_http().make_span_with(|request: &Request| {
                tracing::info_span!("request", method = %request.method(), path = request.uri().path())
            })),
    );
    let listener = tokio::net::TcpListener::bind(config.options.listen).await?;
    tracing::info!(address = %listener.local_addr()?, "HTTP service listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            tracing::info!("shutdown requested; draining active requests");
        })
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;
    #[tokio::test]
    async fn errors_are_not_cacheable() {
        let response = response_headers(Router::new())
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store, max-age=0"
        );
    }
}
