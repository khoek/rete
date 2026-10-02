//! Bounded, non-retrying HTTP forwarding, with optional Cloud Run service authentication.
use axum::{
    body::{Body, to_bytes},
    extract::{OriginalUri, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use url::Url;

#[derive(Clone, Copy, Debug)]
pub enum UpstreamAuthentication {
    None,
    CloudRun,
}

#[derive(Clone, Debug)]
pub struct ProxyOptions {
    pub upstream: Url,
    pub authentication: UpstreamAuthentication,
    pub timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}
impl ProxyOptions {
    pub fn validate(self) -> anyhow::Result<ProxyConfig> {
        anyhow::ensure!(
            matches!(self.upstream.scheme(), "http" | "https")
                && self.upstream.host_str().is_some()
                && self.upstream.path() == "/"
                && self.upstream.query().is_none()
                && self.upstream.fragment().is_none()
                && self.upstream.username().is_empty()
                && self.upstream.password().is_none(),
            "proxy upstream must be an HTTP(S) origin without credentials, path, query, or fragment"
        );
        if matches!(self.authentication, UpstreamAuthentication::CloudRun) {
            anyhow::ensure!(
                self.upstream.scheme() == "https",
                "Cloud Run upstream must use HTTPS"
            );
        }
        anyhow::ensure!(
            !self.timeout.is_zero() && self.max_request_bytes > 0 && self.max_response_bytes > 0,
            "proxy timeout and body limits must be positive"
        );
        Ok(ProxyConfig(self))
    }
}
pub struct ProxyConfig(ProxyOptions);
impl ProxyConfig {
    pub fn connect(self) -> anyhow::Result<HttpProxy> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(self.0.timeout)
            .build()?;
        Ok(HttpProxy {
            inner: Arc::new(ProxyInner {
                options: self.0,
                http,
                token: Mutex::new(None),
            }),
        })
    }
}
#[derive(Clone)]
pub struct HttpProxy {
    inner: Arc<ProxyInner>,
}
struct ProxyInner {
    options: ProxyOptions,
    http: reqwest::Client,
    token: Mutex<Option<(String, u64)>>,
}
impl HttpProxy {
    pub async fn forward(&self, request: Request) -> Response {
        match tokio::time::timeout(self.inner.options.timeout, self.send(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                tracing::warn!(error = ?error, "upstream request failed; mutation outcome may be unknown");
                if error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)
                {
                    (
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream deadline exceeded; mutation outcome may be unknown",
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::BAD_GATEWAY,
                        "upstream request failed; mutation outcome may be unknown",
                    )
                        .into_response()
                }
            }
            Err(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream deadline exceeded; mutation outcome may be unknown",
            )
                .into_response(),
        }
    }
    async fn send(&self, request: Request) -> anyhow::Result<Response> {
        let original = request
            .extensions()
            .get::<OriginalUri>()
            .map(|uri| &uri.0)
            .unwrap_or_else(|| request.uri());
        let uri = original
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        // Concatenate a validated fixed origin, never interpret a request path as another origin.
        let url = format!(
            "{}{}",
            self.inner.options.upstream.as_str().trim_end_matches('/'),
            uri
        );
        let (parts, body) = request.into_parts();
        let body = match to_bytes(body, self.inner.options.max_request_bytes).await {
            Ok(body) => body,
            Err(_) => {
                return Ok((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds proxy limit",
                )
                    .into_response());
            }
        };
        let mut headers = parts.headers;
        strip_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove("x-serverless-authorization");
        if matches!(
            self.inner.options.authentication,
            UpstreamAuthentication::CloudRun
        ) {
            headers.insert(
                "x-serverless-authorization",
                format!("Bearer {}", self.identity_token().await?).parse()?,
            );
        }
        let mut upstream = self
            .inner
            .http
            .request(parts.method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = upstream.status();
        let mut headers = upstream.headers().clone();
        strip_hop_headers(&mut headers);
        let mut body = Vec::new();
        while let Some(chunk) = upstream
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            anyhow::ensure!(
                body.len().saturating_add(chunk.len()) <= self.inner.options.max_response_bytes,
                "upstream response exceeds proxy limit"
            );
            body.extend_from_slice(&chunk);
        }
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }
    async fn identity_token(&self) -> anyhow::Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut cached = self.inner.token.lock().await;
        if let Some((token, expiry)) = cached.as_ref()
            && *expiry > now + 60
        {
            return Ok(token.clone());
        }
        let audience = self.inner.options.upstream.as_str().trim_end_matches('/');
        let token = self.inner.http.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity")
            .header("Metadata-Flavor", "Google").query(&[("audience", audience), ("format", "full")])
            .timeout(Duration::from_secs(5)).send().await?.error_for_status()?.text().await?;
        use base64::Engine;
        let claims = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("metadata returned an invalid identity token"))?;
        #[derive(serde::Deserialize)]
        struct Claims {
            exp: u64,
            aud: String,
        }
        let claims: Claims = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(claims)?,
        )?;
        anyhow::ensure!(
            claims.exp > now + 60 && claims.aud == audience,
            "metadata identity token has invalid audience or expiry"
        );
        *cached = Some((token.clone(), claims.exp));
        Ok(token)
    }
}
fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_string())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        routing::{any, get},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct Backend {
        url: Url,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Backend {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn backend(app: Router) -> Backend {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Backend { url, task }
    }
    fn proxy(url: Url, timeout: Duration, request_limit: usize) -> HttpProxy {
        ProxyOptions {
            upstream: url,
            authentication: UpstreamAuthentication::None,
            timeout,
            max_request_bytes: request_limit,
            max_response_bytes: 1024,
        }
        .validate()
        .unwrap()
        .connect()
        .unwrap()
    }
    #[tokio::test]
    async fn forwarding_preserves_public_uri_credentials_and_response_contract() {
        let backend = backend(Router::new().fallback(any(|request: Request| async move {
            assert_eq!(request.method(), "PUT");
            assert_eq!(
                request.uri(),
                "/v2/namespaces/team/aegis/hosts?cursor=a%2Fb&n=3"
            );
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Bearer application-token"
            );
            assert!(!request.headers().contains_key("x-untrusted-hop"));
            assert!(!request.headers().contains_key("x-serverless-authorization"));
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            assert_eq!(body.as_ref(), b"{\"test\":true}");
            Response::builder()
                .status(StatusCode::CONFLICT)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::SET_COOKIE, "one=1; Secure")
                .header(header::SET_COOKIE, "two=2; Secure")
                .header(header::WWW_AUTHENTICATE, "Bearer")
                .body(Body::from("{\"error\":\"existing host\"}"))
                .unwrap()
        })))
        .await;
        async fn forward(State(proxy): State<HttpProxy>, request: Request) -> Response {
            proxy.forward(request).await
        }
        let router = Router::new().nest(
            "/v2",
            Router::new()
                .route("/namespaces/{*path}", any(forward))
                .with_state(proxy(backend.url.clone(), Duration::from_secs(2), 1024)),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v2/namespaces/team/aegis/hosts?cursor=a%2Fb&n=3")
                    .header(header::AUTHORIZATION, "Bearer application-token")
                    .header(header::CONNECTION, "x-untrusted-hop")
                    .header("x-untrusted-hop", "remove")
                    .header("x-serverless-authorization", "Bearer forged")
                    .body(Body::from("{\"test\":true}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            b"{\"error\":\"existing host\"}"
        );
    }
    #[tokio::test]
    async fn cloud_run_auth_does_not_replace_application_authorization() {
        let backend = backend(Router::new().fallback(any(|request: Request| async move {
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Bearer user-token"
            );
            assert_eq!(
                request.headers()["x-serverless-authorization"],
                "Bearer service-token"
            );
            StatusCode::NO_CONTENT
        })))
        .await;
        // A local HTTP fixture stands in for Cloud Run's HTTPS endpoint. Production validation requires HTTPS.
        let proxy = ProxyConfig(ProxyOptions {
            upstream: backend.url.clone(),
            authentication: UpstreamAuthentication::CloudRun,
            timeout: Duration::from_secs(2),
            max_request_bytes: 1024,
            max_response_bytes: 1024,
        })
        .connect()
        .unwrap();
        *proxy.inner.token.lock().await = Some((
            "service-token".into(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
        ));
        let response = proxy
            .forward(
                Request::builder()
                    .uri("/v2/oauth/token")
                    .header(header::AUTHORIZATION, "Bearer user-token")
                    .header("x-serverless-authorization", "Bearer forged")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
    #[tokio::test]
    async fn redirects_are_returned_and_mutations_are_never_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let backend = backend(Router::new().fallback(any(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(header::LOCATION, "https://identity.example/authorize")
                    .body(Body::empty())
                    .unwrap()
            }
        })))
        .await;
        let response = proxy(backend.url.clone(), Duration::from_secs(2), 1024)
            .forward(
                Request::builder()
                    .method("POST")
                    .uri("/v2/oauth/token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://identity.example/authorize"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn body_limits_and_deadlines_bound_slow_paths() {
        let backend = backend(Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                "late"
            }),
        ))
        .await;
        let proxy = proxy(backend.url.clone(), Duration::from_millis(30), 4);
        let response = proxy
            .forward(
                Request::builder()
                    .uri("/")
                    .body(Body::from("12345"))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response = proxy
            .forward(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
