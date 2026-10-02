use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub const RESPONSE_TYPE_CODE: &str = "code";
pub const TOKEN_TYPE_BEARER: &str = "bearer";
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";

pub mod path {
    pub const OAUTH_AUTHORIZE: &str = "/oauth/authorize";
    pub const OAUTH_CALLBACK: &str = "/oauth/callback";
    pub const OAUTH_TOKEN: &str = "/oauth/token";
    pub const OAUTH_REVOKE: &str = "/oauth/revoke";
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum PkceCodeChallengeMethod {
    #[serde(rename = "S256")]
    S256,
}

impl PkceCodeChallengeMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

pub fn is_valid_pkce_code_verifier(verifier: &str) -> bool {
    let length = verifier.len();
    (43..=128).contains(&length)
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

pub fn is_valid_pkce_code_challenge(challenge: &str) -> bool {
    let length = challenge.len();
    (43..=128).contains(&length)
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

pub fn pkce_s256_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OAuthAuthorizeResponseType {
    #[serde(rename = "code")]
    Code,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthAuthorizeRequest {
    pub response_type: OAuthAuthorizeResponseType,
    pub client_id: String,
    pub redirect_uri: Url,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: PkceCodeChallengeMethod,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OAuthTokenGrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthTokenRequest {
    pub grant_type: OAuthTokenGrantType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl OAuthTokenRequest {
    pub fn authorization_code(
        client_id: impl Into<String>,
        code: impl Into<String>,
        redirect_uri: Url,
        code_verifier: impl Into<String>,
    ) -> Self {
        Self {
            grant_type: OAuthTokenGrantType::AuthorizationCode,
            client_id: Some(client_id.into()),
            code: Some(code.into()),
            redirect_uri: Some(redirect_uri),
            code_verifier: Some(code_verifier.into()),
            refresh_token: None,
        }
    }

    pub fn refresh_token(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Self {
        Self {
            grant_type: OAuthTokenGrantType::RefreshToken,
            client_id: Some(client_id.into()),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_helper_generates_expected_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(is_valid_pkce_code_verifier(verifier));
        assert_eq!(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            pkce_s256_code_challenge(verifier)
        );
    }

    #[test]
    fn pkce_method_serializes_to_standard_name() {
        let json = serde_json::to_string(&PkceCodeChallengeMethod::S256)
            .expect("pkce method should serialize");
        assert_eq!("\"S256\"", json);
    }

    #[test]
    fn oauth_token_request_serializes_standard_public_client_fields() {
        let request = OAuthTokenRequest::authorization_code(
            "test-client",
            "code-123",
            Url::parse("http://127.0.0.1:7777/callback").expect("url"),
            "verifier-123",
        );

        let json = serde_json::to_string(&request).expect("request should serialize");
        assert!(json.contains("\"grant_type\":\"authorization_code\""));
        assert!(json.contains("\"client_id\":\"test-client\""));
        assert!(json.contains("\"code\":\"code-123\""));
        assert!(json.contains("\"redirect_uri\":\"http://127.0.0.1:7777/callback\""));
        assert!(json.contains("\"code_verifier\":\"verifier-123\""));

        let decoded: OAuthTokenRequest =
            serde_json::from_str(&json).expect("request should deserialize");
        assert_eq!(OAuthTokenGrantType::AuthorizationCode, decoded.grant_type);
        assert_eq!(Some("test-client"), decoded.client_id.as_deref());
        assert_eq!(Some("code-123"), decoded.code.as_deref());
    }
}
