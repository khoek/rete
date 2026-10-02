use anyhow::{Context, bail};
use hmac::{Hmac, KeyInit, Mac};
use rand::{RngExt, distr::Alphanumeric};
use sha2::Sha256;
use std::{convert::TryFrom, sync::Arc};

type HmacSha256 = Hmac<Sha256>;
const REFRESH_SESSION_ID_LEN: usize = 32;
const REFRESH_FAMILY_ID_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueToken {
    value: String,
    id: String,
    verifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueTokenCodec {
    prefix: Arc<str>,
    pepper: Arc<str>,
}

impl OpaqueTokenCodec {
    pub fn new(prefix: impl Into<String>, pepper: impl Into<String>) -> anyhow::Result<Self> {
        let prefix = prefix.into();
        let pepper = pepper.into();
        if prefix.trim().is_empty() || prefix.contains('.') || prefix.contains(char::is_whitespace)
        {
            bail!("opaque token prefix must be non-empty and contain no dots or whitespace");
        }
        if pepper.trim().is_empty() {
            bail!("opaque token pepper must not be empty");
        }
        Ok(Self {
            prefix: Arc::from(prefix),
            pepper: Arc::from(pepper),
        })
    }

    pub fn issue(&self) -> anyhow::Result<OpaqueToken> {
        OpaqueToken::issue(&self.prefix, &self.pepper)
    }

    pub fn parse(&self, value: &str) -> anyhow::Result<Option<OpaqueToken>> {
        OpaqueToken::parse(value, &self.prefix, &self.pepper)
    }
}

impl OpaqueToken {
    fn issue(prefix: &str, pepper: &str) -> anyhow::Result<Self> {
        let id = random_urlsafe_string(24);
        let secret = random_urlsafe_string(48);
        let value = format!("{prefix}.{id}.{secret}");
        Ok(Self {
            verifier: token_verifier(pepper, &value)?,
            value,
            id,
        })
    }

    fn parse(value: &str, expected_prefix: &str, pepper: &str) -> anyhow::Result<Option<Self>> {
        let mut parts = value.split('.');
        let prefix = parts.next();
        let id = parts.next();
        let secret = parts.next();
        if parts.next().is_some() {
            return Ok(None);
        }
        let (Some(prefix), Some(id), Some(secret)) = (prefix, id, secret) else {
            return Ok(None);
        };
        if prefix != expected_prefix || id.is_empty() || secret.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            value: value.to_string(),
            id: id.to_string(),
            verifier: token_verifier(pepper, value)?,
        }))
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenCodec {
    token: OpaqueTokenCodec,
    ttl_seconds: u64,
}

impl RefreshTokenCodec {
    pub fn new(
        token_prefix: impl Into<String>,
        token_pepper: impl Into<String>,
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        if ttl_seconds == 0 {
            bail!("refresh token ttl_seconds must be > 0");
        }
        i64::try_from(ttl_seconds).context("refresh token ttl_seconds exceeds i64")?;
        Ok(Self {
            token: OpaqueTokenCodec::new(token_prefix, token_pepper)?,
            ttl_seconds,
        })
    }

    pub fn issue(&self, now_unix: i64) -> anyhow::Result<IssuedRefreshToken> {
        IssuedRefreshToken::issue(&self.token, now_unix, self.expires_unix(now_unix)?)
    }

    pub fn issue_replacement(
        &self,
        now_unix: i64,
    ) -> anyhow::Result<IssuedRefreshTokenReplacement> {
        IssuedRefreshTokenReplacement::issue(&self.token, now_unix, self.expires_unix(now_unix)?)
    }

    pub fn parse(&self, value: &str) -> anyhow::Result<Option<OpaqueToken>> {
        self.token.parse(value)
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    fn expires_unix(&self, issued_unix: i64) -> anyhow::Result<i64> {
        issued_unix
            .checked_add(
                i64::try_from(self.ttl_seconds).context("refresh token ttl_seconds exceeds i64")?,
            )
            .context("refresh token expiry exceeds i64")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedRefreshTokenReplacement {
    token: OpaqueToken,
    issued_unix: i64,
    expires_unix: i64,
}

impl IssuedRefreshTokenReplacement {
    fn issue(
        token: &OpaqueTokenCodec,
        issued_unix: i64,
        expires_unix: i64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            token: token.issue()?,
            issued_unix,
            expires_unix,
        })
    }

    pub fn token_id(&self) -> &str {
        self.token.id()
    }

    pub fn token_verifier(&self) -> &str {
        self.token.verifier()
    }

    pub fn issued_unix(&self) -> i64 {
        self.issued_unix
    }

    pub fn expires_unix(&self) -> i64 {
        self.expires_unix
    }

    pub fn value(&self) -> &str {
        self.token.value()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedRefreshToken {
    token: OpaqueToken,
    sid: String,
    family_id: String,
    issued_unix: i64,
    expires_unix: i64,
}

impl IssuedRefreshToken {
    fn issue(
        token: &OpaqueTokenCodec,
        issued_unix: i64,
        expires_unix: i64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            token: token.issue()?,
            sid: random_urlsafe_string(REFRESH_SESSION_ID_LEN),
            family_id: random_urlsafe_string(REFRESH_FAMILY_ID_LEN),
            issued_unix,
            expires_unix,
        })
    }

    pub fn token_id(&self) -> &str {
        self.token.id()
    }

    pub fn token_verifier(&self) -> &str {
        self.token.verifier()
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    pub fn issued_unix(&self) -> i64 {
        self.issued_unix
    }

    pub fn expires_unix(&self) -> i64 {
        self.expires_unix
    }

    pub fn value(&self) -> &str {
        self.token.value()
    }
}

pub fn random_urlsafe_string(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn token_verifier(pepper: &str, token: &str) -> anyhow::Result<String> {
    if pepper.trim().is_empty() {
        bail!("refresh token pepper must not be empty");
    }
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes())
        .context("failed to initialize refresh token verifier")?;
    mac.update(token.as_bytes());
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::RefreshTokenCodec;

    #[test]
    fn issued_refresh_token_contains_session_family_and_expiry() {
        let codec = RefreshTokenCodec::new("rt", "test-pepper", 300).expect("token codec");
        let issued = codec.issue(1_000).expect("refresh token should issue");

        assert!(issued.value().starts_with("rt."));
        assert_eq!(32, issued.sid().len());
        assert_eq!(32, issued.family_id().len());
        assert_eq!(1_000, issued.issued_unix());
        assert_eq!(1_300, issued.expires_unix());
        assert_eq!(issued.value(), issued.token.value());
    }

    #[test]
    fn refresh_token_codec_issues_and_parses_tokens() {
        let codec = RefreshTokenCodec::new("rt", "test-pepper", 300).expect("codec");
        let issued = codec.issue(1_000).expect("issued token");
        let parsed = codec
            .parse(issued.value())
            .expect("parse should not fail")
            .expect("token should parse");

        assert_eq!(issued.token_id(), parsed.id());
        assert_eq!(issued.token_verifier(), parsed.verifier());
        assert_eq!(1_300, issued.expires_unix());
    }

    #[test]
    fn refresh_token_codec_issues_replacements_with_rolling_expiry() {
        let codec = RefreshTokenCodec::new("rt", "test-pepper", 300).expect("codec");
        let first = codec.issue_replacement(1_000).expect("first replacement");
        let second = codec.issue_replacement(1_300).expect("second replacement");

        assert_eq!(1_000, first.issued_unix());
        assert_eq!(1_300, first.expires_unix());
        assert_eq!(1_300, second.issued_unix());
        assert_eq!(1_600, second.expires_unix());
        codec
            .issue_replacement(i64::MAX)
            .expect_err("overflowing expiry should fail");
    }
}
