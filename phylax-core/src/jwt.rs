use crate::{AccessClaims, ScopeSet, Subject, random_urlsafe_string};
use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use std::convert::TryFrom;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub iss: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
    pub kid: String,
    pub ttl_seconds: u64,
}

#[derive(Clone)]
pub struct JwtKeys {
    enc: EncodingKey,
    dec: DecodingKey,
    kid: String,
    ttl: Duration,
    ttl_seconds: u64,
}

#[derive(Clone)]
pub struct JwtIssuer {
    pub issuer: String,
    keys: Arc<JwtKeys>,
}

impl JwtIssuer {
    pub fn from_config(cfg: &JwtConfig) -> anyhow::Result<Self> {
        if cfg.iss.trim().is_empty() {
            anyhow::bail!("JWT iss must not be empty");
        }
        if cfg.kid.trim().is_empty() {
            anyhow::bail!("JWT kid must not be empty");
        }
        if cfg.ttl_seconds == 0 {
            anyhow::bail!("JWT ttl_seconds must be > 0");
        }
        let ttl_seconds = i64::try_from(cfg.ttl_seconds).context("JWT ttl_seconds exceeds i64")?;
        let enc = EncodingKey::from_ed_pem(cfg.private_key_pem.as_bytes())
            .context("loading Ed25519 private key PEM for JWT")?;
        let dec = DecodingKey::from_ed_pem(cfg.public_key_pem.as_bytes())
            .context("loading Ed25519 public key PEM for JWT")?;
        let issuer = Self {
            issuer: cfg.iss.clone(),
            keys: Arc::new(JwtKeys {
                enc,
                dec,
                kid: cfg.kid.clone(),
                ttl: Duration::seconds(ttl_seconds),
                ttl_seconds: cfg.ttl_seconds,
            }),
        };
        issuer
            .verify_keypair()
            .context("JWT signing keypair self-test failed")?;
        Ok(issuer)
    }

    pub fn access_token_ttl_seconds(&self) -> u64 {
        self.keys.ttl_seconds
    }

    pub fn kid(&self) -> &str {
        &self.keys.kid
    }

    pub fn sign_access(
        &self,
        subject: Subject,
        client_id: &str,
        audience: impl IntoIterator<Item = impl Into<String>>,
        scope: ScopeSet,
        sid: Option<String>,
    ) -> anyhow::Result<String> {
        let now = OffsetDateTime::now_utc();
        let exp = now
            .checked_add(self.keys.ttl)
            .context("JWT access token expiry exceeds representable timestamp")?
            .unix_timestamp();
        self.encode(&AccessClaims {
            iss: self.issuer.clone(),
            sub: subject,
            aud: audience.into_iter().map(Into::into).collect(),
            exp,
            iat: now.unix_timestamp(),
            jti: random_urlsafe_string(24),
            client_id: client_id.to_string(),
            scope,
            sid,
            authorized_party: Some(client_id.to_string()),
        })
    }

    fn encode<T>(&self, claims: &T) -> anyhow::Result<String>
    where
        T: serde::Serialize,
    {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.keys.kid.clone());
        header.typ = Some("at+jwt".to_string());
        Ok(jsonwebtoken::encode(&header, claims, &self.keys.enc)?)
    }

    pub fn validator(&self, audience: &str) -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[audience]);
        validation
    }

    pub fn decode_access(&self, token: &str, audience: &str) -> anyhow::Result<AccessClaims> {
        let data =
            jsonwebtoken::decode::<AccessClaims>(token, &self.keys.dec, &self.validator(audience))?;
        Ok(data.claims)
    }

    fn verify_keypair(&self) -> anyhow::Result<()> {
        let audience = "phylax-key-self-test";
        let subject = Subject::new("service:phylax-key-self-test")?;
        let token = self.sign_access(
            subject.clone(),
            "phylax-key-self-test",
            [audience],
            ScopeSet::new(["phylax:self-test"])?,
            None,
        )?;
        let claims = self.decode_access(&token, audience)?;
        if claims.sub != subject {
            anyhow::bail!("JWT signing keypair self-test decoded an unexpected subject");
        }
        Ok(())
    }
}

pub fn decode_unverified_claims<T>(token: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    Ok(jsonwebtoken::dangerous::insecure_decode::<T>(token)?.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ISSUER_URL: &str = "https://issuer.example";
    const TEST_JWT_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJrDacL3YbnqbSgqln/U3xQDJecnkbomYj2epYq1kOrs\n-----END PRIVATE KEY-----\n";
    const TEST_JWT_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAKs4Q7xlLOlFhkhFnJixaYKFlK0AK1R6pMizMX68Ujcw=\n-----END PUBLIC KEY-----\n";
    const OTHER_JWT_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAo6uPyy4T89mHsvAb1mlFTEcOanXSz0ZtisC+wsXNlHg=\n-----END PUBLIC KEY-----\n";

    fn test_issuer() -> JwtIssuer {
        JwtIssuer::from_config(&JwtConfig {
            iss: TEST_ISSUER_URL.to_string(),
            private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            kid: "test-kid".to_string(),
            ttl_seconds: 300,
        })
        .expect("test issuer config should be valid")
    }

    #[test]
    fn access_token_round_trips() {
        let issuer = test_issuer();
        let token = issuer
            .sign_access(
                Subject::new("principal:example").expect("subject"),
                "client",
                ["api.example"],
                ScopeSet::new(["read", "write"]).expect("scopes"),
                Some("sid".to_string()),
            )
            .expect("token should sign");

        let claims = issuer
            .decode_access(&token, "api.example")
            .expect("token should decode");

        assert_eq!("principal:example", claims.sub.as_str());
        assert_eq!("client", claims.client_id);
        assert!(claims.has_scope("read"));
        assert_eq!(Some("sid"), claims.sid.as_deref());
    }

    #[test]
    fn config_rejects_mismatched_keypair() {
        let issuer = JwtIssuer::from_config(&JwtConfig {
            iss: TEST_ISSUER_URL.to_string(),
            private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            public_key_pem: OTHER_JWT_PUBLIC_KEY_PEM.to_string(),
            kid: "test-kid".to_string(),
            ttl_seconds: 300,
        });

        assert!(issuer.is_err());
    }
}
