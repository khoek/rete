//! Configurable identity directories for services using Firestore. No application paths or providers are built in.
use anyhow::Context;
use arche_firestore::*;
use ed25519_dalek::pkcs8::{
    DecodePrivateKey, EncodePrivateKey, EncodePublicKey,
    spki::der::pem::LineEnding as Pkcs8LineEnding,
};
use firestore::{
    FirestoreConsistencySelector, FirestoreTransactionOps, FirestoreWritePrecondition,
};
use getrandom::{SysRng, rand_core::UnwrapErr};
use phylax_core::JwtConfig;
use phylax_core::random_urlsafe_string;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAccessTokenConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredRefreshTokenConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pepper: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct StoredAuthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token: Option<StoredAccessTokenConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<StoredRefreshTokenConfig>,
}

fn generate_api_token_keypair_pem() -> anyhow::Result<(String, String)> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng));
    let private_key_pem = signing_key.to_pkcs8_pem(Pkcs8LineEnding::LF)?.to_string();
    let public_key_pem = signing_key
        .verifying_key()
        .to_public_key_pem(Pkcs8LineEnding::LF)?;
    Ok((private_key_pem, public_key_pem))
}

fn derive_api_token_public_key_pem(private_key_pem: &str) -> anyhow::Result<String> {
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_key_pem)
        .context("parsing identity.access_token.private_key_pem")?;
    Ok(signing_key
        .verifying_key()
        .to_public_key_pem(Pkcs8LineEnding::LF)?)
}

fn derive_api_token_kid(public_key_pem: &str) -> String {
    let digest = Sha256::digest(public_key_pem.as_bytes());
    let mut suffix = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    format!("api-token-{suffix}")
}

#[derive(Clone, Debug)]
pub struct IdentityConfig {
    pub api_token: ApiTokenConfig,
    pub refresh_token: RefreshTokenConfig,
}

fn validate_identity_config(stored: StoredAuthConfig) -> anyhow::Result<IdentityConfig> {
    let access_token = stored.access_token.unwrap_or_default();
    let auth_refresh_token = stored.refresh_token.unwrap_or_default();

    let missing_fields = [
        (
            "identity.issuer_url",
            normalized_text(stored.issuer_url.as_ref()).is_none(),
        ),
        (
            "identity.access_token.private_key_pem",
            normalized_text(access_token.private_key_pem.as_ref()).is_none(),
        ),
        (
            "identity.access_token.public_key_pem",
            normalized_text(access_token.public_key_pem.as_ref()).is_none(),
        ),
        (
            "identity.access_token.kid",
            normalized_text(access_token.kid.as_ref()).is_none(),
        ),
        (
            "identity.access_token.audience",
            normalized_text(access_token.audience.as_ref()).is_none(),
        ),
        (
            "identity.access_token.ttl_seconds",
            access_token.ttl_seconds.unwrap_or(0) == 0,
        ),
        (
            "identity.refresh_token.pepper",
            normalized_text(auth_refresh_token.pepper.as_ref()).is_none(),
        ),
        (
            "identity.refresh_token.ttl_seconds",
            auth_refresh_token.ttl_seconds.unwrap_or(0) == 0,
        ),
    ]
    .into_iter()
    .filter_map(|(field, missing)| missing.then_some(field))
    .collect::<Vec<_>>();

    if !missing_fields.is_empty() {
        anyhow::bail!(
            "Identity config is missing required fields: {}",
            missing_fields.join(", ")
        );
    }

    let private_key_pem = normalized_text(access_token.private_key_pem.as_ref())
        .expect("validated private key should exist");
    let public_key_pem = normalized_text(access_token.public_key_pem.as_ref())
        .expect("validated public key should exist");
    let derived_public_key_pem = derive_api_token_public_key_pem(private_key_pem)?;
    if public_key_pem != derived_public_key_pem.trim() {
        anyhow::bail!("identity.access_token.public_key_pem does not match private_key_pem");
    }

    let config = IdentityConfig {
        api_token: ApiTokenConfig {
            iss: normalized_text(stored.issuer_url.as_ref())
                .expect("validated issuer_url should exist")
                .to_string(),
            private_key_pem: private_key_pem.to_string(),
            public_key_pem: public_key_pem.to_string(),
            kid: normalized_text(access_token.kid.as_ref())
                .expect("validated kid should exist")
                .to_string(),
            audience: normalized_text(access_token.audience.as_ref())
                .expect("validated audience should exist")
                .to_string(),
            ttl_seconds: access_token
                .ttl_seconds
                .expect("validated ttl_seconds should exist"),
        },
        refresh_token: RefreshTokenConfig {
            pepper: normalized_text(auth_refresh_token.pepper.as_ref())
                .expect("validated refresh_token.pepper should exist")
                .to_string(),
            ttl_seconds: auth_refresh_token
                .ttl_seconds
                .expect("validated refresh_token.ttl_seconds should exist"),
        },
    };
    anyhow::ensure!(
        config.api_token.iss.starts_with("https://"),
        "auth issuer must use HTTPS"
    );
    anyhow::ensure!(
        !config.api_token.audience.trim().is_empty(),
        "auth audience must not be empty"
    );
    for ttl in [
        config.api_token.ttl_seconds,
        config.refresh_token.ttl_seconds,
    ] {
        anyhow::ensure!(
            ttl > 0 && i64::try_from(ttl).is_ok(),
            "auth TTL must fit a positive i64"
        );
    }
    Ok(config)
}

#[derive(Clone, Debug)]
pub struct IdentityOptions {
    pub document_path: String,
}

#[derive(Clone, Debug)]
pub struct IdentityLocation {
    document_path: String,
}

impl IdentityOptions {
    pub fn validate(self) -> anyhow::Result<IdentityLocation> {
        let segments = self.document_path.split('/').collect::<Vec<_>>();
        anyhow::ensure!(
            segments.len() >= 2
                && segments.len() % 2 == 0
                && segments
                    .iter()
                    .all(|s| !s.is_empty() && *s != "." && *s != ".."),
            "identity document_path must be a relative Firestore document path"
        );
        Ok(IdentityLocation {
            document_path: self.document_path,
        })
    }
}

impl IdentityLocation {
    pub fn connect(self, db: Db) -> IdentityStore {
        let parent = format!("{}/{}", db.inner().get_documents_path(), self.document_path);
        IdentityStore { db, parent }
    }
}

#[derive(Clone)]
pub struct IdentityStore {
    db: Db,
    parent: String,
}

#[derive(Clone, Debug)]
pub struct IdentityBootstrapOptions {
    pub issuer_url: String,
    pub audience: String,
    pub access_token_ttl_seconds: u64,
    pub refresh_token_ttl_seconds: u64,
}

impl Default for IdentityBootstrapOptions {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            audience: String::new(),
            access_token_ttl_seconds: 300,
            refresh_token_ttl_seconds: 2_592_000,
        }
    }
}

pub struct ValidatedIdentityBootstrap {
    options: IdentityBootstrapOptions,
}

impl IdentityBootstrapOptions {
    pub fn validate(self) -> anyhow::Result<ValidatedIdentityBootstrap> {
        let issuer = url::Url::parse(&self.issuer_url)?;
        anyhow::ensure!(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none(),
            "identity issuer must be an HTTPS URL without credentials, query, or fragment"
        );
        anyhow::ensure!(
            !self.audience.trim().is_empty(),
            "identity audience must not be empty"
        );
        for ttl in [
            self.access_token_ttl_seconds,
            self.refresh_token_ttl_seconds,
        ] {
            anyhow::ensure!(
                ttl > 0 && i64::try_from(ttl).is_ok(),
                "identity TTL must fit a positive i64"
            );
        }
        Ok(ValidatedIdentityBootstrap { options: self })
    }
}

impl ValidatedIdentityBootstrap {
    fn generate(self) -> anyhow::Result<StoredAuthConfig> {
        let options = self.options;
        let (private_key_pem, public_key_pem) = generate_api_token_keypair_pem()?;
        Ok(StoredAuthConfig {
            issuer_url: Some(options.issuer_url),
            access_token: Some(StoredAccessTokenConfig {
                private_key_pem: Some(private_key_pem),
                kid: Some(derive_api_token_kid(&public_key_pem)),
                public_key_pem: Some(public_key_pem),
                audience: Some(options.audience),
                ttl_seconds: Some(options.access_token_ttl_seconds),
            }),
            refresh_token: Some(StoredRefreshTokenConfig {
                pepper: Some(random_urlsafe_string(64)),
                ttl_seconds: Some(options.refresh_token_ttl_seconds),
            }),
        })
    }
}

impl IdentityStore {
    pub fn parent(&self) -> &str {
        &self.parent
    }

    pub async fn load_config(&self) -> anyhow::Result<IdentityConfig> {
        let (parent, document) = self
            .parent
            .rsplit_once('/')
            .expect("validated document path");
        let (parent, collection) = parent.rsplit_once('/').expect("validated collection path");
        let stored = load_optional_typed_at::<StoredAuthConfig>(
            self.db.inner(),
            parent,
            collection,
            document,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("identity config {} is required", self.parent))?;
        validate_identity_config(stored)
    }

    /// Explicit initialization: never changes an existing directory's keys or configuration.
    pub async fn bootstrap(&self, options: ValidatedIdentityBootstrap) -> anyhow::Result<()> {
        let (parent, document) = self.parent.rsplit_once('/').expect("document path");
        let (parent, collection) = parent.rsplit_once('/').expect("collection path");
        if let Some(existing) = load_optional_typed_at::<StoredAuthConfig>(
            self.db.inner(),
            parent,
            collection,
            document,
        )
        .await?
        {
            let existing = validate_identity_config(existing)?;
            anyhow::ensure!(
                existing.api_token.iss == options.options.issuer_url
                    && existing.api_token.audience == options.options.audience
                    && existing.api_token.ttl_seconds == options.options.access_token_ttl_seconds
                    && existing.refresh_token.ttl_seconds
                        == options.options.refresh_token_ttl_seconds,
                "existing identity configuration differs; setup never changes keys or token settings"
            );
            return Ok(());
        }
        create_typed_at(
            self.db.inner(),
            parent,
            collection,
            document,
            &options.generate()?,
        )
        .await
    }

    pub fn auth_store(
        &self,
        config: &IdentityConfig,
        login_session_ttl_seconds: u64,
    ) -> anyhow::Result<crate::FirestoreAuthStore> {
        Ok(crate::FirestoreAuthStore::new(
            self.db.shared(),
            self.parent.clone(),
            crate::FirestoreAuthStoreConfig::new(
                &config.refresh_token.pepper,
                config.refresh_token.ttl_seconds,
                login_session_ttl_seconds,
            )?,
        ))
    }

    pub async fn user(&self, user_id: &str) -> anyhow::Result<Option<UserRecord>> {
        validate_user_id(user_id)?;
        let user = get_stored_obj_at_if_exists::<UserRecord>(
            self.db.inner(),
            &self.parent,
            "users",
            user_id,
        )
        .await?;
        if let Some(user) = &user {
            anyhow::ensure!(user.id == user_id, "user document does not match its id");
        }
        Ok(user)
    }

    pub async fn authorize(
        &self,
        provider: &str,
        provider_sub: &str,
    ) -> anyhow::Result<Option<UserRecord>> {
        let identity = get_stored_obj_at_if_exists::<ExternalIdentity>(
            self.db.inner(),
            &self.parent,
            "identities",
            &external_identity_id(provider, provider_sub),
        )
        .await?;
        let Some(identity) = identity else {
            return Ok(None);
        };
        anyhow::ensure!(
            identity.provider == provider && identity.provider_sub == provider_sub,
            "external identity does not match its provider subject"
        );
        let user = self
            .user(&identity.user_id)
            .await?
            .context("external identity references a missing user")?;
        // Provider subjects, never email addresses, establish identity. Email is display data.
        Ok(Some(user))
    }

    /// Creates a user and binds an external subject in one Firestore transaction.
    /// Existing identities cannot be reassigned by provisioning another user.
    pub async fn create_user(
        &self,
        user: &UserRecord,
        identity: &ExternalIdentity,
    ) -> anyhow::Result<()> {
        validate_user_id(&user.id)?;
        anyhow::ensure!(
            identity.user_id == user.id
                && !identity.provider.is_empty()
                && !identity.provider_sub.is_empty(),
            "invalid external identity"
        );
        let mut tx = self.db.inner().begin_transaction().await?;
        tx.update_object_at(
            &self.parent,
            "users",
            &user.id,
            user,
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tx.update_object_at(
            &self.parent,
            "identities",
            external_identity_id(&identity.provider, &identity.provider_sub),
            identity,
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<()> {
        validate_user_id(user_id)?;
        let mut tx = self.db.inner().begin_transaction().await?;
        let db = self.db.inner().clone_with_consistency_selector(
            FirestoreConsistencySelector::Transaction(tx.transaction_id().clone()),
        );
        let mut user =
            get_stored_obj_at_if_exists::<UserRecord>(&db, &self.parent, "users", user_id)
                .await?
                .context("user does not exist")?;
        anyhow::ensure!(user.id == user_id, "user document does not match its id");
        user.disabled = disabled;
        user.session_version = user
            .session_version
            .checked_add(1)
            .context("session version overflow")?;
        tx.update_object_at(
            &self.parent,
            "users",
            user_id,
            &user,
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentity {
    pub provider: String,
    pub provider_sub: String,
    pub user_id: String,
}

pub fn external_identity_id(provider: &str, provider_sub: &str) -> String {
    use base64::Engine;
    let mut hash = Sha256::new();
    hash.update(provider.as_bytes());
    hash.update(b"\0");
    hash.update(provider_sub.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
}

fn validate_user_id(user_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !user_id.is_empty()
            && !user_id.contains(['/', '@'])
            && !user_id.chars().any(char::is_whitespace),
        "invalid user id"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiTokenConfig {
    /// Public token issuer URL.
    pub iss: String,
    /// PKCS#8 Ed25519 private key in PEM ("BEGIN PRIVATE KEY")
    pub private_key_pem: String,
    /// Public Ed25519 key PEM ("BEGIN PUBLIC KEY")
    pub public_key_pem: String,
    /// kid to stamp on tokens & advertise in JWKS.
    pub kid: String,
    /// Audience stamped on first-party API access tokens.
    pub audience: String,
    /// JWT lifetime in seconds (short; e.g. 300)
    pub ttl_seconds: u64,
}

impl ApiTokenConfig {
    pub fn jwt_config(&self) -> JwtConfig {
        JwtConfig {
            iss: self.iss.clone(),
            private_key_pem: self.private_key_pem.clone(),
            public_key_pem: self.public_key_pem.clone(),
            kid: self.kid.clone(),
            ttl_seconds: self.ttl_seconds,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RefreshTokenConfig {
    pub pepper: String,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub disabled: bool,
    pub session_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_locations_and_bootstrap_are_validated_before_connecting() {
        for path in ["", "/users/a", "a", "a//b/c", "a/../b/c"] {
            assert!(
                IdentityOptions {
                    document_path: path.into()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            IdentityOptions {
                document_path: "tenants/one/auth/config".into()
            }
            .validate()
            .is_ok()
        );
        assert!(IdentityBootstrapOptions::default().validate().is_err());
        let stored = IdentityBootstrapOptions {
            issuer_url: "https://identity.example/v2".into(),
            audience: "example".into(),
            ..Default::default()
        }
        .validate()
        .unwrap()
        .generate()
        .unwrap();
        let config = validate_identity_config(stored).unwrap();
        phylax_core::JwtIssuer::from_config(&config.api_token.jwt_config()).unwrap();
    }
    #[test]
    fn external_subjects_are_scoped_to_the_provider() {
        assert_ne!(
            external_identity_id("https://one.example", "123"),
            external_identity_id("https://two.example", "123")
        );
        assert_ne!(
            external_identity_id("ab", "c"),
            external_identity_id("a", "bc")
        );
    }
}
