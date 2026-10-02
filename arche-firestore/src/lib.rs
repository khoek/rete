use anyhow::Context;
use firestore::{
    FirestoreDb, FirestoreDbOptions, FirestoreDocument, FirestoreValue, FirestoreWritePrecondition,
    errors::FirestoreError,
};
use gcloud_sdk::{BoxSource, Source, Token, TokenSourceType};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;

pub fn deserialize_stored_document<T>(document: &FirestoreDocument) -> Result<T, FirestoreError>
where
    T: DeserializeOwned,
{
    // Firestore's typed decoder injects `_firestore_*` document metadata into the
    // Serde map. Domain records are intentionally strict, so decode only persisted fields.
    let fields = FirestoreValue::from_map(
        document
            .fields
            .iter()
            .map(|(name, value)| (name, FirestoreValue::from(value.clone()))),
    );
    T::deserialize(fields).map_err(|error| match error {
        FirestoreError::DeserializeError(error) => {
            FirestoreError::DeserializeError(error.with_document_path(document.name.clone()))
        }
        error => error,
    })
}

pub async fn get_stored_obj_at_if_exists<T>(
    db: &FirestoreDb,
    parent: &str,
    collection: &str,
    document_id: &str,
) -> Result<Option<T>, FirestoreError>
where
    T: DeserializeOwned,
{
    db.fluent()
        .select()
        .by_id_in(collection)
        .parent(parent)
        .one(document_id)
        .await?
        .map(|document| deserialize_stored_document(&document))
        .transpose()
}

#[derive(Clone)]
pub struct Db(Arc<FirestoreDb>);

pub enum Credentials {
    ApplicationDefault,
    AccessToken(String),
}

pub struct DatabaseOptions {
    pub project_id: Option<String>,
    pub database_id: String,
    pub credentials: Credentials,
    pub connect_timeout: std::time::Duration,
}
impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            project_id: None,
            database_id: "(default)".into(),
            credentials: Credentials::ApplicationDefault,
            connect_timeout: std::time::Duration::from_secs(30),
        }
    }
}
pub struct DatabaseConfig(DatabaseOptions);
impl DatabaseOptions {
    pub fn from_env() -> Self {
        Self {
            project_id: std::env::var("GOOGLE_CLOUD_PROJECT").ok(),
            database_id: std::env::var("FIRESTORE_DATABASE_ID")
                .unwrap_or_else(|_| "(default)".into()),
            ..Self::default()
        }
    }
    pub fn validate(self) -> anyhow::Result<DatabaseConfig> {
        if let Some(project) = &self.project_id {
            anyhow::ensure!(
                !project.is_empty()
                    && project
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
                "invalid Firestore project id"
            );
        }
        anyhow::ensure!(
            self.database_id == "(default)"
                || (!self.database_id.is_empty()
                    && self
                        .database_id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
            "invalid Firestore database id"
        );
        anyhow::ensure!(
            !self.connect_timeout.is_zero(),
            "database connection timeout must be positive"
        );
        if let Credentials::AccessToken(token) = &self.credentials {
            anyhow::ensure!(!token.trim().is_empty(), "access token is empty");
        }
        Ok(DatabaseConfig(self))
    }
}
impl DatabaseConfig {
    pub async fn connect(self) -> anyhow::Result<Db> {
        let timeout = self.0.connect_timeout;
        tokio::time::timeout(timeout, async {
            let options = match self.0.project_id {
                Some(project) => FirestoreDbOptions::new(project),
                None => FirestoreDbOptions::for_default_project_id()
                    .await
                    .context("GCP project id not detected; set GOOGLE_CLOUD_PROJECT")?,
            }
            .with_database_id(self.0.database_id);
            let db = match self.0.credentials {
                Credentials::ApplicationDefault => FirestoreDb::with_options(options).await?,
                Credentials::AccessToken(access_token) => {
                    let source: BoxSource = Box::new(StaticAccessTokenSource { access_token });
                    FirestoreDb::with_options_token_source(
                        options,
                        gcloud_sdk::GCP_DEFAULT_SCOPES.clone(),
                        TokenSourceType::ExternalSource(source),
                    )
                    .await?
                }
            };
            Ok::<_, anyhow::Error>(Db::from_firestore(db))
        })
        .await
        .context("Firestore connection deadline exceeded")?
    }
}
impl Db {
    pub fn from_firestore(db: FirestoreDb) -> Self {
        Self(Arc::new(db))
    }
    pub fn shared(&self) -> Arc<FirestoreDb> {
        self.0.clone()
    }
    pub fn inner(&self) -> &FirestoreDb {
        &self.0
    }
}

struct StaticAccessTokenSource {
    access_token: String,
}

#[async_trait::async_trait]
impl Source for StaticAccessTokenSource {
    async fn token(&self) -> gcloud_sdk::error::Result<Token> {
        Ok(Token::new(
            "Bearer".to_string(),
            secret_vault_value::SecretValue::from(self.access_token.clone()),
            firestore::FirestoreInstant::now()
                .checked_add(firestore::jiff::SignedDuration::from_secs(30 * 60))
                .expect("valid token expiry"),
        ))
    }
}

pub async fn load_optional_typed<T: DeserializeOwned>(
    db: &FirestoreDb,
    collection: &str,
    doc: &str,
) -> anyhow::Result<Option<T>> {
    load_optional_typed_at(db, db.get_documents_path(), collection, doc).await
}

pub async fn load_optional_typed_at<T: DeserializeOwned>(
    db: &FirestoreDb,
    parent: &str,
    collection: &str,
    doc: &str,
) -> anyhow::Result<Option<T>> {
    get_stored_obj_at_if_exists::<T>(db, parent, collection, doc)
        .await
        .with_context(|| format!("loading document {parent}/{collection}/{doc}"))
}

pub async fn create_typed<T>(
    db: &FirestoreDb,
    collection: &str,
    doc: &str,
    value: &T,
) -> anyhow::Result<()>
where
    T: Serialize + DeserializeOwned + Sync + Send,
{
    create_typed_at(db, db.get_documents_path(), collection, doc, value).await
}

pub async fn create_typed_at<T>(
    db: &FirestoreDb,
    parent: &str,
    collection: &str,
    doc: &str,
    value: &T,
) -> anyhow::Result<()>
where
    T: Serialize + DeserializeOwned + Sync + Send,
{
    db.fluent()
        .update()
        .in_col(collection)
        .precondition(FirestoreWritePrecondition::Exists(false))
        .document_id(doc)
        .parent(parent)
        .object(value)
        .execute::<()>()
        .await?;

    Ok(())
}

pub fn normalized_text(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn is_firestore_data_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<FirestoreError>()
        .is_some_and(|error| matches!(error, FirestoreError::DataConflictError(_)))
}

pub fn should_retry_bootstrap_conflict(
    error: &anyhow::Error,
    doc_path: &str,
    attempt: usize,
) -> bool {
    if !is_firestore_data_conflict(error) || attempt + 1 >= CONFIG_BOOTSTRAP_MAX_RETRIES {
        return false;
    }

    tracing::warn!(
        attempt = attempt + 1,
        doc_path,
        "Firestore bootstrap write conflicted; reloading and retrying"
    );
    true
}

pub const CONFIG_BOOTSTRAP_MAX_RETRIES: usize = 8;
