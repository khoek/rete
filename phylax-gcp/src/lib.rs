pub mod identity;

use firestore::{
    FirestoreConsistencySelector, FirestoreDb, FirestoreTransactionOps, FirestoreWritePrecondition,
    errors::FirestoreError,
};
use phylax_core::{
    AuthorizationCodeOAuthStore, OAuthAccessGrant, OAuthAccessGrantError, OAuthAuthorizationCode,
    OAuthAuthorizationCodeExchange, OAuthAuthorizationCodeExchangeRequest,
    OAuthAuthorizationCodeGrantRequest, OAuthAuthorizationCodeIssueRequest,
    OAuthCommittedRefreshTokenGrant, OAuthGrantError, OAuthIssuedAuthorizationCode,
    OAuthLoginSession, OAuthRefreshTokenGrantRequest, OAuthRefreshTokenIssueRequest,
    OAuthVerifiedIdentity, RefreshTokenValidation, Subject,
    backend::{
        IssuedRefreshToken, OpaqueTokenCodec, RefreshTokenCodec, RefreshTokenRotationRequest,
    },
    oauth::{PkceCodeChallengeMethod, pkce_s256_code_challenge},
};
use reqwest::blocking::Client as BlockingHttpClient;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{convert::TryFrom, future::Future, sync::Arc};

const AUTH_SESSION_PRUNE_BATCH: u32 = 64;
const TRANSACTION_MAX_ATTEMPTS: usize = 5;
const AUTH_OAUTH_COLLECTION: &str = "oauth";
const AUTH_OAUTH_CONFIG_DOC: &str = "config";
const AUTH_OAUTH_FLOWS_COLLECTION: &str = "flows";
const AUTH_OAUTH_AUTHORIZATION_CODE_FLOW_DOC: &str = "authorization_code";
const AUTH_OAUTH_LOGIN_SESSIONS_COLLECTION: &str = "login_sessions";
const AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION: &str = "codes";
const AUTH_GRANTS_COLLECTION: &str = "grants";
const AUTH_REFRESH_TOKENS_COLLECTION: &str = "refresh_tokens";
const AUTHORIZATION_CODE_TOKEN_PREFIX: &str = "ac";
const REFRESH_TOKEN_PREFIX: &str = "rt";

#[derive(Clone, Debug)]
pub struct FirestoreAuthStoreConfig {
    authorization_code_tokens: OpaqueTokenCodec,
    refresh_tokens: RefreshTokenCodec,
    login_session_ttl_seconds: i64,
}

impl FirestoreAuthStoreConfig {
    pub fn new(
        refresh_token_pepper: impl Into<String>,
        refresh_token_ttl_seconds: u64,
        login_session_ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        let refresh_token_pepper = refresh_token_pepper.into();
        let login_session_ttl_seconds =
            checked_positive_i64_ttl(login_session_ttl_seconds, "OAuth login session")?;
        Ok(Self {
            authorization_code_tokens: OpaqueTokenCodec::new(
                AUTHORIZATION_CODE_TOKEN_PREFIX,
                refresh_token_pepper.clone(),
            )?,
            refresh_tokens: RefreshTokenCodec::new(
                REFRESH_TOKEN_PREFIX,
                refresh_token_pepper,
                refresh_token_ttl_seconds,
            )?,
            login_session_ttl_seconds,
        })
    }

    pub fn with_codecs(
        authorization_code_tokens: OpaqueTokenCodec,
        refresh_tokens: RefreshTokenCodec,
        login_session_ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            authorization_code_tokens,
            refresh_tokens,
            login_session_ttl_seconds: checked_positive_i64_ttl(
                login_session_ttl_seconds,
                "OAuth login session",
            )?,
        })
    }
}

#[derive(Clone)]
pub struct FirestoreAuthStore {
    db: Arc<FirestoreDb>,
    parent: String,
    authorization_code_tokens: OpaqueTokenCodec,
    refresh_tokens: RefreshTokenCodec,
    login_session_ttl_seconds: i64,
}

impl FirestoreAuthStore {
    pub fn new(
        db: Arc<FirestoreDb>,
        parent: impl Into<String>,
        config: FirestoreAuthStoreConfig,
    ) -> Self {
        Self {
            db,
            parent: parent.into(),
            authorization_code_tokens: config.authorization_code_tokens,
            refresh_tokens: config.refresh_tokens,
            login_session_ttl_seconds: config.login_session_ttl_seconds,
        }
    }

    fn oauth_parent(&self) -> String {
        format!(
            "{}/{}/{}",
            self.parent, AUTH_OAUTH_COLLECTION, AUTH_OAUTH_CONFIG_DOC
        )
    }

    fn oauth_authorization_code_flow_parent(&self) -> String {
        format!(
            "{}/{}/{}",
            self.oauth_parent(),
            AUTH_OAUTH_FLOWS_COLLECTION,
            AUTH_OAUTH_AUTHORIZATION_CODE_FLOW_DOC
        )
    }

    async fn put_login_session(&self, sid: &str, sess: OAuthLoginSession) -> anyhow::Result<()> {
        self.db
            .fluent()
            .insert()
            .into(AUTH_OAUTH_LOGIN_SESSIONS_COLLECTION)
            .document_id(sid)
            .parent(self.oauth_authorization_code_flow_parent())
            .object(&AuthSessionRecord::try_from_session(sess)?)
            .execute::<()>()
            .await?;
        Ok(())
    }

    async fn take_login_session(&self, sid: &str) -> anyhow::Result<Option<OAuthLoginSession>> {
        self.retry_transaction("take login session", || async {
            let mut tx = self.db.begin_transaction().await?;
            let tx_db = self.tx_db(&tx);
            let session = tx_db
                .fluent()
                .select()
                .by_id_in(AUTH_OAUTH_LOGIN_SESSIONS_COLLECTION)
                .parent(self.oauth_authorization_code_flow_parent())
                .obj::<AuthSessionRecord>()
                .one(sid)
                .await?;
            let Some(session) = session else {
                tx.rollback().await.ok();
                return Ok(None);
            };
            tx.delete_by_id_at(
                &self.oauth_authorization_code_flow_parent(),
                AUTH_OAUTH_LOGIN_SESSIONS_COLLECTION,
                sid,
                Some(FirestoreWritePrecondition::Exists(true)),
            )?;
            tx.commit().await?;
            Ok(Some(session.into_session(self.login_session_ttl_seconds)))
        })
        .await
    }

    async fn prune_expired_login_sessions(&self, now_unix: i64) -> anyhow::Result<usize> {
        let cutoff = now_unix.saturating_sub(self.login_session_ttl_seconds);
        let docs = self
            .db
            .fluent()
            .select()
            .from(AUTH_OAUTH_LOGIN_SESSIONS_COLLECTION)
            .parent(self.oauth_authorization_code_flow_parent())
            .filter(|q| q.for_all([q.field("created_unix").less_than(cutoff)]))
            .limit(AUTH_SESSION_PRUNE_BATCH)
            .query()
            .await?;

        let mut deleted = 0usize;
        for doc in docs {
            let Some(doc_id) = firestore_document_id(&doc.name) else {
                tracing::warn!(
                    document_name = doc.name,
                    "skipping auth session prune for malformed document name"
                );
                continue;
            };

            if let Err(error) = self.take_login_session(doc_id).await {
                tracing::warn!(doc_id, error = ?error, "failed to prune expired auth session");
                continue;
            }

            deleted += 1;
        }

        Ok(deleted)
    }

    async fn put_authorization_code(
        &self,
        code_id: &str,
        code: OAuthAuthorizationCode,
    ) -> anyhow::Result<()> {
        self.db
            .fluent()
            .insert()
            .into(AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION)
            .document_id(code_id)
            .parent(self.oauth_authorization_code_flow_parent())
            .object(&AuthorizationCodeRecord::try_from_code(code)?)
            .execute::<()>()
            .await?;
        Ok(())
    }

    async fn issue_authorization_code(
        &self,
        request: OAuthAuthorizationCodeIssueRequest<'_>,
    ) -> anyhow::Result<OAuthIssuedAuthorizationCode> {
        let token = self.authorization_code_tokens.issue()?;
        self.put_authorization_code(
            token.id(),
            OAuthAuthorizationCode {
                token_verifier: token.verifier().to_string(),
                client_id: request.client_id.to_string(),
                redirect_uri: request.redirect_uri.to_string(),
                provider_sub: request.provider_sub.to_string(),
                principal: request.principal.to_string(),
                pkce_challenge: request.pkce_challenge.to_string(),
                pkce_challenge_method: request.pkce_challenge_method,
                created_unix: request.now_unix,
                expires_unix: request.expires_unix,
            },
        )
        .await?;
        Ok(OAuthIssuedAuthorizationCode {
            code: token.value().to_string(),
        })
    }

    async fn validate_authorization_code(
        &self,
        request: OAuthAuthorizationCodeExchangeRequest<'_>,
    ) -> anyhow::Result<Option<OAuthAuthorizationCodeExchange>> {
        let Some(record) = self
            .db
            .fluent()
            .select()
            .by_id_in(AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION)
            .parent(self.oauth_authorization_code_flow_parent())
            .obj::<AuthorizationCodeRecord>()
            .one(request.code_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(authorization_code_exchange_from_record(&record, &request))
    }

    async fn exchange_oauth_authorization_code<E, F, Fut>(
        &self,
        request: OAuthAuthorizationCodeGrantRequest<'_>,
        authorize: F,
    ) -> Result<Option<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: FnOnce(OAuthVerifiedIdentity) -> Fut + Send,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send,
    {
        let Some(parsed) = self
            .authorization_code_tokens
            .parse(request.code)
            .map_err(OAuthGrantError::internal)?
        else {
            return Ok(None);
        };
        let expected_pkce_challenge = pkce_s256_code_challenge(request.code_verifier);
        let exchange = OAuthAuthorizationCodeExchangeRequest {
            code_id: parsed.id(),
            expected_token_verifier: parsed.verifier(),
            expected_client_id: request.client_id,
            expected_redirect_uri: request.redirect_uri,
            expected_pkce_challenge: &expected_pkce_challenge,
            now_unix: request.now_unix,
        };
        let Some(identity) = self
            .validate_authorization_code(exchange)
            .await
            .map_err(OAuthGrantError::internal)?
            .map(|code| OAuthVerifiedIdentity {
                provider_sub: code.provider_sub,
                principal: code.principal,
            })
        else {
            return Ok(None);
        };
        let access_grant = match authorize(identity.clone()).await {
            Ok(access_grant) => access_grant,
            Err(OAuthAccessGrantError::AccessDenied(error)) => {
                if self
                    .consume_authorization_code(exchange)
                    .await
                    .map_err(OAuthGrantError::internal)?
                {
                    return Err(OAuthGrantError::access_denied(error));
                }
                return Ok(None);
            }
            Err(OAuthAccessGrantError::Internal(error)) => {
                return Err(OAuthGrantError::internal(error));
            }
        };
        let refresh = self
            .refresh_tokens
            .issue(request.now_unix)
            .map_err(OAuthGrantError::internal)?;

        if !self
            .exchange_authorization_code_and_issue_oauth_refresh_token(
                exchange,
                OAuthRefreshTokenIssueRequest {
                    client_id: request.client_id,
                    provider_sub: &identity.provider_sub,
                    principal: &identity.principal,
                    now_unix: request.now_unix,
                },
                &refresh,
            )
            .await
            .map_err(OAuthGrantError::internal)?
        {
            return Ok(None);
        }

        Ok(Some(OAuthCommittedRefreshTokenGrant {
            access_grant,
            sid: refresh.sid().to_string(),
            refresh_token: refresh.value().to_string(),
            refresh_expires_unix: refresh.expires_unix(),
        }))
    }

    async fn exchange_authorization_code_and_issue_oauth_refresh_token(
        &self,
        exchange: OAuthAuthorizationCodeExchangeRequest<'_>,
        issue: OAuthRefreshTokenIssueRequest<'_>,
        refresh: &IssuedRefreshToken,
    ) -> anyhow::Result<bool> {
        self.retry_transaction(
            "exchange authorization code and issue OAuth refresh token",
            || async {
                self.exchange_authorization_code_and_issue_oauth_refresh_token_once(
                    &exchange, &issue, refresh,
                )
                .await
            },
        )
        .await
    }

    async fn consume_authorization_code(
        &self,
        exchange: OAuthAuthorizationCodeExchangeRequest<'_>,
    ) -> anyhow::Result<bool> {
        self.retry_transaction("consume authorization code", || async {
            self.consume_authorization_code_once(&exchange).await
        })
        .await
    }

    async fn exchange_oauth_refresh_token<E, F, Fut>(
        &self,
        request: OAuthRefreshTokenGrantRequest<'_>,
        authorize: F,
    ) -> Result<RefreshTokenValidation<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: Fn(OAuthVerifiedIdentity) -> Fut + Clone + Send + Sync,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send,
    {
        let Some(parsed) = self
            .refresh_tokens
            .parse(request.refresh_token)
            .map_err(OAuthGrantError::internal)?
        else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        let next_refresh = self
            .refresh_tokens
            .issue_replacement(request.now_unix)
            .map_err(OAuthGrantError::internal)?;
        self.retry_oauth_transaction("exchange OAuth refresh token", || {
            let authorize = authorize.clone();
            async {
                self.exchange_oauth_refresh_token_once(
                    &RefreshTokenRotationRequest {
                        token_id: parsed.id(),
                        expected_token_verifier: parsed.verifier(),
                        expected_client_id: request.client_id,
                        next_token_id: next_refresh.token_id(),
                        next_token_verifier: next_refresh.token_verifier(),
                        next_expires_unix: next_refresh.expires_unix(),
                        now_unix: next_refresh.issued_unix(),
                    },
                    next_refresh.value(),
                    authorize,
                )
                .await
            }
        })
        .await
    }

    async fn exchange_oauth_refresh_token_once<E, F, Fut>(
        &self,
        request: &RefreshTokenRotationRequest<'_>,
        next_refresh_token: &str,
        authorize: F,
    ) -> Result<RefreshTokenValidation<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: Fn(OAuthVerifiedIdentity) -> Fut + Send + Sync,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send,
    {
        let mut tx = self
            .db
            .begin_transaction()
            .await
            .map_err(oauth_internal_firestore)?;
        let tx_db = self.tx_db(&tx);
        let record = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_REFRESH_TOKENS_COLLECTION)
            .parent(&self.parent)
            .obj::<RefreshTokenRecord>()
            .one(request.token_id)
            .await
            .map_err(oauth_internal_firestore)?;

        let Some(record) = record else {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        };

        let session = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .obj::<GrantRecord>()
            .one(&record.sid)
            .await
            .map_err(oauth_internal_firestore)?;

        let Some(session) = session else {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        };
        let token_matches = refresh_token_matches(
            &record,
            &session,
            request.expected_token_verifier,
            request.expected_client_id,
        );

        if record.is_expired_at(request.now_unix)
            || !token_matches
            || session.is_revoked_or_expired_at(request.now_unix)
        {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        }

        let provider_sub = match session.provider_sub.clone() {
            Some(provider_sub) => provider_sub,
            None => {
                tx.rollback().await.ok();
                return Ok(RefreshTokenValidation::Invalid);
            }
        };
        let principal = match session.principal.clone() {
            Some(principal) => principal,
            None => {
                tx.rollback().await.ok();
                return Ok(RefreshTokenValidation::Invalid);
            }
        };
        let access_grant = match authorize(OAuthVerifiedIdentity {
            provider_sub,
            principal,
        })
        .await
        {
            Ok(access_grant) => access_grant,
            Err(error) => {
                tx.rollback().await.ok();
                return Err(oauth_grant_error_from_policy(error));
            }
        };
        let (next_record, next_session) = rotated_refresh_records(&record, &session, request)
            .map_err(OAuthGrantError::internal)?;
        let refresh_expires_unix = next_record.expires_at_unix();

        tx.delete_by_id_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.token_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )
        .map_err(oauth_internal_firestore)?;
        tx.update_object_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.next_token_id,
            &next_record,
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )
        .map_err(oauth_internal_firestore)?;
        tx.update_object_at(
            &self.parent,
            AUTH_GRANTS_COLLECTION,
            &record.sid,
            &next_session,
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )
        .map_err(oauth_internal_firestore)?;
        tx.commit().await.map_err(oauth_internal_firestore)?;

        Ok(RefreshTokenValidation::Valid(
            OAuthCommittedRefreshTokenGrant {
                access_grant,
                sid: record.sid,
                refresh_token: next_refresh_token.to_string(),
                refresh_expires_unix,
            },
        ))
    }

    async fn revoke_oauth_refresh_token(
        &self,
        token_id: &str,
        expected_token_verifier: &str,
        now_unix: i64,
    ) -> anyhow::Result<()> {
        self.retry_transaction("revoke OAuth refresh token", || async {
            self.revoke_oauth_refresh_token_once(token_id, expected_token_verifier, now_unix)
                .await
        })
        .await
    }

    pub async fn revoke_oauth_refresh_token_value(
        &self,
        token: &str,
        now_unix: i64,
    ) -> anyhow::Result<()> {
        let Some(parsed) = self.refresh_tokens.parse(token)? else {
            return Ok(());
        };
        self.revoke_oauth_refresh_token(parsed.id(), parsed.verifier(), now_unix)
            .await
    }

    pub async fn revoke_refresh_sessions_for_subject(
        &self,
        subject: &Subject,
        client_id: &str,
        now_unix: i64,
    ) -> anyhow::Result<usize> {
        let documents = self
            .db
            .fluent()
            .select()
            .from(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .filter(|query| {
                query.for_all([query.field("subject").equal(subject.as_str().to_string())])
            })
            .query()
            .await?;
        let mut revoked = 0usize;
        for document in documents {
            let Some(sid) = firestore_document_id(&document.name) else {
                tracing::warn!(
                    document_name = document.name,
                    "skipping refresh-session revocation for malformed document name"
                );
                continue;
            };
            if self
                .revoke_refresh_session(sid, subject, client_id, now_unix)
                .await?
            {
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    pub async fn revoke_refresh_session(
        &self,
        sid: &str,
        expected_subject: &Subject,
        expected_client_id: &str,
        now_unix: i64,
    ) -> anyhow::Result<bool> {
        self.retry_transaction("revoke refresh session", || async {
            self.revoke_refresh_session_by_id_once(
                sid,
                expected_subject,
                expected_client_id,
                now_unix,
            )
            .await
        })
        .await
    }

    pub async fn transition_refresh_session_subject(
        &self,
        sid: &str,
        expected_subject: &Subject,
        next_subject: &Subject,
        expected_client_id: &str,
        now_unix: i64,
    ) -> anyhow::Result<RefreshSessionSubjectTransition> {
        self.retry_transaction("transition refresh-session subject", || async {
            self.transition_refresh_session_subject_once(
                sid,
                expected_subject,
                next_subject,
                expected_client_id,
                now_unix,
            )
            .await
        })
        .await
    }

    async fn transition_refresh_session_subject_once(
        &self,
        sid: &str,
        expected_subject: &Subject,
        next_subject: &Subject,
        expected_client_id: &str,
        now_unix: i64,
    ) -> anyhow::Result<RefreshSessionSubjectTransition> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let Some(mut session) = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .obj::<GrantRecord>()
            .one(sid)
            .await?
        else {
            tx.rollback().await.ok();
            anyhow::bail!("refresh session `{sid}` does not exist");
        };
        if session.client_id != expected_client_id {
            tx.rollback().await.ok();
            anyhow::bail!("refresh session `{sid}` belongs to another client");
        }
        if session.is_revoked_or_expired_at(now_unix) {
            tx.rollback().await.ok();
            anyhow::bail!("refresh session `{sid}` is revoked or expired");
        }
        if &session.subject == next_subject {
            tx.rollback().await.ok();
            return Ok(RefreshSessionSubjectTransition::AlreadyTransitioned);
        }
        if &session.subject != expected_subject {
            tx.rollback().await.ok();
            anyhow::bail!(
                "refresh session `{sid}` has subject `{}`, expected `{}`",
                session.subject.as_str(),
                expected_subject.as_str()
            );
        }
        session.subject = next_subject.clone();
        tx.update_object_at(
            &self.parent,
            AUTH_GRANTS_COLLECTION,
            sid,
            &session,
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit().await?;
        Ok(RefreshSessionSubjectTransition::Transitioned)
    }

    async fn revoke_refresh_session_by_id_once(
        &self,
        sid: &str,
        expected_subject: &Subject,
        expected_client_id: &str,
        now_unix: i64,
    ) -> anyhow::Result<bool> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let Some(mut session) = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .obj::<GrantRecord>()
            .one(sid)
            .await?
        else {
            tx.rollback().await.ok();
            return Ok(false);
        };
        if &session.subject != expected_subject || session.client_id != expected_client_id {
            tx.rollback().await.ok();
            return Ok(false);
        }
        if session.revoked_unix.is_some() {
            tx.rollback().await.ok();
            return Ok(false);
        }
        session.revoked_unix = Some(now_unix);
        tx.update_object_at(
            &self.parent,
            AUTH_GRANTS_COLLECTION,
            sid,
            &session,
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit().await?;
        Ok(true)
    }

    async fn create_refresh_session(
        &self,
        session: RefreshSessionCreationRequest<'_>,
        refresh: RefreshTokenCreationRequest<'_>,
    ) -> anyhow::Result<()> {
        self.retry_transaction("create refresh session", || async {
            let mut tx = self.db.begin_transaction().await?;
            tx.update_object_at(
                &self.parent,
                AUTH_GRANTS_COLLECTION,
                session.sid,
                &GrantRecord {
                    client_id: session.client_id.to_string(),
                    subject: session.subject.clone(),
                    provider_sub: None,
                    principal: None,
                    created_unix: session.now_unix,
                    expires_unix: session.expires_unix,
                    revoked_unix: None,
                    expire_at: timestamp(session.expires_unix, "refresh session expiry")?,
                },
                None,
                Some(FirestoreWritePrecondition::Exists(false)),
                vec![],
            )?;
            self.create_refresh_token_in_tx(&mut tx, refresh)?;
            tx.commit().await?;
            Ok(())
        })
        .await
    }

    pub async fn issue_refresh_token(
        &self,
        request: RefreshTokenIssueRequest<'_>,
    ) -> anyhow::Result<IssuedRefreshSession> {
        let issued = self.refresh_tokens.issue(request.now_unix)?;
        self.create_refresh_session(
            RefreshSessionCreationRequest {
                sid: issued.sid(),
                subject: request.subject.clone(),
                client_id: request.client_id,
                now_unix: issued.issued_unix(),
                expires_unix: issued.expires_unix(),
            },
            RefreshTokenCreationRequest {
                sid: issued.sid(),
                family_id: issued.family_id(),
                token_id: issued.token_id(),
                token_verifier: issued.token_verifier(),
                client_id: request.client_id,
                now_unix: issued.issued_unix(),
                expires_unix: issued.expires_unix(),
            },
        )
        .await?;
        Ok(IssuedRefreshSession::new(issued, request.subject))
    }

    async fn rotate_refresh_token(
        &self,
        request: RefreshTokenRotationRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<RefreshTokenRotation>> {
        self.retry_transaction("rotate refresh token", || async {
            self.rotate_refresh_token_once(&request).await
        })
        .await
    }

    pub async fn exchange_refresh_token(
        &self,
        request: RefreshTokenGrantRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<RefreshTokenExchange>> {
        let Some(parsed) = self.refresh_tokens.parse(request.refresh_token)? else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        let next_refresh = self.refresh_tokens.issue_replacement(request.now_unix)?;
        let rotation = match self
            .rotate_refresh_token(RefreshTokenRotationRequest {
                token_id: parsed.id(),
                expected_token_verifier: parsed.verifier(),
                expected_client_id: request.client_id,
                next_token_id: next_refresh.token_id(),
                next_token_verifier: next_refresh.token_verifier(),
                next_expires_unix: next_refresh.expires_unix(),
                now_unix: next_refresh.issued_unix(),
            })
            .await?
        {
            RefreshTokenValidation::Valid(rotation) => rotation,
            RefreshTokenValidation::Invalid => return Ok(RefreshTokenValidation::Invalid),
        };

        Ok(RefreshTokenValidation::Valid(RefreshTokenExchange {
            sid: rotation.sid,
            subject: rotation.subject,
            refresh_token: next_refresh.value().to_string(),
            expires_unix: rotation.expires_unix,
        }))
    }

    pub async fn inspect_refresh_token(
        &self,
        request: RefreshTokenGrantRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<RefreshTokenInspection>> {
        let Some(parsed) = self.refresh_tokens.parse(request.refresh_token)? else {
            return Ok(RefreshTokenValidation::Invalid);
        };
        self.retry_transaction("inspect refresh token", || async {
            let tx = self.db.begin_transaction().await?;
            let tx_db = self.tx_db(&tx);
            let record = tx_db
                .fluent()
                .select()
                .by_id_in(AUTH_REFRESH_TOKENS_COLLECTION)
                .parent(&self.parent)
                .obj::<RefreshTokenRecord>()
                .one(parsed.id())
                .await?;
            let Some(record) = record else {
                tx.rollback().await.ok();
                return Ok(RefreshTokenValidation::Invalid);
            };
            let session = tx_db
                .fluent()
                .select()
                .by_id_in(AUTH_GRANTS_COLLECTION)
                .parent(&self.parent)
                .obj::<GrantRecord>()
                .one(&record.sid)
                .await?;
            let Some(session) = session else {
                tx.rollback().await.ok();
                return Ok(RefreshTokenValidation::Invalid);
            };
            let valid = !record.is_expired_at(request.now_unix)
                && refresh_token_matches(&record, &session, parsed.verifier(), request.client_id)
                && !session.is_revoked_or_expired_at(request.now_unix);
            tx.rollback().await.ok();
            if !valid {
                return Ok(RefreshTokenValidation::Invalid);
            }
            let expires_unix = record.expires_at_unix();
            Ok(RefreshTokenValidation::Valid(RefreshTokenInspection {
                sid: record.sid,
                subject: session.subject,
                expires_unix,
            }))
        })
        .await
    }

    fn tx_db(&self, tx: &firestore::FirestoreTransaction) -> firestore::FirestoreDb {
        self.db
            .clone_with_consistency_selector(FirestoreConsistencySelector::Transaction(
                tx.transaction_id().clone(),
            ))
    }

    async fn exchange_authorization_code_and_issue_oauth_refresh_token_once(
        &self,
        exchange: &OAuthAuthorizationCodeExchangeRequest<'_>,
        issue: &OAuthRefreshTokenIssueRequest<'_>,
        refresh: &IssuedRefreshToken,
    ) -> anyhow::Result<bool> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let record = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION)
            .parent(self.oauth_authorization_code_flow_parent())
            .obj::<AuthorizationCodeRecord>()
            .one(exchange.code_id)
            .await?;

        let Some(record) = record else {
            tx.rollback().await.ok();
            return Ok(false);
        };

        if issue.now_unix != refresh.issued_unix() {
            tx.rollback().await.ok();
            anyhow::bail!(
                "OAuth refresh token issue timestamp does not match issued token timestamp"
            );
        }

        if authorization_code_exchange_from_record(&record, exchange).is_none() {
            if record.is_expired_at(exchange.now_unix) {
                tx.delete_by_id_at(
                    &self.oauth_authorization_code_flow_parent(),
                    AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION,
                    exchange.code_id,
                    Some(FirestoreWritePrecondition::Exists(true)),
                )?;
                tx.commit().await?;
            } else {
                tx.rollback().await.ok();
            }
            return Ok(false);
        }

        tx.delete_by_id_at(
            &self.oauth_authorization_code_flow_parent(),
            AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION,
            exchange.code_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )?;
        tx.update_object_at(
            &self.parent,
            AUTH_GRANTS_COLLECTION,
            refresh.sid(),
            &GrantRecord {
                client_id: issue.client_id.to_string(),
                subject: Subject::new(format!("user:{}", issue.principal))?,
                provider_sub: Some(issue.provider_sub.to_string()),
                principal: Some(issue.principal.to_string()),
                created_unix: refresh.issued_unix(),
                expires_unix: refresh.expires_unix(),
                revoked_unix: None,
                expire_at: timestamp(refresh.expires_unix(), "OAuth refresh session expiry")?,
            },
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        self.create_oauth_refresh_token_in_tx(
            &mut tx,
            RefreshTokenCreationRequest {
                sid: refresh.sid(),
                family_id: refresh.family_id(),
                client_id: issue.client_id,
                now_unix: refresh.issued_unix(),
                token_id: refresh.token_id(),
                token_verifier: refresh.token_verifier(),
                expires_unix: refresh.expires_unix(),
            },
        )?;
        tx.commit().await?;

        Ok(true)
    }

    async fn consume_authorization_code_once(
        &self,
        exchange: &OAuthAuthorizationCodeExchangeRequest<'_>,
    ) -> anyhow::Result<bool> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let record = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION)
            .parent(self.oauth_authorization_code_flow_parent())
            .obj::<AuthorizationCodeRecord>()
            .one(exchange.code_id)
            .await?;

        let Some(record) = record else {
            tx.rollback().await.ok();
            return Ok(false);
        };

        if authorization_code_exchange_from_record(&record, exchange).is_none() {
            if record.is_expired_at(exchange.now_unix) {
                tx.delete_by_id_at(
                    &self.oauth_authorization_code_flow_parent(),
                    AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION,
                    exchange.code_id,
                    Some(FirestoreWritePrecondition::Exists(true)),
                )?;
                tx.commit().await?;
            } else {
                tx.rollback().await.ok();
            }
            return Ok(false);
        }

        tx.delete_by_id_at(
            &self.oauth_authorization_code_flow_parent(),
            AUTH_OAUTH_AUTHORIZATION_CODES_COLLECTION,
            exchange.code_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )?;
        tx.commit().await?;
        Ok(true)
    }

    fn create_oauth_refresh_token_in_tx(
        &self,
        tx: &mut firestore::FirestoreTransaction,
        request: RefreshTokenCreationRequest<'_>,
    ) -> anyhow::Result<()> {
        tx.update_object_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.token_id,
            &RefreshTokenRecord {
                sid: request.sid.to_string(),
                family_id: request.family_id.to_string(),
                token_verifier: request.token_verifier.to_string(),
                client_id: request.client_id.to_string(),
                created_unix: request.now_unix,
                expires_unix: request.expires_unix,
                expire_at: timestamp(request.expires_unix, "refresh token expiry")?,
            },
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        Ok(())
    }

    fn create_refresh_token_in_tx(
        &self,
        tx: &mut firestore::FirestoreTransaction,
        request: RefreshTokenCreationRequest<'_>,
    ) -> anyhow::Result<()> {
        tx.update_object_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.token_id,
            &RefreshTokenRecord {
                sid: request.sid.to_string(),
                family_id: request.family_id.to_string(),
                token_verifier: request.token_verifier.to_string(),
                client_id: request.client_id.to_string(),
                created_unix: request.now_unix,
                expires_unix: request.expires_unix,
                expire_at: timestamp(request.expires_unix, "refresh token expiry")?,
            },
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        Ok(())
    }

    async fn revoke_oauth_refresh_token_once(
        &self,
        token_id: &str,
        expected_token_verifier: &str,
        now_unix: i64,
    ) -> anyhow::Result<()> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let record = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_REFRESH_TOKENS_COLLECTION)
            .parent(&self.parent)
            .obj::<RefreshTokenRecord>()
            .one(token_id)
            .await?;
        let Some(record) = record else {
            tx.rollback().await.ok();
            return Ok(());
        };
        if record.token_verifier != expected_token_verifier {
            tx.rollback().await.ok();
            return Ok(());
        }
        let session = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .obj::<GrantRecord>()
            .one(&record.sid)
            .await?;
        let Some(mut session) = session else {
            tx.rollback().await.ok();
            return Ok(());
        };
        if session.revoked_unix.is_none() {
            session.revoked_unix = Some(now_unix);
            tx.update_object_at(
                &self.parent,
                AUTH_GRANTS_COLLECTION,
                &record.sid,
                &session,
                None,
                Some(FirestoreWritePrecondition::Exists(true)),
                vec![],
            )?;
            tx.commit().await?;
        } else {
            tx.rollback().await.ok();
        }
        Ok(())
    }

    async fn rotate_refresh_token_once(
        &self,
        request: &RefreshTokenRotationRequest<'_>,
    ) -> anyhow::Result<RefreshTokenValidation<RefreshTokenRotation>> {
        let mut tx = self.db.begin_transaction().await?;
        let tx_db = self.tx_db(&tx);
        let record = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_REFRESH_TOKENS_COLLECTION)
            .parent(&self.parent)
            .obj::<RefreshTokenRecord>()
            .one(request.token_id)
            .await?;
        let Some(record) = record else {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        };

        let session = tx_db
            .fluent()
            .select()
            .by_id_in(AUTH_GRANTS_COLLECTION)
            .parent(&self.parent)
            .obj::<GrantRecord>()
            .one(&record.sid)
            .await?;
        let Some(session) = session else {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        };
        let token_matches = refresh_token_matches(
            &record,
            &session,
            request.expected_token_verifier,
            request.expected_client_id,
        );

        if record.is_expired_at(request.now_unix)
            || !token_matches
            || session.is_revoked_or_expired_at(request.now_unix)
        {
            tx.rollback().await.ok();
            return Ok(RefreshTokenValidation::Invalid);
        }
        let (next_record, next_session) = rotated_refresh_records(&record, &session, request)?;
        let refresh_expires_unix = next_record.expires_at_unix();

        tx.delete_by_id_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.token_id,
            Some(FirestoreWritePrecondition::Exists(true)),
        )?;
        tx.update_object_at(
            &self.parent,
            AUTH_REFRESH_TOKENS_COLLECTION,
            request.next_token_id,
            &next_record,
            None,
            Some(FirestoreWritePrecondition::Exists(false)),
            vec![],
        )?;
        tx.update_object_at(
            &self.parent,
            AUTH_GRANTS_COLLECTION,
            &record.sid,
            &next_session,
            None,
            Some(FirestoreWritePrecondition::Exists(true)),
            vec![],
        )?;
        tx.commit().await?;

        Ok(RefreshTokenValidation::Valid(RefreshTokenRotation {
            sid: record.sid,
            subject: next_session.subject,
            expires_unix: refresh_expires_unix,
        }))
    }

    async fn retry_transaction<T, Fut, F>(&self, label: &'static str, mut f: F) -> anyhow::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        for attempt in 0..TRANSACTION_MAX_ATTEMPTS {
            match f().await {
                Ok(value) => return Ok(value),
                Err(error)
                    if is_firestore_data_conflict(&error)
                        && attempt + 1 < TRANSACTION_MAX_ATTEMPTS =>
                {
                    tracing::warn!(
                        attempt = attempt + 1,
                        label,
                        "retrying Firestore auth transaction after data conflict"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("transaction retry loop always returns on final attempt")
    }

    async fn retry_oauth_transaction<T, Fut, F>(
        &self,
        label: &'static str,
        mut f: F,
    ) -> Result<T, OAuthGrantError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, OAuthGrantError>>,
    {
        for attempt in 0..TRANSACTION_MAX_ATTEMPTS {
            match f().await {
                Ok(value) => return Ok(value),
                Err(OAuthGrantError::Internal(error))
                    if is_firestore_data_conflict(&error)
                        && attempt + 1 < TRANSACTION_MAX_ATTEMPTS =>
                {
                    tracing::warn!(
                        attempt = attempt + 1,
                        label,
                        "retrying Firestore auth transaction after data conflict"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("transaction retry loop always returns on final attempt")
    }
}

#[async_trait::async_trait]
impl AuthorizationCodeOAuthStore for FirestoreAuthStore {
    async fn put_login_session(&self, sid: &str, session: OAuthLoginSession) -> anyhow::Result<()> {
        FirestoreAuthStore::put_login_session(self, sid, session).await
    }

    async fn take_login_session(&self, sid: &str) -> anyhow::Result<Option<OAuthLoginSession>> {
        FirestoreAuthStore::take_login_session(self, sid).await
    }

    async fn prune_expired_login_sessions(&self, now_unix: i64) -> anyhow::Result<usize> {
        FirestoreAuthStore::prune_expired_login_sessions(self, now_unix).await
    }

    async fn issue_authorization_code(
        &self,
        request: OAuthAuthorizationCodeIssueRequest<'_>,
    ) -> anyhow::Result<OAuthIssuedAuthorizationCode> {
        FirestoreAuthStore::issue_authorization_code(self, request).await
    }

    async fn exchange_authorization_code<E, F, Fut>(
        &self,
        request: OAuthAuthorizationCodeGrantRequest<'_>,
        authorize: F,
    ) -> Result<Option<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: FnOnce(OAuthVerifiedIdentity) -> Fut + Send,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send,
    {
        FirestoreAuthStore::exchange_oauth_authorization_code(self, request, authorize).await
    }

    async fn exchange_refresh_token<E, F, Fut>(
        &self,
        request: OAuthRefreshTokenGrantRequest<'_>,
        authorize: F,
    ) -> Result<RefreshTokenValidation<OAuthCommittedRefreshTokenGrant<E>>, OAuthGrantError>
    where
        E: Serialize + Send + Sync + 'static,
        F: Fn(OAuthVerifiedIdentity) -> Fut + Clone + Send + Sync,
        Fut: Future<Output = Result<OAuthAccessGrant<E>, OAuthAccessGrantError>> + Send,
    {
        FirestoreAuthStore::exchange_oauth_refresh_token(self, request, authorize).await
    }
}

#[derive(Clone, Debug)]
pub struct FirestoreRestAuthStore {
    project_id: String,
    database_id: String,
    auth_document_path: String,
}

impl FirestoreRestAuthStore {
    pub fn new(project_id: impl Into<String>, auth_document_path: impl Into<String>) -> Self {
        Self::with_database(project_id, "(default)", auth_document_path)
    }

    pub fn with_database(
        project_id: impl Into<String>,
        database_id: impl Into<String>,
        auth_document_path: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            database_id: database_id.into(),
            auth_document_path: auth_document_path.into(),
        }
    }

    fn issue_refresh_token(
        &self,
        http: &BlockingHttpClient,
        access_token: &str,
        request: FirestoreRestRefreshTokenIssueRequest<'_>,
    ) -> anyhow::Result<IssuedRefreshSession> {
        let refresh_config = self.load_refresh_token_config(http, access_token)?;
        let issued = RefreshTokenCodec::new(
            REFRESH_TOKEN_PREFIX,
            refresh_config.pepper,
            refresh_config.ttl_seconds,
        )?
        .issue(request.now_unix)?;
        let subject = Subject::new(request.subject)?;
        self.commit_writes(
            http,
            access_token,
            self.refresh_session_writes(&issued, request)?,
        )?;
        Ok(IssuedRefreshSession::new(issued, subject))
    }

    fn delete_unconsumed_refresh_session(
        &self,
        http: &BlockingHttpClient,
        access_token: &str,
        issued: &IssuedRefreshSession,
    ) -> anyhow::Result<bool> {
        let issued_token = issued.inner();
        let token_path =
            self.auth_child_document_path(AUTH_REFRESH_TOKENS_COLLECTION, issued_token.token_id());
        let Some(token) = self.get_document(http, access_token, &token_path)? else {
            return Ok(false);
        };
        if !refresh_token_document_matches(&token, issued_token)? {
            return Ok(false);
        }
        let update_time = document_update_time(&token, &token_path)?;

        let session_path =
            self.auth_child_document_path(AUTH_GRANTS_COLLECTION, issued_token.sid());
        let Some(session) = self.get_document(http, access_token, &session_path)? else {
            return Ok(false);
        };
        if !refresh_session_document_matches(
            &session,
            issued,
            &document_string_field(&token, "client_id")?,
        )? {
            return Ok(false);
        }
        let session_update_time = document_update_time(&session, &session_path)?;
        self.commit_writes(
            http,
            access_token,
            self.unconsumed_refresh_session_delete_writes(
                issued_token,
                &update_time,
                &session_update_time,
            )?,
        )?;
        Ok(true)
    }

    fn load_refresh_token_config(
        &self,
        http: &BlockingHttpClient,
        access_token: &str,
    ) -> anyhow::Result<RestRefreshTokenConfig> {
        let auth = self
            .get_document(http, access_token, &self.auth_document_path)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Firestore document `{}` is missing",
                    self.auth_document_path
                )
            })?;
        Ok(RestRefreshTokenConfig {
            pepper: document_string_field(&auth, "refresh_token.pepper")?,
            ttl_seconds: u64::try_from(document_integer_field(&auth, "refresh_token.ttl_seconds")?)
                .map_err(|_| {
                    anyhow::anyhow!("Firestore field `refresh_token.ttl_seconds` is negative")
                })?,
        })
    }

    fn refresh_session_writes(
        &self,
        issued: &IssuedRefreshToken,
        request: FirestoreRestRefreshTokenIssueRequest<'_>,
    ) -> anyhow::Result<serde_json::Value> {
        let subject = Subject::new(request.subject)?;
        let expire_at = firestore_timestamp_value(issued.expires_unix(), "refresh expiry")?;
        let session_name = self
            .document_name(&self.auth_child_document_path(AUTH_GRANTS_COLLECTION, issued.sid()))?;
        let refresh_name = self.document_name(
            &self.auth_child_document_path(AUTH_REFRESH_TOKENS_COLLECTION, issued.token_id()),
        )?;
        Ok(json!([
            {
                "update": {
                    "name": session_name,
                    "fields": {
                        "client_id": { "stringValue": request.client_id },
                        "created_unix": { "integerValue": issued.issued_unix().to_string() },
                        "expires_unix": { "integerValue": issued.expires_unix().to_string() },
                        "expire_at": { "timestampValue": expire_at.clone() },
                        "subject": { "stringValue": subject.as_str() },
                    }
                },
                "currentDocument": { "exists": false }
            },
            {
                "update": {
                    "name": refresh_name,
                    "fields": {
                        "client_id": { "stringValue": request.client_id },
                        "created_unix": { "integerValue": issued.issued_unix().to_string() },
                        "expires_unix": { "integerValue": issued.expires_unix().to_string() },
                        "expire_at": { "timestampValue": expire_at },
                        "family_id": { "stringValue": issued.family_id() },
                        "sid": { "stringValue": issued.sid() },
                        "token_verifier": { "stringValue": issued.token_verifier() },
                    }
                },
                "currentDocument": { "exists": false }
            }
        ]))
    }

    fn unconsumed_refresh_session_delete_writes(
        &self,
        issued: &IssuedRefreshToken,
        token_update_time: &str,
        session_update_time: &str,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(json!([
            {
                "delete": self.document_name(
                    &self.auth_child_document_path(
                        AUTH_REFRESH_TOKENS_COLLECTION,
                        issued.token_id(),
                    )
                )?,
                "currentDocument": { "updateTime": token_update_time }
            },
            {
                "delete": self.document_name(
                    &self.auth_child_document_path(AUTH_GRANTS_COLLECTION, issued.sid())
                )?,
                "currentDocument": { "updateTime": session_update_time }
            }
        ]))
    }

    fn get_document(
        &self,
        http: &BlockingHttpClient,
        access_token: &str,
        document_path: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let response = http
            .get(self.document_url(document_path)?)
            .bearer_auth(access_token)
            .send()
            .map_err(|error| anyhow::anyhow!("failed to query Firestore document: {error}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status().is_success() {
            return response
                .json::<serde_json::Value>()
                .map(Some)
                .map_err(|error| anyhow::anyhow!("failed to parse Firestore document: {error}"));
        }
        let status = response.status();
        let body = response.text().unwrap_or_default();
        anyhow::bail!("Firestore get for `{document_path}` failed with {status}: {body}");
    }

    fn commit_writes(
        &self,
        http: &BlockingHttpClient,
        access_token: &str,
        writes: serde_json::Value,
    ) -> anyhow::Result<()> {
        let response = http
            .post(self.commit_url())
            .bearer_auth(access_token)
            .json(&json!({ "writes": writes }))
            .send()
            .map_err(|error| anyhow::anyhow!("failed to commit Firestore writes: {error}"))?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let body = response.text().unwrap_or_default();
        anyhow::bail!("Firestore commit failed with {status}: {body}");
    }

    fn document_name(&self, document_path: &str) -> anyhow::Result<String> {
        if document_path.trim().is_empty() {
            anyhow::bail!("Firestore document path must not be empty");
        }
        Ok(format!(
            "projects/{}/databases/{}/documents/{document_path}",
            self.project_id, self.database_id
        ))
    }

    fn document_url(&self, document_path: &str) -> anyhow::Result<String> {
        Ok(format!(
            "https://firestore.googleapis.com/v1/{}",
            self.document_name(document_path)?
        ))
    }

    fn commit_url(&self) -> String {
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents:commit",
            self.project_id, self.database_id
        )
    }

    fn auth_child_document_path(&self, collection: &str, document_id: &str) -> String {
        format!("{}/{}/{}", self.auth_document_path, collection, document_id)
    }
}

#[derive(Clone)]
pub struct FirestoreRestAuthClient<P> {
    store: FirestoreRestAuthStore,
    http: BlockingHttpClient,
    access_token_provider: P,
}

pub trait FirestoreRestAccessTokenProvider: Clone + Send + Sync + 'static {
    fn access_token(&self) -> anyhow::Result<String>;
}

impl<F> FirestoreRestAccessTokenProvider for F
where
    F: Fn() -> anyhow::Result<String> + Clone + Send + Sync + 'static,
{
    fn access_token(&self) -> anyhow::Result<String> {
        self()
    }
}

impl FirestoreRestAccessTokenProvider for Arc<dyn Fn() -> anyhow::Result<String> + Send + Sync> {
    fn access_token(&self) -> anyhow::Result<String> {
        self()
    }
}

impl<P> FirestoreRestAuthClient<P>
where
    P: FirestoreRestAccessTokenProvider,
{
    pub fn new(store: FirestoreRestAuthStore, access_token_provider: P) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            http: BlockingHttpClient::builder().build()?,
            access_token_provider,
        })
    }

    pub fn with_http(
        store: FirestoreRestAuthStore,
        http: BlockingHttpClient,
        access_token_provider: P,
    ) -> Self {
        Self {
            store,
            http,
            access_token_provider,
        }
    }

    pub fn issue_refresh_token(
        &self,
        request: FirestoreRestRefreshTokenIssueRequest<'_>,
    ) -> anyhow::Result<IssuedRefreshSession> {
        self.store
            .issue_refresh_token(&self.http, &self.access_token()?, request)
    }

    pub fn delete_unconsumed_refresh_session(
        &self,
        issued: &IssuedRefreshSession,
    ) -> anyhow::Result<bool> {
        self.store
            .delete_unconsumed_refresh_session(&self.http, &self.access_token()?, issued)
    }

    fn access_token(&self) -> anyhow::Result<String> {
        self.access_token_provider.access_token()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirestoreRestRefreshTokenIssueRequest<'a> {
    pub subject: &'a str,
    pub client_id: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RestRefreshTokenConfig {
    pepper: String,
    ttl_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AuthSessionRecord {
    pub client_id: String,
    pub state: String,
    pub pkce_challenge: String,
    pub pkce_challenge_method: PkceCodeChallengeMethod,
    pub provider_session_state: String,
    pub redirect_uri: String,
    pub created_unix: i64,
    #[serde(default, with = "::firestore::serialize_as_optional_timestamp")]
    pub expire_at: Option<firestore::FirestoreInstant>,
}

impl AuthSessionRecord {
    pub fn expires_at_unix(&self, login_session_ttl_seconds: i64) -> i64 {
        self.expire_at
            .map(|expire_at| expire_at.as_second())
            .unwrap_or_else(|| self.created_unix.saturating_add(login_session_ttl_seconds))
    }
}

impl AuthSessionRecord {
    fn try_from_session(session: OAuthLoginSession) -> anyhow::Result<Self> {
        Ok(Self {
            client_id: session.client_id,
            state: session.state,
            pkce_challenge: session.pkce_challenge,
            pkce_challenge_method: session.pkce_challenge_method,
            provider_session_state: session.provider_session_state,
            redirect_uri: session.redirect_uri,
            created_unix: session.created_unix,
            expire_at: timestamp(session.expires_unix, "OAuth login session expiry")?,
        })
    }
}

impl AuthSessionRecord {
    fn into_session(self, login_session_ttl_seconds: i64) -> OAuthLoginSession {
        OAuthLoginSession {
            expires_unix: self.expires_at_unix(login_session_ttl_seconds),
            client_id: self.client_id,
            state: self.state,
            pkce_challenge: self.pkce_challenge,
            pkce_challenge_method: self.pkce_challenge_method,
            provider_session_state: self.provider_session_state,
            redirect_uri: self.redirect_uri,
            created_unix: self.created_unix,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AuthorizationCodeRecord {
    pub token_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub provider_sub: String,
    pub principal: String,
    pub pkce_challenge: String,
    pub pkce_challenge_method: PkceCodeChallengeMethod,
    pub created_unix: i64,
    #[serde(default, with = "::firestore::serialize_as_optional_timestamp")]
    pub expire_at: Option<firestore::FirestoreInstant>,
}

impl AuthorizationCodeRecord {
    pub fn expires_at_unix(&self) -> i64 {
        self.expire_at
            .map(|expire_at| expire_at.as_second())
            .unwrap_or(self.created_unix)
    }

    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix()
    }
}

impl AuthorizationCodeRecord {
    fn try_from_code(code: OAuthAuthorizationCode) -> anyhow::Result<Self> {
        Ok(Self {
            token_verifier: code.token_verifier,
            client_id: code.client_id,
            redirect_uri: code.redirect_uri,
            provider_sub: code.provider_sub,
            principal: code.principal,
            pkce_challenge: code.pkce_challenge,
            pkce_challenge_method: code.pkce_challenge_method,
            created_unix: code.created_unix,
            expire_at: timestamp(code.expires_unix, "OAuth authorization code expiry")?,
        })
    }
}

fn authorization_code_exchange_from_record(
    record: &AuthorizationCodeRecord,
    request: &OAuthAuthorizationCodeExchangeRequest<'_>,
) -> Option<OAuthAuthorizationCodeExchange> {
    if record.is_expired_at(request.now_unix)
        || record.token_verifier != request.expected_token_verifier
        || record.client_id != request.expected_client_id
        || record.redirect_uri != request.expected_redirect_uri
        || record.pkce_challenge_method != PkceCodeChallengeMethod::S256
        || record.pkce_challenge != request.expected_pkce_challenge
    {
        return None;
    }
    Some(OAuthAuthorizationCodeExchange {
        provider_sub: record.provider_sub.clone(),
        principal: record.principal.clone(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RefreshTokenRecord {
    pub sid: String,
    pub family_id: String,
    pub token_verifier: String,
    pub client_id: String,
    pub created_unix: i64,
    pub expires_unix: i64,
    #[serde(default, with = "::firestore::serialize_as_optional_timestamp")]
    pub expire_at: Option<firestore::FirestoreInstant>,
}

impl RefreshTokenRecord {
    pub fn expires_at_unix(&self) -> i64 {
        self.expire_at
            .map(|expire_at| expire_at.as_second())
            .unwrap_or(self.expires_unix)
    }

    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GrantRecord {
    pub client_id: String,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    pub created_unix: i64,
    pub expires_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix: Option<i64>,
    #[serde(default, with = "::firestore::serialize_as_optional_timestamp")]
    pub expire_at: Option<firestore::FirestoreInstant>,
}

impl GrantRecord {
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_unix
    }

    pub fn is_revoked_or_expired_at(&self, now_unix: i64) -> bool {
        self.revoked_unix.is_some() || self.is_expired_at(now_unix)
    }
}

fn rotated_refresh_records(
    record: &RefreshTokenRecord,
    session: &GrantRecord,
    request: &RefreshTokenRotationRequest<'_>,
) -> anyhow::Result<(RefreshTokenRecord, GrantRecord)> {
    if request.next_expires_unix <= request.now_unix {
        anyhow::bail!("replacement refresh token expiry must be after its issuance");
    }
    let expires_unix = request.next_expires_unix;
    let expire_at = timestamp(expires_unix, "refresh token expiry")?;
    let mut next_session = session.clone();
    next_session.expires_unix = expires_unix;
    next_session.expire_at = expire_at;
    Ok((
        RefreshTokenRecord {
            sid: record.sid.clone(),
            family_id: record.family_id.clone(),
            token_verifier: request.next_token_verifier.to_string(),
            client_id: record.client_id.clone(),
            created_unix: request.now_unix,
            expires_unix,
            expire_at,
        },
        next_session,
    ))
}

#[cfg(test)]
fn oauth_refresh_validation_from_records(
    record: &RefreshTokenRecord,
    session: &GrantRecord,
    request: &phylax_core::backend::RefreshTokenValidationRequest<'_>,
) -> RefreshTokenValidation<phylax_core::OAuthRefreshTokenRotation> {
    if record.is_expired_at(request.now_unix)
        || !refresh_token_matches(
            record,
            session,
            request.expected_token_verifier,
            request.expected_client_id,
        )
        || session.is_expired_at(request.now_unix)
    {
        return RefreshTokenValidation::Invalid;
    }
    if session.revoked_unix.is_some() {
        return RefreshTokenValidation::Invalid;
    }
    let (Some(provider_sub), Some(principal)) = (&session.provider_sub, &session.principal) else {
        return RefreshTokenValidation::Invalid;
    };
    RefreshTokenValidation::Valid(phylax_core::OAuthRefreshTokenRotation {
        sid: record.sid.clone(),
        provider_sub: provider_sub.clone(),
        principal: principal.clone(),
        expires_unix: record.expires_at_unix(),
    })
}

fn refresh_token_matches(
    record: &RefreshTokenRecord,
    session: &GrantRecord,
    expected_token_verifier: &str,
    expected_client_id: &str,
) -> bool {
    record.token_verifier == expected_token_verifier
        && record.client_id == expected_client_id
        && session.client_id == expected_client_id
}

fn oauth_grant_error_from_policy(error: OAuthAccessGrantError) -> OAuthGrantError {
    match error {
        OAuthAccessGrantError::AccessDenied(error) => OAuthGrantError::access_denied(error),
        OAuthAccessGrantError::Internal(error) => OAuthGrantError::internal(error),
    }
}

fn oauth_internal_firestore(error: FirestoreError) -> OAuthGrantError {
    OAuthGrantError::internal(error.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefreshTokenCreationRequest<'a> {
    pub sid: &'a str,
    pub family_id: &'a str,
    pub client_id: &'a str,
    pub now_unix: i64,
    pub token_id: &'a str,
    pub token_verifier: &'a str,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefreshSessionCreationRequest<'a> {
    pub sid: &'a str,
    pub subject: Subject,
    pub client_id: &'a str,
    pub now_unix: i64,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenIssueRequest<'a> {
    pub subject: Subject,
    pub client_id: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedRefreshSession {
    issued: IssuedRefreshToken,
    subject: Subject,
}

impl IssuedRefreshSession {
    fn new(issued: IssuedRefreshToken, subject: Subject) -> Self {
        Self { issued, subject }
    }

    fn inner(&self) -> &IssuedRefreshToken {
        &self.issued
    }

    fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn refresh_token(&self) -> &str {
        self.issued.value()
    }

    pub fn session_id(&self) -> &str {
        self.issued.sid()
    }

    pub fn expires_unix(&self) -> i64 {
        self.issued.expires_unix()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshSessionSubjectTransition {
    Transitioned,
    AlreadyTransitioned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshTokenGrantRequest<'a> {
    pub refresh_token: &'a str,
    pub client_id: &'a str,
    pub now_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenExchange {
    pub sid: String,
    pub subject: Subject,
    pub refresh_token: String,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenInspection {
    pub sid: String,
    pub subject: Subject,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenRotation {
    pub sid: String,
    pub subject: Subject,
    pub expires_unix: i64,
}

fn checked_positive_i64_ttl(value: u64, label: &str) -> anyhow::Result<i64> {
    if value == 0 {
        anyhow::bail!("{label} TTL must be > 0");
    }
    i64::try_from(value).map_err(|_| anyhow::anyhow!("{label} TTL exceeds i64"))
}

fn timestamp(unix: i64, label: &str) -> anyhow::Result<Option<firestore::FirestoreInstant>> {
    firestore::FirestoreInstant::new(unix, 0)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{label} timestamp is not representable: {unix}"))
}

fn firestore_timestamp_value(unix: i64, label: &str) -> anyhow::Result<String> {
    timestamp(unix, label)?.map_or_else(
        || anyhow::bail!("{label} timestamp is missing"),
        |timestamp| Ok(timestamp.to_string()),
    )
}

fn is_firestore_data_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<FirestoreError>()
        .is_some_and(|error| matches!(error, FirestoreError::DataConflictError(_)))
}

fn firestore_document_id(document_name: &str) -> Option<&str> {
    document_name
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

fn document_string_field(document: &serde_json::Value, field_path: &str) -> anyhow::Result<String> {
    let value = document_field(document, field_path)?;
    value
        .get("stringValue")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Firestore field `{field_path}` is not a non-empty string"))
}

fn document_integer_field(document: &serde_json::Value, field_path: &str) -> anyhow::Result<i64> {
    let value = document_field(document, field_path)?;
    value
        .get("integerValue")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("Firestore field `{field_path}` is not an integer"))?
        .parse::<i64>()
        .map_err(|error| {
            anyhow::anyhow!("Firestore field `{field_path}` is not a valid integer: {error}")
        })
}

fn document_has_field(document: &serde_json::Value, field_path: &str) -> bool {
    document_field(document, field_path).is_ok()
}

fn refresh_token_document_matches(
    document: &serde_json::Value,
    issued: &IssuedRefreshToken,
) -> anyhow::Result<bool> {
    Ok(document_string_field(document, "sid")? == issued.sid()
        && document_string_field(document, "family_id")? == issued.family_id()
        && document_string_field(document, "token_verifier")? == issued.token_verifier()
        && document_integer_field(document, "created_unix")? == issued.issued_unix()
        && document_integer_field(document, "expires_unix")? == issued.expires_unix())
}

fn refresh_session_document_matches(
    document: &serde_json::Value,
    issued: &IssuedRefreshSession,
    expected_client_id: &str,
) -> anyhow::Result<bool> {
    let issued_token = issued.inner();
    Ok(!document_has_field(document, "revoked_unix")
        && document_string_field(document, "client_id")? == expected_client_id
        && document_string_field(document, "subject")? == issued.subject().as_str()
        && document_integer_field(document, "created_unix")? == issued_token.issued_unix()
        && document_integer_field(document, "expires_unix")? == issued_token.expires_unix())
}

fn document_update_time(
    document: &serde_json::Value,
    document_path: &str,
) -> anyhow::Result<String> {
    document
        .get("updateTime")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Firestore document `{document_path}` has no updateTime"))
}

fn document_field<'a>(
    document: &'a serde_json::Value,
    field_path: &str,
) -> anyhow::Result<&'a serde_json::Value> {
    let segments = field_path.split('.').collect::<Vec<_>>();
    if segments.is_empty() {
        anyhow::bail!("Firestore field path must not be empty");
    }
    let mut current = document
        .get("fields")
        .ok_or_else(|| anyhow::anyhow!("Firestore document has no fields"))?;
    for (index, segment) in segments.iter().enumerate() {
        if segment.trim().is_empty() {
            anyhow::bail!("Firestore field path `{field_path}` contains an empty segment");
        }
        let value = current
            .get(*segment)
            .ok_or_else(|| anyhow::anyhow!("Firestore field `{field_path}` is missing"))?;
        if index + 1 == segments.len() {
            return Ok(value);
        }
        current = value
            .get("mapValue")
            .and_then(|value| value.get("fields"))
            .ok_or_else(|| {
                anyhow::anyhow!("Firestore field `{segment}` in `{field_path}` is not a map")
            })?;
    }
    unreachable!("segments is non-empty")
}

#[allow(dead_code)]
fn _assert_deserializable<T: DeserializeOwned>() {}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationCodeRecord, FirestoreAuthStoreConfig, FirestoreRestAuthStore,
        FirestoreRestRefreshTokenIssueRequest, GrantRecord, IssuedRefreshSession,
        RefreshTokenCodec, RefreshTokenRecord, authorization_code_exchange_from_record,
        document_integer_field, document_string_field, document_update_time,
        oauth_refresh_validation_from_records, refresh_session_document_matches,
        refresh_token_document_matches, rotated_refresh_records, timestamp,
    };
    use phylax_core::{
        OAuthAuthorizationCodeExchangeRequest, RefreshTokenValidation, Subject,
        backend::{RefreshTokenRotationRequest, RefreshTokenValidationRequest},
        oauth::PkceCodeChallengeMethod,
    };
    use serde_json::json;

    #[test]
    fn auth_store_config_rejects_invalid_login_session_ttl() {
        FirestoreAuthStoreConfig::new("test-pepper", 600, 0)
            .expect_err("zero login session ttl should fail");
        FirestoreAuthStoreConfig::new("test-pepper", 600, u64::MAX)
            .expect_err("oversized login session ttl should fail");
    }

    #[test]
    fn authorization_code_validation_requires_exact_proof() {
        let record = AuthorizationCodeRecord {
            token_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "http://127.0.0.1:7777/callback".to_string(),
            provider_sub: "provider-sub".to_string(),
            principal: "principal@example.com".to_string(),
            pkce_challenge: "challenge".to_string(),
            pkce_challenge_method: PkceCodeChallengeMethod::S256,
            created_unix: 1_000,
            expire_at: timestamp(2_000, "test authorization code expiry").unwrap(),
        };
        let request = OAuthAuthorizationCodeExchangeRequest {
            code_id: "code",
            expected_token_verifier: "verifier",
            expected_client_id: "client",
            expected_redirect_uri: "http://127.0.0.1:7777/callback",
            expected_pkce_challenge: "challenge",
            now_unix: 1_000,
        };

        let exchange = authorization_code_exchange_from_record(&record, &request)
            .expect("matching authorization code should validate");
        assert_eq!("provider-sub", exchange.provider_sub);
        assert_eq!("principal@example.com", exchange.principal);

        assert!(
            authorization_code_exchange_from_record(
                &record,
                &OAuthAuthorizationCodeExchangeRequest {
                    expected_token_verifier: "wrong",
                    ..request
                },
            )
            .is_none()
        );
    }

    #[test]
    fn oauth_refresh_validation_requires_verifier_and_client_binding() {
        let record = RefreshTokenRecord {
            sid: "sid".to_string(),
            family_id: "family".to_string(),
            token_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            created_unix: 1_000,
            expires_unix: 2_000,
            expire_at: None,
        };
        let session = GrantRecord {
            client_id: "client".to_string(),
            subject: Subject::new("user:principal@example.com").unwrap(),
            provider_sub: Some("provider-sub".to_string()),
            principal: Some("principal@example.com".to_string()),
            created_unix: 1_000,
            expires_unix: 2_000,
            revoked_unix: None,
            expire_at: None,
        };
        let request = RefreshTokenValidationRequest {
            token_id: "token",
            expected_token_verifier: "verifier",
            expected_client_id: "client",
            now_unix: 1_500,
        };

        let RefreshTokenValidation::Valid(rotation) =
            oauth_refresh_validation_from_records(&record, &session, &request)
        else {
            panic!("matching refresh token should validate");
        };
        assert_eq!("sid", rotation.sid);
        assert_eq!("provider-sub", rotation.provider_sub);
        assert_eq!("principal@example.com", rotation.principal);

        assert_eq!(
            RefreshTokenValidation::Invalid,
            oauth_refresh_validation_from_records(
                &record,
                &session,
                &RefreshTokenValidationRequest {
                    expected_token_verifier: "wrong",
                    ..request
                },
            )
        );
        assert_eq!(
            RefreshTokenValidation::Invalid,
            oauth_refresh_validation_from_records(
                &record,
                &session,
                &RefreshTokenValidationRequest {
                    expected_client_id: "other-client",
                    ..request
                },
            )
        );
    }

    #[test]
    fn refresh_rotation_renews_token_and_grant_expiry() {
        let record = RefreshTokenRecord {
            sid: "sid".to_string(),
            family_id: "family".to_string(),
            token_verifier: "old-verifier".to_string(),
            client_id: "client".to_string(),
            created_unix: 1_000,
            expires_unix: 1_600,
            expire_at: timestamp(1_600, "old refresh expiry").unwrap(),
        };
        let session = GrantRecord {
            client_id: "client".to_string(),
            subject: Subject::new("host:test").unwrap(),
            provider_sub: None,
            principal: None,
            created_unix: 1_000,
            expires_unix: 1_600,
            revoked_unix: None,
            expire_at: timestamp(1_600, "old grant expiry").unwrap(),
        };
        let (next_record, next_session) = rotated_refresh_records(
            &record,
            &session,
            &RefreshTokenRotationRequest {
                token_id: "old-token",
                expected_token_verifier: "old-verifier",
                expected_client_id: "client",
                next_token_id: "next-token",
                next_token_verifier: "next-verifier",
                next_expires_unix: 1_800,
                now_unix: 1_500,
            },
        )
        .expect("rotation records");

        assert_eq!("sid", next_record.sid);
        assert_eq!("family", next_record.family_id);
        assert_eq!("next-verifier", next_record.token_verifier);
        assert_eq!(1_500, next_record.created_unix);
        assert_eq!(1_800, next_record.expires_unix);
        assert_eq!(
            timestamp(1_800, "expected refresh expiry").unwrap(),
            next_record.expire_at
        );
        assert_eq!(1_000, next_session.created_unix);
        assert_eq!(1_800, next_session.expires_unix);
        assert_eq!(
            timestamp(1_800, "expected grant expiry").unwrap(),
            next_session.expire_at
        );
    }

    #[test]
    fn document_field_helpers_read_nested_firestore_values() {
        let document = json!({
            "updateTime": "2026-06-17T00:00:00.123456Z",
            "fields": {
                "refresh_token": {
                    "mapValue": {
                        "fields": {
                            "pepper": { "stringValue": "test-pepper" },
                            "ttl_seconds": { "integerValue": "3600" }
                        }
                    }
                }
            }
        });

        assert_eq!(
            document_update_time(&document, "v2/auth/refresh_tokens/token").unwrap(),
            "2026-06-17T00:00:00.123456Z"
        );
        assert_eq!(
            document_string_field(&document, "refresh_token.pepper").unwrap(),
            "test-pepper"
        );
        assert_eq!(
            document_integer_field(&document, "refresh_token.ttl_seconds").unwrap(),
            3_600
        );
    }

    #[test]
    fn rest_refresh_session_writes_create_session_and_token_atomically() {
        let store = FirestoreRestAuthStore::new("project-a", "v2/auth");
        let issued = RefreshTokenCodec::new("rt", "test-pepper", 600)
            .unwrap()
            .issue(1_000)
            .unwrap();
        let writes = store
            .refresh_session_writes(
                &issued,
                FirestoreRestRefreshTokenIssueRequest {
                    subject: "service:agent-1",
                    client_id: "aegis-agent",
                    now_unix: 1_000,
                },
            )
            .unwrap();
        let writes = writes.as_array().unwrap();

        assert_eq!(writes.len(), 2);
        assert_eq!(
            writes[0]["update"]["name"],
            format!(
                "projects/project-a/databases/(default)/documents/v2/auth/grants/{}",
                issued.sid()
            )
        );
        assert_eq!(
            writes[0]["update"]["fields"]["subject"]["stringValue"],
            "service:agent-1"
        );
        assert_eq!(
            writes[0]["update"]["fields"]["expire_at"]["timestampValue"],
            "1970-01-01T00:26:40Z"
        );
        assert_eq!(writes[0]["currentDocument"]["exists"], false);
        assert_eq!(
            writes[1]["update"]["name"],
            format!(
                "projects/project-a/databases/(default)/documents/v2/auth/refresh_tokens/{}",
                issued.token_id()
            )
        );
        assert_eq!(
            writes[1]["update"]["fields"]["token_verifier"]["stringValue"],
            issued.token_verifier()
        );
        assert_eq!(
            writes[1]["update"]["fields"]["expire_at"]["timestampValue"],
            "1970-01-01T00:26:40Z"
        );
        assert_eq!(writes[1]["currentDocument"]["exists"], false);
    }

    #[test]
    fn rest_cleanup_matchers_verify_issued_token_and_session_identity() {
        let issued = RefreshTokenCodec::new("rt", "test-pepper", 600)
            .unwrap()
            .issue(1_000)
            .unwrap();
        let issued_session =
            IssuedRefreshSession::new(issued.clone(), Subject::new("service:agent-1").unwrap());
        let token = json!({
            "fields": {
                "client_id": { "stringValue": "aegis-agent" },
                "created_unix": { "integerValue": issued.issued_unix().to_string() },
                "expires_unix": { "integerValue": issued.expires_unix().to_string() },
                "family_id": { "stringValue": issued.family_id() },
                "sid": { "stringValue": issued.sid() },
                "token_verifier": { "stringValue": issued.token_verifier() }
            }
        });
        let session = json!({
            "fields": {
                "client_id": { "stringValue": "aegis-agent" },
                "created_unix": { "integerValue": issued.issued_unix().to_string() },
                "expires_unix": { "integerValue": issued.expires_unix().to_string() },
                "subject": { "stringValue": "service:agent-1" }
            }
        });

        assert!(refresh_token_document_matches(&token, &issued).unwrap());
        assert!(
            refresh_session_document_matches(&session, &issued_session, "aegis-agent").unwrap()
        );

        let mut revoked_session = session;
        revoked_session["fields"]["revoked_unix"] = json!({ "integerValue": "1001" });
        assert!(
            !refresh_session_document_matches(&revoked_session, &issued_session, "aegis-agent")
                .unwrap()
        );
    }

    #[test]
    fn rest_unconsumed_refresh_session_delete_writes_use_update_time_preconditions() {
        let store = FirestoreRestAuthStore::new("project-a", "v2/auth");
        let issued = RefreshTokenCodec::new("rt", "test-pepper", 600)
            .unwrap()
            .issue(1_000)
            .unwrap();
        let writes = store
            .unconsumed_refresh_session_delete_writes(
                &issued,
                "2026-06-17T00:00:00.123456Z",
                "2026-06-17T00:00:01.123456Z",
            )
            .unwrap();
        let writes = writes.as_array().unwrap();

        assert_eq!(writes.len(), 2);
        assert_eq!(
            writes[0]["delete"],
            format!(
                "projects/project-a/databases/(default)/documents/v2/auth/refresh_tokens/{}",
                issued.token_id()
            )
        );
        assert_eq!(
            writes[0]["currentDocument"]["updateTime"],
            "2026-06-17T00:00:00.123456Z"
        );
        assert_eq!(
            writes[1]["delete"],
            format!(
                "projects/project-a/databases/(default)/documents/v2/auth/grants/{}",
                issued.sid()
            )
        );
        assert_eq!(
            writes[1]["currentDocument"]["updateTime"],
            "2026-06-17T00:00:01.123456Z"
        );
    }
}
