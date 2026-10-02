use async_trait::async_trait;
use openidconnect::core::*;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use phylax_core::{
    AuthorizationCodeOAuthProvider, OAuthProviderAuthorization, OAuthProviderAuthorizationRequest,
    OAuthProviderCodeExchangeRequest, OAuthVerifiedIdentity,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcOptions {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}
pub struct ValidatedOidcOptions(OidcOptions);
impl OidcOptions {
    pub fn validate(self) -> anyhow::Result<ValidatedOidcOptions> {
        for value in [&self.issuer_url, &self.redirect_uri] {
            let url = url::Url::parse(value)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
                    && url.query().is_none(),
                "OIDC URLs must be HTTPS URLs without credentials, queries, or fragments"
            );
        }
        anyhow::ensure!(
            !self.client_id.trim().is_empty() && !self.client_secret.trim().is_empty(),
            "OIDC client credentials are required"
        );
        Ok(ValidatedOidcOptions(self))
    }
}
type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct OidcProvider {
    client: OidcClient,
    http_client: openidconnect::reqwest::Client,
}

impl OidcProvider {
    pub async fn connect(cfg: ValidatedOidcOptions) -> anyhow::Result<Self> {
        let http_client = openidconnect::reqwest::Client::builder()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(cfg.0.issuer_url.clone())?,
            &http_client,
        )
        .await?;
        let client: OidcClient = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(cfg.0.client_id.clone()),
            Some(ClientSecret::new(cfg.0.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(cfg.0.redirect_uri.clone())?);
        Ok(Self {
            client,
            http_client,
        })
    }
}

#[async_trait]
impl AuthorizationCodeOAuthProvider for OidcProvider {
    fn authorization_url(
        &self,
        request: OAuthProviderAuthorizationRequest,
    ) -> anyhow::Result<OAuthProviderAuthorization> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let nonce = Nonce::new_random();
        let authorize_nonce = nonce.clone();
        let (auth_url, _state, _nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                || CsrfToken::new(request.state),
                move || authorize_nonce.clone(),
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        Ok(OAuthProviderAuthorization {
            url: auth_url.to_string(),
            session_state: serde_json::to_string(&OidcSessionState {
                pkce_verifier: pkce_verifier.secret().to_string(),
                nonce: nonce.secret().to_string(),
            })?,
        })
    }

    async fn exchange_code(
        &self,
        request: OAuthProviderCodeExchangeRequest,
    ) -> anyhow::Result<OAuthVerifiedIdentity> {
        let session: OidcSessionState = serde_json::from_str(&request.session_state)
            .map_err(|error| anyhow::anyhow!("invalid OIDC session state: {error}"))?;
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(request.code))
            .map_err(|error| anyhow::anyhow!("authorization code exchange failed: {error}"))?
            .set_pkce_verifier(openidconnect::PkceCodeVerifier::new(session.pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|error| anyhow::anyhow!("authorization code exchange failed: {error}"))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("no id_token in response"))?;
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &Nonce::new(session.nonce))
            .map_err(|error| anyhow::anyhow!("invalid id_token: {error}"))?;
        if claims.email_verified() != Some(true) {
            anyhow::bail!("verified email required");
        }

        Ok(OAuthVerifiedIdentity {
            provider_sub: claims.subject().to_string(),
            principal: canonical_oauth_principal(
                claims
                    .email()
                    .map(|email| email.as_str())
                    .ok_or_else(|| anyhow::anyhow!("email claim required"))?,
            )?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OidcSessionState {
    pkce_verifier: String,
    nonce: String,
}

fn canonical_oauth_principal(value: &str) -> anyhow::Result<String> {
    let value = value.trim().to_ascii_lowercase();
    anyhow::ensure!(
        !value.is_empty() && !value.chars().any(char::is_whitespace),
        "verified email is invalid"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_validation_has_no_deployment_specific_assumptions() {
        let valid = OidcOptions {
            issuer_url: "https://identity.example/tenant".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://aegis.example/v2/oauth/callback".into(),
        };
        valid.clone().validate().unwrap();
        assert!(
            OidcOptions {
                issuer_url: "http://identity.example".into(),
                ..valid.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            OidcOptions {
                redirect_uri: "https://user:password@aegis.example/callback".into(),
                ..valid.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            OidcOptions {
                client_secret: "".into(),
                ..valid
            }
            .validate()
            .is_err()
        );
    }
}
