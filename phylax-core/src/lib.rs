mod claims;
mod endpoint;
mod jwt;
pub mod oauth;
mod oauth_endpoint;
mod opaque_token;

pub mod dangerous {
    pub use crate::jwt::decode_unverified_claims;
}

pub use claims::{AUTHORIZED_PARTY_CLAIM, AccessClaims, ScopeSet, Subject};
pub use endpoint::{
    AccessTokenGrant, FormRevokeTokenEndpoint, FormRevokeTokenGrant, FormRevokeTokenRequest,
    JsonRefreshTokenEndpoint, JsonRefreshTokenExchange, JsonRefreshTokenGrant,
    JsonRefreshTokenGrantRequest, JsonRefreshTokenRequest, JsonRefreshTokenResponse,
    RefreshTokenValidation, TokenEndpointError, form_revoke_token_router,
    json_refresh_token_router,
};
pub use jwt::{JwtConfig, JwtIssuer};
pub use oauth_endpoint::{
    AuthorizationCodeOAuthConfig, AuthorizationCodeOAuthEndpoint, AuthorizationCodeOAuthPolicy,
    AuthorizationCodeOAuthProvider, AuthorizationCodeOAuthStore, OAuthAccessGrant,
    OAuthAccessGrantError, OAuthAuthorizationCode, OAuthAuthorizationCodeExchange,
    OAuthAuthorizationCodeExchangeRequest, OAuthAuthorizationCodeGrantRequest,
    OAuthAuthorizationCodeIssueRequest, OAuthCallbackQuery, OAuthCommittedRefreshTokenGrant,
    OAuthEndpointError, OAuthGrantError, OAuthIssuedAuthorizationCode, OAuthLoginSession,
    OAuthProviderAuthorization, OAuthProviderAuthorizationRequest,
    OAuthProviderCodeExchangeRequest, OAuthRefreshTokenGrantRequest, OAuthRefreshTokenIssueRequest,
    OAuthRefreshTokenRotation, OAuthTokenFormRequest, OAuthTokenSuccess, OAuthVerifiedIdentity,
    authorization_code_oauth_router, authorization_code_oauth_router_without_callback,
};
pub use opaque_token::random_urlsafe_string;

pub mod backend {
    pub use crate::endpoint::{RefreshTokenRotationRequest, RefreshTokenValidationRequest};
    pub use crate::opaque_token::{
        IssuedRefreshToken, IssuedRefreshTokenReplacement, OpaqueToken, OpaqueTokenCodec,
        RefreshTokenCodec,
    };
}
