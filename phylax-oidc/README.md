# phylax-oidc

Provider-neutral OIDC adapter implementing
`phylax_core::AuthorizationCodeOAuthProvider`. Supply named `OidcOptions`, validate
them, and connect the resulting configuration. Issuer discovery and token exchange
have bounded HTTP deadlines and do not follow redirects.

The adapter requests `openid`, `email`, and `profile`, validates the ID token and
nonce, requires a verified email, and returns the provider's immutable subject and
canonical email. Applications own account approval, identity mapping, scopes,
audiences, and session storage. No application routes, Firestore paths, or Google
client configuration are built into this crate.
