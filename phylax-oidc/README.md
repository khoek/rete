# phylax-oidc

OpenID Connect integration for `phylax-core`.

Discovers the configured issuer, performs authorization-code exchange with PKCE,
and validates ID tokens and nonces. Returns the provider subject and verified
email; applications decide account access. Network operations have explicit deadlines.
