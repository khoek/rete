# phylax-core

Reusable OAuth and access-token primitives for Rust services and clients.

- Typed subjects, scopes, and JWT access claims with Ed25519 issuance/verification.
- Authorization-code and PKCE flows with explicit provider, storage, and access-policy contracts.
- Refresh-token encoding, validation, revocation, and rotation primitives.
- Axum adapters for authorization, token exchange, refresh, and revocation endpoints.

Applications choose identity providers, approved accounts, scopes, audiences, and
storage. This crate contains no application routes, namespace permissions, or
provider-specific account policy. `phylax-oidc` implements the OIDC provider
contract; `phylax-gcp` supplies Firestore persistence.

The `dangerous` module exposes explicitly unverified JWT decoding for inspection;
its results must not establish authorization.
