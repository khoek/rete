# phylax-core

OAuth and access-token primitives for Rust services and clients.

- Typed subjects, scopes, and JWT claims
- Authorization-code and PKCE flows
- Refresh-token encoding, validation, and rotation
- Axum endpoints with provider, storage, and access-policy contracts

`dangerous` exposes unverified JWT decoding for inspection, never authorization.
