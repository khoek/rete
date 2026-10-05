# phylax-gcp

Firestore storage for Phylax authentication.

- OAuth login sessions, authorization codes, grants, and rotating refresh tokens
- Account directories with optional provider/subject bindings and disablement
- Live access-session validation for immediate revocation
- Explicit signing-key initialization that preserves existing keys

Applications choose document paths and authorization policy. Enable the
[TTL policies](infra/firestore/README.md) for expired-record cleanup.
