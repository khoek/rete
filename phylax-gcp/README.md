# phylax-gcp

Firestore persistence for Phylax authentication primitives. It depends on
`phylax-core` and the small `firestore-common` storage helpers, with no dependency
on either API application or the shared HTTP runtime.

The auth stores persist OAuth login sessions, authorization codes, grants, and
rotating refresh tokens. They enforce expiry and transaction preconditions.

`identity` provides a configurable account directory: issuer/subject bindings,
approved user records, disablement/session versions, token configuration, and
explicit signing-key initialization. Applications select the document location,
issuer, audience, provider, and authorization policy; there are no built-in
application paths, namespace roles, or email-based authorization rules.

```rust,ignore
let directory = phylax_gcp::identity::IdentityOptions {
    document_path: "services/example/identity/config".into(),
}.validate()?.connect(db);
```

Identity initialization validates named options and preserves existing key
material. It rejects conflicting settings. Account creation binds an external
subject and its user in a single transaction, so an existing subject cannot be
reassigned by creating another account.

Enable the [authentication TTL policies](infra/firestore/README.md) for eventual
cleanup. Request-time expiry checks do not depend on TTL cleanup timing.
