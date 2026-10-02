# firestore-common

Small Firestore helpers with no HTTP, authentication, or application dependency.

`DatabaseOptions` chooses a project, database, credentials (ADC or an explicit
access token), and connection deadline. `validate()` consumes raw options into a
`DatabaseConfig`; `connect()` performs the bounded connection. `Db` exposes the
underlying Firestore client for application-specific queries and transactions.

```rust,ignore
let db = firestore_common::DatabaseOptions {
    project_id: Some(project),
    ..Default::default()
}.validate()?.connect().await?;
```

Typed reads decode persisted fields without the Firestore client's injected
metadata, allowing strict Serde record schemas. Create-only writes use existence
preconditions and discard response metadata. Conflict helpers support explicit,
bounded initialization attempts. This crate defines no collection names, record
schemas, identity policy, or automatic migrations.
