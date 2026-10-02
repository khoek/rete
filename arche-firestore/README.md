# arche-firestore

Connection and document helpers for the `firestore` SDK.

- Validated configuration and a client initialization deadline
- Application Default Credentials or an explicit access token
- Typed reads that exclude SDK-injected metadata
- Create-only writes and bootstrap conflict helpers

`Db` exposes the underlying client for queries and transactions.
