# arche-web

Reusable HTTP infrastructure. This crate has no database, account-directory, OIDC,
Aegis, or Deus dependencies.

- `server`: validated listener/deadline options, response cache policy, tracing,
  and graceful Tokio/Axum serving. Trace spans omit query strings.
- `proxy`: bounded HTTP forwarding to a fixed validated origin, with explicit
  deadlines/body limits and no redirects or request retries. It preserves methods,
  raw paths/queries, application authorization, status, headers, and bodies while
  removing hop-by-hop headers. Optional Cloud Run authentication uses
  `X-Serverless-Authorization` separately from application `Authorization`, following
  [Google's service authentication contract](https://docs.cloud.google.com/run/docs/authenticating/service-to-service).
- `error`: a small JSON HTTP error representation that hides internal errors from
  clients while logging their cause.

Options validate into runtime configuration before opening listeners or clients.
Applications own routes, authentication policy, and authorization.

Related pieces have separate dependency boundaries:
[firestore-common](../firestore-common/README.md) owns database access;
[phylax-gcp](../phylax-gcp/README.md) owns Firestore authentication/identity stores;
[phylax-oidc](../phylax-oidc/README.md) implements provider login.
