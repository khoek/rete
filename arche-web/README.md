# arche-web

Shared HTTP infrastructure for Axum services.

- `server`: listener configuration, request deadlines, tracing, and graceful shutdown
- `proxy`: bounded forwarding with optional Cloud Run service authentication
- `error`: JSON errors with internal details confined to logs
