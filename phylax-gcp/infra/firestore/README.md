# Authentication TTL policies

Enable `expire_at` cleanup for the `login_sessions`, `codes`, `grants`, and
`refresh_tokens` collection groups. Request-time expiry checks remain authoritative.

From the Rete workspace:

```sh
./phylax-gcp/infra/firestore/apply_auth_ttls.sh PROJECT_ID [DATABASE_ID]
```
