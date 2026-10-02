# Auth TTL policies

Enable Firestore TTL on `expire_at` for Phylax's authentication collection groups:
`login_sessions`, `codes`, `grants`, and `refresh_tokens`. Policies apply regardless
of parent path, including independent identity directories and namespace grants.
Expiry is enforced synchronously by the application; TTL removes abandoned records.

```sh
./phylax-gcp/infra/firestore/apply_auth_ttls.sh PROJECT_ID [DATABASE_ID]
```

The script submits bounded `gcloud` requests without rewriting documents.
Applications configure TTL policies for their own additional collection groups.
