#!/usr/bin/env bash

set -euo pipefail

project_id="${1:?usage: ./apply_auth_ttls.sh <gcp-project-id> [database-id]}"
database_id="${2:-"(default)"}"

collections=(
  "login_sessions"
  "codes"
  "grants"
  "refresh_tokens"
)

for collection in "${collections[@]}"; do
  timeout --signal=TERM --kill-after=10s 120s gcloud firestore fields ttls update expire_at \
    --project="${project_id}" \
    --database="${database_id}" \
    --collection-group="${collection}" \
    --enable-ttl \
    --async
done

echo
echo "TTL enablement requested for auth expire_at fields in database ${database_id}."
echo "Check progress with:"
for collection in "${collections[@]}"; do
  echo "  gcloud firestore fields ttls list --project=${project_id} --database=${database_id} --collection-group=${collection}"
done
