#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
runtime="${CONTAINER_RUNTIME:-podman}"
run_id="soca-odoo-$(date +%s)-$$"
network="$run_id"
db="$run_id-db"
image="localhost/odoo-soca-test:latest"
cleanup() {
  "$runtime" rm -f "$run_id-host" "$db" >/dev/null 2>&1 || true
  "$runtime" network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
"$runtime" network create "$network" >/dev/null
"$runtime" run -d --name "$db" --network "$network" -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=soca-disposable-test -e POSTGRES_DB=postgres docker.io/library/postgres:16@sha256:485935f94cc7165afa896978809c37b592dc07f0a37d2c8f645f12412d0212c8 >/dev/null
"$runtime" build -t "$image" -f Containerfile .
for attempt in $(seq 1 60); do
  if "$runtime" exec "$db" pg_isready -U odoo >/dev/null 2>&1; then break; fi
  if [ "$attempt" = 60 ]; then exit 1; fi
  sleep 1
done
"$runtime" run --rm --name "$run_id-host" --network "$network" --entrypoint odoo "$image" --db_host="$db" --db_user=odoo --db_password=soca-disposable-test --database=soca_test --init=auth_soca --test-enable --test-tags=/auth_soca --stop-after-init --without-demo=True --http-interface=127.0.0.1 --log-level=test
