#!/usr/bin/env sh
# Drops the given keyholders' databases (default: every .env-keyholder<N> in
# the project root) and runs setup-db.sh again, so they come back empty and
# built from the current db/schema.sql.
#
# Everything in those databases is lost; that is the point. It is for local
# development after a schema change. WITH (FORCE) disconnects a keyholder that
# is still running, so stop them first if you want a clean log.
#
#   npm run db:reset                         # every keyholder
#   sh scripts/reset-db.sh .env-keyholder2   # just one
set -eu

cd "$(dirname "$0")/.."
. scripts/find-psql.sh

if [ "${NODE_ENV:-}" = production ]; then
  echo "Refusing to drop databases with NODE_ENV=production." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- .env-keyholder[0-9]*
  if [ ! -f "$1" ]; then
    echo "No .env-keyholder<N> file found; nothing to reset." >&2
    exit 1
  fi
fi

for env_file in "$@"; do
  if [ ! -f "$env_file" ]; then
    echo "$env_file: no such file" >&2
    exit 1
  fi
  case $env_file in /*) ;; *) env_file="./$env_file" ;; esac

  (
    set -a
    . "$env_file"
    set +a

    : "${PGDATABASE:?PGDATABASE is not set in $env_file}"

    env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
      "$PSQL" -X -q -v ON_ERROR_STOP=1 -d postgres -v db_name="$PGDATABASE" <<'SQL'
SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'db_name')\gexec
SQL

    echo "$env_file: dropped database '$PGDATABASE'."
  )
done

exec sh scripts/setup-db.sh "$@"
