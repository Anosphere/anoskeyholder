#!/usr/bin/env sh
# Gives each keyholder read access to its validator's anos database. Safe to
# re-run.
#
# For each env file given (default: every .env-keyholder<N> in the project
# root), as a superuser over the local unix socket:
#   1. in the postgres database: creates the ANOS_PGUSER role if it is
#      missing and syncs its password to ANOS_PGPASSWORD,
#   2. in ANOS_PGDATABASE: grants CONNECT on the database, USAGE on schema
#      public and SELECT on accounts and stakes. Nothing else: the keyholder
#      reads a moderator's keys and stake and writes nothing there.
#
# The anos database is the validator's, created by anossoftware's own
# db:setup; this script never creates or changes a table.
#
#   local (Homebrew):   npm run db:grant-anos-read                     # every keyholder
#                       sh scripts/grant-anos-read.sh .env-keyholder2  # just one
#   VM (Debian):        sudo -u postgres sh scripts/grant-anos-read.sh .env-keyholder1
set -eu

cd "$(dirname "$0")/.."
. scripts/find-psql.sh

if [ "$#" -eq 0 ]; then
  set -- .env-keyholder[0-9]*
  if [ ! -f "$1" ]; then
    echo "No .env-keyholder<N> file found. Create .env-keyholder1 from the README's Configuration section first." >&2
    exit 1
  fi
fi

for env_file in "$@"; do
  if [ ! -f "$env_file" ]; then
    echo "$env_file: no such file" >&2
    exit 1
  fi
  case $env_file in /*) ;; *) env_file="./$env_file" ;; esac

  # A subshell, so one file's variables never leak into the next.
  (
    set -a
    . "$env_file"
    set +a

    : "${ANOS_PGDATABASE:?ANOS_PGDATABASE is not set in $env_file}"
    : "${ANOS_PGUSER:?ANOS_PGUSER is not set in $env_file}"
    : "${ANOS_PGPASSWORD:?ANOS_PGPASSWORD is not set in $env_file}"

    # The role: as the current OS user over the local socket, so the app's
    # PG* variables are unset for this call. %I and %L in format() quote
    # identifiers and literals safely.
    env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
      "$PSQL" -X -q -v ON_ERROR_STOP=1 -d postgres \
      -v reader="$ANOS_PGUSER" -v reader_password="$ANOS_PGPASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'reader', :'reader_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'reader')\gexec

SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'reader', :'reader_password')\gexec
SQL

    # The grants: in the anos database, still as the superuser.
    env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
      "$PSQL" -X -q -v ON_ERROR_STOP=1 -d "$ANOS_PGDATABASE" \
      -v reader="$ANOS_PGUSER" -v db_name="$ANOS_PGDATABASE" <<'SQL'
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db_name', :'reader')\gexec

SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'reader')\gexec

SELECT format('GRANT SELECT ON accounts, stakes TO %I', :'reader')\gexec
SQL

    echo "$env_file: role '$ANOS_PGUSER' may read accounts and stakes in '$ANOS_PGDATABASE'."
  )
done
