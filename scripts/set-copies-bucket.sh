#!/usr/bin/env sh
# Writes the SHARE_COPIES_BUCKET line into this keyholder's .env: the name of
# the bucket every share is also copied to (docs/schemas.md, section 16),
# <project id>-share-copies, in the project this VM runs in. Safe to re-run.
#
# The project id is read from the VM's own metadata server. Then, in .env in
# the project root, the file make-keys wrote:
#   1. no SHARE_COPIES_BUCKET line: a comment line and the line are added at
#      the end,
#   2. the line names that bucket: nothing is changed,
#   3. the line names another bucket: nothing is changed and the script
#      stops, naming both.
# It prints one line, "SHARE_COPIES_BUCKET: written <name>" or
# "SHARE_COPIES_BUCKET: already <name>". It stops, saying which, when there
# is no .env or the metadata server does not answer. No other line of .env
# is read, changed or shown. The bucket itself is not touched: the Cloud
# Shell line makes it (the operator guide, step 15).
#
# No argument. Run it as the user that owns .env:
#
#   VM (Debian):   sudo -iu anos sh /opt/anos/keyholdersoftware/scripts/set-copies-bucket.sh
set -eu

cd "$(dirname "$0")/.."

ENV_FILE=.env
METADATA=http://169.254.169.254/computeMetadata/v1

if [ ! -f "$ENV_FILE" ]; then
  echo "$ENV_FILE: no such file. Run 'npm run make-keys -- --id <N>' first; it writes .env." >&2
  exit 1
fi

# The project id: the call the worker script makes for the KMS key name.
if ! PROJECT=$(curl -sS -f -m 10 -H 'Metadata-Flavor: Google' "$METADATA/project/project-id"); then
  echo "The metadata server at 169.254.169.254 does not answer. Is this a Compute Engine VM?" >&2
  exit 1
fi
# A project id is lowercase letters, digits and hyphens. Nothing else goes
# into a file the database scripts source.
case $PROJECT in
  '' | *[!a-z0-9-]*)
    echo "The metadata server at 169.254.169.254 answered \"$PROJECT\", not a project id." >&2
    exit 1
    ;;
esac
BUCKET="$PROJECT-share-copies"

# The line as it stands, read with sed on that line alone.
if grep -q '^SHARE_COPIES_BUCKET=' "$ENV_FILE"; then
  CURRENT=$(sed -n 's/^SHARE_COPIES_BUCKET=//p' "$ENV_FILE" | head -n 1)
  if [ "$CURRENT" != "$BUCKET" ]; then
    echo "SHARE_COPIES_BUCKET in $ENV_FILE is $CURRENT, but this VM's project gives $BUCKET." >&2
    exit 1
  fi
  echo "SHARE_COPIES_BUCKET: already $BUCKET"
  exit 0
fi

# A last line without its newline gets one first, so the comment starts on
# a line of its own.
if [ -n "$(tail -c 1 "$ENV_FILE")" ]; then
  echo >> "$ENV_FILE"
fi
{
  echo "# The bucket every share is also copied to, in this VM's own project; written by scripts/set-copies-bucket.sh."
  echo "SHARE_COPIES_BUCKET=$BUCKET"
} >> "$ENV_FILE"
echo "SHARE_COPIES_BUCKET: written $BUCKET"
