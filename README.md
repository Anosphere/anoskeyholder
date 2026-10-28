# keyholdersoftware

The keyholder server for the anos system: an Express 5 server backed by
PostgreSQL, laid out like anossoftware and masterpodsoftware so the three read
alike. One keyholder runs on each validator's VM next to anossoftware and
reads two tables of that validator's anos database. Five validators, five
keyholders.

It holds Shamir shares. The phone splits each of four secrets into five
shares, one per keyholder, and sends each keyholder its share encrypted to
that keyholder's receiving key. No keyholder ever holds a whole secret, and
the keyholder never splits or combines anything; it stores what it is handed,
wrapped as the table below says, and gives it back to the right party. The
specification is `docs/schemas.md`; `docs/build-plan.md` is how it was built.

| `shareType`       | The secret                                                    | Who gets the share back                 |
| ----------------- | ------------------------------------------------------------- | --------------------------------------- |
| `securitybucket1` | the key one add to security bucket one was encrypted under    | a moderator or an attestor              |
| `securitybucket2` | the key one add to security bucket two was encrypted under    | a moderator or an attestor              |
| `breakglasskey`   | the anos account's break-glass key                            | the keyholder, for the recovery pod     |
| `backupcode`      | the anoPod's backup code                                      | the keyholder, for the recovery pod     |

Besides the shares, the keyholder stores two ids per person, both computed by
the phone: the `lookupId`, stored as handed, and the `publicLedgerId`, stored
encrypted and read back by moderators.

## Requirements

- Node.js 24 or newer (X25519, ML-KEM-1024, P-256, ML-DSA-87, HKDF and AES-GCM
  are built in; the server has no crypto dependency)
- PostgreSQL 17 or newer, running locally, with the validator's anos database
  in it (anossoftware's `npm run db:setup`)

## Getting started

On the VM, as the user `anos`, in `/opt/anos/keyholdersoftware`, after the
validator; the operator guide, `guides/operator-guide.md`, kept beside the repos in the testnet folder,
is the whole install, both servers, in the order of the visit:

```bash
npm ci
npm run make-keys -- --id <N>                   # keyholder.key (mode 0600) and .env; five lines in .env to fill
sudo -u postgres sh scripts/setup-db.sh         # role, database, schema
sudo -u postgres sh scripts/grant-anos-read.sh  # the read-only role in the anos database
npm start                                       # loads network/testnet.env, then .env
```

Then `POST http://127.0.0.1:3200/get-keyholder-public-key` with `{}` on the
VM answers this keyholder's receiving key.

## Scripts

| Command                          | Description                                                                 |
| -------------------------------- | --------------------------------------------------------------------------- |
| `npm start`                      | Run this keyholder: `node --env-file=network/testnet.env --env-file=.env src/server.js` |
| `npm run dev`                    | Same, restarting on file changes                                            |
| `npm run make-keys -- --id <N>`  | Once, on the VM: the receiving pair and the bucket-one key into `keyholder.key` (JSON, mode 0600, never shown) and `.env` with the id, two random database passwords, the key file's path and five `<fill in>` lines (the Cloud KMS key name, the home computer's two public halves, the two YubiKeys' public keys). Refuses to run when either file exists. Prints the receiving public halves and the lines to fill; nothing to paste. `--key-file <path>` puts the key elsewhere. |
| `npm run db:setup`               | Create the role, the database and the schema (idempotent; adds missing tables to a live database). Loads `network/testnet.env` then `.env`; pass a machine file to use another. On the VM: `sudo -u postgres sh scripts/setup-db.sh`. |
| `npm run db:reset`               | Drop that database and run setup again. Everything in it is lost.          |
| `npm run db:grant-anos-read`     | In the anos database, as a superuser: create the `ANOS_PGUSER` role if missing, sync its password, grant `CONNECT`, `USAGE` on `public` and `SELECT` on `accounts` and `stakes`, nothing else. The same two files. On the VM: `sudo -u postgres sh scripts/grant-anos-read.sh`. |

## Who may call what

Every route is a `POST` with a JSON body. Four levels, the moderator level
in a wider form on the two bucket key routes:

| Level     | Meaning                                                                                                   |
| --------- | --------------------------------------------------------------------------------------------------------- |
| none      | Plain JSON body, no signature.                                                                            |
| pod       | Signed by an anoPod's current masterpod session keys, both signatures. The keys are fetched from the masterpod for every call. |
| moderator | Signed by an anos account's primary key pair, both signatures, and the account holds moderator stake in the validator's anos database. |
| moderator or attestor | Signed as a moderator; the account holds moderator stake or attestor stake (`STAKE_MIN_ATTESTOR_ANOS`, default 1000). The two bucket key routes only, since 2026-10-26 (`docs/schemas.md` section 13). |
| keyholder | One P-256 signature by either of the two YubiKeys listed in the env file.                                  |

Four middlewares, `requirePod`, `requireModerator`, `requireModeratorOrAttestor`
and `requireKeyholder` (`src/auth/`). Failing them: `401` for anything wrong
with a signature, a session or a nonce, `403 not a moderator` (`403 not a
moderator or attestor` on the two bucket key routes), `502 masterpod
unavailable` when the masterpod does not answer. Other errors are `{ error: '<reason>' }` with
`400` for a bad shape or value, `403` for a caller who may not do this, `404`
for a thing that does not exist, `409` for a conflict with what is already
there, `502` when another server did not answer.

### The request envelope

The envelope is the masterpod's. The field that names the signer differs by
level: `anopodId` for a pod, `accountId` for a moderator, `yubikey` (the
lowercase hex of the YubiKey's 33-byte public key) for the keyholder.

```json
{
  "payload": {
    "accountId": "<hex 32 bytes, the moderator's anos account>",
    "path":      "/get-security-bucket-one-key",
    "timestamp": "2026-10-24T18:00:00.000Z",
    "nonce":     "<hex 16 to 32 bytes, never reused>",
    "body":      { "lookupId": "<hex 32>", "responseKey": { "x25519": "<hex 32>", "mlkem": "<hex 1568>" } }
  },
  "signatures": { "ecdsa": "<hex 64>", "mldsa": "<hex 4627>" }
}
```

The signatures are over the RFC 8785 canonical bytes of `payload`
(`canonicalize` on both ends): P-256 as 64-byte r||s (DER accepted, since a
PIV slot signs in DER) and ML-DSA-87, pure, empty context; the keyholder
level has `ecdsa` only. The middlewares check, in order: the shape, `path` is
this route, `timestamp` is within `TIMESTAMP_WINDOW_SECONDS` of the server
clock, the level's own checks (the pod's session keys from the masterpod and
its expiry; the moderator's keys and stake from the anos database; the
YubiKey is one of the two), the signatures, and `nonce` is new (`401 replay`
otherwise). `body` is the route's own object. Who is asking always comes from
the verified signature, never from the body.

Ids are 32 bytes, hex on the wire (base64 accepted), `BYTEA` in the database.
Hex is the wire form for every byte string.

## Endpoints

| Route                           | Level     | Does                                                                                       |
| ------------------------------- | --------- | ------------------------------------------------------------------------------------------ |
| `/get-keyholder-public-key`     | none      | `{ keyholderId, receivingKey: { x25519, mlkem } }`: the public halves the phone encrypts every share to |
| `/receive-share`                | pod       | Deposits one share: `{ lookupId, publicLedgerId, shareType, keyId, share }`, the share encrypted to the receiving key; the first share for a lookup id writes the owner; `201 { shareId, keyholderId }` |
| `/get-security-bucket-one-key`  | moderator or attestor | Every `securitybucket1` share of a lookup id, newest first, each encrypted to the caller's one-time `responseKey` |
| `/get-security-bucket-two-key`  | moderator or attestor | The same for `securitybucket2`                                                 |
| `/get-public-ledger-id`         | moderator | The owner's public ledger id, encrypted to the caller's `responseKey`                      |
| `/get-break-glass-key`          | keyholder | Every `breakglasskey` share of a lookup id as stored: the KMS-wrapped share encrypted to the home computer's hybrid key. Nothing is opened |
| `/get-backup-code`              | keyholder | The same for `backupcode`                                                                  |
| `/decrypt-break-glass-key`      | keyholder | Takes `{ shareId, kmsBlob, destination: { url, hybridKey } }`: opens the KMS layer the home computer handed back, encrypts the share to the destination's key and posts it to a recovery pod on an allowed host; `{ shareId, delivered: true, recoveryPod: { status, body } }` |
| `/decrypt-backup-code`          | keyholder | The same for a `backupcode` share                                                          |

And one route on the masterpod, added for the keyholders:

| Route (masterpod)               | Level     | Does                                                                                       |
| ------------------------------- | --------- | ------------------------------------------------------------------------------------------ |
| `/get-anopod-session-keys`      | none      | `{ anopodId }` in, the pod's current session public keys and their expiry out; `requirePod` calls it on every `/receive-share` |

The objects each route takes and answers, with every check in order, are in
`docs/schemas.md` section 5.

## What the server stores

Authenticated data (AAD) binds a ciphertext to its row, so a blob moved to
another row does not open. For a share at rest the AAD is `share_id ||
lookup_id || share_type || key_id`; for the public ledger id it is
`lookup_id`. In transit (phone to keyholder, keyholder to moderator or
recovery pod) it is `lookup_id || share_type || key_id`.

| `shareType`       | `wrap`               | Stored `share`                                                                                       |
| ----------------- | -------------------- | ---------------------------------------------------------------------------------------------------- |
| `securitybucket1` | `env-aes-gcm-v1`     | AES-256-GCM under `BUCKET_ONE_KEY`: `iv (12) || ciphertext || tag (16)`                              |
| `securitybucket2` | `kms-v1`             | the KMS ciphertext of the share                                                                      |
| `breakglasskey`   | `kms-home-hybrid-v1` | the KMS ciphertext of the share, then encrypted to the home computer's hybrid key with the same AAD   |
| `backupcode`      | `kms-home-hybrid-v1` | as above                                                                                             |

So a break-glass or backup-code blob at rest needs two parties to open: the
home computer's private key, which never touches the VM, and the KMS key,
which only this VM's service account may use. The get routes hand the blob
out, the home computer peels the hybrid layer, the decrypt routes peel the
KMS layer and forward the share.

The server opens exactly three things: the share the phone encrypted to its
receiving key, on arrival; a bucket share, for a moderator; a KMS-wrapped
share the home computer hands back, to forward it. It never holds a whole
secret and never writes a plaintext share to disk or log.

The KMS (`src/kms/`) has one interface, `encrypt(plaintext, aad)` and
`decrypt(ciphertext, aad)`, and one provider, Cloud KMS (`gcp.js`:
`@google-cloud/kms` on the key `KMS_KEY_NAME`, protection level HSM, in the
operator's own project and region, credentials from the VM's service
account); `kms.js` re-exports it. At boot the server encrypts and decrypts
a fixed plaintext through it and logs `KMS ok`, or stops with
`KMS self-test failed: <reason>`.

Encrypting to a hybrid key (`src/crypto/hybrid.js`, spec 7.1): a fresh X25519
pair `e`, `ss1 = X25519(e, R.x25519)`, `(ct, ss2) = ML-KEM-1024.Encaps(R.mlkem)`,
`key = HKDF-SHA-256(ss1 || ss2, salt = e.public || ct, info = 'keyholder/hybrid/v1', 32)`,
then AES-256-GCM; the wire form is `e.public (32) || ct (1568) || iv (12) || c || tag (16)`.

## Database tables

`db/schema.sql`, applied by `npm run db:setup`. No foreign keys; the
services keep the references straight. Every table and column has a
`COMMENT ON` (`\d+ <table>` in psql). No row ever changes: `owners` and
`shares` refuse `UPDATE` and `DELETE` through a trigger, and there is no
`updated_at`.

| Table    | Holds                                                                                                    |
| -------- | -------------------------------------------------------------------------------------------------------- |
| `owners` | One row per person: `lookup_id` as handed, `public_ledger_id` under the KMS key, the `anopod_id` that deposited first |
| `shares` | One row per share received: the wrapped `share`, its `wrap`, its `share_type`, the phone's `key_id` (unique) |
| `nonces` | The replay cache of signed requests, one table for every signer; swept by each insert                    |

Because the names follow libpq, `psql` connects to a keyholder's database with
no arguments once its file is loaded:

```bash
set -a && . network/testnet.env && . .env && set +a && psql
```

## Configuration

Two env files, loaded in this order by `npm start` and by the systemd unit
(`node --env-file=network/testnet.env --env-file=.env src/server.js`); where
both name a variable the later file wins. `src/config/env.js` reads them
once at boot.

- `network/testnet.env`, committed: every value that is the same on every
  VM of the testnet. No secrets. Each line has a comment.
- `.env`, git-ignored: what differs per machine, written by
  `npm run make-keys -- --id <N>`: four lines with values and five left as
  `<fill in>` for the operator, each under a comment saying what goes there.
  `.example.env` shows them.

Shared values, in `network/testnet.env`:

| Variable                         | Testnet                            | Description                                                                 |
| -------------------------------- | ---------------------------------- | --------------------------------------------------------------------------- |
| `PGHOST`, `PGPORT`               | `127.0.0.1`, `5432`                | The keyholder's own database server, the VM itself                          |
| `PGUSER`, `PGDATABASE`           | `keyholdersoftware`, `keyholder`   | Its role and database                                                       |
| `ANOS_PGHOST`, `ANOS_PGPORT`     | `127.0.0.1`, `5432`                | The validator's anos database server, the same VM                           |
| `ANOS_PGUSER`, `ANOS_PGDATABASE` | `keyholder_reader`, `anos`         | The read-only role and the database                                         |
| `PORT`                           | `3200`                             | Port the server listens on, behind the doorman                              |
| `STAKE_MIN_MODERATOR_ANOS`       | `1000`                             | Whole anos, the same value as the validator's; converted to millionths once |
| `STAKE_MIN_ATTESTOR_ANOS`        | `1000`                             | Whole anos, the same value as the validator's; attestor stake at or above it admits an account to the two bucket key routes; `1000` when the line is absent |
| `WEB_ORIGIN`                     | `<fill in>`                        | The wallet's origin for CORS, scheme, host and port, no path; a comma-separated list when there is more than one |
| `MASTERPOD_URL`                  | `<fill in>`                        | The masterpod's load balancer, scheme, host and port, no path: where `/get-anopod-session-keys` is |
| `RECOVERY_POD_HOSTS`             | `<fill in>`                        | Comma-separated hosts a decrypt route may post a share to: the masterpod's load balancer host alone, no scheme, no port |
| `TIMESTAMP_WINDOW_SECONDS`       | `120`                              | Allowed clock difference on a signed request, each way; nonces live twice this long |

Machine values, in `.env`:

| Variable                                           | Description                                                                 |
| -------------------------------------------------- | --------------------------------------------------------------------------- |
| `KEYHOLDER_ID`                                     | This keyholder's number, its validator's id; answered as `keyholderId`      |
| `PGPASSWORD`                                       | The keyholder's own role's password, 32 hex characters from make-keys       |
| `ANOS_PGPASSWORD`                                  | The read-only role's password, 32 hex characters from make-keys             |
| `KEY_FILE`                                         | The key file, relative to the repo root or absolute; `./keyholder.key` when the line is absent. JSON `{ receivingX25519PrivateKey, receivingMlkemPrivateKey, bucketOneKey }` (PKCS#8 DER hex of 48 and 86 bytes, and 32 bytes hex), mode 0600: the server refuses a file that is missing, not a regular file, unreadable, or readable by group or other, naming the path and the mode |
| `KMS_KEY_NAME`                                     | `<fill in>` from make-keys: the Cloud KMS key, `projects/<project>/locations/<region>/keyRings/anos-testnet/cryptoKeys/keyholder-<N>`, protection level HSM |
| `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY`  | `<fill in>` from make-keys: the home computer's hybrid public key, raw hex (32 and 1568 bytes), from the operator's keyholder GUI |
| `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2` | `<fill in>` from make-keys: the two YubiKeys' P-256 public keys, 33 bytes hex, from the same GUI |

`src/config/env.js` checks all of them at boot: `KEYHOLDER_ID` and the
stake minimums as positive integers, the public keys as hex of the right
length, `WEB_ORIGIN` and `RECOVERY_POD_HOSTS` as lists with at least one
item (hosts lowercased), the rest as present. A value still `<fill in>` is
refused by name: `KMS_KEY_NAME is still "<fill in>": fill it in
network/testnet.env or .env`. `PORT`, the two hosts and ports,
`TIMESTAMP_WINDOW_SECONDS` and the attestor minimum keep their defaults in
the code, though the shared file names them too. The key file is read and
the receiving pair loaded into key objects at boot
(`src/crypto/keyholder-keys.js`), so a value that is hex of the right
length but not a key fails there.

The `<fill in>` values are double-quoted in both files because the
database scripts source them with `sh`, which would read a bare `<` as a
redirection; Node strips the quotes.

## Running

One VM is one validator and one keyholder: one keyholder process, started
by `npm start` or by the systemd unit `deploy/anos-keyholder.service`,
which runs the same command as the user `anos` in
`/opt/anos/keyholdersoftware` and restarts it five seconds after a
failure. The boot log, in order:

```
Keyholder <id>
Connected to PostgreSQL 17.x at 127.0.0.1:5432/keyholder
Connected to the anos database (PostgreSQL 17.x) at 127.0.0.1:5432/anos, read only
KMS ok
Keyholder <id> listening on http://localhost:3200
```

A configuration error stops the process with a message naming the
variable, the key file or the KMS failure; under systemd it is retried
every five seconds, and `journalctl -fu anos-keyholder` shows the reason
each time. The masterpod must be up on `MASTERPOD_URL` for `/receive-share`
to verify a pod; the moderator routes need the validator's anos database
and nothing else.

## On a validator's VM

The install, both servers on one Debian 13 worker VM, is the operator
guide, `guides/operator-guide.md`, kept beside the repos in the testnet folder:
the VM and its packages, the Cloud KMS key in the
operator's own project and the VM's region, the user `anos` and the two
clones under `/opt/anos`, `make-keys` in each repo, the databases, the
registry row and the systemd units, in the order of the onboarding visit.

At boot the keyholder round-trips a fixed plaintext through that key and
logs `KMS ok`; a wrong key name, a missing role on the key or an
unreachable API stops it with `KMS self-test failed: <reason>` before it
listens. The home computer's private key and the YubiKeys' private keys
never touch the VM: only their public halves are in `.env`.

## Layout

```
src/
  server.js              boots: prints who this is, checks both databases, self-tests Cloud KMS, listens, shuts down cleanly
  app.js                 builds the Express app: CORS, JSON limit, mounts the routers
  config/env.js          reads and validates the two env files once (network/testnet.env, then .env)
  db/pool.js             the shared pg pool to the keyholder's database, query() and closePool()
  db/anos-pool.js        the read-only pool to the validator's anos database, anosQuery() and closeAnosPool()
  db/transaction.js      withTransaction(fn) and the unique-violation check
  crypto/                bytes, canonical JSON, SHA-256, P-256 and ML-DSA-87 (copies of anossoftware's);
                         aead.js (AES-256-GCM), hybrid.js (X25519 + ML-KEM-1024, spec 7.1), key-file.js (reads and checks the key file),
                         keyholder-keys.js (the key material, loaded at boot from the key file and .env)
  kms/                   kms.js (the interface, a re-export of the one provider) and gcp.js (Cloud KMS)
  util/                  ids, is-object, the ok/refuse/answer result shape, version (the commit and tag git reports, for /health)
  auth/                  requirePod, requireModerator, requireModeratorOrAttestor, requireKeyholder; the envelope, the shared checks, nonces,
                         the masterpod client, the anos reads
  info/                  /get-keyholder-public-key
  shares/                /receive-share (receive.service.js), the moderator reads (moderator.service.js),
                         the keyholder reads and decrypt-and-forward (keyholder.service.js, forward.js);
                         wraps.js (spec section 6), share-types.js, the queries, handlers and router
  health/                GET /health: status, uptime, database round trip, id, commit, tag
  middleware/            404 and the central error handler
db/
  schema.sql             the whole schema, built from nothing
scripts/
  setup-db.sh            role, database and schema, from network/testnet.env and the machine file (idempotent)
  reset-db.sh            drop and set up again
  grant-anos-read.sh     the read-only role and its grants in the anos database
  find-psql.sh           finds psql
  make-keys.js           once, on the VM: the key file and .env; prints the receiving public halves and the lines to fill
network/
  testnet.env            every value that is the same on every VM, committed
deploy/
  anos-keyholder.service the systemd unit, identical on every VM
docs/
  schemas.md             the specification: tables, routes, objects, crypto, variables, notes from the build
  build-plan.md          how it was built
```

Each feature folder owns its router (the paths and their levels), its
handlers (HTTP in and out only), its services (the checks in the spec's
order, returning `ok(status, body)` or `refuse(status, reason)`) and its
queries (the SQL). Every multi-row write is one transaction through
`db/transaction.js`.

## Deferred, by decision

- Who may read buckets, and when: today any moderator or attestor, any
  lookup id, no user in the loop, no release log. For the testnet.
- Rotation of the receiving key, the home key, the YubiKeys, the bucket-one
  key or the KMS key. The `wrap` column is there for it.
- The real public ledger id algorithm and the lookup id rule; the web app
  uses stand-ins.
- Break-glass shares from the wallet app.
- The keyholder's home application (the YubiKey, the home private key, the
  get, peel, decrypt sequence) and the recovery pod on the masterpod,
  including what it does with the posted share.
- Discovery: how the real phone learns the five keyholders and their keys.
  The web app hardcodes them.
- Anti-abuse limits, purging owners who never finished, metadata privacy.
