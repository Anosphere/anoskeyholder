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

```bash
npm install
npm run make-keys                 # prints the key lines; paste them into .env-keyholder1
# write .env-keyholder1 from the Configuration section below; repeat for 2 to 5
npm run db:setup                  # role, databases, schema
npm run db:grant-anos-read        # the read-only role in each anos database
KEYHOLDER=1 npm start             # one terminal per keyholder
```

Then `POST http://localhost:3201/get-keyholder-public-key` with `{}` answers
keyholder 1's receiving key. The web app that drives it is
`~/Desktop/Z/test/keyholder-test-web-app` (`ng serve` on 4200), which deposits
shares on `http://localhost:3201` to `3205`.

## Scripts

| Command                          | Description                                                                 |
| -------------------------------- | --------------------------------------------------------------------------- |
| `KEYHOLDER=N npm start`          | Run keyholder N (loads `.env-keyholderN`)                                   |
| `KEYHOLDER=N npm run dev`        | Same, restarting on file changes                                            |
| `npm run db:setup`               | For every `.env-keyholder<N>`: the role, the database, the schema (idempotent; adds missing tables to a live database). Pass a file to do just one. |
| `npm run db:reset`               | Drop those databases and run setup again. Local data is lost; use after a change to an existing table. |
| `npm run db:grant-anos-read`     | For every `.env-keyholder<N>`: in its anos database, as a superuser, create the `ANOS_PGUSER` role if missing, sync its password, grant `CONNECT`, `USAGE` on `public` and `SELECT` on `accounts` and `stakes`, nothing else. Pass a file to do just one. |
| `npm run make-keys`              | Print fresh env lines: the receiving pair, a home pair (public for the env, private shown once for the home computer), two P-256 pairs standing in for YubiKeys (public for the env, private shown once), `BUCKET_ONE_KEY`, `KMS_LOCAL_KEY`. |

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
`decrypt(ciphertext, aad)`, and two providers chosen by `KMS_PROVIDER`:
`gcp` (`@google-cloud/kms` on the key `KMS_KEY_NAME`, credentials from the
VM's service account) and `local` (AES-256-GCM under `KMS_LOCAL_KEY`, for
this Mac).

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
set -a && source .env-keyholder1 && set +a && psql
```

## Configuration

One keyholder = one process = one file `.env-keyholderN`, started with
`KEYHOLDER=N npm start` (`node --env-file=.env-keyholder$KEYHOLDER
src/server.js`), as the validators are. The files are git-ignored and there
is no example file in the repository; this is `.env-keyholder1` for the
local setup, with the key lines from `npm run make-keys`:

```bash
PORT=3201
KEYHOLDER_ID=1

# The keyholder's own database.
PGHOST=127.0.0.1
PGPORT=5432
PGDATABASE=keyholder1
PGUSER=keyholdersoftware
PGPASSWORD=<a password>

# The validator's anos database, read only.
ANOS_PGHOST=127.0.0.1
ANOS_PGPORT=5432
ANOS_PGDATABASE=anos1
ANOS_PGUSER=keyholder_reader
ANOS_PGPASSWORD=<a password>

# Whole anos, the same values as the validator's env. The attestor minimum
# defaults to 1000 when its line is missing.
STAKE_MIN_MODERATOR_ANOS=1000
STAKE_MIN_ATTESTOR_ANOS=1000

WEB_ORIGIN=http://localhost:4200
MASTERPOD_URL=http://localhost:3100
RECOVERY_POD_HOSTS=localhost,127.0.0.1
TIMESTAMP_WINDOW_SECONDS=120

# From npm run make-keys: PKCS#8 DER in hex, 48 and 86 bytes.
RECEIVING_X25519_PRIVATE_KEY=<96 hex characters>
RECEIVING_MLKEM_PRIVATE_KEY=<172 hex characters>

# From npm run make-keys: the home computer's public halves, raw hex, 32 and 1568 bytes.
HOME_X25519_PUBLIC_KEY=<64 hex characters>
HOME_MLKEM_PUBLIC_KEY=<3136 hex characters>

# The two YubiKeys' P-256 public keys, 33-byte compressed points (or the stand-ins from make-keys).
KEYHOLDER_PUBLIC_KEY_1=<66 hex characters>
KEYHOLDER_PUBLIC_KEY_2=<66 hex characters>

# 32 bytes hex each.
BUCKET_ONE_KEY=<64 hex characters>
KMS_PROVIDER=local
KMS_LOCAL_KEY=<64 hex characters>
```

| Variable                                                                    | Default                 | Description                                                                                   |
| --------------------------------------------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------- |
| `PORT`                                                                      | `3200`                  | Port the server listens on (`3201` to `3205` locally)                                         |
| `KEYHOLDER_ID`                                                              | required                | This keyholder's number, its validator's id; answered as `keyholderId`                        |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`                    | host `127.0.0.1`, port `5432`, rest required | The keyholder's own database: `keyholder1` to `keyholder5`, role `keyholdersoftware` locally |
| `ANOS_PGHOST`, `ANOS_PGPORT`, `ANOS_PGDATABASE`, `ANOS_PGUSER`, `ANOS_PGPASSWORD` | host `127.0.0.1`, port `5432`, rest required | The validator's anos database, read only: `anos1` to `anos5` locally, `anos` on a VM, role `keyholder_reader` |
| `STAKE_MIN_MODERATOR_ANOS`                                                  | required                | Whole anos, the same value as the validator's env; converted to millionths once               |
| `STAKE_MIN_ATTESTOR_ANOS`                                                   | `1000`                  | Whole anos, the same value as the validator's env; attestor stake at or above it admits an account to the two bucket key routes; converted to millionths once |
| `WEB_ORIGIN`                                                                | `http://localhost:4200` | CORS allow-list, the phone                                                                    |
| `MASTERPOD_URL`                                                             | `http://localhost:3100` | Where `/get-anopod-session-keys` is                                                           |
| `RECOVERY_POD_HOSTS`                                                        | `localhost,127.0.0.1`   | Comma-separated hosts a decrypt route may post to                                             |
| `TIMESTAMP_WINDOW_SECONDS`                                                  | `120`                   | Allowed clock difference on a signed request, each way; nonces live twice this long           |
| `RECEIVING_X25519_PRIVATE_KEY`, `RECEIVING_MLKEM_PRIVATE_KEY`               | required                | The receiving key pair, PKCS#8 DER hex (48 and 86 bytes)                                      |
| `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY`                           | required                | The home computer's hybrid public key, raw hex (32 and 1568 bytes)                            |
| `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2`                          | required                | The two YubiKeys' P-256 public keys, 33 bytes hex                                             |
| `BUCKET_ONE_KEY`                                                            | required                | 32 bytes hex, wraps bucket-one shares                                                         |
| `KMS_PROVIDER`                                                              | `local`                 | `local` or `gcp`                                                                              |
| `KMS_LOCAL_KEY`                                                             | required when `local`   | 32 bytes hex                                                                                  |
| `KMS_KEY_NAME`                                                              | required when `gcp`     | `projects/.../locations/.../keyRings/.../cryptoKeys/...`, protection level HSM                 |

`src/config/env.js` checks all of them at boot: every private value fails
when missing or the wrong length, `KMS_PROVIDER` must be one of the two and
its one variable present. The receiving key pair is loaded into key objects
at boot too (`src/crypto/keyholder-keys.js`), so a value that is hex of the
right length but not a key fails there.

## Running five keyholders

Each keyholder is one process with its own file, `.env-keyholder1` to
`.env-keyholder5`. They listen on 3201 to 3205, use databases `keyholder1`
to `keyholder5` under the role `keyholdersoftware`, and read `anos1` to
`anos5` as `keyholder_reader`, all in the one local PostgreSQL. Each needs
its own `npm run make-keys` output, or the five receiving keys would be the
same; the home key and the YubiKey keys may well be shared.

```bash
npm run db:setup              # five databases
npm run db:grant-anos-read    # keyholder_reader in anos1 to anos5
KEYHOLDER=1 npm start         # one terminal per keyholder
```

The masterpod must be up on `MASTERPOD_URL` for `/receive-share` to verify a
pod; the moderator routes need the validator's anos database and nothing
else.

## On a validator's VM

One VM is one validator and one keyholder, so the VM has one
`.env-keyholder1` (or whatever the validator's id is) with `PGDATABASE` its
own database, `ANOS_PGDATABASE=anos`, `KMS_PROVIDER=gcp` and `KMS_KEY_NAME`
a Cloud KMS key whose protection level is HSM. The VM's service account needs
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on that key and nothing more;
the client reads its credentials from the VM. The home computer's private key
never touches the VM; `make-keys` prints it once, on the machine that runs it.

```bash
sudo -u postgres sh scripts/setup-db.sh .env-keyholder1
sudo -u postgres sh scripts/grant-anos-read.sh .env-keyholder1
KEYHOLDER=1 npm start
```

## Layout

```
src/
  server.js              boots: checks both databases, listens, shuts down cleanly
  app.js                 builds the Express app: CORS, JSON limit, mounts the routers
  config/env.js          reads and validates the environment once
  db/pool.js             the shared pg pool to the keyholder's database, query() and closePool()
  db/anos-pool.js        the read-only pool to the validator's anos database, anosQuery() and closeAnosPool()
  db/transaction.js      withTransaction(fn) and the unique-violation check
  crypto/                bytes, canonical JSON, SHA-256, P-256 and ML-DSA-87 (copies of anossoftware's);
                         aead.js (AES-256-GCM), hybrid.js (X25519 + ML-KEM-1024, spec 7.1), keyholder-keys.js (the key material, loaded at boot)
  kms/                   kms.js (the interface), local.js and gcp.js (the providers)
  util/                  ids, is-object, the ok/refuse/answer result shape
  auth/                  requirePod, requireModerator, requireModeratorOrAttestor, requireKeyholder; the envelope, the shared checks, nonces,
                         the masterpod client, the anos reads
  info/                  /get-keyholder-public-key
  shares/                /receive-share (receive.service.js), the moderator reads (moderator.service.js),
                         the keyholder reads and decrypt-and-forward (keyholder.service.js, forward.js);
                         wraps.js (spec section 6), share-types.js, the queries, handlers and router
  health/                GET /health: status, uptime, database round trip
  middleware/            404 and the central error handler
db/
  schema.sql             the whole schema, built from nothing
scripts/
  setup-db.sh            role, databases, schema for each env file (idempotent)
  reset-db.sh            drop and set up again
  grant-anos-read.sh     the read-only role and its grants in each anos database
  find-psql.sh           finds Homebrew's keg-only psql
  make-keys.js           prints fresh key lines for an env file
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
