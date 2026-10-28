# Schemas: the keyholder

Design settled 2026-10-24 over four rounds of questions. This file is the
specification for the build laid out in `build-plan.md`: every table, every
route, every object a route receives and answers, what the server does to a
share before storing it, and what the phone has to produce. Nothing is built
yet; the README is written as part of the build and, until then, this file
is the only description.

## 0. What the keyholder is

A third Express 5 + PostgreSQL server, laid out like anossoftware and
masterpodsoftware so the three read alike. One keyholder runs on each
validator's VM next to anossoftware, and reads two tables of that
validator's anos database. Five validators, five keyholders.

It holds Shamir shares. The phone splits each of four secrets into five
shares, one per keyholder, and sends each keyholder its share. No keyholder
ever holds a whole secret, and the keyholder never splits or combines
anything; it stores what it is handed and gives it back to the right party.
The four secrets:

| `shareType` | The secret | Who gets the share back |
| ----------- | ---------- | ----------------------- |
| `securitybucket1` | the key one add to security bucket one was encrypted under (masterpod) | a moderator |
| `securitybucket2` | the key one add to security bucket two was encrypted under (masterpod) | a moderator |
| `breakglasskey` | the anos account's break-glass key | the keyholder, for the recovery pod |
| `backupcode` | the anoPod's backup code (masterpod) | the keyholder, for the recovery pod |

Besides the shares, the keyholder stores two ids per person: the `lookupId`
and the `publicLedgerId`. Both are 32-byte values the phone computes and
hands over; the keyholder stores them and computes neither. The public
ledger id is stored encrypted and read back by moderators.

Four parties talk to it. The phone deposits shares. A moderator, an anos
account with moderator stake, asks for bucket shares and public ledger ids.
The keyholder's own home computer, authenticated with a YubiKey, pulls
break-glass and backup-code blobs and then has the server unwrap and
forward them to a recovery pod. The server itself calls the masterpod once
per deposit, to fetch the depositing pod's session keys, and posts to a
recovery pod when told to.

## 1. Conventions

- Every authenticated request is `{ payload, signatures }`, signatures over
  the RFC 8785 canonical bytes of `payload` (the `canonicalize` npm package
  on both ends, as in the siblings). Who is asking always comes from the
  verified signature, never from the body.
- Signatures: P-256 (64 bytes r||s over the SHA-256 of the message, DER
  accepted) and ML-DSA-87 (4627 bytes, pure, empty context), hex on the wire.
  P-256 public keys 33 bytes compressed (65 accepted), ML-DSA-87 public keys
  2592 bytes. The signature helpers are copies of anossoftware's
  `src/crypto/`.
- Hybrid public keys are two keys side by side: X25519 (32 bytes) and
  ML-KEM-1024 (1568 bytes), as `{ x25519, mlkem }` hex. Section 7 says how
  something is encrypted to one.
- Ids are 32 bytes: 64 lowercase hex characters on the wire, `BYTEA` with a
  length check in the database. Hex is the wire form for every byte string;
  base64 is accepted wherever hex is (`decodeBytes` tells them apart by
  length).
- JSON field names are camelCase, database names snake_case, table names
  plural.
- Amounts of anos are millionths, `BIGINT`, as in anossoftware; the only
  amount here is the moderator stake minimum, read from the env file in whole
  anos and converted once.
- Timestamps are ISO 8601 strings.
- Every table has `created_at`. No row in this server ever changes, so there
  is no `updated_at` and no `set_updated_at` trigger; `owners` and `shares`
  are append-only, enforced by a trigger. Every table and column gets a
  `COMMENT ON`. No foreign keys, as in the siblings; the services keep the
  references straight.
- Errors are `{ error: '<reason>' }`: `400` bad shape or value, `401`
  anything wrong with a signature, a session or a nonce, `403` a caller who
  may not do this, `404` a thing that does not exist, `409` a conflict with
  what is already there, `502` another server did not answer. Reasons are
  short lowercase phrases.
- The server opens exactly three things: the share the phone encrypted to
  its receiving key, on arrival; a bucket share, for a moderator; a
  KMS-wrapped share the home computer hands back, to forward it. It never
  holds a whole secret and never writes a plaintext share to disk or log.

## 2. Who may call what

Four levels. A route's level is given with the route in section 5.

| Level | Meaning | Routes |
| ----- | ------- | ------ |
| none | Plain JSON body, no signature. | `/get-keyholder-public-key` |
| pod | Signed by an anoPod's current masterpod session keys, both signatures (section 3.1). | `/receive-share` |
| moderator | Signed by an anos account's primary key pair, both signatures, and the account holds moderator stake (3.2). | `/get-security-bucket-one-key`, `/get-security-bucket-two-key`, `/get-public-ledger-id` |
| keyholder | One P-256 signature by either of the two YubiKeys listed in the env file (3.3). | `/get-break-glass-key`, `/get-backup-code`, `/decrypt-break-glass-key`, `/decrypt-backup-code` |

Three middlewares: `requirePod`, `requireModerator`, `requireKeyholder`.
Failing them: `401` for the signature, session or nonce, `403 not a
moderator`.

## 3. Request signing

The envelope is the masterpod's. The field that names the signer differs
by level: `anopodId` for a pod, `accountId` for a moderator, `yubikey` for
the keyholder.

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

`body` is the route's object from section 5. Common to the three
middlewares, in this order, stopping at the first failure:

1. Shape: `payload` an object with the signer field, `path`, `timestamp`,
   `nonce` as strings and `body` an object; `signatures` an object with
   string `ecdsa`, and string `mldsa` at the pod and moderator levels.
   Otherwise `400 bad request shape`.
2. `path` equals the request path, else `401 path mismatch`.
3. `timestamp` parses and is within `TIMESTAMP_WINDOW_SECONDS` (120) of the
   server clock either way, else `401 timestamp outside window`.
4. The level's own checks (3.1 to 3.3).
5. `nonce` decodes to 16 to 32 bytes and `INSERT INTO nonces` succeeds; a
   duplicate is `401 replay`. The insert also deletes expired nonces.
   `expires_at` is now plus twice the window. One table for every signer.
6. `req.body` becomes `payload.body`; the signer is on `req.pod`,
   `req.moderator` or `req.yubikey`.

### 3.1 Pod

`anopodId` decodes to 32 bytes, else `400`. The server posts
`{ anopodId }` to `MASTERPOD_URL/get-anopod-session-keys` (section 5.10)
with a 5-second timeout. No answer or a `5xx`: `502 masterpod unavailable`.
`404`: `401 unknown anopod`. The answer's `ephemeralExpiresAt` in the past:
`401 session expired`. Both signatures verify over the canonical payload
against the answer's `ephemeralAuthKey` and `ephemeralAuthKeyPq`, else `401
bad signature`. Keys are fetched for every call and never cached: a new
unlock replaces them.

### 3.2 Moderator

`accountId` decodes to 32 bytes, else `400`. From the anos database, read
only: `SELECT public_key1, public_key_pq1 FROM accounts WHERE account_id =
$1`, none: `401 unknown account`; `SELECT moderator_stake FROM stakes WHERE
account_id = $1`, none or below `STAKE_MIN_MODERATOR_ANOS` in millionths:
`403 not a moderator`. Both signatures verify against the two keys, else
`401 bad signature`. Any moderator may call any moderator route for any
lookup id; limits are a testnet matter (section 11).

### 3.3 Keyholder

`yubikey` is lowercase hex of a 33-byte compressed P-256 public key and
equals `KEYHOLDER_PUBLIC_KEY_1` or `KEYHOLDER_PUBLIC_KEY_2`, else `401
unknown key`. `signatures.ecdsa` verifies over the canonical payload
against that key, else `401 bad signature`. 64-byte r||s and DER are both
accepted, since a PIV slot signs in DER. There is no post-quantum signature
at this level: forging it yields blobs only the home computer's hybrid key
opens.

## 4. Tables

The DDL below goes into `db/schema.sql` in this order, each table with its
header comment, trigger and `COMMENT ON` lines in the style of the sibling
schemas. `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`
throughout, so `npm run db:setup` adds what is missing to a live database.

```sql
-- Refuses UPDATE and DELETE on append-only tables.
CREATE OR REPLACE FUNCTION refuse_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;
```

### owners

One row per person, written by the first `/receive-share` call for a lookup
id, never changed.

```sql
CREATE TABLE IF NOT EXISTS owners (
  lookup_id        BYTEA       PRIMARY KEY CHECK (octet_length(lookup_id) = 32),
  public_ledger_id BYTEA       NOT NULL CHECK (octet_length(public_ledger_id) <= 1024),
  anopod_id        BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE TRIGGER owners_append_only
  BEFORE UPDATE OR DELETE ON owners
  FOR EACH ROW EXECUTE FUNCTION refuse_change();
```

`lookup_id` and `anopod_id` are stored as handed. `public_ledger_id` is the
32-byte id as handed, encrypted under the KMS key with `lookup_id` as
authenticated data (section 6); the column is wider than 32 because KMS
ciphertext carries a header.

### shares

One row per share received. Several rows per lookup id and type are normal:
every add to a security bucket has its own key, and a backup code is
replaced when it rotates. `key_id` tells them apart.

```sql
CREATE TABLE IF NOT EXISTS shares (
  share_id   BYTEA       PRIMARY KEY CHECK (octet_length(share_id) = 32),
  lookup_id  BYTEA       NOT NULL CHECK (octet_length(lookup_id) = 32),
  share_type TEXT        NOT NULL CHECK (share_type IN ('securitybucket1', 'securitybucket2', 'breakglasskey', 'backupcode')),
  key_id     BYTEA       NOT NULL UNIQUE CHECK (octet_length(key_id) = 32),
  share      BYTEA       NOT NULL CHECK (octet_length(share) <= 8192),
  wrap       TEXT        NOT NULL CHECK (wrap IN ('env-aes-gcm-v1', 'kms-v1', 'kms-home-hybrid-v1')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shares_lookup_id_share_type_idx ON shares (lookup_id, share_type, created_at DESC);
CREATE OR REPLACE TRIGGER shares_append_only
  BEFORE UPDATE OR DELETE ON shares
  FOR EACH ROW EXECUTE FUNCTION refuse_change();
```

`share_id` is 32 random bytes made by the server. `key_id` is the 32 random
bytes the phone made for the secret this share belongs to, the same on all
five keyholders and, later, in the masterpod's records of what that key
encrypted; a repeated `key_id` is refused. `share` is the share bytes
protected as `wrap` says (section 6); the column is wide enough for a share
of a 32-byte secret under every wrap, with room for KMS headers and larger
secrets.

### nonces

```sql
CREATE TABLE IF NOT EXISTS nonces (
  nonce      BYTEA       PRIMARY KEY CHECK (octet_length(nonce) BETWEEN 16 AND 32),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires_at_idx ON nonces (expires_at);
```

Rows are deleted as they expire by the insert that adds a new one.

## 5. Routes

Every route is a `POST` with a JSON body. The level `none` route takes the
body as shown; every other route takes the section 3 envelope and the body
shown is `payload.body`. Checks run in the order listed and stop at the
first failure. Every multi-row write is one database transaction.
`keyholderId` in answers is `KEYHOLDER_ID`, the number of this keyholder,
the same as its validator's id.

### 5.1 POST /get-keyholder-public-key (none)

Body: `{}`.

Answer: `200 { keyholderId, receivingKey: { x25519, mlkem } }`, the public
halves of `RECEIVING_X25519_PRIVATE_KEY` and `RECEIVING_MLKEM_PRIVATE_KEY`,
raw bytes in hex (32 and 1568). The phone encrypts every share to this key
before sending it.

### 5.2 POST /receive-share (pod)

The phone deposits one share. The signer, `payload.anopodId`, is the pod
the share belongs to.

```json
{
  "lookupId":       "<hex 32>",
  "publicLedgerId": "<hex 32>",
  "shareType":      "securitybucket1",
  "keyId":          "<hex 32, made by the phone for this secret>",
  "share":          "<hex, the share encrypted to the receiving key, at most 4096 bytes>"
}
```

Checks:

1. Shape: the five string fields; `400 bad request shape`.
2. `lookupId`, `publicLedgerId`, `keyId` decode to 32 bytes; `shareType` is
   one of the four; `share` decodes to at most 4096 bytes. `400` naming the
   field.
3. `keyId` is not in `shares`: else `409 key id already stored`.
4. `share` opens with the receiving private key (section 7) with
   authenticated data `lookupId || shareType || keyId` (raw bytes; the type
   as UTF-8), and the plaintext is 1 to 256 bytes: else `400 share does not
   open`. A share of a 32-byte secret is 33 bytes.
5. `owners` has no row for `lookupId`: one is written with
   `public_ledger_id` encrypted under KMS (authenticated data `lookupId`)
   and `anopod_id = payload.anopodId`. It has one: its `anopod_id` must
   equal `payload.anopodId`, else `409 anopod mismatch`. The handed
   `publicLedgerId` is not compared against the stored one.
6. The share bytes are wrapped as section 6 says for `shareType` and
   inserted with a fresh `share_id`.

Steps 5 and 6 are one transaction; the KMS calls happen before it opens.

Answer: `201 { shareId, keyholderId }`.

### 5.3 POST /get-security-bucket-one-key (moderator)
### 5.4 POST /get-security-bucket-two-key (moderator)

Body: `{ lookupId, responseKey: { x25519, mlkem } }`. `responseKey` is a
hybrid public key the moderator's app made for this one request; the answer
is encrypted to it, so a recording of the connection is useless later.

Checks: shape; `lookupId` 32 bytes; `responseKey.x25519` 32 bytes,
`responseKey.mlkem` 1568 bytes (`400` naming the field); an `owners` row
exists, else `404 unknown lookup id`.

Reads: every `shares` row with that `lookup_id` and the route's type
(`securitybucket1` or `securitybucket2`), newest first. Each share is
unwrapped (section 6) and encrypted to `responseKey` with authenticated
data `lookupId || shareType || keyId`.

Answer: `200 { lookupId, shareType, keyholderId, shares: [ { shareId,
keyId, createdAt, share } ] }`, `share` the hybrid ciphertext in hex. An
owner with no shares of that type gets an empty list.

### 5.5 POST /get-public-ledger-id (moderator)

Body: `{ lookupId, responseKey }`, as above. Checks as above.

Reads the owner's `public_ledger_id`, decrypts it with KMS (authenticated
data `lookupId`), encrypts the 32 bytes to `responseKey` with authenticated
data `lookupId`.

Answer: `200 { lookupId, publicLedgerId }`, `publicLedgerId` the hybrid
ciphertext in hex. Nothing else.

### 5.6 POST /get-break-glass-key (keyholder)
### 5.7 POST /get-backup-code (keyholder)

Body: `{ lookupId }`. Checks: shape; 32 bytes; an `owners` row exists,
else `404 unknown lookup id`.

Reads every `shares` row with that `lookup_id` and the route's type
(`breakglasskey` or `backupcode`), newest first. The `share` column is
returned as stored: the KMS-wrapped share, encrypted to the home computer's
hybrid key. The server opens nothing here.

Answer: `200 { lookupId, shareType, keyholderId, shares: [ { shareId,
keyId, createdAt, blob } ] }`, `blob` hex. The home computer opens the
hybrid layer with its private key and gets the KMS-wrapped share, which
only this server, through KMS, can open.

### 5.8 POST /decrypt-break-glass-key (keyholder)
### 5.9 POST /decrypt-backup-code (keyholder)

The home computer hands back a KMS-wrapped share and says where the share
goes.

```json
{
  "shareId":     "<hex 32, from the get route>",
  "kmsBlob":     "<hex, the KMS-wrapped share the home computer unwrapped, at most 4096 bytes>",
  "destination": {
    "url":       "https://masterpod.example/recovery-pod/<id>",
    "hybridKey": { "x25519": "<hex 32>", "mlkem": "<hex 1568>" }
  }
}
```

Checks:

1. Shape; `400 bad request shape`.
2. `shareId` decodes and its row exists, else `404 unknown share`; the
   row's `share_type` is the route's, else `400 wrong share type`.
3. `destination.url` parses as an `http` or `https` URL whose host is in
   `RECOVERY_POD_HOSTS`, else `403 destination not allowed`.
   `destination.hybridKey` has the two lengths, else `400`.
4. `kmsBlob` decrypts through KMS with authenticated data `shareId ||
   lookupId || shareType || keyId` taken from the row, else `400 blob does
   not open`. The blob is bound to this row: a blob from another share does
   not open here.
5. The plaintext share is encrypted to `destination.hybridKey` with
   authenticated data `lookupId || shareType || keyId` and posted to
   `destination.url` as

   ```json
   { "keyholderId": 1, "lookupId": "<hex>", "shareType": "backupcode", "keyId": "<hex>", "share": "<hex>" }
   ```

   with a 10-second timeout. No answer: `502 recovery pod unreachable`.

Answer: `200 { shareId, delivered: true, recoveryPod: { status, body } }`,
`status` the recovery pod's HTTP status and `body` its JSON answer, or its
text if it did not send JSON. The recovery pod's own route is the
masterpod's business and is not in this build.

### 5.10 masterpod: POST /get-anopod-session-keys (none)

The one addition to masterpodsoftware. Body: `{ anopodId }`. Checks:
shape and 32 bytes, `400 bad request shape`; the row exists, else `404
unknown anopod`.

Answer: `200 { anopodId, ephemeralAuthKey, ephemeralAuthKeyPq,
ephemeralExpiresAt }`, the row's current session public keys in hex (33
and 2592) and the expiry. Public keys are public; the route has no
signature. Lives in `src/anopods/` beside `/get-anopod-profile`.

## 6. What the server stores, per type

Authenticated data (AAD) binds a ciphertext to its row, so a blob moved to
another row does not open. For a share, AAD is `share_id || lookup_id ||
share_type || key_id`, raw bytes with the type as UTF-8; for the public
ledger id it is `lookup_id`. The `wrap` column says which of the three
layouts a share has, so a future key rotation can tell old rows from new.

| `shareType` | `wrap` | Stored `share` |
| ----------- | ------ | -------------- |
| `securitybucket1` | `env-aes-gcm-v1` | AES-256-GCM under `BUCKET_ONE_KEY`: `iv (12) || ciphertext || tag (16)` |
| `securitybucket2` | `kms-v1` | the KMS ciphertext of the share |
| `breakglasskey` | `kms-home-hybrid-v1` | the KMS ciphertext of the share, then encrypted to the home computer's hybrid key (`HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY`) with the same AAD |
| `backupcode` | `kms-home-hybrid-v1` | as above |

So a break-glass or backup-code blob at rest needs two parties to open:
the home computer's private key, which never touches the VM, and the KMS
key, which only this VM's service account may use. The flow in 5.6 to 5.9
peels them in that order.

The KMS module has one interface, `encrypt(plaintext, aad)` and
`decrypt(ciphertext, aad)`, and two providers chosen by `KMS_PROVIDER`:

- `gcp`: `@google-cloud/kms`, `encrypt` / `decrypt` on the key
  `KMS_KEY_NAME` (a `cryptoKeys` resource name whose protection level is
  HSM) with `additionalAuthenticatedData`. Credentials come from the VM's
  service account; locally, Google's own `GOOGLE_APPLICATION_CREDENTIALS`.
  Plaintext is at most 64 KiB; shares are tiny.
- `local`: AES-256-GCM under `KMS_LOCAL_KEY` with the same AAD, `iv (12) ||
  ciphertext || tag (16)`. For this Mac. Behaves the same, logs nothing.

## 7. Crypto

Every helper is `node:crypto`; Node 24 has X25519, ML-KEM-1024 (`encapsulate`,
`decapsulate`), P-256, ML-DSA-87, HKDF and AES-GCM built in. No crypto
dependency on the server. The phone uses `@noble/curves` (`x25519`) and
`@noble/post-quantum` (`ml_kem1024`); both directions were tested against
Node on 2026-10-24 and agree.

### 7.1 Encrypting to a hybrid key

Recipient key `R = { x25519 (32), mlkem (1568) }`, plaintext `m`, AAD `a`:

1. Fresh X25519 pair `e`; `ss1 = X25519(e.private, R.x25519)`, 32 bytes.
2. `(ct, ss2) = ML-KEM-1024.Encaps(R.mlkem)`, `ct` 1568 bytes, `ss2` 32.
3. `key = HKDF-SHA-256(ikm = ss1 || ss2, salt = e.public || ct, info =
   'keyholder/hybrid/v1', 32)`.
4. `iv` 12 random bytes; `c || tag = AES-256-GCM(key, iv, m, a)`.
5. Wire: `e.public (32) || ct (1568) || iv (12) || c || tag (16)`, hex. That
   is 1628 bytes plus the plaintext.

Decrypting reverses it with `R`'s two private keys. The salt binds the key
to this encapsulation, so a ciphertext cannot be re-targeted. The info
string gets a new version if anything here changes.

### 7.2 Key encodings

Raw bytes on the wire and in the env for public keys: X25519 32, ML-KEM-1024
1568, P-256 33 compressed. Node takes SPKI DER, which for a fixed
algorithm is a constant prefix in front of the raw bytes, as
anossoftware's `signatures.js` does for P-256 and ML-DSA-87:

| Key | SPKI prefix (hex) |
| --- | ----------------- |
| X25519 | `302a300506032b656e032100` |
| ML-KEM-1024 | `30820632300b06096086480165030404030382062100` |

Private keys in the env file are PKCS#8 DER in hex, like a validator's
`PRIVATE_KEY`: 48 bytes for X25519, 86 for ML-KEM-1024 (Node exports the
seed form). `createPrivateKey({ key, format: 'der', type: 'pkcs8' })` loads
both; checked 2026-10-24.

### 7.3 Signatures

`src/crypto/{bytes,canonical,hash,signatures}.js` are anossoftware's,
verbatim. The keyholder signs nothing; it verifies pod, moderator and
YubiKey signatures.

## 8. The phone (test web app 3)

What the phone does for the keyholder, built into a copy of
`masterpod-test-web-app` (build plan step 8). The real apps will do the
same.

| Thing | How |
| ----- | --- |
| keyholders | a constant list of the five base URLs, `http://localhost:3201` to `3205` for the rig |
| receiving keys | `/get-keyholder-public-key` on each, fetched into RAM when the keyholder panel loads |
| `publicLedgerId` | the user's own algorithm, not yet written anywhere. Stand-in until it lands: `SHA-256('stand-in/' || anopodId hex)`, deterministic per pod, one function to replace |
| `lookupId` | `SHA-256(UTF-8(firstName || lastName || first 16 hex characters of publicLedgerId))`. The server never checks it. Stand-in rule, to be confirmed with the real algorithm |
| split | `shamir-secret-sharing` `split(secret, 5, 3)`: five shares of 33 bytes for a 32-byte secret, any three rebuild it. 5 and 3 are app constants |
| `keyId` | 32 random bytes per secret, the same for all five keyholders |
| `share` for keyholder N | share N encrypted to keyholder N's receiving key (7.1) with AAD `lookupId || shareType || keyId` |
| the call | `/receive-share` on keyholder N, the section 3 envelope signed by the pod's session keys with `path` `/receive-share` and a fresh nonce; five calls per secret, one per keyholder |
| when | after a successful add to bucket one or two: the bucket key, as `securitybucket1` or `securitybucket2`; after a successful `/complete-setup`: the backup code, as `backupcode` |
| `breakglasskey` | not from this app: the break-glass key is the wallet's, later |

## 9. Environment variables

One keyholder = one process = one file `.env-keyholderN`, started with
`KEYHOLDER=N npm start` (`node --env-file=.env-keyholder$KEYHOLDER
src/server.js`), as the validators are. `scripts/make-keys.js` prints
fresh values for every key line.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PORT` | `3200` | `3201` to `3205` locally |
| `KEYHOLDER_ID` | required | this keyholder's number, its validator's id |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | host `127.0.0.1`, port `5432`, rest required | the keyholder's own database: `keyholder1` to `keyholder5`, role `keyholdersoftware` locally |
| `ANOS_PGHOST`, `ANOS_PGPORT`, `ANOS_PGDATABASE`, `ANOS_PGUSER`, `ANOS_PGPASSWORD` | host `127.0.0.1`, port `5432`, rest required | the validator's anos database, read only: `anos1` to `anos5` locally, `anos` on a VM, role `keyholder_reader` |
| `STAKE_MIN_MODERATOR_ANOS` | required | whole anos, the same value as the validator's env |
| `WEB_ORIGIN` | `http://localhost:4200` | CORS allow-list, the phone |
| `MASTERPOD_URL` | `http://localhost:3100` | where `/get-anopod-session-keys` is |
| `RECOVERY_POD_HOSTS` | `localhost,127.0.0.1` | comma-separated hosts a decrypt route may post to |
| `TIMESTAMP_WINDOW_SECONDS` | `120` | allowed clock difference on a signed request, each way |
| `RECEIVING_X25519_PRIVATE_KEY`, `RECEIVING_MLKEM_PRIVATE_KEY` | required | the receiving key pair, PKCS#8 DER hex |
| `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY` | required | the home computer's hybrid public key, raw hex |
| `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2` | required | the two YubiKeys' P-256 public keys, 33 bytes hex |
| `BUCKET_ONE_KEY` | required | 32 bytes hex, wraps bucket-one shares |
| `KMS_PROVIDER` | `local` | `local` or `gcp` |
| `KMS_LOCAL_KEY` | required when `local` | 32 bytes hex |
| `KMS_KEY_NAME` | required when `gcp` | `projects/.../locations/.../keyRings/.../cryptoKeys/...` |

Every private value fails at boot when missing or the wrong length
(`src/config/env.js`, as in the siblings).

Since the testnet build (2026-10-27) these live in two files, the committed
`network/testnet.env` and the machine file `.env`; the private values moved
to the key file, the local KMS provider is gone, and `WEB_ORIGIN`,
`MASTERPOD_URL`, `RECOVERY_POD_HOSTS` and `KMS_KEY_NAME` are required:
section 14.

## 10. Scripts

| Command | Description |
| ------- | ----------- |
| `KEYHOLDER=N npm start` / `npm run dev` | run keyholder N (`dev` restarts on file changes) |
| `npm run db:setup` | for every `.env-keyholder<N>`: the role, the database, the schema; pass a file to do one |
| `npm run db:reset` | drop and set up again; local only |
| `npm run db:grant-anos-read` | for every `.env-keyholder<N>`: in its anos database, as a superuser, create the `ANOS_PGUSER` role if missing, sync its password, grant `CONNECT`, `USAGE` on `public` and `SELECT` on `accounts` and `stakes`, nothing else |
| `npm run make-keys` | print fresh env lines: the receiving pair, a home pair (public for the env, private shown once for the home computer), two P-256 pairs standing in for YubiKeys (public for the env, private shown once), `BUCKET_ONE_KEY`, `KMS_LOCAL_KEY` |

## 11. Deferred, by decision

- Who may read buckets, and when: today any moderator, any lookup id, no
  user in the loop, no release log. For the testnet.
- Rotation of the receiving key, the home key, the YubiKeys, the bucket-one
  key or the KMS key. The `wrap` column is there for it.
- The real public ledger id algorithm and the lookup id rule; the app uses
  the stand-ins of section 8.
- Break-glass shares from the wallet app.
- The keyholder's home application (the YubiKey, the home private key, the
  get, peel, decrypt sequence) and the recovery pod on the masterpod,
  including what it does with the posted share.
- Discovery: how the real phone learns the five keyholders and their keys.
  The app hardcodes them.
- Anti-abuse limits, purging owners who never finished, metadata privacy.

## 12. Notes from the build

Built 2026-10-24, straight through from this file and `build-plan.md`, and
verified on the throwaway rig of build plan step 9: one keyholder on 3299
(`KEYHOLDER_ID=9`, `KMS_PROVIDER=local`), a masterpod on 3300 from the
masterpodsoftware working tree, a recovery pod listener on 3399, databases
`anosrig`, `masterpodrig` and `keyholderrig`, all dropped afterwards; 89
checks, every route, every refusal of section 5, the tables after each step.
Where this file left a detail open, the simplest thing was chosen and is
recorded here; nothing above was changed.

- Key material is loaded once at boot by `src/crypto/keyholder-keys.js`: the
  receiving pair as key objects, the home public key, the bucket-one key and
  the two YubiKey keys as Buffers. A value that is hex of the right length
  but not a key fails there, before the server listens. `env.js` enforces
  the PKCS#8 lengths of 7.2: 48 bytes for X25519, 86 for ML-KEM-1024 (the
  seed form Node exports; checked again on Node 24.22).
- Reasons for values that do not decode, in the masterpod's style, `400
  invalid <field>`: `invalid anopodId`, `invalid accountId`, `invalid nonce`
  (the middlewares); `invalid lookupId`, `invalid publicLedgerId`, `invalid
  keyId`, `invalid shareType`, `invalid share` (5.2); `invalid
  responseKey.x25519`, `invalid responseKey.mlkem` (5.3 to 5.5); `invalid
  destination.hybridKey` and `invalid kmsBlob`, a blob that does not decode
  or exceeds 4096 bytes (5.8, 5.9). A `shareId` that does not decode is `404
  unknown share`, as 5.8 words it. Base64 is accepted wherever hex is, so a
  short base64-looking `kmsBlob` decodes and then fails as `blob does not
  open`.
- The three middlewares compare `payload.path` with `req.baseUrl +
  req.path`. The nonce is recorded after the level's own checks, in the
  spec's order, so a refused request never uses a nonce up; nonces live `2 *
  TIMESTAMP_WINDOW_SECONDS` in the one table. `req.pod` and `req.moderator`
  are 32-byte Buffers; `req.yubikey` is the hex of the key that verified.
- The masterpod client posts `{ anopodId }` in hex with a JSON content type
  and a 5-second timeout. Anything but a `200` with usable keys or a `404` is
  `502 masterpod unavailable`: a `5xx`, a `400`, no answer, or a `200` whose
  keys or expiry do not parse.
- `/receive-share` draws the fresh `share_id` first, since it is part of the
  authenticated data, then wraps the share (the KMS calls and the hybrid
  encryption to the home key) and only then opens the transaction, as 5.2
  says. A unique violation inside it, two deposits racing past the checks,
  answers `409 key id already stored` for `shares_key_id_key` and `409
  concurrent first deposit` for `owners_pkey`; the phone retries.
- Stored sizes with the local KMS, for a 33-byte share: 61 bytes under
  `env-aes-gcm-v1` and `kms-v1`, 1689 under `kms-home-hybrid-v1`; the public
  ledger id is 60 bytes. Cloud KMS ciphertext is longer; the columns have
  room.
- Reads list shares newest first by `created_at`. `/get-keyholder-public-key`
  ignores its body. `/health` checks the keyholder's own database; the anos
  pool is checked at boot and on every moderator request.
- `RECOVERY_POD_HOSTS` is matched against the URL's host name, lowercased,
  exactly: the port is ignored and `localhost` does not cover `127.0.0.1`
  (the default lists both). The post to the recovery pod carries a JSON
  content type and the 10-second timeout. `delivered: true` means the
  recovery pod answered, whatever its status; its JSON, or its text when it
  sent none, comes back in `recoveryPod.body`.
- The `gcp` KMS provider maps gRPC `INVALID_ARGUMENT` (code 3) on `decrypt`
  to null and passes no CRC32C fields. It was not run: the rig used `local`,
  and Cloud KMS runs only on the VM.
- `nonces` has no `created_at`, as its DDL in section 4 says; it is the one
  table without one.
- `scripts/make-keys.js` prints the home private key and the stand-in
  YubiKey private keys as comment lines, once; they go to the home computer
  and nowhere else. `db:grant-anos-read` runs both of its `psql` calls as the
  current OS user over the local socket, like `setup-db.sh`, and never
  touches a table.
- The masterpod's `/get-anopod-session-keys` answers `400 bad request shape`
  for a body whose `anopodId` is not a string or not 32 bytes, `404 unknown
  anopod` otherwise, as 5.10 says; it is recorded in masterpodsoftware's
  `docs/schemas.md` section 11.
- The web app (`keyholder-test-web-app`, a copy of the masterpod test app):
  `KEYHOLDERS`, `SHARE_COUNT = 5` and `SHARE_THRESHOLD = 3` live in
  `src/app/keyholders.ts`; the stand-ins of section 8
  (`standInPublicLedgerId`, `lookupId`) are in `crypto.service.ts`, each
  marked STAND-IN; `hkdf` took a salt parameter (empty for the masterpod
  derivations, `e.public || ct` for 7.1); `ApiService.sign()` exposes the
  envelope builder for the keyholder calls, and `ApiService.podName` keeps
  the pod's first and last name, from the create payload or from
  `/get-anopod-profile` fetched once after an unlock. Shares go out
  sequentially after a successful add to bucket one or two (the bucket key)
  and after a successful `/complete-setup` (the backup code, before it is
  dropped); a keyholder whose receiving key is not in RAM is loaded first;
  every error is logged in the Keyholders section and never fails the add or
  the setup; a pod whose name is not in RAM sends nothing and logs why. The
  browser-side hybrid encryption (noble X25519 and ML-KEM-1024, WebCrypto
  HKDF with salt and AES-GCM with AAD, exactly as `crypto.service.ts` writes
  it) was run under Node against `hybrid.js` on 2026-10-24: five shares of a
  split secret opened on the server side, a wrong AAD was refused, and any
  three shares rebuilt the secret.
- Rig deviations from the plan's letter: the rig anos database used a
  throwaway role `anosrig` instead of the existing `anossoftware` role, so
  the setup script's `ALTER ROLE ... PASSWORD` never touched the user's role;
  the shares the rig deposited were 33 random bytes, since the server never
  splits or combines (the real split was checked separately, above).

Not verified in this build: the Cloud KMS provider; a real YubiKey (two
P-256 pairs from `make-keys` stood in, one signing r||s and one DER); the
home computer and the recovery pod (the rig peeled and forwarded with the
rig's own keys and listener); the web app against a running keyholder from
a browser (the user drives `ng serve`); five keyholders side by side (the
rig ran one; the others differ only by env file).

## 13. Attestor stake on the bucket key routes (2026-10-26)

Design settled 2026-10-26 (`~/Desktop/Z/forclaude/attestor.md`). An
attestor (masterpod spec 13: a pod named `attestor...`, an anos account
staked for `attestor`) checks a person's security buckets when attesting
an assisted trade, exactly as a moderator does for a recovery case. The
two bucket key routes therefore accept attestor stake as well as moderator
stake. Nothing else changes: `/get-public-ledger-id` stays moderator-only,
the moderator level of 3.2 is untouched, the shares and their crypto are
untouched. Built by
`~/Desktop/Z/forclaude/attestor-build-1-validators-and-keyholders.md`.

### 13.1 The rule

For `/get-security-bucket-one-key` and `/get-security-bucket-two-key`
only, step 4 of 3.2 becomes: the account exists (`401 unknown account`),
and its `stakes` row has `moderator_stake` at or above
`STAKE_MIN_MODERATOR_ANOS` or `attestor_stake` at or above
`STAKE_MIN_ATTESTOR_ANOS`, both in millionths; neither, or no row: `403
not a moderator or attestor`. Then both signatures against the primary
key pair, the nonce, `req.moderator` as before (the shares service does
not care which stake let the caller in).

A new middleware, `requireModeratorOrAttestor`, beside `requireModerator`,
which stays as it is for `/get-public-ledger-id`. The read on the anos
database is one query on `stakes` for both columns; the grant of
`db:grant-anos-read` (`SELECT` on `stakes`) already covers it.

### 13.2 Environment

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `STAKE_MIN_ATTESTOR_ANOS` | `1000` | whole anos, the same value as the validator's `STAKE_MIN_ATTESTOR_ANOS` |

A default, unlike the moderator minimum, so the five keyholders running
under `--watch` keep booting the moment the code lands; the user adds the
line to each `.env-keyholderN` as they like.

### 13.3 Notes from the build

Built 2026-10-26 straight from this section and
`~/Desktop/Z/forclaude/attestor-build-1-validators-and-keyholders.md`, and
checked by `test/rig-attestor-stake.mjs` (24 checks): a throwaway anos
database `anosrig` (role `anosrig`, anossoftware's whole `db/schema.sql`)
with three accounts whose pair one the rig holds (moderator stake at the
minimum, attestor stake at the minimum, both at 999 anos), a throwaway
`keyholderrig` with one owner, one `securitybucket1` share and one
`securitybucket2` share written straight into the tables, wrapped as
section 6 says with the rig's own keys, and a keyholder on 3299 booted
three times: with the variable unset (the default; the account at 999 anos
is `403 not a moderator or attestor`), set to 999 (that account then passes
the two bucket routes and is still `403 not a moderator` on
`/get-public-ledger-id`), and set to a word (it refuses to boot, naming the
variable). Both databases and roles were dropped afterwards; the five live
keyholders reloaded under `--watch` and boot with the default. Where this
section left a detail open, the simplest thing was chosen and is recorded
here; nothing above was changed.

- **The variable** is read by a small `optionalAnos(name, fallbackAnos)`
  beside `requiredAnos` in `env.js`, built on `optionalInteger`: unset or
  empty is the default, anything but a positive integer fails at boot, and
  the value lands in `env.stakes.minimums.attestor` in millionths as
  BigInt, like the moderator minimum.
- **The read** is `anos.queries.js` `findStakes(accountId)`: both columns
  in one query, `{ moderator, attestor }` BigInts, or `null` without a
  row. `findModeratorStake` stays as it is for `requireModerator`.
- **The middleware** `src/auth/require-moderator-or-attestor.js` is a copy
  of `require-moderator.js` with step 4 changed. The order of section 3 is
  kept, so the stake is checked before the signatures and the nonce, and a
  refused non-attestor has not used its nonce up (rig-checked). The
  validator's attestor gate orders it the other way, stake after nonce
  (anossoftware 13.3). `req.moderator` is set whichever stake admitted the
  caller; the shares services and the answers are untouched and nothing
  records which stake it was.
- **No example env file** is tracked (the README's Configuration block is
  the example), so the line went there; the user adds
  `STAKE_MIN_ATTESTOR_ANOS=1000` to each `.env-keyholderN` at will.
- **The rig** imported the server's own `aead.js` and `hybrid.js` to wrap
  the rows it wrote (the row aad `share_id || lookup_id || share_type ||
  key_id`; the public ledger id under the local KMS key with `lookup_id`)
  and to open every answer with the response private keys and the
  transport aad, so the attestor's answer was checked to be the same share
  as the moderator's, opening to the same bytes, not just a `200`.
- **No schema change, no grant change**: `stakes.attestor_stake` exists
  and `db:grant-anos-read` grants `SELECT` on the whole `stakes` table.

## 14. Testnet readiness (2026-10-27)

Built 2026-10-27 as the second half of testnet build 1, straight from
`~/Desktop/Z-TestNet/forclaude/testnet-build-1-code-ready.md` (FINAL,
decided in its planning chat), after the validator half in anossoftware.
`~/Desktop/Z-TestNet` is the testnet tree: fresh repos, one network, no
local development. Nothing about the routes, the tables, the wraps or the
crypto changed. No check ran but `node --check` on each JavaScript file
written or edited: the first boot on the validator 1 VM is the test.
Sections 9, 10 and 12 describe the local setup as it was and stay as
history: the `.env-keyholderN` files, `KEYHOLDER=N npm start` and the
local KMS provider are gone.

### 14.1 The decisions, as they apply to this repo

- **Two env files per start.** `network/testnet.env`, committed, holds
  every value that is the same on every VM, each line with a comment:
  `PGHOST`, `PGPORT`, `PGUSER=keyholdersoftware`, `PGDATABASE=keyholder`,
  `ANOS_PGHOST`, `ANOS_PGPORT`, `ANOS_PGUSER=keyholder_reader`,
  `ANOS_PGDATABASE=anos`, `PORT=3200`, `STAKE_MIN_MODERATOR_ANOS=1000`,
  `STAKE_MIN_ATTESTOR_ANOS=1000`, `WEB_ORIGIN`, `MASTERPOD_URL` and
  `RECOVERY_POD_HOSTS` as `<fill in>`, `TIMESTAMP_WINDOW_SECONDS=120`.
  `.env`, git-ignored, holds what differs per machine: `KEYHOLDER_ID`,
  `PGPASSWORD`, `ANOS_PGPASSWORD`, `KEY_FILE`, then `KMS_KEY_NAME`,
  `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY`, `KEYHOLDER_PUBLIC_KEY_1`,
  `KEYHOLDER_PUBLIC_KEY_2`. `npm start`, `npm run dev` and the unit run
  `node --env-file=network/testnet.env --env-file=.env src/server.js`; Node
  applies later files over earlier ones (Node 24.22.0, checked in the
  planning chat). No `KEYHOLDER` start variable: the id is a line in `.env`.
- **`<fill in>`.** The three addresses in the shared file are filled by the
  user once the Hetzner load balancers have DNS names (`MASTERPOD_URL` and
  `RECOVERY_POD_HOSTS` from the masterpod's, `WEB_ORIGIN` from the wallet's;
  the masterpod's own `RECOVERY_POD_URL_BASE` must be built from the same
  host); the five lines in `.env` are filled by the operator at the visit.
  `required()` in `env.js` refuses the literal with `X is still
  "<fill in>": fill it in network/testnet.env or .env`; every other
  required helper (`requiredInteger`, `requiredHex`, `requiredAnos`, the
  list parsers) goes through it. A keyholder refuses to start until every
  one is filled, by design.
- **The key file.** `KEY_FILE` names it (default `./keyholder.key`), JSON
  `{ "receivingX25519PrivateKey", "receivingMlkemPrivateKey", "bucketOneKey" }`:
  PKCS#8 DER hex of 48 and 86 bytes as before, and 32 bytes hex; mode 0600,
  written once with the exclusive-create flag. `src/crypto/key-file.js`
  `readKeyFile(path, fields)` refuses a file that is missing, not a regular
  file, unreadable, or has any group or other bit set, naming the path and
  the mode, then requires each field to be lowercase hex of its length;
  `keyholder-keys.js` reads it and runs the same loaders as before.
  `RECEIVING_X25519_PRIVATE_KEY`, `RECEIVING_MLKEM_PRIVATE_KEY`,
  `BUCKET_ONE_KEY` and `KMS_LOCAL_KEY` left the env. `HOME_X25519_PUBLIC_KEY`,
  `HOME_MLKEM_PUBLIC_KEY`, `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2`
  and `KMS_KEY_NAME` stay in `.env`: public halves from the operator's GUI
  and YubiKeys, and a resource name.
- **make-keys writes; nothing is pasted.** `npm run make-keys -- --id <N>
  [--key-file <path>]`: both existence checks before any write, then the
  key file (`wx`, 0600) with a fresh receiving pair and 32 random bytes as
  `bucketOneKey`, and `.env` (`wx`, 0644 so `sudo -u postgres` can read it;
  tightening it to 0600 is testnet-month work) with `KEYHOLDER_ID`,
  `PGPASSWORD` and `ANOS_PGPASSWORD` (32 hex characters each from
  `randomBytes(16)`), `KEY_FILE`, and the five `<fill in>` lines, each
  under a one-line comment saying what goes there. Prints `Keyholder <N>`,
  the receiving public halves as information (x25519 32 bytes, mlkem 1568
  bytes, raw hex; the keyholder serves them live and nobody records them),
  the five lines left to fill, and the next commands. No stand-in home or
  YubiKey keys are generated anywhere any more. A private key is never
  printed.
- **Cloud KMS only.** `src/kms/local.js` is deleted; `kms.js` is
  `export { encrypt, decrypt } from './gcp.js'` with its comment rewritten;
  `gcp.js` is unchanged. `env.js` reads `kms: { keyName: required('KMS_KEY_NAME') }`
  and no longer reads `KMS_PROVIDER`. Each operator's key lives in the
  operator's own Google Cloud project, in the region their VM is in; no
  region appears in code or config, only inside `KMS_KEY_NAME`.
- **The self-test at boot.** `src/server.js`, after the two database checks
  and before listening: the fixed plaintext `anos keyholder kms self-test`
  encrypted with the fixed aad `self-test` through `kms.js`, decrypted,
  compared with `Buffer.equals`; `KMS ok`. A thrown error, a null from
  decrypt, or bytes that differ log `KMS self-test failed: <message>` and
  exit 1, like the two database checks.
- **CORS from env.** `WEB_ORIGIN` is a required comma-separated list,
  parsed as the masterpod's `optionalList` does but without a default;
  `src/app.js` passes the frozen array to `cors`. `MASTERPOD_URL` (keeping
  the trailing-slash strip) and `RECOVERY_POD_HOSTS` (keeping the
  lowercasing) are required too. The dev defaults `http://localhost:4200`,
  `http://localhost:3100` and `localhost,127.0.0.1` left the code; `PORT`,
  the hosts and ports, `TIMESTAMP_WINDOW_SECONDS` and the attestor minimum
  keep their defaults, and the shared file names them anyway.
- **Health.** `GET /health` answers `{ status, uptime, db, keyholder: { id },
  version: { commit, tag } }`. `src/util/version.js` runs
  `git rev-parse --short HEAD` and `git describe --tags --exact-match` once
  at boot, each `null` when git or the repo is absent or the command fails.
- **Boot log.** `Keyholder <id>`, the two PostgreSQL lines, `KMS ok`, then
  listening.
- **The unit.** `deploy/anos-keyholder.service`, identical on every VM: user
  `anos`, `/opt/anos/keyholdersoftware`, `/usr/bin/node`,
  `Restart=on-failure` every 5 s, `NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`.
- **The scripts.** `setup-db.sh`, `reset-db.sh` and `grant-anos-read.sh`
  load `network/testnet.env` and then the machine file, default `.env`, in
  that order, inside the per-file subshell; comments and messages updated.
- **The VM.** Debian 13, PostgreSQL 17 from Debian's own packages, Node 24
  from NodeSource, service user `anos`, both repos under `/opt/anos`, no
  external IP (the doorman holds it). The install is the operator guide,
  `guides/operator-guide.md`, kept beside the repos in the testnet folder.

### 14.2 Files and variables

New: `src/crypto/key-file.js`, `src/util/version.js`, `network/testnet.env`,
`deploy/anos-keyholder.service`, `.example.env` (the first tracked example
here).

Changed: `src/config/env.js`, `src/crypto/keyholder-keys.js`,
`src/kms/kms.js`, `src/server.js`, `src/app.js`,
`src/health/health.router.js`, `src/health/health.service.js`,
`scripts/make-keys.js` (rewritten), `scripts/setup-db.sh`,
`scripts/reset-db.sh`, `scripts/grant-anos-read.sh`, `package.json`,
`.gitignore` (`*.key` added), `README.md`, this file.

Deleted: `src/kms/local.js`.

| Variable | Where | Value |
| -------- | ----- | ----- |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE` | shared | `127.0.0.1`, `5432`, `keyholdersoftware`, `keyholder` |
| `ANOS_PGHOST`, `ANOS_PGPORT`, `ANOS_PGUSER`, `ANOS_PGDATABASE` | shared | `127.0.0.1`, `5432`, `keyholder_reader`, `anos` |
| `PORT` | shared | `3200` |
| `STAKE_MIN_MODERATOR_ANOS`, `STAKE_MIN_ATTESTOR_ANOS` | shared | `1000`, `1000` |
| `WEB_ORIGIN`, `MASTERPOD_URL`, `RECOVERY_POD_HOSTS` | shared | `<fill in>` |
| `TIMESTAMP_WINDOW_SECONDS` | shared | `120` |
| `KEYHOLDER_ID`, `PGPASSWORD`, `ANOS_PGPASSWORD`, `KEY_FILE` | machine (`.env`, from make-keys) | the id, 32 hex characters twice, `./keyholder.key` |
| `KMS_KEY_NAME`, `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY`, `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2` | machine (`.env`, filled by the operator) | `<fill in>` until filled |

Gone: `RECEIVING_X25519_PRIVATE_KEY`, `RECEIVING_MLKEM_PRIVATE_KEY`,
`BUCKET_ONE_KEY`, `KMS_PROVIDER`, `KMS_LOCAL_KEY`, the `KEYHOLDER` start
variable, the `.env-keyholderN` files.

### 14.3 Notes from the build

Where the plan was silent, the simplest thing was chosen and is recorded
here; nothing in 14.1 was changed.

- **`<fill in>` is double-quoted in both env files**
  (`KMS_KEY_NAME="<fill in>"`). The three database scripts source
  `network/testnet.env` and `.env` with `sh`, where a bare `<fill in>` is a
  redirection. Node's `--env-file` strips single, double or backtick
  quotes, so `env.js` still sees the literal `<fill in>` and refuses it.
  The values may be filled with or without quotes. make-keys writes the
  five lines quoted the same way.
- **The list parsers.** `requiredList(name)` is the masterpod's parser
  through `required()`, and `requiredHostList(name)` lowercases its items
  on top of it; the old `requiredHostList(name, fallback)` is gone.
- **Paths are resolved against the repo root**, not the working directory:
  `key-file.js` and `version.js` locate the repo from `import.meta.url`,
  and `make-keys.js` writes `.env` and a relative `--key-file` there. `npm`
  and the unit run in the repo root anyway.
- **`.env` is chmod-ed to 0644 after the write**, so an operator's umask
  cannot leave it unreadable to postgres. The key file is created 0600
  under `wx` and never chmod-ed: a umask can only narrow that, and anything
  narrower still passes the server's check.
- **make-keys reuses its own helpers** (`hybridPair`, `rawPublic`,
  `pkcs8Hex`, `hex`); `p256Pair` and the P-256 entries of the prefix tables
  went with the stand-in YubiKeys. `hybrid.js` `generateHybridKeyPair`
  stays, unused by the script as before.
- **The `KMS_KEY_NAME` comment** make-keys writes is one long line that
  carries the resource name pattern with the id filled in
  (`.../cryptoKeys/keyholder-<N>`), so the operator copies the shape.
- **The self-test** also fails when decrypt returns bytes that are not the
  plaintext (`the plaintext came back changed`), beside the null case
  (`the ciphertext did not decrypt under the key`); both land in
  `KMS self-test failed: <message>`.
- **Comments elsewhere stay as history**: `src/crypto/aead.js` still lists
  "the local KMS provider" among its users and `src/shares/wraps.js` still
  names `BUCKET_ONE_KEY` as the bucket-one wrap's key. Neither file is in
  the approved list; the key is the same bytes, read from the key file now.
- **Health** composes the fixed facts in `health.service.js` `identity()`
  and the router spreads them into the answer, as in anossoftware.
- **`version.js`** is the same file as anossoftware's, its own copy: git
  with `cwd` the repo root and stderr ignored; a non-zero exit, a missing
  binary or empty output is `null`.
- **`engines`** stays at Node 24 or newer.
- **One line outside the listed README sections changed**: the `psql`
  one-liner under Database tables sourced `.env-keyholder1`, a file that
  no longer exists; it now sources the two files.
- **`node --check`** passed on the ten JavaScript files written or edited.
  Nothing booted, no database was touched, no scratch file was written.
