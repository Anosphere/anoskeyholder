# Build plan: the keyholder

For a fresh chat. The specification is `docs/schemas.md`; this file says in
what order to build it, which files each step touches, and how to verify
it. The design was settled with the user on 2026-10-24 over four rounds of
questions; the answers are all folded into `schemas.md`, so nothing here
needs the old conversation. The folder `~/Desktop/Z/keyholdersoftware` holds
only these two documents when the build starts.

## Before starting

Read, in this order: `docs/schemas.md`, this file. Then, in
`~/Desktop/Z/anossoftware`: `README.md` (the layout, the env file
conventions, the validator pattern), `src/config/env.js`, `src/crypto/`
(copied verbatim here), `src/stakes/stake-purposes.js` (how the stake
minimum is read and compared), `src/transfer/` (the router / handlers /
service / queries pattern), `scripts/`. Then, in
`~/Desktop/Z/masterpodsoftware`: `src/auth/require-session.js`,
`src/auth/signed-request.js`, `src/auth/nonces.queries.js`,
`src/util/result.js`, `src/db/transaction.js`, `src/anopods/` (the new route
goes there), `README.md` (the format this README copies). Then
`~/Desktop/Z/test/masterpod-test-web-app/src/app/` (`crypto.service.ts`,
`api.service.ts`, `app.ts`, `app.html`) for step 8.

House rules, from the user:

- The user commits. Never commit. The user will `git init` this folder and
  the new web app folder. End the work with the list of changed and new
  files, what changed in each, and a suggested commit message per step, so
  the user can commit step by step.
- No test suites, fixtures or smoke scripts in either repo. Verify on a
  throwaway rig (step 9) with scripts kept in the scratchpad. The user drives
  the phone side from test web app 3 and will build the home side tomorrow.
- The spec is the spec. The only changes to existing code are listed under
  "Approved changes" below; anything else in existing code gets a one-line
  question first. New files are free. Where the spec leaves a detail open,
  pick the simplest thing and write it into `schemas.md` section 12.
- Node comes from nvm: `source ~/.nvm/nvm.sh` before `node` or `npm` in a
  shell. Node 24.22 is installed; ML-KEM-1024 `encapsulate` / `decapsulate`,
  X25519, P-256, ML-DSA-87, HKDF and AES-GCM are all built in. PostgreSQL is
  Homebrew's `postgresql@17`; `scripts/find-psql.sh` locates `psql`.
- Files named `.env*` cannot be read or written by Claude. The README's
  Configuration section lists every variable with its meaning, and
  `npm run make-keys` prints the key lines; the user creates
  `.env-keyholder1` to `5`. Nothing in the repo is named `.env*`, not even
  an example file; the example lives in the README.
- Do not touch the user's running servers: the five validators on 3001 to
  3005 (run with `--watch` from their working tree), the masterpod on 3100,
  `ng serve` on 4200. Do not run `db:grant-anos-read` against the user's
  `anos1` to `anos5`; the user runs it. The rig uses its own databases and
  ports (step 9).
- Build straight through, all steps, then report. Keep the step boundaries
  visible in the report so the diff reads step by step.

## Approved changes to existing code

In `~/Desktop/Z/masterpodsoftware`, spec 5.10, and nothing else there:

1. `src/anopods/anopods.service.js`: `sessionKeys(body)`: shape, 32 bytes,
   `findById`, `404 unknown anopod`, answer with the four fields in hex and
   ISO.
2. `src/anopods/anopods.handlers.js`: `getAnopodSessionKeys`.
3. `src/anopods/anopods.router.js`: `anopodsRouter.post('/get-anopod-session-keys',
   getAnopodSessionKeys)`, level none.
4. `src/app.js`: the route added to the anopods router's comment line.
5. `README.md`: the route in the endpoints table, level none, one line.
6. `docs/schemas.md`: section 11, one note: the route, the date, why (the
   keyholders).

Nothing in `~/Desktop/Z/anossoftware` changes. The keyholder's
`db:grant-anos-read` adds a role and read grants to anos databases; on the
rig only, in this build.

## Steps

### 1. Skeleton

New repository `~/Desktop/Z/keyholdersoftware`, laid out like the siblings:

- `package.json`: `"type": "module"`, `"engines": { "node": ">=24" }`,
  dependencies `express`, `pg`, `cors`, `canonicalize`, `@google-cloud/kms`;
  scripts `start` (`node --env-file=.env-keyholder$KEYHOLDER src/server.js`),
  `dev` (same with `--watch`), `db:setup`, `db:reset`, `db:grant-anos-read`,
  `make-keys`.
- `src/server.js`: as anossoftware's, minus genesis: check both pools with
  `SHOW server_version`, listen, graceful shutdown draining both.
- `src/app.js`: `cors({ origin: env.webOrigin })`, `express.json({ limit:
  '1mb' })`, `/health`, the two feature routers, `notFound`, `errorHandler`.
- `src/config/env.js`: every variable of spec section 9, `required`,
  `requiredInteger`, `requiredAnos`, `requiredHex(name, bytes)`,
  `requiredHostList`, with the defaults the spec gives; `KMS_LOCAL_KEY` and
  `KMS_KEY_NAME` required according to `KMS_PROVIDER`.
- `src/db/pool.js` (own database, `query`, `closePool`),
  `src/db/anos-pool.js` (the read-only pool from `env.anosDb`, `anosQuery`,
  `closeAnosPool`), `src/db/transaction.js` (masterpod's `withTransaction`).
- `src/health/`, `src/middleware/error-handler.js`, `not-found.js`,
  `src/util/ids.js`, `is-object.js`, `result.js`: copies of the masterpod's.
- `scripts/find-psql.sh`, `setup-db.sh`, `reset-db.sh`: anossoftware's,
  with `.env-keyholder[0-9]*` in place of `.env-validator[0-9]*` and no
  registry file. `scripts/grant-anos-read.sh`: spec section 10, one
  superuser `psql -d postgres` for the role, then one `psql -d
  $ANOS_PGDATABASE` for the grants, per env file.
- `.gitignore`: `node_modules/`, `.env*`.

`npm install`. Nothing runs yet without an env file; the rig in step 9 is
the first start.

Suggested commit: `keyholder skeleton: server, env, two pools, scripts`.

### 2. Schema

`db/schema.sql`: the conventions block in the siblings' style,
`refuse_change()`, then `owners`, `shares`, `nonces` as spec section 4,
each with its header comment, trigger, index and `COMMENT ON` for the table
and every column.

Suggested commit: `owners, shares and nonces: schema`.

### 3. Crypto and KMS

All new files.

- `src/crypto/bytes.js`, `canonical.js`, `hash.js`, `signatures.js`: copied
  verbatim from anossoftware.
- `src/crypto/aead.js`: `seal(key, plaintext, aad)` and `open(key, blob,
  aad)` for AES-256-GCM, `iv (12) || ciphertext || tag (16)`, `open`
  returning null on a bad tag.
- `src/crypto/hybrid.js`: spec 7.1 and 7.2. `decodeHybridPublicKey({ x25519,
  mlkem })` (both lengths, or null), `encryptToHybrid(recipient, plaintext,
  aad)` (the wire bytes), `decryptHybrid(privateKeys, blob, aad)` (null when
  it does not open), `loadHybridPrivateKeys(x25519Pkcs8Hex, mlkemPkcs8Hex)`
  and `publicKeyOf(privateKeys)` giving the raw public halves for
  `/get-keyholder-public-key`. The SPKI prefixes of 7.2 as constants.
- `src/kms/kms.js`: `encrypt(plaintext, aad)`, `decrypt(ciphertext, aad)`
  choosing the provider once from `env.kms.provider`; `src/kms/local.js`
  on `aead.js` under `env.kms.localKey`; `src/kms/gcp.js` on
  `KeyManagementServiceClient` with `name: env.kms.keyName` and
  `additionalAuthenticatedData`, `decrypt` returning null on
  `INVALID_ARGUMENT`. The client is created lazily, so a `local` keyholder
  never loads Google code.

Suggested commit: `hybrid encryption, aead, kms with local and gcp providers`.

### 4. Request checking

All new files, under `src/auth/`.

- `nonces.queries.js`: `insertNonce(nonce, expiresAt)` returning false on a
  duplicate, deleting expired rows first.
- `signed-request.js`: `parseSignedRequest(body, signerField, { mldsa })`
  returning `{ payload, signatures }` or `{ reason }`; `verifyBoth(payload,
  signatures, ecdsaKey, mldsaKey)` and `verifyEcdsa(payload, signature,
  key)` over the canonical bytes.
- `common-checks.js`: the shared steps of spec section 3 (path, timestamp,
  nonce) as functions the three middlewares call in the spec's order.
- `masterpod.client.js`: `fetchSessionKeys(anopodId)` posting to
  `env.masterpodUrl + '/get-anopod-session-keys'` with
  `AbortSignal.timeout(5000)`, returning `{ keys }`, `{ notFound: true }` or
  `{ unavailable: true }`.
- `anos.queries.js`: `findAccountKeys(accountId)` and
  `findModeratorStake(accountId)` on the anos pool, read only.
- `require-pod.js`, `require-moderator.js`, `require-keyholder.js`: the
  three middlewares of spec 3.1 to 3.3, setting `req.pod` (the anopod id as
  a Buffer), `req.moderator` (the account id) or `req.yubikey` (which key
  verified), and `req.body = payload.body`.

Suggested commit: `pod, moderator and keyholder request checks`.

### 5. Shares

`src/info/info.router.js` + `info.handlers.js`: `/get-keyholder-public-key`
(spec 5.1), answering from `hybrid.js` and `env.keyholderId`.

`src/shares/`:

- `shares.queries.js`: `findOwner(lookupId)`, `insertOwner(client, row)`,
  `keyIdExists(keyId)`, `insertShare(client, row)`, `findShare(shareId)`,
  `listShares(lookupId, shareType)` newest first.
- `wraps.js`: spec section 6. `aadFor(share)` (`share_id || lookup_id ||
  share_type || key_id`), `wrapShare(shareType, plaintext, aad)` returning
  `{ share, wrap }`, `unwrapBucketShare(row)` for the two bucket wraps,
  `kmsDecryptBlob(row, kmsBlob)` for the decrypt routes.
- `receive.service.js`: `/receive-share`, checks 1 to 6 of spec 5.2, the
  KMS calls before the transaction, owner and share in one transaction.
- `moderator.service.js`: `getBucketKey(moderator, body, shareType)` behind
  `/get-security-bucket-one-key` and `/get-security-bucket-two-key` (spec
  5.3, 5.4), `getPublicLedgerId(moderator, body)` behind
  `/get-public-ledger-id` (5.5).
- `keyholder.service.js`: `getBlobs(body, shareType)` behind
  `/get-break-glass-key` and `/get-backup-code` (5.6, 5.7);
  `decryptAndForward(body, shareType)` behind `/decrypt-break-glass-key` and
  `/decrypt-backup-code` (5.8, 5.9), with
  `forward.js`: `postToRecoveryPod(destination, object)` checking the host
  against `env.recoveryPodHosts`, `AbortSignal.timeout(10000)`, returning
  `{ status, body }` or `{ unreachable: true }`.
- `shares.handlers.js`, `shares.router.js`: the eight routes, each behind
  its middleware: `/receive-share` behind `requirePod`; the three moderator
  routes behind `requireModerator`; the four keyholder routes behind
  `requireKeyholder`. Mount both routers in `app.js`.

Suggested commit: `receive, moderator reads, keyholder reads and decrypt-and-forward`.

### 6. The masterpod route

The approved changes, in `~/Desktop/Z/masterpodsoftware`. `npm run dev`
there is the user's; do not restart it. The rig in step 9 starts its own
masterpod from this working tree.

Suggested commit, in that repo: `get-anopod-session-keys for the keyholders`.

### 7. Keys script and README

- `scripts/make-keys.js`: spec section 10, `node:crypto` only. Prints, with
  a comment line above each group: `RECEIVING_X25519_PRIVATE_KEY`,
  `RECEIVING_MLKEM_PRIVATE_KEY` and their public halves as a comment;
  `HOME_X25519_PUBLIC_KEY`, `HOME_MLKEM_PUBLIC_KEY` with the private halves
  as a comment marked "for the home computer, shown once";
  `KEYHOLDER_PUBLIC_KEY_1`, `KEYHOLDER_PUBLIC_KEY_2` with the private halves
  as a comment marked "stand-ins for the two YubiKeys"; `BUCKET_ONE_KEY`;
  `KMS_LOCAL_KEY`. Fresh values every run.
- `README.md`: what the server is; the levels table of spec section 2; the
  envelope; Database tables; Endpoints (the nine routes with level and one
  line each, plus the masterpod route); Configuration (every variable of
  spec section 9 as an example env file block for `.env-keyholder1`, since
  no example file may exist in the repo); the five-keyholder local setup
  (`db:setup`, `db:grant-anos-read`, `KEYHOLDER=1 npm start`); the VM notes
  (one keyholder, `anos`, `KMS_PROVIDER=gcp`, the service account's KMS
  role); Layout; the deferred list.

Suggested commit: `key generator; document the keyholder`.

### 8. Test web app 3

New repository `~/Desktop/Z/test/keyholder-test-web-app` ("test web app
3"; rename if the user prefers): a copy of
`~/Desktop/Z/test/masterpod-test-web-app` without `node_modules/`, `.git/`,
`.angular/` and `dist/`, `npm install`, then `npm install
shamir-secret-sharing`. Everything the copy did it still does; the
additions are spec section 8. The user runs `ng serve` on 4200 themselves;
verify with `ng build` only.

- `src/app/keyholders.ts` (new): `KEYHOLDERS`, the five base URLs;
  `SHARE_COUNT = 5`, `SHARE_THRESHOLD = 3`.
- `crypto.service.ts`: `x25519` from `@noble/curves/ed25519.js` beside the
  existing `ml_kem1024`; `encryptToHybrid(recipient, plaintext, aad)` as
  spec 7.1 with WebCrypto HKDF and AES-GCM; `splitSecret(secret)` on
  `shamir-secret-sharing`; `standInPublicLedgerId(anopodIdHex)` and
  `lookupId(firstName, lastName, publicLedgerIdHex)` as spec section 8,
  each with a comment saying it is a stand-in; `newKeyId()`.
- `keyholder-api.service.ts` (new): `getPublicKey(baseUrl)` and
  `receiveShare(baseUrl, body)`, the latter building the section 3 envelope
  with the session keys the existing `ApiService` holds (expose them from
  it, or move `signed()`'s envelope building into a shared helper, whichever
  is the smaller change), posting to `baseUrl + '/receive-share'`.
- `app.ts` / `app.html`: a "Keyholders" section: a Load button fetching the
  five receiving keys and showing keyholder id and the first bytes of each
  key; the pod's stand-in public ledger id and lookup id shown; a log of
  shares sent (keyholder, type, key id, share id or the error). A
  `sendShares(shareType, secret)` method: key id, split, one encrypted share
  and one signed call per keyholder, sequential, errors logged and not
  fatal. Called from `addToBucketOne` and `addToBucketTwo` after a
  successful add with the bucket key, and from `completeSetup` after a
  successful post with the backup code, before the code is dropped.
- `api.service.ts`: the pod's first and last name kept after create or
  unlock, for the lookup id (unlock does not return them today: take them
  from `/get-anopod-profile` once after unlock).

Suggested commit, in that repo: `keyholder test app: receiving keys, shares to five keyholders`.

### 9. Verification rig

Before the report. In the scratchpad, never in a repo. The rig has one
keyholder, one anos database, one masterpod and one recovery pod listener,
all throwaway, none of the user's.

- Databases, via the projects' own scripts with rig env files kept in the
  scratchpad: `anosrig` (role `anossoftware`, which exists; `sh
  scripts/setup-db.sh <rig file>` in anossoftware creates the database and
  applies the schema and the validators registry), `masterpodrig` (role
  `masterpodrig`), `keyholderrig` (role `keyholderrig`), and `npm run
  db:grant-anos-read -- <rig file>` for role `keyholderrig_reader` on
  `anosrig`.
- Rows inserted directly with `psql`: in `anosrig`, an account with rig
  P-256 and ML-DSA-87 keys and a `stakes` row with `moderator_stake` at the
  minimum, and a second account with no stake; in `masterpodrig`, an
  `anopods` row with rig session keys (any 16-byte credential id and a
  dummy COSE key; the WebAuthn columns are not read by the new route) and
  `ephemeral_expires_at` an hour ahead.
- Processes: the rig masterpod on port 3300 from the masterpodsoftware
  working tree; the rig keyholder on port 3299 with `KMS_PROVIDER=local`,
  `MASTERPOD_URL=http://localhost:3300`, `RECOVERY_POD_HOSTS=localhost`, keys
  from `npm run make-keys`; a recovery pod listener on port 3399 (`node:http`,
  one POST route) holding a rig hybrid private key and printing what opens.
- `rig.mjs` with `node:crypto` and the project's `src/crypto/` and
  `src/crypto/hybrid.js`, playing the phone, a moderator, the home computer
  with the stand-in YubiKey key, and checking the tables after each step:
  the public key route; four `/receive-share` calls (one per type) for pod
  P; then refused: a replayed nonce, an old timestamp, a wrong path, a bad
  signature, a share encrypted to the wrong key, a repeated key id, the
  same lookup id from a second pod (anopod mismatch), an expired session
  (update the row's expiry), the masterpod stopped (502); a second bucket-one
  share for P; moderator reads of bucket one (two shares, newest first),
  bucket two, the public ledger id, each opened with the rig response
  private key and compared with what the phone sent; the second account
  refused with `403 not a moderator`; an unknown lookup id `404`;
  `/get-backup-code` and `/get-break-glass-key` with each stand-in YubiKey
  key, a third key refused; the home peel: open each blob with the rig home
  private key to get the KMS blob; `/decrypt-backup-code` and
  `/decrypt-break-glass-key` to the listener, the listener opening the share
  and matching the original; a blob from the other share refused (`blob does
  not open`), the wrong route for a share (`wrong share type`), a host not
  on the list (`403`), the listener stopped (`502`); an `UPDATE shares`
  through `psql` refused by the trigger.
- Drop the three rig databases and roles and stop the three rig processes
  at the end.

### 10. Report

The changed and new files per step, what changed, the suggested commit
messages, the env file block for `.env-keyholder1`, what was verified on
the rig and what was not (the Google KMS provider runs only on the VM; the
YubiKey, the home computer and the recovery pod were stand-ins), and
anything left open, also written into `schemas.md` section 12.

## Out of scope, by decision

Spec section 11. Also: the real public ledger id algorithm (stand-ins in
the app), break-glass shares from the wallet app, the home application and
the recovery pod, Shamir threshold choices beyond the app constants,
discovery of keyholders by the real phone, moderator limits and release
logs. The user builds the keyholder GUI next; nothing in this build pulls,
peels or forwards a share except the rig.
