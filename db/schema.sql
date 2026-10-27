-- db/schema.sql
--
-- The whole database schema, built from nothing. scripts/setup-db.sh applies
-- it to every keyholder's database.
--
-- Safe to run again on a database that already has it: tables use IF NOT
-- EXISTS, functions and triggers use OR REPLACE, comments just overwrite.
-- It never alters a table that already exists, though. After changing this
-- file, rebuild the local databases from scratch with
--
--   npm run db:reset
--
-- Naming conventions:
--   * PostgreSQL folds unquoted identifiers to lowercase, so everything is
--     lowercase snake_case. camelCase or Capitalised names would have to be
--     double-quoted in every query forever.
--   * Table names are plural nouns (a row is one share, the table holds
--     shares).
--
-- Storage conventions (the same as anossoftware and masterpodsoftware, so
-- the three schemas read alike):
--   * Ids, keys and ciphertexts are raw bytes, stored as BYTEA, not as hex
--     text. Where the length is fixed, a CHECK enforces it. Encode to hex at
--     the API boundary.
--   * Nothing in this database is a plaintext secret: a share is wrapped as
--     its wrap column says (spec section 6) and a public ledger id is KMS
--     ciphertext. No foreign keys; the services keep the references straight.
--
-- Timestamps: every table has created_at. No row in this database ever
-- changes, so there is no updated_at and no set_updated_at trigger; owners
-- and shares refuse UPDATE and DELETE outright through refuse_change().
--
-- Comments live in the database itself and show up in psql with \d+ <table>.

-- IF NOT EXISTS raises a NOTICE for every table that is already there. On a
-- re-run that is one line of noise per table, so only warnings and up show.
SET client_min_messages = warning;

-- Refuses UPDATE and DELETE on append-only tables (owners, shares): a row is
-- the record of what was handed over, once.
CREATE OR REPLACE FUNCTION refuse_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;


-- ---------------------------------------------------------------------------
-- owners: one row per person, written by the first /receive-share call for a
-- lookup id, never changed. lookup_id and anopod_id are stored as handed;
-- public_ledger_id is the 32-byte id encrypted under the KMS key with
-- lookup_id as authenticated data, so the column is wider than 32 (KMS
-- ciphertext carries a header). Every later share for the lookup id must
-- come from the same anoPod.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS owners (
  lookup_id        BYTEA       PRIMARY KEY CHECK (octet_length(lookup_id) = 32),
  public_ledger_id BYTEA       NOT NULL CHECK (octet_length(public_ledger_id) <= 1024),
  anopod_id        BYTEA       NOT NULL CHECK (octet_length(anopod_id) = 32),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER owners_append_only
  BEFORE UPDATE OR DELETE ON owners
  FOR EACH ROW EXECUTE FUNCTION refuse_change();

COMMENT ON TABLE  owners                  IS 'One row per person, written by the first /receive-share call for a lookup id, never changed.';
COMMENT ON COLUMN owners.lookup_id        IS 'The 32-byte lookup id the phone computed and handed over, stored as handed. The server never checks how it was made.';
COMMENT ON COLUMN owners.public_ledger_id IS 'The 32-byte public ledger id as handed, encrypted under the KMS key with lookup_id as authenticated data. Wider than 32 because KMS ciphertext carries a header. Read back by moderators through /get-public-ledger-id.';
COMMENT ON COLUMN owners.anopod_id        IS 'The anoPod that deposited the first share: the verified signer of that call. Every later share for this lookup id must be signed by it (409 anopod mismatch otherwise).';
COMMENT ON COLUMN owners.created_at       IS 'When the row was inserted. Set by default, never changed.';


-- ---------------------------------------------------------------------------
-- shares: one row per share received. Several rows per lookup id and type
-- are normal: every add to a security bucket has its own key, and a backup
-- code is replaced when it rotates. key_id tells them apart and is unique
-- across the table, so a repeated key id is refused. share holds the share
-- bytes protected as wrap says (spec section 6), with authenticated data
-- share_id || lookup_id || share_type || key_id binding the blob to its row;
-- the column is wide enough for a share of a 32-byte secret under every
-- wrap, with room for KMS headers and larger secrets.
-- ---------------------------------------------------------------------------

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

COMMENT ON TABLE  shares            IS 'One row per share received: a Shamir share of one of the four secrets, protected as wrap says. Append-only.';
COMMENT ON COLUMN shares.share_id   IS 'Random id, 32 raw bytes, made by the server at insert. Part of the authenticated data of share.';
COMMENT ON COLUMN shares.lookup_id  IS 'The owner the share belongs to (owners.lookup_id).';
COMMENT ON COLUMN shares.share_type IS 'Which secret the share is of: securitybucket1, securitybucket2, breakglasskey or backupcode.';
COMMENT ON COLUMN shares.key_id     IS 'The 32 random bytes the phone made for the secret this share belongs to, the same on all five keyholders. Unique: a repeated key id is refused with 409.';
COMMENT ON COLUMN shares.share      IS 'The share bytes protected as wrap says (spec section 6). Authenticated data: share_id || lookup_id || share_type (UTF-8) || key_id.';
COMMENT ON COLUMN shares.wrap       IS 'The layout of share: env-aes-gcm-v1 (AES-256-GCM under BUCKET_ONE_KEY, iv || ciphertext || tag), kms-v1 (the KMS ciphertext) or kms-home-hybrid-v1 (the KMS ciphertext, then encrypted to the home computer''s hybrid key). Tells old rows from new after a key rotation.';
COMMENT ON COLUMN shares.created_at IS 'When the row was inserted. Set by default, never changed. Reads list newest first.';


-- ---------------------------------------------------------------------------
-- nonces: the replay cache of signed requests (spec section 3, step 5), one
-- table for every signer: a pod, a moderator or a YubiKey. Rows are deleted
-- as they expire by the insert that adds a new one.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS nonces (
  nonce      BYTEA       PRIMARY KEY CHECK (octet_length(nonce) BETWEEN 16 AND 32),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires_at_idx ON nonces (expires_at);

COMMENT ON TABLE  nonces            IS 'The replay cache of signed requests, one table for every signer. A duplicate nonce is 401 replay. Expired rows are swept by the next insert.';
COMMENT ON COLUMN nonces.nonce      IS 'The request''s nonce, 16 to 32 raw bytes, never reused.';
COMMENT ON COLUMN nonces.expires_at IS 'now plus twice TIMESTAMP_WINDOW_SECONDS at insert, past which the timestamp check refuses the request anyway.';
