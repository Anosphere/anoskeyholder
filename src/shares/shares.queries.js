import { pool, query } from '../db/pool.js';

/**
 * SQL for the owners and shares tables. Ids and blobs are Buffers of raw
 * bytes, matching the BYTEA columns; pg sends a Buffer parameter as bytea.
 * Writes take the transaction's client first; reads use the pool.
 */

/** A shares row in camelCase. Byte columns stay Buffers. */
function shareRow(row) {
  return {
    shareId: row.share_id,
    lookupId: row.lookup_id,
    shareType: row.share_type,
    keyId: row.key_id,
    share: row.share,
    wrap: row.wrap,
    createdAt: row.created_at,
  };
}

const SHARE_COLUMNS = 'share_id, lookup_id, share_type, key_id, share, wrap, created_at';

/**
 * The owners row for `lookupId`: { lookupId, publicLedgerId (the KMS
 * ciphertext), anopodId, createdAt }, or null when no share was ever
 * deposited for this lookup id.
 */
export async function findOwner(lookupId) {
  const { rows } = await query('SELECT lookup_id, public_ledger_id, anopod_id, created_at FROM owners WHERE lookup_id = $1', [
    lookupId,
  ]);
  if (rows.length === 0) return null;
  const row = rows[0];
  return { lookupId: row.lookup_id, publicLedgerId: row.public_ledger_id, anopodId: row.anopod_id, createdAt: row.created_at };
}

/**
 * Inserts the owners row on `client`: `row` is { lookupId, publicLedgerId
 * (already KMS-encrypted), anopodId }. A second first deposit racing this one
 * throws a unique violation (db/transaction.js isUniqueViolation).
 */
export async function insertOwner(client, row) {
  await client.query('INSERT INTO owners (lookup_id, public_ledger_id, anopod_id) VALUES ($1, $2, $3)', [
    row.lookupId,
    row.publicLedgerId,
    row.anopodId,
  ]);
}

/** True when a share with this key id was already stored. */
export async function keyIdExists(keyId) {
  const { rows } = await query('SELECT EXISTS (SELECT 1 FROM shares WHERE key_id = $1) AS found', [keyId]);
  return rows[0].found;
}

/**
 * Inserts a share on `client`: `row` is { shareId, lookupId, shareType,
 * keyId, share (the wrapped bytes), wrap }. A repeated key id throws a
 * unique violation.
 */
export async function insertShare(client, row) {
  await client.query(
    `INSERT INTO shares (share_id, lookup_id, share_type, key_id, share, wrap)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [row.shareId, row.lookupId, row.shareType, row.keyId, row.share, row.wrap],
  );
}

/** The shares row with this id, or null. */
export async function findShare(shareId, db = pool) {
  const { rows } = await db.query(`SELECT ${SHARE_COLUMNS} FROM shares WHERE share_id = $1`, [shareId]);
  return rows.length === 0 ? null : shareRow(rows[0]);
}

/** Every share of `shareType` for `lookupId`, newest first. */
export async function listShares(lookupId, shareType) {
  const { rows } = await query(
    `SELECT ${SHARE_COLUMNS} FROM shares
     WHERE lookup_id = $1 AND share_type = $2
     ORDER BY created_at DESC`,
    [lookupId, shareType],
  );
  return rows.map(shareRow);
}
