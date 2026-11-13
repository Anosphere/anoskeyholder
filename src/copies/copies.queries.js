import { query } from '../db/pool.js';

/**
 * SQL for the share copies (spec section 16): the waiting_copies table, one
 * row per share whose copy is not in the bucket yet, and the read of a share
 * with its owner as a copy's file holds them. Ids and blobs are Buffers of
 * raw bytes. The one write that belongs to a deposit takes the transaction's
 * client first; everything else uses the pool.
 */

/**
 * A timestamp column as PostgreSQL holds it, as text in UTC with
 * microseconds: 2026-11-16T03:04:05.123456Z. pg would hand back a Date,
 * which keeps milliseconds only, and a copy must be able to put its row
 * back exactly.
 */
const utc = (column) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

/**
 * Adds the waiting row of the share `shareId` on `client`: the transaction
 * that saves the share, so the two land together or not at all.
 */
export async function insertWaitingCopy(client, shareId) {
  await client.query('INSERT INTO waiting_copies (share_id) VALUES ($1)', [shareId]);
}

/** How many shares wait for their copy. */
export async function countWaitingCopies() {
  const { rows } = await query('SELECT count(*)::int AS waiting FROM waiting_copies');
  return rows[0].waiting;
}

/** The ids of the shares that wait for their copy, oldest first, at most `limit`. */
export async function listWaitingCopies(limit) {
  const { rows } = await query('SELECT share_id FROM waiting_copies ORDER BY created_at, share_id LIMIT $1', [limit]);
  return rows.map((row) => row.share_id);
}

/**
 * The share `shareId` and its owner, every column of both rows:
 *   { share: { shareId, lookupId, shareType, keyId, share, wrap, createdAt },
 *     owner: { lookupId, publicLedgerId, anopodId, createdAt } }
 * Byte columns are Buffers, as stored; the two createdAt are strings (see
 * utc above). Null when the share or its owner is not there.
 */
export async function findShareWithOwner(shareId) {
  const { rows } = await query(
    `SELECT s.share_id, s.lookup_id, s.share_type, s.key_id, s.share, s.wrap,
            ${utc('s.created_at')} AS created_at,
            o.public_ledger_id, o.anopod_id,
            ${utc('o.created_at')} AS owner_created_at
     FROM shares s
     JOIN owners o ON o.lookup_id = s.lookup_id
     WHERE s.share_id = $1`,
    [shareId],
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    share: {
      shareId: row.share_id,
      lookupId: row.lookup_id,
      shareType: row.share_type,
      keyId: row.key_id,
      share: row.share,
      wrap: row.wrap,
      createdAt: row.created_at,
    },
    owner: {
      lookupId: row.lookup_id,
      publicLedgerId: row.public_ledger_id,
      anopodId: row.anopod_id,
      createdAt: row.owner_created_at,
    },
  };
}

/** Removes the waiting row of the share `shareId`: its file is in the bucket. */
export async function deleteWaitingCopy(shareId) {
  await query('DELETE FROM waiting_copies WHERE share_id = $1', [shareId]);
}
