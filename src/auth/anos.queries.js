import { anosQuery } from '../db/anos-pool.js';

/**
 * The reads on the validator's anos database (spec 3.2 and 13.1), through
 * the read-only pool. Ids are Buffers of 32 raw bytes, matching the BYTEA
 * columns. Nothing here writes.
 */

/**
 * The primary key pair of the account `accountId`: { publicKey1,
 * publicKeyPq1 } as raw Buffers (the P-256 key, 33 or 65 bytes, and the
 * ML-DSA-87 key, 2592 bytes), or null when there is no such account.
 */
export async function findAccountKeys(accountId) {
  const { rows } = await anosQuery('SELECT public_key1, public_key_pq1 FROM accounts WHERE account_id = $1', [
    accountId,
  ]);
  if (rows.length === 0) return null;
  return { publicKey1: rows[0].public_key1, publicKeyPq1: rows[0].public_key_pq1 };
}

/**
 * The account's moderator stake in millionths as a BigInt (the column is a
 * BIGINT, which pg hands over as a decimal string), or null when the account
 * has no stakes row.
 */
export async function findModeratorStake(accountId) {
  const { rows } = await anosQuery('SELECT moderator_stake FROM stakes WHERE account_id = $1', [accountId]);
  if (rows.length === 0) return null;
  return BigInt(rows[0].moderator_stake);
}

/**
 * The account's moderator and attestor stakes in millionths as BigInts,
 * { moderator, attestor }, or null when the account has no stakes row: the
 * one read of the moderator-or-attestor level (spec 13.1), both columns in
 * one query. findModeratorStake above stays as it is for the moderator
 * level.
 */
export async function findStakes(accountId) {
  const { rows } = await anosQuery('SELECT moderator_stake, attestor_stake FROM stakes WHERE account_id = $1', [accountId]);
  if (rows.length === 0) return null;
  return { moderator: BigInt(rows[0].moderator_stake), attestor: BigInt(rows[0].attestor_stake) };
}
