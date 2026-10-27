import { env } from '../config/env.js';
import { decodeHybridPublicKey, encryptToHybrid } from '../crypto/hybrid.js';
import * as kms from '../kms/kms.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { findOwner, listShares } from './shares.queries.js';
import { transportAad, unwrapBucketShare } from './wraps.js';

/**
 * The three moderator routes (spec 5.3 to 5.5). The caller, req.moderator,
 * is a verified moderator; who asked is not recorded and any moderator may
 * read any lookup id (spec section 11), so the services take `body` only.
 * Every answer is encrypted to the response key the moderator's app made for
 * this one request, so a recording of the connection is useless later.
 */

const BAD_SHAPE = 'bad request shape';

/**
 * The shared checks: shape, lookupId 32 bytes, responseKey two halves of the
 * right lengths, an owners row. Returns { lookupId, responseKey, owner } or
 * { refusal }.
 */
async function checkRead(body) {
  if (!isObject(body) || typeof body.lookupId !== 'string' || !isObject(body.responseKey)) {
    return { refusal: refuse(400, BAD_SHAPE) };
  }
  if (typeof body.responseKey.x25519 !== 'string' || typeof body.responseKey.mlkem !== 'string') {
    return { refusal: refuse(400, BAD_SHAPE) };
  }
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null) return { refusal: refuse(400, 'invalid lookupId') };
  const responseKey = decodeHybridPublicKey(body.responseKey);
  if (responseKey === null) {
    const field = decodeHybridPublicKey({ x25519: body.responseKey.x25519, mlkem: 'a'.repeat(3136) }) === null ? 'x25519' : 'mlkem';
    return { refusal: refuse(400, `invalid responseKey.${field}`) };
  }
  const owner = await findOwner(lookupId);
  if (owner === null) return { refusal: refuse(404, 'unknown lookup id') };
  return { lookupId, responseKey, owner };
}

/**
 * POST /get-security-bucket-one-key and /get-security-bucket-two-key, with
 * `shareType` securitybucket1 or securitybucket2. Every share of that type
 * for the lookup id, newest first, each unwrapped and encrypted to the
 * response key with aad lookupId || shareType || keyId. An owner with no
 * shares of the type gets an empty list.
 */
export async function getBucketKey(body, shareType) {
  const checked = await checkRead(body);
  if (checked.refusal) return checked.refusal;
  const { lookupId, responseKey } = checked;

  const shares = [];
  for (const row of await listShares(lookupId, shareType)) {
    const plaintext = await unwrapBucketShare(row);
    if (plaintext === null) throw new Error(`share ${toHex(row.shareId)} does not open under its wrap`);
    shares.push({
      shareId: toHex(row.shareId),
      keyId: toHex(row.keyId),
      createdAt: row.createdAt.toISOString(),
      share: toHex(encryptToHybrid(responseKey, plaintext, transportAad(lookupId, shareType, row.keyId))),
    });
  }
  return ok(200, { lookupId: toHex(lookupId), shareType, keyholderId: env.keyholderId, shares });
}

/**
 * POST /get-public-ledger-id. The owner's public ledger id, decrypted with
 * KMS (aad lookupId) and encrypted to the response key (aad lookupId).
 * Nothing else.
 */
export async function getPublicLedgerId(body) {
  const checked = await checkRead(body);
  if (checked.refusal) return checked.refusal;
  const { lookupId, responseKey, owner } = checked;

  const publicLedgerId = await kms.decrypt(owner.publicLedgerId, lookupId);
  if (publicLedgerId === null) throw new Error(`public ledger id of ${toHex(lookupId)} does not open`);
  return ok(200, {
    lookupId: toHex(lookupId),
    publicLedgerId: toHex(encryptToHybrid(responseKey, publicLedgerId, lookupId)),
  });
}
