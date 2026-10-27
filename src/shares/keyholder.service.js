import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { decodeHybridPublicKey, encryptToHybrid } from '../crypto/hybrid.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { allowedDestination, postToRecoveryPod } from './forward.js';
import { findOwner, findShare, listShares } from './shares.queries.js';
import { kmsDecryptBlob, transportAad } from './wraps.js';

/**
 * The four keyholder routes (spec 5.6 to 5.9), called by the keyholder's own
 * home computer with a YubiKey (req.yubikey). The two get routes hand out
 * blobs as stored; the two decrypt routes peel the KMS layer off a blob the
 * home computer opened and forward the share to a recovery pod. The server
 * opens nothing on a get.
 */

const BAD_SHAPE = 'bad request shape';

/** A KMS blob handed back is at most 4096 bytes. */
const kmsBlobLength = (n) => n >= 1 && n <= 4096;

/**
 * POST /get-break-glass-key and /get-backup-code, with `shareType`
 * breakglasskey or backupcode. Body { lookupId }. Every share of that type
 * for the lookup id, newest first, the share column as stored: the
 * KMS-wrapped share encrypted to the home computer's hybrid key.
 */
export async function getBlobs(body, shareType) {
  if (!isObject(body) || typeof body.lookupId !== 'string') return refuse(400, BAD_SHAPE);
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null) return refuse(400, 'invalid lookupId');
  if ((await findOwner(lookupId)) === null) return refuse(404, 'unknown lookup id');

  const shares = (await listShares(lookupId, shareType)).map((row) => ({
    shareId: toHex(row.shareId),
    keyId: toHex(row.keyId),
    createdAt: row.createdAt.toISOString(),
    blob: toHex(row.share),
  }));
  return ok(200, { lookupId: toHex(lookupId), shareType, keyholderId: env.keyholderId, shares });
}

/**
 * POST /decrypt-break-glass-key and /decrypt-backup-code, with `shareType`
 * breakglasskey or backupcode. Body { shareId, kmsBlob, destination: { url,
 * hybridKey } }. The checks of spec 5.8 in order, then the share encrypted
 * to the destination's key and posted there.
 */
export async function decryptAndForward(body, shareType) {
  // 1. Shape.
  if (!isObject(body) || typeof body.shareId !== 'string' || typeof body.kmsBlob !== 'string') {
    return refuse(400, BAD_SHAPE);
  }
  const { destination } = body;
  if (!isObject(destination) || typeof destination.url !== 'string' || !isObject(destination.hybridKey)) {
    return refuse(400, BAD_SHAPE);
  }

  // 2. The share: its row exists and is of this route's type.
  const shareId = decodeId(body.shareId);
  const row = shareId === null ? null : await findShare(shareId);
  if (row === null) return refuse(404, 'unknown share');
  if (row.shareType !== shareType) return refuse(400, 'wrong share type');

  // 3. The destination: an http or https URL on an allowed host, and a
  //    hybrid key of the right lengths. The blob must decode too.
  const url = allowedDestination(destination.url);
  if (url === null) return refuse(403, 'destination not allowed');
  const hybridKey = decodeHybridPublicKey(destination.hybridKey);
  if (hybridKey === null) return refuse(400, 'invalid destination.hybridKey');
  const kmsBlob = decodeBytes(body.kmsBlob, kmsBlobLength);
  if (kmsBlob === null) return refuse(400, 'invalid kmsBlob');

  // 4. The blob opens through KMS with this row's authenticated data.
  const plaintext = await kmsDecryptBlob(row, kmsBlob);
  if (plaintext === null) return refuse(400, 'blob does not open');

  // 5. The share, encrypted to the destination's key, posted to the recovery pod.
  const share = encryptToHybrid(hybridKey, plaintext, transportAad(row.lookupId, shareType, row.keyId));
  const delivery = await postToRecoveryPod(url, {
    keyholderId: env.keyholderId,
    lookupId: toHex(row.lookupId),
    shareType,
    keyId: toHex(row.keyId),
    share: toHex(share),
  });
  if (delivery.unreachable) return refuse(502, 'recovery pod unreachable');

  return ok(200, {
    shareId: toHex(shareId),
    delivered: true,
    recoveryPod: { status: delivery.status, body: delivery.body },
  });
}
