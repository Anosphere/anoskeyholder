import { env } from '../config/env.js';
import { decodeBytes } from '../crypto/bytes.js';
import { decryptHybrid } from '../crypto/hybrid.js';
import { receivingPrivateKeys } from '../crypto/keyholder-keys.js';
import { isUniqueViolation, withTransaction } from '../db/transaction.js';
import * as kms from '../kms/kms.js';
import { decodeId, randomId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { isShareType } from './share-types.js';
import { findOwner, insertOwner, insertShare, keyIdExists } from './shares.queries.js';
import { aadFor, transportAad, wrapShare } from './wraps.js';

/**
 * POST /receive-share (spec 5.2): the phone deposits one share. `pod` is the
 * verified signer, req.pod, the anoPod the share belongs to; `body` is
 * payload.body.
 */

const BAD_SHAPE = 'bad request shape';

/** The share as received is at most 4096 bytes; the plaintext inside it is 1 to 256. */
const receivedShareLength = (n) => n >= 1 && n <= 4096;
const plaintextShareLength = (n) => n >= 1 && n <= 256;

export async function receiveShare(pod, body) {
  // 1. Shape: the five string fields.
  if (!isObject(body)) return refuse(400, BAD_SHAPE);
  for (const field of ['lookupId', 'publicLedgerId', 'shareType', 'keyId', 'share']) {
    if (typeof body[field] !== 'string') return refuse(400, BAD_SHAPE);
  }

  // 2. Values, each refusal naming the field.
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null) return refuse(400, 'invalid lookupId');
  const publicLedgerId = decodeId(body.publicLedgerId);
  if (publicLedgerId === null) return refuse(400, 'invalid publicLedgerId');
  const keyId = decodeId(body.keyId);
  if (keyId === null) return refuse(400, 'invalid keyId');
  const { shareType } = body;
  if (!isShareType(shareType)) return refuse(400, 'invalid shareType');
  const received = decodeBytes(body.share, receivedShareLength);
  if (received === null) return refuse(400, 'invalid share');

  // 3. The key id is new.
  if (await keyIdExists(keyId)) return refuse(409, 'key id already stored');

  // 4. The share opens with the receiving key, bound to lookupId || shareType || keyId.
  const plaintext = decryptHybrid(receivingPrivateKeys, received, transportAad(lookupId, shareType, keyId));
  if (plaintext === null || !plaintextShareLength(plaintext.length)) return refuse(400, 'share does not open');

  // 5. The owner: the first share for a lookup id writes the row, every later
  //    one must come from the same pod. The handed publicLedgerId is not
  //    compared against the stored one.
  const owner = await findOwner(lookupId);
  if (owner !== null && !owner.anopodId.equals(pod)) return refuse(409, 'anopod mismatch');
  const ownerRow =
    owner === null ? { lookupId, publicLedgerId: await kms.encrypt(publicLedgerId, lookupId), anopodId: pod } : null;

  // 6. The share, wrapped as section 6 says under a fresh share id. The KMS
  //    calls are done before the transaction opens.
  const shareId = randomId();
  const { share, wrap } = await wrapShare(shareType, plaintext, aadFor({ shareId, lookupId, shareType, keyId }));

  try {
    await withTransaction(async (client) => {
      if (ownerRow !== null) await insertOwner(client, ownerRow);
      await insertShare(client, { shareId, lookupId, shareType, keyId, share, wrap });
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      // Two deposits racing past the checks above: a repeated key id, or two
      // first deposits for the same lookup id at once.
      return refuse(409, err.constraint === 'shares_key_id_key' ? 'key id already stored' : 'concurrent first deposit');
    }
    throw err;
  }

  return ok(201, { shareId: toHex(shareId), keyholderId: env.keyholderId });
}
