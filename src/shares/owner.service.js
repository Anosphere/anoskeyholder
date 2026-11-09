import { env } from '../config/env.js';
import { decodeId, toHex } from '../util/ids.js';
import { isObject } from '../util/is-object.js';
import { ok, refuse } from '../util/result.js';
import { findOwner } from './shares.queries.js';

/**
 * The owner lookup, POST /get-owner (spec section 15), the one unsigned
 * route of the shares feature. A locked-out person's wallet calls it: the
 * person has lost the pod and has nothing to sign with, so the route is
 * level none like /get-keyholder-public-key. The wallet computes the lookup
 * id from the birth record and asks every keyholder at once which pod
 * deposited for it, and uses the anoPod id answered for the masterpod's
 * challenge and as the recovery passkey's user handle. Nothing is
 * decrypted: the public ledger id is not read.
 */

const BAD_SHAPE = 'bad request shape';

/**
 * POST /get-owner. Body { lookupId }. The checks of spec 15.1 in order:
 * shape, lookupId 32 bytes, an owners row. Answers the lookup id, the
 * anoPod id that deposited the first share, in full, and this keyholder's
 * number.
 */
export async function getOwner(body) {
  if (!isObject(body) || typeof body.lookupId !== 'string') return refuse(400, BAD_SHAPE);
  const lookupId = decodeId(body.lookupId);
  if (lookupId === null) return refuse(400, 'invalid lookupId');
  const owner = await findOwner(lookupId);
  if (owner === null) return refuse(404, 'unknown lookup id');
  return ok(200, { lookupId: toHex(lookupId), anopodId: toHex(owner.anopodId), keyholderId: env.keyholderId });
}
