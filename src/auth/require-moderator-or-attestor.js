import { env } from '../config/env.js';
import { decodeId } from '../util/ids.js';
import { answer, refuse } from '../util/result.js';
import { findAccountKeys, findStakes } from './anos.queries.js';
import { checkPath, checkTimestamp, recordNonce } from './common-checks.js';
import { parseSignedRequest, verifyBoth } from './signed-request.js';

/**
 * The moderator level widened to attestors (spec 13.1), for the two bucket
 * key routes only: a request signed by an anos account's primary key pair,
 * both signatures, the account holding moderator stake or attestor stake in
 * the validator's anos database. A copy of require-moderator.js, which
 * stays as it is for /get-public-ledger-id, with step 4 reading both stake
 * columns in one query (anos.queries.js findStakes) and refusing with 403
 * not a moderator or attestor. On success `req.moderator` is the account id
 * as a 32-byte Buffer and `req.body` is `payload.body`, as before: the
 * shares service does not care which stake let the caller in.
 */
export async function requireModeratorOrAttestor(req, res, next) {
  // 1. Shape.
  const parsed = parseSignedRequest(req.body, 'accountId', { mldsa: true });
  if (parsed.reason) return answer(res, refuse(400, parsed.reason));
  const { payload, signatures } = parsed;

  // 2. and 3. The path and the timestamp.
  const common = checkPath(payload, req) ?? checkTimestamp(payload);
  if (common) return answer(res, common);

  // 4. The account: it exists, holds moderator stake or attestor stake, and
  //    both signatures are by its primary key pair.
  const accountId = decodeId(payload.accountId);
  if (accountId === null) return answer(res, refuse(400, 'invalid accountId'));
  const keys = await findAccountKeys(accountId);
  if (keys === null) return answer(res, refuse(401, 'unknown account'));
  const stakes = await findStakes(accountId);
  const admitted =
    stakes !== null &&
    (stakes.moderator >= env.stakes.minimums.moderator || stakes.attestor >= env.stakes.minimums.attestor);
  if (!admitted) return answer(res, refuse(403, 'not a moderator or attestor'));
  if (!verifyBoth(payload, signatures, keys.publicKey1, keys.publicKeyPq1)) {
    return answer(res, refuse(401, 'bad signature'));
  }

  // 5. The nonce is new.
  const replay = await recordNonce(payload);
  if (replay) return answer(res, replay);

  // 6. The caller, and the route's object.
  req.moderator = accountId;
  req.body = payload.body;
  next();
}
