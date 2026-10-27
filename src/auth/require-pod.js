import { decodeId } from '../util/ids.js';
import { answer, refuse } from '../util/result.js';
import { checkPath, checkTimestamp, recordNonce } from './common-checks.js';
import { fetchSessionKeys } from './masterpod.client.js';
import { parseSignedRequest, verifyBoth } from './signed-request.js';

/**
 * The pod level (spec 3.1): a request signed by an anoPod's current
 * masterpod session keys, both signatures. Runs the steps of section 3 in
 * order and stops at the first failure; on success `req.pod` is the pod's id
 * as a 32-byte Buffer and `req.body` is `payload.body`, the route's own
 * object, so a handler reads the caller from req.pod and nothing else.
 */
export async function requirePod(req, res, next) {
  // 1. Shape.
  const parsed = parseSignedRequest(req.body, 'anopodId', { mldsa: true });
  if (parsed.reason) return answer(res, refuse(400, parsed.reason));
  const { payload, signatures } = parsed;

  // 2. and 3. The path and the timestamp.
  const common = checkPath(payload, req) ?? checkTimestamp(payload);
  if (common) return answer(res, common);

  // 4. The pod: its id decodes, the masterpod knows it, its session is
  //    alive, and both signatures are by its current session keys.
  const anopodId = decodeId(payload.anopodId);
  if (anopodId === null) return answer(res, refuse(400, 'invalid anopodId'));
  const found = await fetchSessionKeys(anopodId);
  if (found.unavailable) return answer(res, refuse(502, 'masterpod unavailable'));
  if (found.notFound) return answer(res, refuse(401, 'unknown anopod'));
  const { keys } = found;
  if (keys.ephemeralExpiresAt.getTime() <= Date.now()) return answer(res, refuse(401, 'session expired'));
  if (!verifyBoth(payload, signatures, keys.ephemeralAuthKey, keys.ephemeralAuthKeyPq)) {
    return answer(res, refuse(401, 'bad signature'));
  }

  // 5. The nonce is new.
  const replay = await recordNonce(payload);
  if (replay) return answer(res, replay);

  // 6. The caller, and the route's object.
  req.pod = anopodId;
  req.body = payload.body;
  next();
}
