import { env } from '../config/env.js';
import { keyholderPublicKeys } from '../crypto/keyholder-keys.js';
import { answer, refuse } from '../util/result.js';
import { checkPath, checkTimestamp, recordNonce } from './common-checks.js';
import { parseSignedRequest, verifyEcdsa } from './signed-request.js';

/**
 * The keyholder level (spec 3.3): a request signed by one of the two
 * YubiKeys listed in the env file, one P-256 signature (64-byte r||s or
 * DER, since a PIV slot signs in DER). There is no post-quantum signature
 * at this level: forging it yields blobs only the home computer's hybrid
 * key opens. On success `req.yubikey` is the hex of the key that verified
 * and `req.body` is `payload.body`.
 */
export async function requireKeyholder(req, res, next) {
  // 1. Shape.
  const parsed = parseSignedRequest(req.body, 'yubikey', { mldsa: false });
  if (parsed.reason) return answer(res, refuse(400, parsed.reason));
  const { payload, signatures } = parsed;

  // 2. and 3. The path and the timestamp.
  const common = checkPath(payload, req) ?? checkTimestamp(payload);
  if (common) return answer(res, common);

  // 4. The key: one of the two in the env file, exactly as written there
  //    (lowercase hex of a 33-byte compressed point), and the signature is
  //    by it.
  const index = env.keyholderPublicKeys.indexOf(payload.yubikey);
  if (index === -1) return answer(res, refuse(401, 'unknown key'));
  if (!verifyEcdsa(payload, signatures.ecdsa, keyholderPublicKeys[index])) {
    return answer(res, refuse(401, 'bad signature'));
  }

  // 5. The nonce is new.
  const replay = await recordNonce(payload);
  if (replay) return answer(res, replay);

  // 6. The caller, and the route's object.
  req.yubikey = payload.yubikey;
  req.body = payload.body;
  next();
}
