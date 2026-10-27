import { env } from '../config/env.js';
import { ECDSA_P256, ML_DSA_87, decodePublicKey } from '../crypto/signatures.js';
import { toHex } from '../util/ids.js';

/**
 * The one call this server makes to the masterpod: POST
 * /get-anopod-session-keys (spec 5.10), for a pod's current session public
 * keys, so a /receive-share signature can be checked (spec 3.1). Keys are
 * fetched for every call and never cached: a new unlock replaces them.
 */

/** How long the masterpod has to answer. */
const TIMEOUT_MS = 5_000;

/**
 * Fetches the session keys of the pod `anopodId` (a 32-byte Buffer).
 * Returns one of
 *   { keys: { ephemeralAuthKey, ephemeralAuthKeyPq, ephemeralExpiresAt } }
 *     (two raw key Buffers and a Date),
 *   { notFound: true }       the masterpod answered 404: no such pod,
 *   { unavailable: true }    no answer in time, a 5xx, or an answer that is
 *                            not a usable set of keys.
 */
export async function fetchSessionKeys(anopodId) {
  let response;
  try {
    response = await fetch(`${env.masterpodUrl}/get-anopod-session-keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ anopodId: toHex(anopodId) }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    return { unavailable: true };
  }
  if (response.status === 404) return { notFound: true };
  if (!response.ok) return { unavailable: true };

  let body;
  try {
    body = await response.json();
  } catch {
    return { unavailable: true };
  }
  const ephemeralAuthKey = decodePublicKey(ECDSA_P256, body?.ephemeralAuthKey);
  const ephemeralAuthKeyPq = decodePublicKey(ML_DSA_87, body?.ephemeralAuthKeyPq);
  const expires = Date.parse(body?.ephemeralExpiresAt);
  if (ephemeralAuthKey === null || ephemeralAuthKeyPq === null || Number.isNaN(expires)) {
    return { unavailable: true };
  }
  return { keys: { ephemeralAuthKey, ephemeralAuthKeyPq, ephemeralExpiresAt: new Date(expires) } };
}
