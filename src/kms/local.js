import { env } from '../config/env.js';
import { open, seal } from '../crypto/aead.js';

/**
 * The local KMS provider: AES-256-GCM under KMS_LOCAL_KEY with the same
 * authenticated data the Cloud KMS provider gets, iv (12) || ciphertext ||
 * tag (16). For this Mac. Behaves the same as gcp.js and logs nothing.
 */

const key = Buffer.from(env.kms.localKey, 'hex');

/** The ciphertext of `plaintext` under the local key with `aad`. */
export async function encrypt(plaintext, aad) {
  return seal(key, plaintext, aad);
}

/** The plaintext of `ciphertext`, or null when it does not open under the local key with `aad`. */
export async function decrypt(ciphertext, aad) {
  return open(key, ciphertext, aad);
}
