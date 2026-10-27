import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * AES-256-GCM, the one symmetric cipher here. The bucket-one wrap, the local
 * KMS provider and the last layer of a hybrid ciphertext (hybrid.js) all use
 * it, with the same layout: iv (12) || ciphertext || tag (16), the IV random
 * per call. `aad` is the authenticated data that binds a blob to its place
 * (spec section 6): the same bytes must be handed to open(), or the tag
 * fails and nothing comes out.
 */

/** Byte length of the random IV at the front of a blob. */
export const IV_BYTES = 12;

/** Byte length of the GCM tag at the end of a blob. */
export const TAG_BYTES = 16;

/** Byte length of an AES-256 key. */
export const KEY_BYTES = 32;

/** Encrypts `plaintext` under `key` (32 bytes) with `aad`: iv || ciphertext || tag. All Buffers. */
export function seal(key, plaintext, aad) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

/**
 * The reverse of seal(): the plaintext, or null when the blob is too short,
 * the key or the aad is not the one it was sealed with, or the blob was
 * changed. Never throws on bad input.
 */
export function open(key, blob, aad) {
  if (blob.length < IV_BYTES + TAG_BYTES) return null;
  const iv = blob.subarray(0, IV_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const ciphertext = blob.subarray(IV_BYTES, blob.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}
