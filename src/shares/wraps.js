import { open, seal } from '../crypto/aead.js';
import { encryptToHybrid } from '../crypto/hybrid.js';
import { bucketOneKey, homePublicKey } from '../crypto/keyholder-keys.js';
import * as kms from '../kms/kms.js';
import { BACKUP_CODE, BREAK_GLASS_KEY, SECURITY_BUCKET_1, SECURITY_BUCKET_2 } from './share-types.js';

/**
 * What the server stores, per share type (spec section 6), and the
 * authenticated data that binds every ciphertext to its place.
 *
 * | shareType       | wrap               | stored share                                   |
 * | securitybucket1 | env-aes-gcm-v1     | AES-256-GCM under BUCKET_ONE_KEY                |
 * | securitybucket2 | kms-v1             | the KMS ciphertext                              |
 * | breakglasskey   | kms-home-hybrid-v1 | the KMS ciphertext, encrypted to the home key   |
 * | backupcode      | kms-home-hybrid-v1 | as above                                        |
 *
 * The wrap column says which layout a row has, so a future key rotation can
 * tell old rows from new.
 */

export const ENV_AES_GCM_V1 = 'env-aes-gcm-v1';
export const KMS_V1 = 'kms-v1';
export const KMS_HOME_HYBRID_V1 = 'kms-home-hybrid-v1';

const WRAP_FOR_TYPE = Object.freeze({
  [SECURITY_BUCKET_1]: ENV_AES_GCM_V1,
  [SECURITY_BUCKET_2]: KMS_V1,
  [BREAK_GLASS_KEY]: KMS_HOME_HYBRID_V1,
  [BACKUP_CODE]: KMS_HOME_HYBRID_V1,
});

/** The wrap a share of `shareType` is stored under. */
export function wrapFor(shareType) {
  return WRAP_FOR_TYPE[shareType];
}

/**
 * The authenticated data of a share at rest: share_id || lookup_id ||
 * share_type (UTF-8) || key_id, raw bytes, from a row or a row-to-be with
 * those four fields as Buffers and a string.
 */
export function aadFor({ shareId, lookupId, shareType, keyId }) {
  return Buffer.concat([shareId, lookupId, Buffer.from(shareType, 'utf8'), keyId]);
}

/**
 * The authenticated data of a share in transit, between the phone and this
 * server (spec 5.2) and between this server and a moderator (5.3, 5.4) or a
 * recovery pod (5.8, 5.9): lookup_id || share_type || key_id.
 */
export function transportAad(lookupId, shareType, keyId) {
  return Buffer.concat([lookupId, Buffer.from(shareType, 'utf8'), keyId]);
}

/**
 * Wraps the plaintext share bytes for storage as the table above says for
 * `shareType`, with `aad` from aadFor(). Returns { share, wrap }. The KMS
 * calls happen here, before the caller opens its transaction.
 */
export async function wrapShare(shareType, plaintext, aad) {
  const wrap = wrapFor(shareType);
  switch (wrap) {
    case ENV_AES_GCM_V1:
      return { share: seal(bucketOneKey, plaintext, aad), wrap };
    case KMS_V1:
      return { share: await kms.encrypt(plaintext, aad), wrap };
    case KMS_HOME_HYBRID_V1:
      return { share: encryptToHybrid(homePublicKey, await kms.encrypt(plaintext, aad), aad), wrap };
    default:
      throw new TypeError(`Unknown share type: ${shareType}`);
  }
}

/**
 * The plaintext share of a bucket row (wrap env-aes-gcm-v1 or kms-v1), for a
 * moderator read. Null when the stored blob does not open, which a row this
 * server wrote never does.
 */
export async function unwrapBucketShare(row) {
  const aad = aadFor(row);
  switch (row.wrap) {
    case ENV_AES_GCM_V1:
      return open(bucketOneKey, row.share, aad);
    case KMS_V1:
      return kms.decrypt(row.share, aad);
    default:
      throw new TypeError(`${row.wrap} is not a bucket wrap`);
  }
}

/**
 * The plaintext share inside `kmsBlob`, the KMS ciphertext the home computer
 * peeled out of a kms-home-hybrid-v1 row and handed back (spec 5.8, 5.9).
 * The aad is the row's, so a blob from another share does not open here.
 * Null when it does not open.
 */
export function kmsDecryptBlob(row, kmsBlob) {
  return kms.decrypt(kmsBlob, aadFor(row));
}
