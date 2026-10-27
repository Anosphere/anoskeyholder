import { env } from '../config/env.js';

/**
 * The Cloud KMS provider: encrypt and decrypt on the key KMS_KEY_NAME, a
 * cryptoKeys resource name whose protection level is HSM, with the
 * authenticated data passed as additionalAuthenticatedData. Credentials come
 * from the VM's service account (locally, Google's own
 * GOOGLE_APPLICATION_CREDENTIALS). Plaintext is at most 64 KiB; shares are
 * tiny. The client is created on the first call.
 */

/** gRPC status INVALID_ARGUMENT: what Cloud KMS answers when a ciphertext does not open. */
const INVALID_ARGUMENT = 3;

let client = null;

async function kmsClient() {
  if (client === null) {
    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    client = new KeyManagementServiceClient();
  }
  return client;
}

/** The KMS ciphertext of `plaintext` with `aad`. */
export async function encrypt(plaintext, aad) {
  const [result] = await (await kmsClient()).encrypt({
    name: env.kms.keyName,
    plaintext,
    additionalAuthenticatedData: aad,
  });
  return Buffer.from(result.ciphertext);
}

/** The plaintext of `ciphertext`, or null when KMS refuses it (wrong key, wrong aad, changed bytes). */
export async function decrypt(ciphertext, aad) {
  try {
    const [result] = await (await kmsClient()).decrypt({
      name: env.kms.keyName,
      ciphertext,
      additionalAuthenticatedData: aad,
    });
    return Buffer.from(result.plaintext);
  } catch (err) {
    if (err?.code === INVALID_ARGUMENT) return null;
    throw err;
  }
}
