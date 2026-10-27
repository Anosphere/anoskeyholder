import { env } from '../config/env.js';

/**
 * The KMS of spec section 6: one interface, encrypt(plaintext, aad) and
 * decrypt(ciphertext, aad), Buffers in and a Buffer out, both async. decrypt
 * is null when the ciphertext does not open under this key and this aad.
 * Under it, every bucket-two share and the KMS layer of every break-glass
 * and backup-code share, and every public ledger id.
 *
 * The provider is chosen once from KMS_PROVIDER: `gcp` is Cloud KMS on the
 * VM (gcp.js), `local` is AES-256-GCM under KMS_LOCAL_KEY on this Mac
 * (local.js). The import is dynamic, so a local keyholder never loads
 * Google's client library.
 */
const provider = env.kms.provider === 'gcp' ? await import('./gcp.js') : await import('./local.js');

export const encrypt = provider.encrypt;
export const decrypt = provider.decrypt;
