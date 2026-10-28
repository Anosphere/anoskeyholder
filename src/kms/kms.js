/**
 * The KMS of spec section 6: one interface, encrypt(plaintext, aad) and
 * decrypt(ciphertext, aad), Buffers in and a Buffer out, both async. decrypt
 * is null when the ciphertext does not open under this key and this aad.
 * Under it, every bucket-two share and the KMS layer of every break-glass
 * and backup-code share, and every public ledger id.
 *
 * Cloud KMS (gcp.js, on the key KMS_KEY_NAME) is the one provider since the
 * testnet build; src/server.js round-trips a fixed plaintext through it at
 * boot, before listening, and stops when that fails.
 */
export { encrypt, decrypt } from './gcp.js';
