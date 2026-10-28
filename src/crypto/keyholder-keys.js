import { env } from '../config/env.js';
import { loadHybridPrivateKeys, publicKeyOf } from './hybrid.js';
import { readKeyFile } from './key-file.js';

/**
 * This keyholder's key material, loaded once when the module is first
 * imported, which happens at boot: a missing or open key file, or a
 * malformed key, fails here, before the server listens.
 *
 *   - the receiving key pair and the bucket-one key, from the key file
 *     (KEY_FILE in .env, written by scripts/make-keys.js): the private
 *     halves open a share on arrival (/receive-share), the public halves are
 *     answered by /get-keyholder-public-key and the phone encrypts every
 *     share to them; the bucket-one key wraps bucket-one shares;
 *   - the home computer's hybrid public key, from .env, the outer layer of
 *     every break-glass and backup-code share at rest (spec section 6);
 *   - the two YubiKeys' P-256 public keys, from .env, which sign
 *     keyholder-level requests.
 */

const keyFile = readKeyFile(env.keyFile, {
  receivingX25519PrivateKey: 48,
  receivingMlkemPrivateKey: 86,
  bucketOneKey: 32,
});

export const receivingPrivateKeys = loadHybridPrivateKeys(keyFile.receivingX25519PrivateKey, keyFile.receivingMlkemPrivateKey);

export const receivingPublicKey = publicKeyOf(receivingPrivateKeys);

export const homePublicKey = Object.freeze({
  x25519: Buffer.from(env.home.x25519PublicKey, 'hex'),
  mlkem: Buffer.from(env.home.mlkemPublicKey, 'hex'),
});

export const bucketOneKey = Buffer.from(keyFile.bucketOneKey, 'hex');

/** The two YubiKey public keys as Buffers, in env order; env.keyholderPublicKeys holds the hex. */
export const keyholderPublicKeys = Object.freeze(env.keyholderPublicKeys.map((hex) => Buffer.from(hex, 'hex')));
