import { env } from '../config/env.js';
import { loadHybridPrivateKeys, publicKeyOf } from './hybrid.js';

/**
 * This keyholder's key material, loaded once from the env file when the
 * module is first imported, which happens at boot: a malformed key fails
 * here, before the server listens.
 *
 *   - the receiving key pair: the private halves open a share on arrival
 *     (/receive-share), the public halves are answered by
 *     /get-keyholder-public-key and the phone encrypts every share to them;
 *   - the home computer's hybrid public key, the outer layer of every
 *     break-glass and backup-code share at rest (spec section 6);
 *   - the bucket-one key, which wraps bucket-one shares;
 *   - the two YubiKeys' P-256 public keys, which sign keyholder-level requests.
 */

export const receivingPrivateKeys = loadHybridPrivateKeys(env.receiving.x25519PrivateKey, env.receiving.mlkemPrivateKey);

export const receivingPublicKey = publicKeyOf(receivingPrivateKeys);

export const homePublicKey = Object.freeze({
  x25519: Buffer.from(env.home.x25519PublicKey, 'hex'),
  mlkem: Buffer.from(env.home.mlkemPublicKey, 'hex'),
});

export const bucketOneKey = Buffer.from(env.bucketOneKey, 'hex');

/** The two YubiKey public keys as Buffers, in env order; env.keyholderPublicKeys holds the hex. */
export const keyholderPublicKeys = Object.freeze(env.keyholderPublicKeys.map((hex) => Buffer.from(hex, 'hex')));
