import {
  createPrivateKey,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
} from 'node:crypto';
import { IV_BYTES, TAG_BYTES, open, seal } from './aead.js';
import { decodeBytes } from './bytes.js';

/**
 * Encrypting to a hybrid public key (spec 7.1): X25519 and ML-KEM-1024 side
 * by side, their two shared secrets run through HKDF-SHA-256 into one
 * AES-256-GCM key. The phone encrypts a share to the keyholder's receiving
 * key this way (@noble on its side, checked against this code); the server
 * encrypts a share to a moderator's response key, to the home computer's key
 * and to a recovery pod's key. Everything here is node:crypto.
 *
 * Wire layout: e.public (32) || ct (1568) || iv (12) || c || tag (16), so a
 * ciphertext is HYBRID_OVERHEAD_BYTES longer than its plaintext. The HKDF
 * salt is e.public || ct, which binds the key to this one encapsulation; the
 * info string gets a new version if anything here changes.
 *
 * Key encodings (spec 7.2): public keys travel and sit in the env as raw
 * bytes; Node takes SPKI DER, which for a fixed algorithm is a constant
 * prefix in front of the raw bytes. Private keys in the env are PKCS#8 DER.
 */

/** Byte length of a raw X25519 public key. */
export const X25519_PUBLIC_BYTES = 32;

/** Byte length of a raw ML-KEM-1024 public key, and of its ciphertext. */
export const MLKEM_PUBLIC_BYTES = 1568;
export const MLKEM_CIPHERTEXT_BYTES = 1568;

/** Bytes a hybrid ciphertext adds to its plaintext: 1628. */
export const HYBRID_OVERHEAD_BYTES = X25519_PUBLIC_BYTES + MLKEM_CIPHERTEXT_BYTES + IV_BYTES + TAG_BYTES;

const INFO = Buffer.from('keyholder/hybrid/v1', 'utf8');
const KEY_BYTES = 32;

// SPKI DER = SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, raw key } }.
// id-X25519 (1.3.101.110) and id-alg-ml-kem-1024 (2.16.840.1.101.3.4.4.3).
export const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
export const MLKEM_SPKI_PREFIX = Buffer.from('30820632300b06096086480165030404030382062100', 'hex');

/** A public KeyObject from raw bytes and the algorithm's SPKI prefix. */
function publicKeyFromRaw(prefix, raw) {
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
}

/** The raw public bytes of a key object (public, or private, whose public half is derived), the SPKI prefix stripped. */
function rawPublicKey(keyObject, prefix) {
  const publicKey = keyObject.type === 'public' ? keyObject : createPublicKey(keyObject);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  if (!spki.subarray(0, prefix.length).equals(prefix)) {
    throw new Error('unexpected SPKI encoding for a hybrid key half');
  }
  return spki.subarray(prefix.length);
}

/**
 * Decodes a hybrid public key as it arrives in JSON, { x25519, mlkem } in hex
 * (base64 accepted), to { x25519, mlkem } Buffers of 32 and 1568 bytes. Null
 * when either half is missing or the wrong length.
 */
export function decodeHybridPublicKey(key) {
  if (typeof key !== 'object' || key === null) return null;
  const x25519 = decodeBytes(key.x25519, [X25519_PUBLIC_BYTES]);
  const mlkem = decodeBytes(key.mlkem, [MLKEM_PUBLIC_BYTES]);
  if (x25519 === null || mlkem === null) return null;
  return { x25519, mlkem };
}

/** key = HKDF-SHA-256(ikm = ss1 || ss2, salt = e.public || ct, info, 32). */
function deriveKey(ss1, ss2, ephemeralPublic, ciphertext) {
  return Buffer.from(
    hkdfSync('sha256', Buffer.concat([ss1, ss2]), Buffer.concat([ephemeralPublic, ciphertext]), INFO, KEY_BYTES),
  );
}

/**
 * Encrypts `plaintext` to `recipient` ({ x25519, mlkem } raw Buffers, from
 * decodeHybridPublicKey or publicKeyOf) with authenticated data `aad`.
 * Returns the wire bytes described above.
 */
export function encryptToHybrid(recipient, plaintext, aad) {
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralPublic = rawPublicKey(ephemeral.publicKey, X25519_SPKI_PREFIX);
  const ss1 = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: publicKeyFromRaw(X25519_SPKI_PREFIX, recipient.x25519),
  });
  const { sharedKey: ss2, ciphertext } = encapsulate(publicKeyFromRaw(MLKEM_SPKI_PREFIX, recipient.mlkem));
  const key = deriveKey(ss1, ss2, ephemeralPublic, ciphertext);
  return Buffer.concat([ephemeralPublic, ciphertext, seal(key, plaintext, aad)]);
}

/**
 * The reverse of encryptToHybrid() with the recipient's private keys
 * ({ x25519, mlkem } KeyObjects from loadHybridPrivateKeys). Null when the
 * blob is too short, was not made for these keys, was changed, or the aad
 * differs. Never throws on bad input. (A wrong ML-KEM ciphertext does not
 * fail at decapsulation, it yields a random secret; the tag then fails.)
 */
export function decryptHybrid(privateKeys, blob, aad) {
  if (blob.length < HYBRID_OVERHEAD_BYTES) return null;
  const ephemeralPublic = blob.subarray(0, X25519_PUBLIC_BYTES);
  const ciphertext = blob.subarray(X25519_PUBLIC_BYTES, X25519_PUBLIC_BYTES + MLKEM_CIPHERTEXT_BYTES);
  const sealed = blob.subarray(X25519_PUBLIC_BYTES + MLKEM_CIPHERTEXT_BYTES);
  try {
    const ss1 = diffieHellman({
      privateKey: privateKeys.x25519,
      publicKey: publicKeyFromRaw(X25519_SPKI_PREFIX, ephemeralPublic),
    });
    const ss2 = decapsulate(privateKeys.mlkem, ciphertext);
    return open(deriveKey(ss1, ss2, ephemeralPublic, ciphertext), sealed, aad);
  } catch {
    return null;
  }
}

/**
 * Loads a hybrid private key from the env file's two PKCS#8 DER hex values
 * (48 bytes for X25519, 86 for ML-KEM-1024) into { x25519, mlkem }
 * KeyObjects. Throws when either is not a key of its algorithm, so a bad env
 * file fails at boot.
 */
export function loadHybridPrivateKeys(x25519Pkcs8Hex, mlkemPkcs8Hex) {
  const x25519 = createPrivateKey({ key: Buffer.from(x25519Pkcs8Hex, 'hex'), format: 'der', type: 'pkcs8' });
  const mlkem = createPrivateKey({ key: Buffer.from(mlkemPkcs8Hex, 'hex'), format: 'der', type: 'pkcs8' });
  if (x25519.asymmetricKeyType !== 'x25519') {
    throw new Error(`expected an X25519 private key, got ${x25519.asymmetricKeyType}`);
  }
  if (mlkem.asymmetricKeyType !== 'ml-kem-1024') {
    throw new Error(`expected an ML-KEM-1024 private key, got ${mlkem.asymmetricKeyType}`);
  }
  return { x25519, mlkem };
}

/** The raw public halves, { x25519 (32), mlkem (1568) } Buffers, of a loaded private key. */
export function publicKeyOf(privateKeys) {
  return {
    x25519: rawPublicKey(privateKeys.x25519, X25519_SPKI_PREFIX),
    mlkem: rawPublicKey(privateKeys.mlkem, MLKEM_SPKI_PREFIX),
  };
}

/**
 * A fresh hybrid key pair, for scripts/make-keys.js and the rig: the private
 * halves as KeyObjects and as PKCS#8 DER hex (the env file form), the public
 * halves raw.
 */
export function generateHybridKeyPair() {
  const x25519 = generateKeyPairSync('x25519');
  const mlkem = generateKeyPairSync('ml-kem-1024');
  const privateKeys = { x25519: x25519.privateKey, mlkem: mlkem.privateKey };
  return {
    privateKeys,
    pkcs8: {
      x25519: x25519.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
      mlkem: mlkem.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
    },
    publicKey: publicKeyOf(privateKeys),
  };
}
