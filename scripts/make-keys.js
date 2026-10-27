import { ECDH, generateKeyPairSync, randomBytes } from 'node:crypto';

/**
 * Prints fresh values for every key line of a .env-keyholderN file (spec
 * sections 9 and 10). Nothing is written anywhere: copy the lines into the
 * env file. Every run prints new values.
 *
 *   npm run make-keys
 *
 * The private halves that do not belong on the keyholder are printed once,
 * as comments: the home computer's hybrid private key, and the private keys
 * of the two P-256 pairs that stand in for the YubiKeys until the real ones
 * are enrolled. Keep them where they belong and nowhere else.
 *
 * Encodings (spec 7.2): private keys PKCS#8 DER in hex (X25519 48 bytes,
 * ML-KEM-1024 86 bytes in the seed form Node exports, P-256 as Node exports
 * it); public keys raw bytes in hex (X25519 32, ML-KEM-1024 1568, P-256 33
 * compressed). Node exports public keys as SPKI DER, a constant prefix in
 * front of the raw bytes for a fixed algorithm, which is cut off here.
 */

const SPKI_PREFIX_BYTES = { x25519: 12, 'ml-kem-1024': 22, p256: 26 };
const RAW_PUBLIC_BYTES = { x25519: 32, 'ml-kem-1024': 1568, p256: 65 };

const hex = (bytes) => Buffer.from(bytes).toString('hex');

function pkcs8Hex(privateKey) {
  return hex(privateKey.export({ format: 'der', type: 'pkcs8' }));
}

function rawPublic(publicKey, algorithm) {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const expected = SPKI_PREFIX_BYTES[algorithm] + RAW_PUBLIC_BYTES[algorithm];
  if (spki.length !== expected) {
    throw new Error(`${algorithm}: SPKI is ${spki.length} bytes, expected ${expected}`);
  }
  return spki.subarray(SPKI_PREFIX_BYTES[algorithm]);
}

/** An X25519 pair and an ML-KEM-1024 pair: the two halves of a hybrid key. */
function hybridPair() {
  const x25519 = generateKeyPairSync('x25519');
  const mlkem = generateKeyPairSync('ml-kem-1024');
  return {
    x25519Private: pkcs8Hex(x25519.privateKey),
    mlkemPrivate: pkcs8Hex(mlkem.privateKey),
    x25519Public: hex(rawPublic(x25519.publicKey, 'x25519')),
    mlkemPublic: hex(rawPublic(mlkem.publicKey, 'ml-kem-1024')),
  };
}

/** A P-256 pair, the public key as a 33-byte compressed point. */
function p256Pair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const uncompressed = rawPublic(publicKey, 'p256');
  const compressed = ECDH.convertKey(uncompressed, 'prime256v1', undefined, undefined, 'compressed');
  return { publicKey: hex(compressed), privateKey: pkcs8Hex(privateKey) };
}

const receiving = hybridPair();
const home = hybridPair();
const yubikey1 = p256Pair();
const yubikey2 = p256Pair();

console.log(`# Receiving key pair: the phone encrypts every share to its public halves,
# which /get-keyholder-public-key answers (raw hex, for reference):
#   x25519 ${receiving.x25519Public}
#   mlkem  ${receiving.mlkemPublic}
RECEIVING_X25519_PRIVATE_KEY=${receiving.x25519Private}
RECEIVING_MLKEM_PRIVATE_KEY=${receiving.mlkemPrivate}

# Home computer's hybrid key: the public halves go in this file. The private
# halves are for the home computer and nothing else; shown once (PKCS#8 DER,
# hex), never on the VM:
#   x25519 private ${home.x25519Private}
#   mlkem  private ${home.mlkemPrivate}
HOME_X25519_PUBLIC_KEY=${home.x25519Public}
HOME_MLKEM_PUBLIC_KEY=${home.mlkemPublic}

# Two P-256 pairs standing in for the two YubiKeys until the real ones are
# enrolled (then put the YubiKeys' public keys here instead). The private
# keys are shown once (PKCS#8 DER, hex), for the home computer's signing:
#   key 1 private ${yubikey1.privateKey}
#   key 2 private ${yubikey2.privateKey}
KEYHOLDER_PUBLIC_KEY_1=${yubikey1.publicKey}
KEYHOLDER_PUBLIC_KEY_2=${yubikey2.publicKey}

# Wraps bucket-one shares (wrap env-aes-gcm-v1).
BUCKET_ONE_KEY=${hex(randomBytes(32))}

# The local KMS key, used when KMS_PROVIDER=local.
KMS_LOCAL_KEY=${hex(randomBytes(32))}`);
