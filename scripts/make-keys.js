import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

/**
 * Makes this keyholder's keys and its machine file, on the VM, once:
 *
 *   npm run make-keys -- --id <N> [--key-file <path>]
 *
 * --id is the keyholder's number, its validator's id; the only thing
 * anyone types. The receiving key pair (X25519 and ML-KEM-1024, which the
 * phone encrypts every share to) and the bucket-one key (32 random bytes,
 * which wraps bucket-one shares) are generated here and written to the key
 * file (default ./keyholder.key: JSON { receivingX25519PrivateKey,
 * receivingMlkemPrivateKey, bucketOneKey } in hex, mode 0600) and never
 * shown. The receiving public halves are printed as information only: the
 * keyholder serves them live (/get-keyholder-public-key) and nobody records
 * them.
 *
 * .env is written beside it, mode 0644 so the database scripts can read it
 * as postgres: KEYHOLDER_ID, two random database passwords and KEY_FILE
 * with values, then the five lines that are filled by hand, each as
 * "<fill in>" under a comment saying what goes there: the Cloud KMS key's
 * resource name, the home computer's two public halves and the two
 * YubiKeys' public keys, from the operator's project and keyholder GUI. No
 * stand-in home or YubiKey keys are generated any more. Everything shared
 * by every VM is in network/testnet.env.
 *
 * Both files are created with the exclusive flag. If either exists the
 * script says which and writes nothing.
 *
 * Encodings (spec 7.2): private keys PKCS#8 DER in hex (X25519 48 bytes,
 * ML-KEM-1024 86 bytes in the seed form Node exports); public keys raw
 * bytes in hex (X25519 32, ML-KEM-1024 1568). Node exports public keys as
 * SPKI DER, a constant prefix in front of the raw bytes for a fixed
 * algorithm, which is cut off here.
 */

const USAGE = 'usage: npm run make-keys -- --id <N> [--key-file <path>]';

/** The repo root: where .env goes and what a relative --key-file is resolved against. */
const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url));

const SPKI_PREFIX_BYTES = { x25519: 12, 'ml-kem-1024': 22 };
const RAW_PUBLIC_BYTES = { x25519: 32, 'ml-kem-1024': 1568 };

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

let args;
try {
  args = parseArgs({
    options: {
      id: { type: 'string' },
      'key-file': { type: 'string', default: './keyholder.key' },
    },
  }).values;
} catch (err) {
  console.error(`${err.message}\n${USAGE}`);
  process.exit(1);
}

const id = args.id;
if (id === undefined || !/^[1-9][0-9]*$/.test(id)) {
  console.error(`--id must be a positive integer, the keyholder's number (its validator's id).\n${USAGE}`);
  process.exit(1);
}
const keyFile = args['key-file'];
const keyFilePath = resolve(REPO_ROOT, keyFile);
const envPath = resolve(REPO_ROOT, '.env');

// Both existence checks before any write, so a second run never half-writes.
const existing = [keyFilePath, envPath].filter((file) => existsSync(file));
if (existing.length > 0) {
  console.error(`${existing.join(' and ')} already exist${existing.length === 1 ? 's' : ''}; nothing written.`);
  process.exit(1);
}

const receiving = hybridPair();

writeFileSync(
  keyFilePath,
  `${JSON.stringify(
    {
      receivingX25519PrivateKey: receiving.x25519Private,
      receivingMlkemPrivateKey: receiving.mlkemPrivate,
      bucketOneKey: hex(randomBytes(32)),
    },
    null,
    2,
  )}\n`,
  { flag: 'wx', mode: 0o600 },
);

const FILL_IN = '"<fill in>"';
const envLines = [
  `KEYHOLDER_ID=${id}`,
  `PGPASSWORD=${hex(randomBytes(16))}`,
  `ANOS_PGPASSWORD=${hex(randomBytes(16))}`,
  `KEY_FILE=${keyFile}`,
  `# The Cloud KMS key's resource name, in your project and the VM's region: projects/<project>/locations/<region>/keyRings/anos-testnet/cryptoKeys/keyholder-${id}`,
  `KMS_KEY_NAME=${FILL_IN}`,
  '# The home computer\'s X25519 public key, raw hex (32 bytes), from the keyholder GUI.',
  `HOME_X25519_PUBLIC_KEY=${FILL_IN}`,
  '# The home computer\'s ML-KEM-1024 public key, raw hex (1568 bytes), from the keyholder GUI.',
  `HOME_MLKEM_PUBLIC_KEY=${FILL_IN}`,
  '# The first YubiKey\'s P-256 public key, a 33-byte compressed point in hex, from the keyholder GUI.',
  `KEYHOLDER_PUBLIC_KEY_1=${FILL_IN}`,
  '# The second YubiKey\'s P-256 public key, a 33-byte compressed point in hex, from the keyholder GUI.',
  `KEYHOLDER_PUBLIC_KEY_2=${FILL_IN}`,
  '',
];
writeFileSync(envPath, envLines.join('\n'), { flag: 'wx', mode: 0o644 });
// The umask may have narrowed the mode at creation; postgres has to read it.
chmodSync(envPath, 0o644);

console.log(`Keyholder ${id}`);
console.log('');
console.log('Receiving key, the public halves the phone encrypts shares to (served live by');
console.log('/get-keyholder-public-key; nothing to record):');
console.log(`  x25519 ${receiving.x25519Public}`);
console.log(`  mlkem  ${receiving.mlkemPublic}`);
console.log('');
console.log(`Wrote ${keyFilePath} (mode 0600, never shown) and ${envPath}.`);
console.log('Five lines in .env are left to fill, each under a comment saying what goes there:');
console.log('  KMS_KEY_NAME, HOME_X25519_PUBLIC_KEY, HOME_MLKEM_PUBLIC_KEY, KEYHOLDER_PUBLIC_KEY_1, KEYHOLDER_PUBLIC_KEY_2');
console.log('');
console.log('Next (the operator guide, steps 7 and 9): the database, the anos read grant, the unit:');
console.log('');
console.log('  sudo -u postgres sh scripts/setup-db.sh');
console.log('  sudo -u postgres sh scripts/grant-anos-read.sh');
console.log('  sudo cp deploy/anos-keyholder.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now anos-keyholder');
