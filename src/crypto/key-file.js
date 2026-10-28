import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The key file: this keyholder's private material, JSON with lowercase-hex
 * values, written once by scripts/make-keys.js with the exclusive-create
 * flag and mode 0600, so it is never overwritten and only its owner reads
 * it. KEY_FILE in .env names it, relative to the repo root or absolute
 * (src/config/env.js; default ./keyholder.key). Its three fields are the
 * receiving pair, receivingX25519PrivateKey and receivingMlkemPrivateKey
 * (PKCS#8 DER, 48 and 86 bytes), and bucketOneKey (32 bytes); keyholder-keys.js
 * loads them.
 *
 * readKeyFile(path, fields) refuses a file that is missing, not a regular
 * file, unreadable, or has any group or other permission bit set, naming
 * the path and the mode it found; then it parses the JSON and requires
 * every field named in `fields` to be lowercase hex of the byte length
 * given there (null: any even length).
 *
 * anossoftware has its own copy; the two repos share no code.
 */

/** The repo root, which a relative KEY_FILE is resolved against. */
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** The group and other permission bits: none may be set on a key file. */
const GROUP_OTHER_BITS = 0o077;

/**
 * Reads the key file at `path` (relative to the repo root, or absolute) and
 * returns the parsed object. `fields` maps each required field to its byte
 * length, or null for any even length. Throws, with a message naming the
 * file, on every failure listed above.
 */
export function readKeyFile(path, fields) {
  const file = resolve(REPO_ROOT, path);

  let stat;
  try {
    stat = statSync(file);
  } catch (err) {
    throw new Error(
      err.code === 'ENOENT' ? `key file ${file} is missing` : `key file ${file} cannot be read: ${err.message}`,
    );
  }
  if (!stat.isFile()) {
    throw new Error(`key file ${file} is not a regular file`);
  }
  const mode = stat.mode & 0o777;
  if ((mode & GROUP_OTHER_BITS) !== 0) {
    throw new Error(
      `key file ${file} has mode ${mode.toString(8).padStart(4, '0')}; it must be readable by its owner only (chmod 600)`,
    );
  }

  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error(`key file ${file} is unreadable: ${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`key file ${file} is not JSON: ${err.message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`key file ${file} must hold a JSON object`);
  }

  for (const [name, bytes] of Object.entries(fields)) {
    const value = parsed[name];
    if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value)) {
      throw new Error(`key file ${file}: ${name} must be lowercase hex with an even number of digits`);
    }
    if (bytes !== null && value.length !== bytes * 2) {
      throw new Error(
        `key file ${file}: ${name} must be ${bytes} bytes (${bytes * 2} hex digits), got ${value.length / 2}`,
      );
    }
  }
  return parsed;
}
