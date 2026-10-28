/**
 * Reads and validates environment variables once at startup.
 * Everything else imports `env` from here instead of touching process.env,
 * so a missing or malformed variable fails at boot rather than mid-request.
 * The variables are spec sections 9 and 14. Two files are loaded, in this
 * order: network/testnet.env, committed, with every value that is the same
 * on every VM of the network, then .env, the machine file
 * scripts/make-keys.js writes, which wins where both name a variable:
 *   node --env-file=network/testnet.env --env-file=.env src/server.js
 */

/** The placeholder a value ships with before it exists (an address, a key name, a public key). */
const FILL_IN = '<fill in>';

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  if (value === FILL_IN) {
    throw new Error(`${name} is still "${FILL_IN}": fill it in network/testnet.env or .env`);
  }
  return value;
}

/** A required variable that must be a positive integer. */
function requiredInteger(name) {
  const value = required(name);
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  return Number(value);
}

/**
 * An optional variable that must be a positive integer when set; `fallback`
 * when it is not set.
 */
function optionalInteger(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer, got "${value}"`);
  }
  return Number(value);
}

/** Millionths of an anos in one anos: the scale of every amount in the anos database. */
const MILLIONTHS_PER_ANOS = 1_000_000n;

/**
 * A required variable holding a whole number of anos (a positive integer),
 * returned in millionths as a BigInt, the scale amounts are compared at.
 */
function requiredAnos(name) {
  return BigInt(requiredInteger(name)) * MILLIONTHS_PER_ANOS;
}

/**
 * An optional variable holding a whole number of anos, `fallbackAnos` when
 * it is not set, returned in millionths as a BigInt like requiredAnos.
 */
function optionalAnos(name, fallbackAnos) {
  return BigInt(optionalInteger(name, fallbackAnos)) * MILLIONTHS_PER_ANOS;
}

/**
 * A required variable holding lowercase hex. When `bytes` is given, the value
 * must decode to exactly that many bytes; otherwise any non-empty length goes.
 */
function requiredHex(name, bytes) {
  const value = required(name);
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) {
    throw new Error(`${name} must be lowercase hex with an even number of digits`);
  }
  if (bytes !== undefined && value.length !== bytes * 2) {
    throw new Error(
      `${name} must be ${bytes} bytes (${bytes * 2} hex digits), got ${value.length / 2}`,
    );
  }
  return value;
}

/**
 * A required comma-separated list (the masterpod's parser, without a
 * default): items trimmed, empty ones dropped, at least one.
 */
function requiredList(name) {
  const value = required(name);
  const items = value.split(',').map((item) => item.trim()).filter((item) => item !== '');
  if (items.length === 0) throw new Error(`${name} must list at least one item, got "${value}"`);
  return Object.freeze(items);
}

/** A required comma-separated list of host names, each lowercased. */
function requiredHostList(name) {
  return Object.freeze(requiredList(name).map((host) => host.toLowerCase()));
}

export const env = Object.freeze({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: Number(process.env.PORT) || 3200,

  // This keyholder's number: its validator's id, answered as keyholderId.
  keyholderId: requiredInteger('KEYHOLDER_ID'),

  // The key file scripts/make-keys.js wrote (JSON, mode 0600): the receiving
  // pair and the bucket-one key, relative to the repo root or absolute.
  // src/crypto/key-file.js checks and reads it, src/crypto/keyholder-keys.js
  // loads it at boot. No private value passes through the environment.
  keyFile: process.env.KEY_FILE || './keyholder.key',

  // The keyholder's own database. Variable names follow libpq (PGHOST,
  // PGUSER, ...), so psql and other PostgreSQL tools read the same env files
  // without any translation.
  db: Object.freeze({
    host: process.env.PGHOST ?? '127.0.0.1',
    port: Number(process.env.PGPORT) || 5432,
    database: required('PGDATABASE'),
    user: required('PGUSER'),
    password: required('PGPASSWORD'),
  }),

  // The validator's anos database, read only (src/db/anos-pool.js): the
  // moderator check reads accounts and stakes there and nothing else.
  anosDb: Object.freeze({
    host: process.env.ANOS_PGHOST ?? '127.0.0.1',
    port: Number(process.env.ANOS_PGPORT) || 5432,
    database: required('ANOS_PGDATABASE'),
    user: required('ANOS_PGUSER'),
    password: required('ANOS_PGPASSWORD'),
  }),

  // The stakes an account must hold to be a moderator (stakes.moderator_stake,
  // spec 3.2) or an attestor (stakes.attestor_stake, spec 13.1): the same
  // values as the validator's env, in whole anos, converted to millionths
  // once here as BigInt. The attestor minimum has a default (13.2), so a
  // keyholder boots without the line in its env file.
  stakes: Object.freeze({
    minimums: Object.freeze({
      moderator: requiredAnos('STAKE_MIN_MODERATOR_ANOS'),
      attestor: optionalAnos('STAKE_MIN_ATTESTOR_ANOS', 1000),
    }),
  }),

  // The phone's origins, a comma-separated list: the CORS allow-list
  // (src/app.js). Required; in network/testnet.env.
  webOrigins: requiredList('WEB_ORIGIN'),

  // Where /get-anopod-session-keys is (src/auth/masterpod.client.js).
  // Required; in network/testnet.env. A trailing slash is dropped.
  masterpodUrl: required('MASTERPOD_URL').replace(/\/+$/, ''),

  // The hosts a decrypt route may post a share to (src/shares/forward.js).
  // Required; in network/testnet.env.
  recoveryPodHosts: requiredHostList('RECOVERY_POD_HOSTS'),

  // How far a signed request's timestamp may be from the server clock,
  // each way. Nonces are kept twice this long.
  timestampWindowSeconds: optionalInteger('TIMESTAMP_WINDOW_SECONDS', 120),

  // The home computer's hybrid public key, raw bytes in hex: the outer layer
  // of every break-glass and backup-code share (spec section 6).
  home: Object.freeze({
    x25519PublicKey: requiredHex('HOME_X25519_PUBLIC_KEY', 32),
    mlkemPublicKey: requiredHex('HOME_MLKEM_PUBLIC_KEY', 1568),
  }),

  // The two YubiKeys' P-256 public keys, 33-byte compressed points in hex.
  // A keyholder-level request names one of them as payload.yubikey (spec 3.3).
  keyholderPublicKeys: Object.freeze([
    requiredHex('KEYHOLDER_PUBLIC_KEY_1', 33),
    requiredHex('KEYHOLDER_PUBLIC_KEY_2', 33),
  ]),

  // The KMS (src/kms/): Cloud KMS, the one provider, on this key, a
  // cryptoKeys resource name in the operator's own project and region.
  kms: Object.freeze({
    keyName: required('KMS_KEY_NAME'),
  }),
});
