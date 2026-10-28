import { createApp } from './app.js';
import { env } from './config/env.js';
import { anosQuery, closeAnosPool } from './db/anos-pool.js';
import { closePool, query } from './db/pool.js';
import { decrypt, encrypt } from './kms/kms.js';

// Who this is, first. The key file was loaded by the imports above
// (src/crypto/keyholder-keys.js), so a missing or open key file has already
// stopped the boot by now.
console.log(`Keyholder ${env.keyholderId}`);

// Verify both database connections before accepting traffic, so a bad
// configuration fails loudly at boot instead of on the first request.
try {
  const { rows } = await query('SHOW server_version');
  console.log(
    `Connected to PostgreSQL ${rows[0].server_version} ` +
      `at ${env.db.host}:${env.db.port}/${env.db.database}`,
  );
} catch (err) {
  console.error('Could not connect to PostgreSQL:', err.message);
  process.exit(1);
}

try {
  const { rows } = await anosQuery('SHOW server_version');
  console.log(
    `Connected to the anos database (PostgreSQL ${rows[0].server_version}) ` +
      `at ${env.anosDb.host}:${env.anosDb.port}/${env.anosDb.database}, read only`,
  );
} catch (err) {
  console.error('Could not connect to the anos database:', err.message);
  process.exit(1);
}

// Cloud KMS, the same way: a fixed plaintext encrypted and decrypted through
// src/kms/kms.js, so a wrong key name, a missing role or an unreachable API
// fails here, not on the first share.
try {
  const plaintext = Buffer.from('anos keyholder kms self-test', 'utf8');
  const aad = Buffer.from('self-test', 'utf8');
  const decrypted = await decrypt(await encrypt(plaintext, aad), aad);
  if (decrypted === null) {
    throw new Error('the ciphertext did not decrypt under the key');
  }
  if (!decrypted.equals(plaintext)) {
    throw new Error('the plaintext came back changed');
  }
  console.log('KMS ok');
} catch (err) {
  console.error('KMS self-test failed:', err.message);
  process.exit(1);
}

const app = createApp();

const server = app.listen(env.port, () => {
  console.log(`Keyholder ${env.keyholderId} listening on http://localhost:${env.port}`);
});

let shuttingDown = false;

/** Stop accepting connections, let in-flight requests finish, drain both pools. */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${signal} received, shutting down...`);

  // Safety net: never hang forever if a connection refuses to close.
  setTimeout(() => {
    console.error('Shutdown timed out, forcing exit');
    process.exit(1);
  }, 10_000).unref();

  try {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    await Promise.all([closePool(), closeAnosPool()]);
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
