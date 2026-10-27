import pg from 'pg';
import { env } from '../config/env.js';

const { Pool } = pg;

/**
 * The connection pool to the validator's anos database, read only. The
 * moderator check (spec 3.2, src/auth/anos.queries.js) reads a moderator's
 * keys from accounts and its stake from stakes; nothing is ever written
 * there. The role (ANOS_PGUSER, keyholder_reader) has SELECT on those two
 * tables and nothing else, granted by scripts/grant-anos-read.sh.
 */
export const anosPool = new Pool({
  ...env.anosDb,
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

anosPool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client (anos database)', err);
});

/** Runs a single read on the anos database using a pooled connection. */
export function anosQuery(text, params) {
  return anosPool.query(text, params);
}

/** Drains the pool. Called once during graceful shutdown. */
export function closeAnosPool() {
  return anosPool.end();
}
