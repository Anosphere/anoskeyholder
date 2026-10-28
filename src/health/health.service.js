import { env } from '../config/env.js';
import { query } from '../db/pool.js';
import { version } from '../util/version.js';

/** Confirms the keyholder's own database is reachable with a trivial round trip. */
export async function checkDatabase() {
  const started = performance.now();
  try {
    await query('SELECT 1');
    return { status: 'ok', latencyMs: Math.round(performance.now() - started) };
  } catch (err) {
    console.error('Database health check failed:', err.message);
    return { status: 'unreachable' };
  }
}

/** What this process is, fixed at boot: its number, and the commit and tag it runs. */
export function identity() {
  return {
    keyholder: { id: env.keyholderId },
    version,
  };
}
