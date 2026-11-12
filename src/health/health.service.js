import { env } from '../config/env.js';
import { countWaitingCopies } from '../copies/copies.queries.js';
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

/**
 * The share copies (src/copies/): how many shares wait for their copy in
 * the bucket. A number that stays above zero means the bucket has stopped
 * taking files. Null when the count fails, which the database check above
 * then reports; this field never changes the status.
 */
export async function checkCopies() {
  try {
    return { waiting: await countWaitingCopies() };
  } catch {
    return { waiting: null };
  }
}

/** What this process is, fixed at boot: its number, and the commit and tag it runs. */
export function identity() {
  return {
    keyholder: { id: env.keyholderId },
    version,
  };
}
