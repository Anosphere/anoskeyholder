import { env } from '../config/env.js';

/**
 * Posting a share to a recovery pod (spec 5.8, 5.9, step 5). The
 * destination comes from the home computer's request; only a host in
 * RECOVERY_POD_HOSTS is ever posted to.
 */

/** How long the recovery pod has to answer. */
const TIMEOUT_MS = 10_000;

/**
 * The destination URL as a URL object when it parses, is http or https and
 * its host is in RECOVERY_POD_HOSTS (compared lowercased, the port ignored);
 * null otherwise.
 */
export function allowedDestination(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (!env.recoveryPodHosts.includes(parsed.hostname.toLowerCase())) return null;
  return parsed;
}

/**
 * Posts `object` as JSON to `url` (a URL from allowedDestination). Returns
 * { status, body } with the recovery pod's HTTP status and its JSON answer,
 * or its text when it did not send JSON; { unreachable: true } when it did
 * not answer in time.
 */
export async function postToRecoveryPod(url, object) {
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(object),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    return { unreachable: true };
  }
  const text = await response.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON: the text as it came.
  }
  return { status: response.status, body };
}
