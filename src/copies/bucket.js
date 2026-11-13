import { env } from '../config/env.js';

/**
 * The two calls to Google behind a share copy (spec section 16), made with
 * Node's own fetch; no package. The first asks the VM's metadata server for
 * an access token of the VM's service account. The second uploads one file
 * to the bucket SHARE_COPIES_BUCKET through Cloud Storage's JSON API, with
 * ifGenerationMatch=0, so a file is only ever created and never replaced.
 * Both are written as Google's own pages give them (read 2026-11-12):
 *   docs.cloud.google.com/compute/docs/access/authenticate-workloads
 *   docs.cloud.google.com/storage/docs/uploading-objects
 *   docs.cloud.google.com/storage/docs/request-preconditions
 *
 * The token is kept in memory and never logged. A reason this module hands
 * back holds a status and Google's message, or why no answer came; never a
 * header and never a byte of a token answer.
 */

/**
 * The metadata server, by its address, as the worker script and
 * scripts/set-copies-bucket.sh call it: an access token for the VM's
 * service account.
 */
const TOKEN_URL = 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token';

/** Cloud Storage's upload endpoint for the bucket. */
const UPLOAD_URL = `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(env.shareCopies.bucket)}/o`;

/** A kept token is used until this long before it ends. */
const TOKEN_MARGIN_MS = 60_000;

/** The kept token, { value, expiresAt } with expiresAt in milliseconds since the epoch, or null. */
let token = null;

/** Why a call gave no answer, in a few words: its time limit ran out, or the cause Node names. */
function describe(err) {
  if (err?.name === 'TimeoutError') return 'no answer in time';
  const cause = err?.cause?.code ?? err?.cause?.message;
  return cause ? `${err.message} (${cause})` : String(err?.message ?? err);
}

/**
 * An access token: the kept one while it has more than TOKEN_MARGIN_MS
 * left, else a new one from the metadata server, which answers
 * { access_token, expires_in (seconds), token_type }. Throws when no usable
 * token comes back; the message never quotes the answer.
 */
async function accessToken(timeoutMs) {
  if (token !== null && Date.now() < token.expiresAt - TOKEN_MARGIN_MS) return token.value;
  token = null;

  const response = await fetch(TOKEN_URL, {
    headers: { 'Metadata-Flavor': 'Google' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // Not JSON: no token in it.
  }
  if (!response.ok) throw new Error(`status ${response.status}`);
  if (typeof body?.access_token !== 'string' || body.access_token === '') {
    throw new Error('the answer holds no token');
  }
  if (!Number.isFinite(body.expires_in) || body.expires_in <= 0) {
    throw new Error('the answer does not say when the token ends');
  }
  token = { value: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
  return token.value;
}

/** The upload of `content` as the file `name`: only when no file of that name is there. */
function upload(name, content, bearer, timeoutMs) {
  return fetch(`${UPLOAD_URL}?uploadType=media&name=${encodeURIComponent(name)}&ifGenerationMatch=0`, {
    method: 'POST',
    headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
    body: content,
    signal: AbortSignal.timeout(timeoutMs),
  });
}

/** Google's own words for a refusal, from its JSON answer { error: { message } }, on one line. */
function refusalMessage(text) {
  let message = text;
  try {
    message = JSON.parse(text)?.error?.message ?? text;
  } catch {
    // Not JSON: the text as it came.
  }
  return String(message).replace(/\s+/g, ' ').trim().slice(0, 300);
}

/**
 * Writes `content` (a JSON string) to the bucket as the file `name`. Each of
 * the two calls has `timeoutMs` to answer. Returns null when the file is in
 * the bucket, else the reason, a short string for the log; never throws.
 *
 *   200  the file is in the bucket
 *   412  a file of that name is already there, from an earlier try: it
 *        counts as written
 *   401  the kept token is dropped and the file is tried once more with a
 *        new one
 *   anything else, or no answer: the bucket did not take the file
 */
export async function putFile(name, content, timeoutMs) {
  for (let attempt = 1; ; attempt += 1) {
    let bearer;
    try {
      bearer = await accessToken(timeoutMs);
    } catch (err) {
      return `no token from the metadata server: ${describe(err)}`;
    }

    let response;
    try {
      response = await upload(name, content, bearer, timeoutMs);
    } catch (err) {
      return `no answer from Cloud Storage: ${describe(err)}`;
    }
    // The body is the file's metadata after a 200 and Google's reason after
    // a refusal. It is read to its end either way; the status alone decides,
    // so a body that breaks off cannot turn a written file into a failure.
    const text = await response.text().catch(() => '');

    if (response.status === 200 || response.status === 412) return null;
    if (response.status === 401) {
      token = null;
      if (attempt === 1) continue;
    }
    return `${response.status} ${refusalMessage(text)}`.trim();
  }
}
