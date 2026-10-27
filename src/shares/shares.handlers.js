import { answer } from '../util/result.js';
import { decryptAndForward, getBlobs } from './keyholder.service.js';
import { getBucketKey, getPublicLedgerId } from './moderator.service.js';
import { receiveShare } from './receive.service.js';
import { BACKUP_CODE, BREAK_GLASS_KEY, SECURITY_BUCKET_1, SECURITY_BUCKET_2 } from './share-types.js';

/**
 * Route handlers for the shares feature. HTTP in and out only: read the
 * request, call the service, send the answer. Behind the middlewares the
 * caller is req.pod, req.moderator or req.yubikey and req.body is the
 * route's own object; the checking and storing lives in the services.
 */

/** POST /receive-share (pod) */
export async function receiveShareHandler(req, res) {
  answer(res, await receiveShare(req.pod, req.body));
}

/** POST /get-security-bucket-one-key (moderator) */
export async function getSecurityBucketOneKey(req, res) {
  answer(res, await getBucketKey(req.body, SECURITY_BUCKET_1));
}

/** POST /get-security-bucket-two-key (moderator) */
export async function getSecurityBucketTwoKey(req, res) {
  answer(res, await getBucketKey(req.body, SECURITY_BUCKET_2));
}

/** POST /get-public-ledger-id (moderator) */
export async function getPublicLedgerIdHandler(req, res) {
  answer(res, await getPublicLedgerId(req.body));
}

/** POST /get-break-glass-key (keyholder) */
export async function getBreakGlassKey(req, res) {
  answer(res, await getBlobs(req.body, BREAK_GLASS_KEY));
}

/** POST /get-backup-code (keyholder) */
export async function getBackupCode(req, res) {
  answer(res, await getBlobs(req.body, BACKUP_CODE));
}

/** POST /decrypt-break-glass-key (keyholder) */
export async function decryptBreakGlassKey(req, res) {
  answer(res, await decryptAndForward(req.body, BREAK_GLASS_KEY));
}

/** POST /decrypt-backup-code (keyholder) */
export async function decryptBackupCode(req, res) {
  answer(res, await decryptAndForward(req.body, BACKUP_CODE));
}
