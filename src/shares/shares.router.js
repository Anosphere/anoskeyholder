import { Router } from 'express';
import { requireKeyholder } from '../auth/require-keyholder.js';
import { requireModerator } from '../auth/require-moderator.js';
import { requireModeratorOrAttestor } from '../auth/require-moderator-or-attestor.js';
import { requirePod } from '../auth/require-pod.js';
import {
  decryptBackupCode,
  decryptBreakGlassKey,
  getBackupCode,
  getBreakGlassKey,
  getOwnerHandler,
  getPublicLedgerIdHandler,
  getSecurityBucketOneKey,
  getSecurityBucketTwoKey,
  receiveShareHandler,
} from './shares.handlers.js';

/**
 * Shares feature router: the eight signed routes and the one unsigned one.
 *
 * Mounted at the root in app.js, so the paths below are the full public
 * paths. Paths are lowercase kebab-case. The level of each route is the
 * middleware in front of it (spec section 2): none (no middleware, spec
 * section 15), pod, moderator or keyholder; the two bucket key routes take
 * a moderator or an attestor (spec 13.1).
 */
export const sharesRouter = Router();

sharesRouter.post('/get-owner', getOwnerHandler);

sharesRouter.post('/receive-share', requirePod, receiveShareHandler);

sharesRouter.post('/get-security-bucket-one-key', requireModeratorOrAttestor, getSecurityBucketOneKey);
sharesRouter.post('/get-security-bucket-two-key', requireModeratorOrAttestor, getSecurityBucketTwoKey);
sharesRouter.post('/get-public-ledger-id', requireModerator, getPublicLedgerIdHandler);

sharesRouter.post('/get-break-glass-key', requireKeyholder, getBreakGlassKey);
sharesRouter.post('/get-backup-code', requireKeyholder, getBackupCode);
sharesRouter.post('/decrypt-break-glass-key', requireKeyholder, decryptBreakGlassKey);
sharesRouter.post('/decrypt-backup-code', requireKeyholder, decryptBackupCode);
