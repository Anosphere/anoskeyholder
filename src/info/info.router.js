import { Router } from 'express';
import { getKeyholderPublicKey } from './info.handlers.js';

/**
 * Info feature router: what anyone may ask this keyholder without signing.
 *
 * Mounted at the root in app.js, so the path below is the full public path.
 * Level none (spec section 2).
 */
export const infoRouter = Router();

infoRouter.post('/get-keyholder-public-key', getKeyholderPublicKey);
