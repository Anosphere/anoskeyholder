import cors from 'cors';
import express from 'express';
import { env } from './config/env.js';
import { healthRouter } from './health/health.router.js';
import { infoRouter } from './info/info.router.js';
import { errorHandler } from './middleware/error-handler.js';
import { notFound } from './middleware/not-found.js';
import { sharesRouter } from './shares/shares.router.js';

/**
 * Builds and returns the Express application.
 * Kept separate from the server so it can be imported without opening a
 * network port.
 */
export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(cors({ origin: env.webOrigin }));
  // The largest request is a /receive-share: a share of at most 4096 bytes
  // and an ML-DSA-87 signature of 4627 bytes, both in hex, well under 1 MB.
  app.use(express.json({ limit: '1mb' }));

  // Feature routers. Each feature folder owns its router, service, etc.
  app.use('/health', healthRouter);
  app.use(infoRouter); // owns /get-keyholder-public-key
  app.use(sharesRouter); // owns /receive-share, the three moderator routes and the four keyholder routes

  // Order matters: these must come after every router.
  app.use(notFound);
  app.use(errorHandler);

  return app;
}
