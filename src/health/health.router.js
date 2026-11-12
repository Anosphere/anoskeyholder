import { Router } from 'express';
import { checkCopies, checkDatabase, identity } from './health.service.js';

export const healthRouter = Router();

healthRouter.get('/', async (req, res) => {
  // Both at once, so the count adds nothing to the wait when the database
  // does not answer. Only the database check decides the status.
  const [db, copies] = await Promise.all([checkDatabase(), checkCopies()]);
  const healthy = db.status === 'ok';

  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    uptime: process.uptime(),
    db,
    copies,
    ...identity(),
  });
});
