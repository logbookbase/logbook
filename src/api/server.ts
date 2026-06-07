import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';
import { serve } from '@hono/node-server';
import { config } from '../lib/config.js';
import { logger } from '../lib/logger.js';
import { sql, closeDb } from '../lib/db.js';
import { HttpError } from '../lib/errors.js';
import { agentsRoutes } from './routes/agents.js';
import { eventsRoutes } from './routes/events.js';
import { buildX402Middleware } from './middleware/x402.js';

export function buildApp(): Hono {
  const app = new Hono();

  app.use('*', cors({ origin: '*' }));

  app.get('/health', async (c) => {
    const start = Date.now();
    let dbOk = false;
    try {
      await sql`SELECT 1`;
      dbOk = true;
    } catch (err) {
      logger.error({ err }, 'db health check failed');
    }
    return c.json({
      status: dbOk ? 'ok' : 'degraded',
      db: dbOk,
      uptime_s: Math.round(process.uptime()),
      response_ms: Date.now() - start,
      version: '0.1.0',
    });
  });

  app.get('/', (c) => c.json({ name: 'logbook', version: '0.1.0' }));

  // x402 payment middleware (only applies to routes it's configured for, like POST /events).
  // If credentials are missing or pay-to is unset, this returns null and the endpoint stays free.
  const x402 = buildX402Middleware();
  if (x402) {
    app.use('*', x402);
  }

  app.route('/', agentsRoutes);
  app.route('/', eventsRoutes);

  app.notFound((c) => c.json({ error: 'not_found' }, 404));

  app.onError((err, c) => {
    if (err instanceof HttpError) {
      return c.json({ error: err.code, message: err.message }, err.statusCode as 400 | 401 | 404 | 409);
    }
    if (err instanceof HTTPException) {
      return err.getResponse();
    }
    logger.error({ err }, 'unhandled error');
    return c.json({ error: 'internal_error' }, 500);
  });

  return app;
}

export async function start(): Promise<void> {
  const app = buildApp();

  const server = serve(
    { fetch: app.fetch, port: config.PORT, hostname: '0.0.0.0' },
    (info) => {
      logger.info({ port: info.port }, 'server listening');
    },
  );

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'shutting down');
    try {
      server.close();
      await closeDb();
      process.exit(0);
    } catch (err) {
      logger.error({ err }, 'shutdown failed');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void start();
}
