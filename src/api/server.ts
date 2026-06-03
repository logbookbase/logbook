import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { config } from '../lib/config.js';
import { logger } from '../lib/logger.js';
import { sql, closeDb } from '../lib/db.js';

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({
    logger,
    trustProxy: true,
    bodyLimit: 1024 * 1024,
  });

  await app.register(cors, { origin: true });
  await app.register(rateLimit, {
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_WINDOW_MS,
  });

  app.get('/health', async () => {
    const start = Date.now();
    let dbOk = false;
    try {
      await sql`SELECT 1`;
      dbOk = true;
    } catch (err) {
      app.log.error({ err }, 'db health check failed');
    }
    return {
      status: dbOk ? 'ok' : 'degraded',
      db: dbOk,
      uptime_s: Math.round(process.uptime()),
      response_ms: Date.now() - start,
      version: '0.1.0',
    };
  });

  app.get('/', async () => ({
    name: 'logbook',
    version: '0.1.0',
  }));

  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({ error: 'not_found' });
  });

  app.setErrorHandler((err, _req, reply) => {
    app.log.error({ err }, 'unhandled error');
    const status = err.statusCode ?? 500;
    reply.code(status).send({
      error: status >= 500 ? 'internal_error' : err.message,
    });
  });

  return app;
}

async function start(): Promise<void> {
  const app = await buildServer();

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'shutting down');
    try {
      await app.close();
      await closeDb();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'shutdown failed');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  try {
    await app.listen({ port: config.PORT, host: '0.0.0.0' });
  } catch (err) {
    app.log.error({ err }, 'failed to start');
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void start();
}
