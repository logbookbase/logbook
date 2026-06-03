import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sql, closeDb } from '../src/lib/db.js';
import { logger } from '../src/lib/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function migrate(): Promise<void> {
  const schemaPath = join(__dirname, '..', 'src', 'db', 'schema.sql');
  const schema = readFileSync(schemaPath, 'utf-8');

  try {
    await sql.unsafe(schema);
    logger.info('schema applied');
  } catch (err) {
    logger.error({ err }, 'migration failed');
    process.exitCode = 1;
  } finally {
    await closeDb();
  }
}

migrate();
