import 'dotenv/config';
import { z } from 'zod';

const ConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  DATABASE_URL: z.string().url(),

  X402_PAY_TO_ADDRESS: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  X402_FACILITATOR_URL: z.string().url().optional(),
  X402_FACILITATOR_API_KEY: z.string().optional(),
  X402_NETWORK: z.enum(['base-mainnet', 'base-sepolia']).default('base-sepolia'),

  PRICE_EVENT_WRITE_USDC: z.coerce.number().int().positive().default(1000),
  PRICE_EVENT_BULK_USDC: z.coerce.number().int().positive().default(50000),

  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60000),
});

export type Config = z.infer<typeof ConfigSchema>;

function loadConfig(): Config {
  const parsed = ConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    console.error('invalid environment configuration:');
    console.error(parsed.error.flatten().fieldErrors);
    process.exit(1);
  }
  return parsed.data;
}

export const config = loadConfig();
