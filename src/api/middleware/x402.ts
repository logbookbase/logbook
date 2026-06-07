import type { MiddlewareHandler } from 'hono';
import { paymentMiddlewareFromConfig } from '@x402/hono';
import { HTTPFacilitatorClient } from '@x402/core/server';
import type { RoutesConfig } from '@x402/core/server';
import type { Network } from '@x402/core/types';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { createFacilitatorConfig } from '@coinbase/x402';
import { config } from '../../lib/config.js';
import { logger } from '../../lib/logger.js';

// Map our env's network string to the CAIP-2 id x402 expects.
const NETWORK_TO_CAIP2: Record<string, Network> = {
  base: 'eip155:8453' as Network,
  'base-sepolia': 'eip155:84532' as Network,
};

/**
 * Build the x402 middleware for POST /events.
 *
 * Returns null when payments are intentionally disabled (no pay-to address,
 * or no CDP credentials). When null, the server skips registration and the
 * endpoint stays free — handy for local dev without CDP keys.
 */
export function buildX402Middleware(): MiddlewareHandler | null {
  const payTo = config.X402_PAY_TO_ADDRESS;
  if (!payTo || payTo === '0x0000000000000000000000000000000000000000') {
    logger.warn('x402: pay-to address not set, payments disabled');
    return null;
  }

  const network = NETWORK_TO_CAIP2[config.X402_NETWORK];
  if (!network) {
    logger.warn({ network: config.X402_NETWORK }, 'x402: unknown network, payments disabled');
    return null;
  }

  const hasCdpCreds = !!(config.CDP_API_KEY_ID && config.CDP_API_KEY_SECRET);
  if (!hasCdpCreds) {
    logger.warn('x402: CDP credentials missing, payments disabled');
    return null;
  }

  const facilitatorConfig = createFacilitatorConfig(
    config.CDP_API_KEY_ID,
    config.CDP_API_KEY_SECRET,
  );
  const facilitatorClient = new HTTPFacilitatorClient(facilitatorConfig);

  const routes: RoutesConfig = {
    'POST /events': {
      accepts: [
        {
          scheme: 'exact',
          price: '$0.001',
          network,
          payTo,
        },
      ],
      description: 'submit a signed event to logbook',
      mimeType: 'application/json',
    },
  };

  logger.info({ network, payTo, price: '$0.001' }, 'x402: payments enabled');

  return paymentMiddlewareFromConfig(
    routes,
    facilitatorClient,
    [{ network, server: new ExactEvmScheme() }],
  );
}
