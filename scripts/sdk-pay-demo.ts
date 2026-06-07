/**
 * Live x402 payment demo.
 *
 * Registers a fresh agent, then logs 1 event by paying $0.001 USDC on Base mainnet.
 * The buyer wallet (BUYER_WALLET_PRIVATE_KEY) and seller wallet (X402_PAY_TO_ADDRESS)
 * can be the same address — in that case USDC just bounces back to itself, net cost
 * is only the gas (a fraction of a cent on Base).
 *
 * Requires the server to be running at http://localhost:3000.
 */
import 'dotenv/config';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import { Logbook } from '../sdk/src/index.js';

const BASE_URL = process.env.LOGBOOK_BASE_URL ?? 'http://localhost:3000';

function getBuyerKey(): `0x${string}` {
  const k = process.env.BUYER_WALLET_PRIVATE_KEY;
  if (!k) {
    throw new Error('BUYER_WALLET_PRIVATE_KEY missing from .env');
  }
  // strip whitespace, ensure 0x prefix
  const trimmed = k.trim();
  return (trimmed.startsWith('0x') ? trimmed : '0x' + trimmed) as `0x${string}`;
}

async function main() {
  console.log('logbook x402 live payment demo');
  console.log('  base url:', BASE_URL);

  // 1. set up the paying account
  const buyerKey = getBuyerKey();
  const account = privateKeyToAccount(buyerKey);
  console.log('  buyer wallet:', account.address);

  // 2. set up the x402 client with the evm scheme
  const x402 = new x402Client();
  registerExactEvmScheme(x402, { signer: account });

  // 3. wrap fetch with payment auto-handling
  const fetchWithPay = wrapFetchWithPayment(globalThis.fetch, x402);

  // 4. register a fresh agent (this is a FREE endpoint, no payment needed)
  console.log('\nregistering a fresh agent...');
  const identity = await Logbook.register({
    displayName: 'x402-demo-' + Date.now(),
    metadata: { source: 'sdk-pay-demo' },
    baseUrl: BASE_URL,
  });
  console.log('  did:', identity.did);

  // 5. create a Logbook client that uses the paying fetch
  const logbook = new Logbook({
    did: identity.did,
    privateKey: identity.privateKey,
    baseUrl: BASE_URL,
    fetch: fetchWithPay,
  });

  // 6. log an event — this triggers a 402, the wrapper signs, retries, settles on-chain
  console.log('\nlogging event with x402 payment ($0.001 USDC on Base)...');
  console.log('  (this involves a real on-chain settlement; expect ~3 seconds)');
  const t0 = Date.now();
  const evt = await logbook.log({
    action: 'demo_paid_event',
    metadata: { note: 'first ever paid event on logbook' },
  });
  const ms = Date.now() - t0;
  console.log('  event id:', evt.id);
  console.log('  seq:', evt.seqNum);
  console.log('  event hash:', evt.eventHash.substring(0, 16) + '...');
  console.log('  elapsed:', ms + 'ms');

  console.log('\n✅ payment cleared. check basescan for the on-chain tx:');
  console.log('  https://basescan.org/address/' + account.address);
}

main().catch((err) => {
  console.error('\nfailed:');
  console.error(err);
  process.exit(1);
});
