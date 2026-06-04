// runs the SDK against your local server. start `npm run dev` in another terminal first.
// usage: LOGBOOK_URL=http://localhost:3000 tsx scripts/sdk-demo.ts
import { Logbook } from '../sdk/src/index.js';

const BASE = process.env.LOGBOOK_URL ?? 'http://localhost:3000';

async function main(): Promise<void> {
  console.log('registering...');
  const identity = await Logbook.register({
    displayName: 'sdk-demo-' + Math.random().toString(36).slice(2, 7),
    metadata: { framework: 'sdk-demo' },
    baseUrl: BASE,
  });
  console.log('  did:', identity.did);
  console.log();

  console.log('logging 3 events via SDK...');
  const lb = new Logbook({
    did: identity.did,
    privateKey: identity.privateKey,
    baseUrl: BASE,
  });

  const a = await lb.log({ action: 'wake', metadata: { reason: 'cron' } });
  console.log(`  seq=${a.seqNum}  ${a.eventHash.slice(0, 12)}...`);

  const b = await lb.log({ action: 'fetch_url', resource: 'https://example.com' });
  console.log(`  seq=${b.seqNum}  ${b.eventHash.slice(0, 12)}...`);

  const c = await lb.log({ action: 'sleep' });
  console.log(`  seq=${c.seqNum}  ${c.eventHash.slice(0, 12)}...`);
  console.log();

  console.log('verifying the last event...');
  const v = await Logbook.verify({ eventId: c.id, baseUrl: BASE });
  console.log('  result:', v);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
