import {
  generateKeypair,
  sign,
  canonicalize,
  didFromPublicKey,
} from '../src/crypto/index.js';

const BASE = process.env.LOGBOOK_URL ?? 'http://localhost:3000';

function registrationMessage(input: {
  public_key: string;
  display_name: string;
  metadata: Record<string, unknown>;
}): string {
  return canonicalize({
    type: 'logbook.register.v1',
    public_key: input.public_key,
    display_name: input.display_name,
    metadata: input.metadata,
  });
}

async function main(): Promise<void> {
  const kp = generateKeypair();
  const did = didFromPublicKey(kp.publicKey);
  const display_name = 'demo-bot-' + Math.random().toString(36).slice(2, 8);
  const metadata = { framework: 'manual-demo' };

  const message = registrationMessage({
    public_key: kp.publicKey,
    display_name,
    metadata,
  });
  const signature = sign(kp.privateKey, message);

  console.log('expected did:', did);
  console.log('registering...');

  const res = await fetch(BASE + '/agents', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      public_key: kp.publicKey,
      display_name,
      metadata,
      signature,
    }),
  });

  const body = await res.json();
  console.log('POST /agents ->', res.status);
  console.log(body);
  console.log();

  if (!res.ok) {
    process.exitCode = 1;
    return;
  }

  console.log('fetching back...');
  const fetched = await fetch(BASE + '/agents/' + encodeURIComponent(did));
  const fetchedBody = await fetched.json();
  console.log('GET /agents/:did ->', fetched.status);
  console.log(fetchedBody);
  console.log();

  console.log('store this keypair for future event signing:');
  console.log('  did:        ', did);
  console.log('  private key:', kp.privateKey);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
