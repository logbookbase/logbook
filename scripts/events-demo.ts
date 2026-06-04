import {
  canonicalize,
  didFromPublicKey,
  eventMessage,
  GENESIS_HASH,
  generateKeypair,
  hashEvent,
  sign,
  type EventPayload,
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

async function post(path: string, body: unknown) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  return { status: res.status, body: json };
}

async function get(path: string) {
  const res = await fetch(BASE + path);
  return { status: res.status, body: await res.json() };
}

async function main(): Promise<void> {
  // register
  const kp = generateKeypair();
  const did = didFromPublicKey(kp.publicKey);
  const display_name = 'log-demo-' + Math.random().toString(36).slice(2, 7);
  const metadata = { framework: 'manual-demo' };

  const regSig = sign(
    kp.privateKey,
    registrationMessage({ public_key: kp.publicKey, display_name, metadata }),
  );
  const reg = await post('/agents', {
    public_key: kp.publicKey,
    display_name,
    metadata,
    signature: regSig,
  });
  console.log('registered:', reg.status, did);
  if (reg.status !== 200) {
    console.error(reg.body);
    process.exit(1);
  }
  console.log();

  // log three events, chained
  const actions = [
    { action: 'swap', resource: 'ETH-USDC', metadata: { amount: 0.5 } },
    { action: 'transfer', resource: '0xabc', metadata: { amount: 10 } },
    { action: 'launch_token', resource: null, metadata: { ticker: 'LOG' } },
  ];

  let prev_hash = GENESIS_HASH;
  let seq_num = 1;
  let lastEventId = '';

  for (const a of actions) {
    const payload: EventPayload = {
      agent_did: did,
      seq_num,
      action: a.action,
      resource: a.resource,
      metadata: a.metadata,
      prev_hash,
    };
    const signature = sign(kp.privateKey, eventMessage(payload));
    const res = await post('/events', { ...payload, signature });
    console.log(`event ${seq_num} (${a.action}):`, res.status);
    if (res.status !== 200) {
      console.error(res.body);
      process.exit(1);
    }
    prev_hash = res.body.event_hash;
    lastEventId = res.body.id;
    seq_num++;
  }
  console.log();

  // list events
  const list = await get(`/agents/${did}/events?limit=10`);
  console.log('list:', list.status, 'count:', list.body.count);
  for (const e of list.body.events) {
    console.log(`  seq=${e.seq_num}  ${e.action}  hash=${e.event_hash.slice(0, 12)}...`);
  }
  console.log();

  // verify the chain
  const verify = await get(`/verify/${lastEventId}`);
  console.log('verify:', verify.status, verify.body);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
