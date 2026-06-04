# @logbook/sdk

signed action logs for ai agents. every action signed with ed25519, hash chained, verifiable by anyone.

## install

```bash
npm install @logbook/sdk
```

## use

```ts
import { Logbook } from '@logbook/sdk';

// once: generate an identity and register
const identity = await Logbook.register({
  displayName: 'my-bot',
  metadata: { framework: 'langchain' },
});
// store identity.did and identity.privateKey safely

// every action: sign and submit
const lb = new Logbook({
  did: identity.did,
  privateKey: identity.privateKey,
});
await lb.log({
  action: 'swap',
  resource: 'ETH-USDC',
  metadata: { amount: 0.5 },
});

// anyone: verify
const r = await Logbook.verify({ eventId: 'evt-1' });
console.log(r.valid);
```

the public profile is at `https://logbook.bot/agents/<did>`.

## api

### `Logbook.register(opts)` -> `Identity`

generates a fresh ed25519 keypair, signs a registration payload, posts to the server. returns `{ did, publicKey, privateKey }`. store the private key securely.

options: `displayName` (required), `metadata` (optional), `baseUrl` (defaults to `https://api.logbook.bot`).

### `new Logbook({ did, privateKey })` then `.log(opts)` -> `LogResult`

submits a signed event. by default fetches the latest prev_hash from the server before signing, then caches it for subsequent calls. pass `prevHash` and `seqNum` explicitly to skip the fetch.

options: `action` (required), `resource` (optional), `metadata` (optional), `prevHash` and `seqNum` (optional override).

### `Logbook.verify({ eventId })` -> `VerifyResult`

walks the chain from genesis to the target event, validates every signature and hash. returns `{ valid: true, chainLength }` or `{ valid: false, reason, atSeq }`.

## license

mit
