import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Logbook, LogbookError, generateKeypair, didFromPublicKey, GENESIS_HASH } from '../src/index.js';
import {
  canonicalize,
  eventMessage,
  hashEvent,
  verify as cryptoVerify,
  registrationMessage,
  type EventPayload,
} from '../src/crypto.js';

type Captured = { url: string; method: string; body: any | null; headers: Record<string, string> };

function makeFetch(handler: (req: Captured) => { status: number; body: any }) {
  return vi.fn(async (input: any, init?: any) => {
    const url = typeof input === 'string' ? input : input.url;
    const method = init?.method ?? 'GET';
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body = init?.body ? JSON.parse(init.body as string) : null;
    const res = handler({ url, method, body, headers });
    return new Response(JSON.stringify(res.body), {
      status: res.status,
      headers: { 'content-type': 'application/json' },
    });
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Logbook.register', () => {
  it('generates keys, signs the registration payload, posts to /agents', async () => {
    let capturedBody: any = null;
    const fetcher = makeFetch((req) => {
      capturedBody = req.body;
      return {
        status: 200,
        body: {
          did: req.body.public_key
            ? 'did:logbook:somethingfromserver'
            : null,
          public_key: req.body.public_key,
          display_name: req.body.display_name,
          metadata: req.body.metadata,
          created_at: '2026-01-01T00:00:00Z',
        },
      };
    });

    const identity = await Logbook.register({
      displayName: 'demo',
      metadata: { framework: 'vitest' },
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });

    expect(identity.did).toMatch(/^did:logbook:/);
    expect(identity.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.privateKey).toMatch(/^[0-9a-f]{64}$/);

    // verify the signature server would receive is correct
    const msg = registrationMessage({
      public_key: capturedBody.public_key,
      display_name: 'demo',
      metadata: { framework: 'vitest' },
    });
    expect(cryptoVerify(identity.publicKey, capturedBody.signature, msg)).toBe(true);
  });

  it('throws LogbookError when server returns 409', async () => {
    const fetcher = makeFetch(() => ({
      status: 409,
      body: { error: 'already_registered', message: 'agent with this public key already exists' },
    }));

    await expect(
      Logbook.register({ displayName: 'x', baseUrl: 'http://test', fetch: fetcher as any }),
    ).rejects.toThrow(LogbookError);
  });
});

describe('Logbook.log', () => {
  it('uses auto-chain: fetches latest then submits seq 1 with GENESIS_HASH when no prior events', async () => {
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    let postBody: any = null;

    const fetcher = makeFetch((req) => {
      if (req.method === 'GET' && req.url.includes('/agents/')) {
        return { status: 200, body: { events: [], count: 0 } };
      }
      if (req.method === 'POST' && req.url.endsWith('/events')) {
        postBody = req.body;
        const payload: EventPayload = {
          agent_did: req.body.agent_did,
          seq_num: req.body.seq_num,
          action: req.body.action,
          resource: req.body.resource,
          metadata: req.body.metadata,
          prev_hash: req.body.prev_hash,
        };
        const hash = hashEvent(payload);
        return {
          status: 200,
          body: {
            id: 'evt-1',
            agent_did: req.body.agent_did,
            seq_num: req.body.seq_num,
            action: req.body.action,
            resource: req.body.resource,
            metadata: req.body.metadata,
            signature: req.body.signature,
            prev_hash: req.body.prev_hash,
            event_hash: hash,
            x402_tx_hash: null,
            created_at: '2026-01-01T00:00:00Z',
          },
        };
      }
      return { status: 404, body: { error: 'not_found' } };
    });

    const lb = new Logbook({
      did,
      privateKey: kp.privateKey,
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });
    const r = await lb.log({ action: 'first', metadata: { k: 1 } });

    expect(postBody.seq_num).toBe(1);
    expect(postBody.prev_hash).toBe(GENESIS_HASH);
    expect(r.seqNum).toBe(1);

    // signature must verify
    const msg = eventMessage({
      agent_did: did,
      seq_num: 1,
      action: 'first',
      resource: null,
      metadata: { k: 1 },
      prev_hash: GENESIS_HASH,
    });
    expect(cryptoVerify(kp.publicKey, postBody.signature, msg)).toBe(true);
  });

  it('uses cached prev_hash on second log() call (no extra GET)', async () => {
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    let getCount = 0;
    let postCount = 0;

    const fetcher = makeFetch((req) => {
      if (req.method === 'GET') {
        getCount++;
        return { status: 200, body: { events: [], count: 0 } };
      }
      postCount++;
      const payload: EventPayload = {
        agent_did: req.body.agent_did,
        seq_num: req.body.seq_num,
        action: req.body.action,
        resource: req.body.resource,
        metadata: req.body.metadata,
        prev_hash: req.body.prev_hash,
      };
      return {
        status: 200,
        body: {
          id: 'evt-' + postCount,
          agent_did: req.body.agent_did,
          seq_num: req.body.seq_num,
          action: req.body.action,
          resource: req.body.resource,
          metadata: req.body.metadata,
          signature: req.body.signature,
          prev_hash: req.body.prev_hash,
          event_hash: hashEvent(payload),
          x402_tx_hash: null,
          created_at: '2026-01-01T00:00:00Z',
        },
      };
    });

    const lb = new Logbook({
      did,
      privateKey: kp.privateKey,
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });

    const r1 = await lb.log({ action: 'a' });
    const r2 = await lb.log({ action: 'b' });

    expect(r1.seqNum).toBe(1);
    expect(r2.seqNum).toBe(2);
    expect(getCount).toBe(1); // GET only called once
    expect(postCount).toBe(2);
  });

  it('explicit prevHash + seqNum skips the chain fetch entirely', async () => {
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    let getCount = 0;

    const fetcher = makeFetch((req) => {
      if (req.method === 'GET') getCount++;
      const payload: EventPayload = {
        agent_did: req.body.agent_did,
        seq_num: req.body.seq_num,
        action: req.body.action,
        resource: req.body.resource,
        metadata: req.body.metadata,
        prev_hash: req.body.prev_hash,
      };
      return {
        status: 200,
        body: {
          id: 'evt-x',
          agent_did: req.body.agent_did,
          seq_num: req.body.seq_num,
          action: req.body.action,
          resource: req.body.resource,
          metadata: req.body.metadata,
          signature: req.body.signature,
          prev_hash: req.body.prev_hash,
          event_hash: hashEvent(payload),
          x402_tx_hash: null,
          created_at: '2026-01-01T00:00:00Z',
        },
      };
    });

    const lb = new Logbook({
      did,
      privateKey: kp.privateKey,
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });
    await lb.log({
      action: 'manual',
      prevHash: 'a'.repeat(64),
      seqNum: 42,
    });

    expect(getCount).toBe(0);
  });
});

describe('Logbook.verify', () => {
  it('returns valid:true on a clean chain', async () => {
    const fetcher = makeFetch(() => ({
      status: 200,
      body: {
        valid: true,
        event_id: 'evt-1',
        agent_did: 'did:logbook:abc',
        chain_length: 3,
      },
    }));
    const r = await Logbook.verify({
      eventId: 'evt-1',
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });
    expect(r.valid).toBe(true);
    if (r.valid) expect(r.chainLength).toBe(3);
  });

  it('returns valid:false with reason on tampered chain', async () => {
    const fetcher = makeFetch(() => ({
      status: 200,
      body: { valid: false, reason: 'hash_mismatch', at_seq: 2 },
    }));
    const r = await Logbook.verify({
      eventId: 'evt-2',
      baseUrl: 'http://test',
      fetch: fetcher as any,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) {
      expect(r.reason).toBe('hash_mismatch');
      expect(r.atSeq).toBe(2);
    }
  });
});

describe('constructor validation', () => {
  it('rejects an invalid did', () => {
    expect(
      () =>
        new Logbook({
          did: 'not-a-did',
          privateKey: 'a'.repeat(64),
        }),
    ).toThrow(LogbookError);
  });

  it('rejects an invalid private key', () => {
    expect(
      () =>
        new Logbook({
          did: 'did:logbook:abc',
          privateKey: 'short',
        }),
    ).toThrow(LogbookError);
  });
});
