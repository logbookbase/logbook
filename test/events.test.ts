import { describe, it, expect, vi, beforeEach } from 'vitest';
import Fastify from 'fastify';
import {
  didFromPublicKey,
  eventMessage,
  GENESIS_HASH,
  generateKeypair,
  hashEvent,
  sign,
  type EventPayload,
} from '../src/crypto/index.js';

vi.mock('../src/db/agents.js', () => ({
  getAgentByDid: vi.fn(),
  createAgent: vi.fn(),
  countEventsForAgent: vi.fn(),
}));
vi.mock('../src/db/events.js', () => ({
  getLatestEventForAgent: vi.fn(),
  getEventById: vi.fn(),
  listEventsForAgent: vi.fn(),
  getEventsUpToSeq: vi.fn(),
  insertEvent: vi.fn(),
}));

import * as agentsDb from '../src/db/agents.js';
import * as eventsDb from '../src/db/events.js';
import { eventsRoutes } from '../src/api/routes/events.js';
import { HttpError } from '../src/lib/errors.js';

async function buildTestApp() {
  const app = Fastify();
  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      reply.code(err.statusCode).send({ error: err.code, message: err.message });
      return;
    }
    reply.code(500).send({ error: 'internal_error' });
  });
  await app.register(eventsRoutes);
  return app;
}

function mockAgent(publicKey: string) {
  const did = didFromPublicKey(publicKey);
  return {
    did,
    public_key: publicKey,
    display_name: 'test',
    metadata: {},
    created_at: new Date('2026-01-01T00:00:00Z'),
  };
}

function buildSignedEvent(
  kp: { publicKey: string; privateKey: string },
  overrides: Partial<EventPayload> = {},
) {
  const did = didFromPublicKey(kp.publicKey);
  const payload: EventPayload = {
    agent_did: did,
    seq_num: 1,
    action: 'test',
    resource: null,
    metadata: {},
    prev_hash: GENESIS_HASH,
    ...overrides,
  };
  const signature = sign(kp.privateKey, eventMessage(payload));
  return { payload, signature, event_hash: hashEvent(payload) };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('POST /events', () => {
  it('accepts a valid first event for a registered agent', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const { payload, signature, event_hash } = buildSignedEvent(kp);

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getLatestEventForAgent).mockResolvedValueOnce(null);
    vi.mocked(eventsDb.insertEvent).mockResolvedValueOnce({
      id: 'evt-1',
      agent_did: payload.agent_did,
      seq_num: '1',
      action: payload.action,
      resource: payload.resource,
      metadata: payload.metadata,
      signature,
      prev_hash: payload.prev_hash,
      event_hash,
      x402_tx_hash: null,
      created_at: new Date('2026-01-01T00:00:00Z'),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.event_hash).toBe(event_hash);
    expect(body.seq_num).toBe(1);
  });

  it('chains a second event when a previous one exists', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);

    const prevHash = 'a'.repeat(64);
    const { payload, signature, event_hash } = buildSignedEvent(kp, {
      seq_num: 2,
      prev_hash: prevHash,
      action: 'second',
    });

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getLatestEventForAgent).mockResolvedValueOnce({
      id: 'evt-1',
      agent_did: did,
      seq_num: '1',
      action: 'first',
      resource: null,
      metadata: {},
      signature: 'x'.repeat(128),
      prev_hash: GENESIS_HASH,
      event_hash: prevHash,
      x402_tx_hash: null,
      created_at: new Date(),
    });
    vi.mocked(eventsDb.insertEvent).mockResolvedValueOnce({
      id: 'evt-2',
      agent_did: payload.agent_did,
      seq_num: '2',
      action: payload.action,
      resource: payload.resource,
      metadata: payload.metadata,
      signature,
      prev_hash: payload.prev_hash,
      event_hash,
      x402_tx_hash: null,
      created_at: new Date(),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature },
    });
    expect(res.statusCode).toBe(200);
  });

  it('rejects an unknown agent with 404', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const { payload, signature } = buildSignedEvent(kp);
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(null);

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe('unknown_agent');
  });

  it('rejects wrong prev_hash with 409', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const { payload, signature } = buildSignedEvent(kp, {
      prev_hash: 'b'.repeat(64),
    });

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getLatestEventForAgent).mockResolvedValueOnce(null);

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe('bad_prev_hash');
  });

  it('rejects wrong seq_num with 409', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const { payload, signature } = buildSignedEvent(kp, { seq_num: 5 });

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getLatestEventForAgent).mockResolvedValueOnce(null);

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe('bad_seq_num');
  });

  it('rejects a bad signature with 401', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const other = generateKeypair();
    const { payload } = buildSignedEvent(kp);
    // sign with a different key
    const wrongSig = sign(other.privateKey, eventMessage(payload));

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getLatestEventForAgent).mockResolvedValueOnce(null);

    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { ...payload, signature: wrongSig },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('bad_signature');
  });

  it('rejects a malformed payload with 400', async () => {
    const app = await buildTestApp();
    const res = await app.inject({
      method: 'POST',
      url: '/events',
      payload: { agent_did: 'x' }, // missing required fields
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('GET /events/:id', () => {
  it('returns the event when found', async () => {
    const app = await buildTestApp();
    vi.mocked(eventsDb.getEventById).mockResolvedValueOnce({
      id: 'evt-1',
      agent_did: 'did:logbook:abc',
      seq_num: '1',
      action: 'test',
      resource: null,
      metadata: {},
      signature: 'x'.repeat(128),
      prev_hash: GENESIS_HASH,
      event_hash: 'a'.repeat(64),
      x402_tx_hash: null,
      created_at: new Date('2026-01-01T00:00:00Z'),
    });
    const res = await app.inject({ method: 'GET', url: '/events/evt-1' });
    expect(res.statusCode).toBe(200);
    expect(res.json().seq_num).toBe(1);
  });

  it('returns 404 when not found', async () => {
    const app = await buildTestApp();
    vi.mocked(eventsDb.getEventById).mockResolvedValueOnce(null);
    const res = await app.inject({ method: 'GET', url: '/events/nope' });
    expect(res.statusCode).toBe(404);
  });
});

describe('GET /agents/:did/events', () => {
  it('returns paginated events for a known agent', async () => {
    const app = await buildTestApp();
    const did = 'did:logbook:abc';
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce({
      did,
      public_key: 'a'.repeat(64),
      display_name: 'x',
      metadata: {},
      created_at: new Date(),
    });
    vi.mocked(eventsDb.listEventsForAgent).mockResolvedValueOnce([
      {
        id: 'e2',
        agent_did: did,
        seq_num: '2',
        action: 'b',
        resource: null,
        metadata: {},
        signature: 'x'.repeat(128),
        prev_hash: 'a'.repeat(64),
        event_hash: 'b'.repeat(64),
        x402_tx_hash: null,
        created_at: new Date(),
      },
      {
        id: 'e1',
        agent_did: did,
        seq_num: '1',
        action: 'a',
        resource: null,
        metadata: {},
        signature: 'x'.repeat(128),
        prev_hash: GENESIS_HASH,
        event_hash: 'a'.repeat(64),
        x402_tx_hash: null,
        created_at: new Date(),
      },
    ]);
    const res = await app.inject({ method: 'GET', url: `/agents/${did}/events` });
    expect(res.statusCode).toBe(200);
    expect(res.json().count).toBe(2);
  });
});

describe('GET /verify/:id', () => {
  it('returns valid=true for an intact chain', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);

    const p1: EventPayload = {
      agent_did: did,
      seq_num: 1,
      action: 'a',
      resource: null,
      metadata: {},
      prev_hash: GENESIS_HASH,
    };
    const h1 = hashEvent(p1);
    const s1 = sign(kp.privateKey, eventMessage(p1));

    const p2: EventPayload = {
      agent_did: did,
      seq_num: 2,
      action: 'b',
      resource: null,
      metadata: {},
      prev_hash: h1,
    };
    const h2 = hashEvent(p2);
    const s2 = sign(kp.privateKey, eventMessage(p2));

    vi.mocked(eventsDb.getEventById).mockResolvedValueOnce({
      id: 'e2',
      agent_did: did,
      seq_num: '2',
      action: p2.action,
      resource: p2.resource,
      metadata: p2.metadata,
      signature: s2,
      prev_hash: p2.prev_hash,
      event_hash: h2,
      x402_tx_hash: null,
      created_at: new Date(),
    });
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getEventsUpToSeq).mockResolvedValueOnce([
      {
        id: 'e1',
        agent_did: did,
        seq_num: '1',
        action: p1.action,
        resource: p1.resource,
        metadata: p1.metadata,
        signature: s1,
        prev_hash: p1.prev_hash,
        event_hash: h1,
        x402_tx_hash: null,
        created_at: new Date(),
      },
      {
        id: 'e2',
        agent_did: did,
        seq_num: '2',
        action: p2.action,
        resource: p2.resource,
        metadata: p2.metadata,
        signature: s2,
        prev_hash: p2.prev_hash,
        event_hash: h2,
        x402_tx_hash: null,
        created_at: new Date(),
      },
    ]);

    const res = await app.inject({ method: 'GET', url: '/verify/e2' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.valid).toBe(true);
    expect(body.chain_length).toBe(2);
  });

  it('returns hash_mismatch when metadata was tampered after signing', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);

    const original: EventPayload = {
      agent_did: did,
      seq_num: 1,
      action: 'a',
      resource: null,
      metadata: { amount: 5 },
      prev_hash: GENESIS_HASH,
    };
    const originalHash = hashEvent(original);
    const originalSig = sign(kp.privateKey, eventMessage(original));

    // db has tampered metadata but old hash and sig
    vi.mocked(eventsDb.getEventById).mockResolvedValueOnce({
      id: 'e1',
      agent_did: did,
      seq_num: '1',
      action: 'a',
      resource: null,
      metadata: { amount: 999 }, // tampered
      signature: originalSig,
      prev_hash: GENESIS_HASH,
      event_hash: originalHash,
      x402_tx_hash: null,
      created_at: new Date(),
    });
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(mockAgent(kp.publicKey));
    vi.mocked(eventsDb.getEventsUpToSeq).mockResolvedValueOnce([
      {
        id: 'e1',
        agent_did: did,
        seq_num: '1',
        action: 'a',
        resource: null,
        metadata: { amount: 999 },
        signature: originalSig,
        prev_hash: GENESIS_HASH,
        event_hash: originalHash,
        x402_tx_hash: null,
        created_at: new Date(),
      },
    ]);

    const res = await app.inject({ method: 'GET', url: '/verify/e1' });
    expect(res.statusCode).toBe(200);
    expect(res.json().valid).toBe(false);
    expect(res.json().reason).toBe('hash_mismatch');
  });
});
