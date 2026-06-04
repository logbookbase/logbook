import { describe, it, expect, vi, beforeEach } from 'vitest';
import Fastify from 'fastify';
import {
  generateKeypair,
  sign,
  canonicalize,
  didFromPublicKey,
} from '../src/crypto/index.js';

// mock the db layer before importing the route
vi.mock('../src/db/agents.js', () => ({
  createAgent: vi.fn(),
  getAgentByDid: vi.fn(),
  countEventsForAgent: vi.fn(),
}));

import * as agentsDb from '../src/db/agents.js';
import { agentsRoutes } from '../src/api/routes/agents.js';
import { HttpError } from '../src/lib/errors.js';

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

async function buildTestApp() {
  const app = Fastify();
  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      reply.code(err.statusCode).send({ error: err.code, message: err.message });
      return;
    }
    reply.code(500).send({ error: 'internal_error' });
  });
  await app.register(agentsRoutes);
  return app;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('POST /agents', () => {
  it('registers a new agent with a valid signature', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    const display_name = 'test-bot';
    const metadata = { framework: 'vitest' };
    const message = registrationMessage({ public_key: kp.publicKey, display_name, metadata });
    const signature = sign(kp.privateKey, message);

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(null);
    vi.mocked(agentsDb.createAgent).mockResolvedValueOnce({
      did,
      public_key: kp.publicKey,
      display_name,
      metadata,
      created_at: new Date('2026-01-01T00:00:00Z'),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/agents',
      payload: { public_key: kp.publicKey, display_name, metadata, signature },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.did).toBe(did);
    expect(body.public_key).toBe(kp.publicKey);
    expect(body.display_name).toBe(display_name);
    expect(vi.mocked(agentsDb.createAgent)).toHaveBeenCalledOnce();
  });

  it('rejects a bad signature with 401', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const display_name = 'test-bot';
    const metadata = {};
    // sign a different message than what we send
    const wrongMessage = registrationMessage({ public_key: kp.publicKey, display_name: 'other', metadata });
    const signature = sign(kp.privateKey, wrongMessage);

    const res = await app.inject({
      method: 'POST',
      url: '/agents',
      payload: { public_key: kp.publicKey, display_name, metadata, signature },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('bad_signature');
    expect(vi.mocked(agentsDb.createAgent)).not.toHaveBeenCalled();
  });

  it('rejects a malformed public_key with 400', async () => {
    const app = await buildTestApp();
    const res = await app.inject({
      method: 'POST',
      url: '/agents',
      payload: {
        public_key: 'not-hex',
        display_name: 'x',
        metadata: {},
        signature: 'a'.repeat(128),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_body');
  });

  it('returns 409 when did already exists', async () => {
    const app = await buildTestApp();
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    const display_name = 'test-bot';
    const metadata = {};
    const message = registrationMessage({ public_key: kp.publicKey, display_name, metadata });
    const signature = sign(kp.privateKey, message);

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce({
      did,
      public_key: kp.publicKey,
      display_name,
      metadata,
      created_at: new Date(),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/agents',
      payload: { public_key: kp.publicKey, display_name, metadata, signature },
    });

    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe('already_registered');
  });
});

describe('GET /agents/:did', () => {
  it('returns a registered agent with event_count', async () => {
    const app = await buildTestApp();
    const did = 'did:logbook:abc';

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce({
      did,
      public_key: 'a'.repeat(64),
      display_name: 'test-bot',
      metadata: {},
      created_at: new Date('2026-01-01T00:00:00Z'),
    });
    vi.mocked(agentsDb.countEventsForAgent).mockResolvedValueOnce(7);

    const res = await app.inject({ method: 'GET', url: '/agents/' + did });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.did).toBe(did);
    expect(body.event_count).toBe(7);
  });

  it('returns 404 for an unknown did', async () => {
    const app = await buildTestApp();
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(null);

    const res = await app.inject({ method: 'GET', url: '/agents/did:logbook:nope' });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe('not_found');
  });
});
