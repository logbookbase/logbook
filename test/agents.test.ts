import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import {
  generateKeypair,
  sign,
  canonicalize,
  didFromPublicKey,
} from '../src/crypto/index.js';

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

function buildTestApp(): Hono {
  const app = new Hono();
  app.route('/', agentsRoutes);
  app.onError((err, c) => {
    if (err instanceof HttpError) {
      return c.json({ error: err.code, message: err.message }, err.statusCode as 400 | 401 | 404 | 409);
    }
    return c.json({ error: 'internal_error' }, 500);
  });
  return app;
}

async function postJson(app: Hono, path: string, body: unknown): Promise<{ status: number; json: any }> {
  const res = await app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function getJson(app: Hono, path: string): Promise<{ status: number; json: any }> {
  const res = await app.request(path);
  return { status: res.status, json: (await res.json()) as any };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('POST /agents', () => {
  it('registers a new agent with a valid signature', async () => {
    const app = buildTestApp();
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

    const { status, json } = await postJson(app, '/agents', {
      public_key: kp.publicKey,
      display_name,
      metadata,
      signature,
    });

    expect(status).toBe(200);
    expect(json.did).toBe(did);
    expect(json.public_key).toBe(kp.publicKey);
    expect(json.display_name).toBe(display_name);
    expect(vi.mocked(agentsDb.createAgent)).toHaveBeenCalledOnce();
  });

  it('rejects a bad signature with 401', async () => {
    const app = buildTestApp();
    const kp = generateKeypair();
    const display_name = 'test-bot';
    const metadata = {};
    const wrongMessage = registrationMessage({ public_key: kp.publicKey, display_name: 'other', metadata });
    const signature = sign(kp.privateKey, wrongMessage);

    const { status, json } = await postJson(app, '/agents', {
      public_key: kp.publicKey,
      display_name,
      metadata,
      signature,
    });

    expect(status).toBe(401);
    expect(json.error).toBe('bad_signature');
    expect(vi.mocked(agentsDb.createAgent)).not.toHaveBeenCalled();
  });

  it('rejects a malformed public_key with 400', async () => {
    const app = buildTestApp();
    const { status, json } = await postJson(app, '/agents', {
      public_key: 'not-hex',
      display_name: 'x',
      metadata: {},
      signature: 'a'.repeat(128),
    });
    expect(status).toBe(400);
    expect(json.error).toBe('invalid_body');
  });

  it('returns 409 when did already exists', async () => {
    const app = buildTestApp();
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

    const { status, json } = await postJson(app, '/agents', {
      public_key: kp.publicKey,
      display_name,
      metadata,
      signature,
    });

    expect(status).toBe(409);
    expect(json.error).toBe('already_registered');
  });
});

describe('GET /agents/:did', () => {
  it('returns a registered agent with event_count', async () => {
    const app = buildTestApp();
    const did = 'did:logbook:abc';

    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce({
      did,
      public_key: 'a'.repeat(64),
      display_name: 'test-bot',
      metadata: {},
      created_at: new Date('2026-01-01T00:00:00Z'),
    });
    vi.mocked(agentsDb.countEventsForAgent).mockResolvedValueOnce(7);

    const { status, json } = await getJson(app, '/agents/' + did);
    expect(status).toBe(200);
    expect(json.did).toBe(did);
    expect(json.event_count).toBe(7);
  });

  it('returns 404 for an unknown did', async () => {
    const app = buildTestApp();
    vi.mocked(agentsDb.getAgentByDid).mockResolvedValueOnce(null);

    const { status, json } = await getJson(app, '/agents/did:logbook:nope');
    expect(status).toBe(404);
    expect(json.error).toBe('not_found');
  });
});
