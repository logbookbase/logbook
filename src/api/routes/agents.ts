import { Hono } from 'hono';
import { z } from 'zod';
import {
  canonicalize,
  didFromPublicKey,
  verify,
} from '../../crypto/index.js';
import {
  createAgent,
  getAgentByDid,
  countEventsForAgent,
} from '../../db/agents.js';
import { badRequest, conflict, notFound, unauthorized } from '../../lib/errors.js';

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

const RegisterBody = z.object({
  public_key: z.string().regex(/^[0-9a-f]{64}$/, 'public_key must be 64 hex chars'),
  display_name: z.string().min(1).max(64),
  metadata: z.record(z.unknown()).default({}),
  signature: z.string().regex(/^[0-9a-f]{128}$/, 'signature must be 128 hex chars'),
});

export const agentsRoutes = new Hono();

agentsRoutes.post('/agents', async (c) => {
  const raw = await c.req.json().catch(() => null);
  const parsed = RegisterBody.safeParse(raw);
  if (!parsed.success) {
    throw badRequest('invalid_body', parsed.error.issues[0]?.message ?? 'invalid body');
  }
  const { public_key, display_name, metadata, signature } = parsed.data;

  const message = registrationMessage({ public_key, display_name, metadata });
  if (!verify(public_key, signature, message)) {
    throw unauthorized('bad_signature', 'signature does not match public key');
  }

  const did = didFromPublicKey(public_key);

  const existing = await getAgentByDid(did);
  if (existing) {
    throw conflict('already_registered', 'agent with this public key already exists');
  }

  const row = await createAgent({ did, publicKey: public_key, displayName: display_name, metadata });

  return c.json({
    did: row.did,
    public_key: row.public_key,
    display_name: row.display_name,
    metadata: row.metadata,
    created_at: row.created_at.toISOString(),
  });
});

agentsRoutes.get('/agents/:did', async (c) => {
  const did = c.req.param('did');
  const row = await getAgentByDid(did);
  if (!row) throw notFound('not_found', 'no agent with that did');

  const eventCount = await countEventsForAgent(did);

  return c.json({
    did: row.did,
    public_key: row.public_key,
    display_name: row.display_name,
    metadata: row.metadata,
    event_count: eventCount,
    created_at: row.created_at.toISOString(),
  });
});
