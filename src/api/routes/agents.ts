import type { FastifyInstance } from 'fastify';
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

// canonical message a client must sign to register.
// keeping it small and explicit so signatures aren't reusable across actions.
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

export async function agentsRoutes(app: FastifyInstance): Promise<void> {
  app.post('/agents', async (req) => {
    const parsed = RegisterBody.safeParse(req.body);
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

    return {
      did: row.did,
      public_key: row.public_key,
      display_name: row.display_name,
      metadata: row.metadata,
      created_at: row.created_at.toISOString(),
    };
  });

  app.get<{ Params: { did: string } }>('/agents/:did', async (req) => {
    const { did } = req.params;
    const row = await getAgentByDid(did);
    if (!row) throw notFound('not_found', 'no agent with that did');

    const eventCount = await countEventsForAgent(did);

    return {
      did: row.did,
      public_key: row.public_key,
      display_name: row.display_name,
      metadata: row.metadata,
      event_count: eventCount,
      created_at: row.created_at.toISOString(),
    };
  });
}
