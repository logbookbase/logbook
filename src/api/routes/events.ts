import { Hono } from 'hono';
import { z } from 'zod';
import {
  eventMessage,
  GENESIS_HASH,
  hashEvent,
  verify,
  type EventPayload,
} from '../../crypto/index.js';
import { getAgentByDid } from '../../db/agents.js';
import {
  getEventById,
  getEventsUpToSeq,
  getLatestEventForAgent,
  insertEvent,
  listEventsForAgent,
  type EventRow,
} from '../../db/events.js';
import { badRequest, conflict, notFound, unauthorized } from '../../lib/errors.js';

const SubmitBody = z.object({
  agent_did: z.string().min(1),
  seq_num: z.number().int().positive(),
  action: z.string().min(1).max(128),
  resource: z.string().max(512).nullable().default(null),
  metadata: z.record(z.unknown()).default({}),
  prev_hash: z.string().regex(/^[0-9a-f]{64}$/),
  signature: z.string().regex(/^[0-9a-f]{128}$/),
});

function serializeEvent(row: EventRow) {
  return {
    id: row.id,
    agent_did: row.agent_did,
    seq_num: Number(row.seq_num),
    action: row.action,
    resource: row.resource,
    metadata: row.metadata,
    signature: row.signature,
    prev_hash: row.prev_hash,
    event_hash: row.event_hash,
    x402_tx_hash: row.x402_tx_hash,
    created_at: row.created_at.toISOString(),
  };
}

const ListQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before_seq: z.coerce.number().int().positive().optional(),
});

export const eventsRoutes = new Hono();

eventsRoutes.post('/events', async (c) => {
  const raw = await c.req.json().catch(() => null);
  const parsed = SubmitBody.safeParse(raw);
  if (!parsed.success) {
    throw badRequest('invalid_body', parsed.error.issues[0]?.message ?? 'invalid body');
  }
  const body = parsed.data;

  const agent = await getAgentByDid(body.agent_did);
  if (!agent) throw notFound('unknown_agent', 'agent does not exist');

  const latest = await getLatestEventForAgent(body.agent_did);
  const expectedPrevHash = latest ? latest.event_hash : GENESIS_HASH;
  const expectedSeq = latest ? Number(latest.seq_num) + 1 : 1;

  if (body.prev_hash !== expectedPrevHash) {
    throw conflict('bad_prev_hash', `expected prev_hash ${expectedPrevHash}`);
  }
  if (body.seq_num !== expectedSeq) {
    throw conflict('bad_seq_num', `expected seq_num ${expectedSeq}`);
  }

  const payload: EventPayload = {
    agent_did: body.agent_did,
    seq_num: body.seq_num,
    action: body.action,
    resource: body.resource,
    metadata: body.metadata,
    prev_hash: body.prev_hash,
  };
  const message = eventMessage(payload);
  if (!verify(agent.public_key, body.signature, message)) {
    throw unauthorized('bad_signature', 'signature does not match agent public key');
  }

  const eventHash = hashEvent(payload);

  const row = await insertEvent({
    agentDid: body.agent_did,
    seqNum: body.seq_num,
    action: body.action,
    resource: body.resource,
    metadata: body.metadata,
    signature: body.signature,
    prevHash: body.prev_hash,
    eventHash,
    x402TxHash: null,
  });

  return c.json(serializeEvent(row));
});

eventsRoutes.get('/events/:id', async (c) => {
  const row = await getEventById(c.req.param('id'));
  if (!row) throw notFound('not_found', 'no event with that id');
  return c.json(serializeEvent(row));
});

eventsRoutes.get('/agents/:did/events', async (c) => {
  const parsed = ListQuery.safeParse(c.req.query());
  if (!parsed.success) {
    throw badRequest('invalid_query', parsed.error.issues[0]?.message ?? 'invalid query');
  }
  const { limit, before_seq } = parsed.data;

  const did = c.req.param('did');
  const agent = await getAgentByDid(did);
  if (!agent) throw notFound('unknown_agent', 'agent does not exist');

  const rows = await listEventsForAgent({
    did,
    limit,
    beforeSeq: before_seq ?? null,
  });

  return c.json({
    events: rows.map(serializeEvent),
    count: rows.length,
  });
});

eventsRoutes.get('/verify/:id', async (c) => {
  const target = await getEventById(c.req.param('id'));
  if (!target) throw notFound('not_found', 'no event with that id');

  const agent = await getAgentByDid(target.agent_did);
  if (!agent) {
    return c.json({ valid: false, reason: 'agent_missing' as const });
  }

  const chain = await getEventsUpToSeq({
    did: target.agent_did,
    seqNum: Number(target.seq_num),
  });

  let expectedSeq = 1;
  let expectedPrevHash = GENESIS_HASH;

  for (const evt of chain) {
    if (Number(evt.seq_num) !== expectedSeq) {
      return c.json({
        valid: false,
        reason: 'seq_gap' as const,
        at_seq: Number(evt.seq_num),
        expected_seq: expectedSeq,
      });
    }
    if (evt.prev_hash !== expectedPrevHash) {
      return c.json({
        valid: false,
        reason: 'broken_chain' as const,
        at_seq: Number(evt.seq_num),
      });
    }

    const payload: EventPayload = {
      agent_did: evt.agent_did,
      seq_num: Number(evt.seq_num),
      action: evt.action,
      resource: evt.resource,
      metadata: evt.metadata,
      prev_hash: evt.prev_hash,
    };

    if (hashEvent(payload) !== evt.event_hash) {
      return c.json({
        valid: false,
        reason: 'hash_mismatch' as const,
        at_seq: Number(evt.seq_num),
      });
    }

    if (!verify(agent.public_key, evt.signature, eventMessage(payload))) {
      return c.json({
        valid: false,
        reason: 'bad_signature' as const,
        at_seq: Number(evt.seq_num),
      });
    }

    expectedSeq = Number(evt.seq_num) + 1;
    expectedPrevHash = evt.event_hash;
  }

  return c.json({
    valid: true as const,
    event_id: target.id,
    agent_did: target.agent_did,
    chain_length: chain.length,
  });
});
