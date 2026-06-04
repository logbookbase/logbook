import type { FastifyInstance } from 'fastify';
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

export async function eventsRoutes(app: FastifyInstance): Promise<void> {
  // submit a new event
  app.post('/events', async (req) => {
    const parsed = SubmitBody.safeParse(req.body);
    if (!parsed.success) {
      throw badRequest('invalid_body', parsed.error.issues[0]?.message ?? 'invalid body');
    }
    const body = parsed.data;

    // agent must exist
    const agent = await getAgentByDid(body.agent_did);
    if (!agent) throw notFound('unknown_agent', 'agent does not exist');

    // determine the expected prev_hash and seq_num from chain state
    const latest = await getLatestEventForAgent(body.agent_did);
    const expectedPrevHash = latest ? latest.event_hash : GENESIS_HASH;
    const expectedSeq = latest ? Number(latest.seq_num) + 1 : 1;

    if (body.prev_hash !== expectedPrevHash) {
      throw conflict('bad_prev_hash', `expected prev_hash ${expectedPrevHash}`);
    }
    if (body.seq_num !== expectedSeq) {
      throw conflict('bad_seq_num', `expected seq_num ${expectedSeq}`);
    }

    // signature check: agent must have signed the canonical payload
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

    return serializeEvent(row);
  });

  // single event lookup
  app.get<{ Params: { id: string } }>('/events/:id', async (req) => {
    const row = await getEventById(req.params.id);
    if (!row) throw notFound('not_found', 'no event with that id');
    return serializeEvent(row);
  });

  // paginated event list for an agent
  const ListQuery = z.object({
    limit: z.coerce.number().int().min(1).max(100).default(50),
    before_seq: z.coerce.number().int().positive().optional(),
  });

  app.get<{ Params: { did: string } }>('/agents/:did/events', async (req) => {
    const parsed = ListQuery.safeParse(req.query);
    if (!parsed.success) {
      throw badRequest('invalid_query', parsed.error.issues[0]?.message ?? 'invalid query');
    }
    const { limit, before_seq } = parsed.data;

    const agent = await getAgentByDid(req.params.did);
    if (!agent) throw notFound('unknown_agent', 'agent does not exist');

    const rows = await listEventsForAgent({
      did: req.params.did,
      limit,
      beforeSeq: before_seq ?? null,
    });

    return {
      events: rows.map(serializeEvent),
      count: rows.length,
    };
  });

  // chain verification: walks from genesis to this event, validates every link
  app.get<{ Params: { id: string } }>('/verify/:id', async (req) => {
    const target = await getEventById(req.params.id);
    if (!target) throw notFound('not_found', 'no event with that id');

    const agent = await getAgentByDid(target.agent_did);
    if (!agent) {
      return { valid: false, reason: 'agent_missing' as const };
    }

    const chain = await getEventsUpToSeq({
      did: target.agent_did,
      seqNum: Number(target.seq_num),
    });

    let expectedSeq = 1;
    let expectedPrevHash = GENESIS_HASH;

    for (const evt of chain) {
      if (Number(evt.seq_num) !== expectedSeq) {
        return {
          valid: false,
          reason: 'seq_gap' as const,
          at_seq: Number(evt.seq_num),
          expected_seq: expectedSeq,
        };
      }
      if (evt.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          reason: 'broken_chain' as const,
          at_seq: Number(evt.seq_num),
        };
      }

      const payload: EventPayload = {
        agent_did: evt.agent_did,
        seq_num: Number(evt.seq_num),
        action: evt.action,
        resource: evt.resource,
        metadata: evt.metadata,
        prev_hash: evt.prev_hash,
      };

      const recomputedHash = hashEvent(payload);
      if (recomputedHash !== evt.event_hash) {
        return {
          valid: false,
          reason: 'hash_mismatch' as const,
          at_seq: Number(evt.seq_num),
        };
      }

      const sigOk = verify(agent.public_key, evt.signature, eventMessage(payload));
      if (!sigOk) {
        return {
          valid: false,
          reason: 'bad_signature' as const,
          at_seq: Number(evt.seq_num),
        };
      }

      expectedSeq = Number(evt.seq_num) + 1;
      expectedPrevHash = evt.event_hash;
    }

    return {
      valid: true as const,
      event_id: target.id,
      agent_did: target.agent_did,
      chain_length: chain.length,
    };
  });
}
