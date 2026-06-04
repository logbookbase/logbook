import { sql } from '../lib/db.js';

export type EventRow = {
  id: string;
  agent_did: string;
  seq_num: string; // bigint comes back as string from postgres-js
  action: string;
  resource: string | null;
  metadata: Record<string, unknown>;
  signature: string;
  prev_hash: string;
  event_hash: string;
  x402_tx_hash: string | null;
  created_at: Date;
};

export async function insertEvent(input: {
  agentDid: string;
  seqNum: number;
  action: string;
  resource: string | null;
  metadata: Record<string, unknown>;
  signature: string;
  prevHash: string;
  eventHash: string;
  x402TxHash: string | null;
}): Promise<EventRow> {
  const [row] = await sql<EventRow[]>`
    INSERT INTO events (
      agent_did, seq_num, action, resource, metadata,
      signature, prev_hash, event_hash, x402_tx_hash
    )
    VALUES (
      ${input.agentDid}, ${input.seqNum}, ${input.action},
      ${input.resource}, ${sql.json(input.metadata as any)},
      ${input.signature}, ${input.prevHash}, ${input.eventHash},
      ${input.x402TxHash}
    )
    RETURNING id, agent_did, seq_num, action, resource, metadata,
              signature, prev_hash, event_hash, x402_tx_hash, created_at
  `;
  if (!row) throw new Error('insert returned no row');
  return row;
}

export async function getLatestEventForAgent(
  did: string,
): Promise<EventRow | null> {
  const [row] = await sql<EventRow[]>`
    SELECT id, agent_did, seq_num, action, resource, metadata,
           signature, prev_hash, event_hash, x402_tx_hash, created_at
    FROM events
    WHERE agent_did = ${did}
    ORDER BY seq_num DESC
    LIMIT 1
  `;
  return row ?? null;
}

export async function getEventById(id: string): Promise<EventRow | null> {
  const [row] = await sql<EventRow[]>`
    SELECT id, agent_did, seq_num, action, resource, metadata,
           signature, prev_hash, event_hash, x402_tx_hash, created_at
    FROM events
    WHERE id = ${id}
  `;
  return row ?? null;
}

export async function listEventsForAgent(input: {
  did: string;
  limit: number;
  beforeSeq: number | null;
}): Promise<EventRow[]> {
  if (input.beforeSeq === null) {
    return sql<EventRow[]>`
      SELECT id, agent_did, seq_num, action, resource, metadata,
             signature, prev_hash, event_hash, x402_tx_hash, created_at
      FROM events
      WHERE agent_did = ${input.did}
      ORDER BY seq_num DESC
      LIMIT ${input.limit}
    `;
  }
  return sql<EventRow[]>`
    SELECT id, agent_did, seq_num, action, resource, metadata,
           signature, prev_hash, event_hash, x402_tx_hash, created_at
    FROM events
    WHERE agent_did = ${input.did} AND seq_num < ${input.beforeSeq}
    ORDER BY seq_num DESC
    LIMIT ${input.limit}
  `;
}

// for chain verification: get all events for an agent in order, up to and
// including the target event. used by GET /verify/:event_id.
export async function getEventsUpToSeq(input: {
  did: string;
  seqNum: number;
}): Promise<EventRow[]> {
  return sql<EventRow[]>`
    SELECT id, agent_did, seq_num, action, resource, metadata,
           signature, prev_hash, event_hash, x402_tx_hash, created_at
    FROM events
    WHERE agent_did = ${input.did} AND seq_num <= ${input.seqNum}
    ORDER BY seq_num ASC
  `;
}
