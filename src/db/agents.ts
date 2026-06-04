import { sql } from '../lib/db.js';

export type AgentRow = {
  did: string;
  public_key: string;
  display_name: string;
  metadata: Record<string, unknown>;
  created_at: Date;
};

export async function createAgent(input: {
  did: string;
  publicKey: string;
  displayName: string;
  metadata: Record<string, unknown>;
}): Promise<AgentRow> {
  const [row] = await sql<AgentRow[]>`
    INSERT INTO agents (did, public_key, display_name, metadata)
    VALUES (${input.did}, ${input.publicKey}, ${input.displayName}, ${sql.json(input.metadata as any)})
    RETURNING did, public_key, display_name, metadata, created_at
  `;
  if (!row) throw new Error('insert returned no row');
  return row;
}

export async function getAgentByDid(did: string): Promise<AgentRow | null> {
  const [row] = await sql<AgentRow[]>`
    SELECT did, public_key, display_name, metadata, created_at
    FROM agents
    WHERE did = ${did}
  `;
  return row ?? null;
}

export async function countEventsForAgent(did: string): Promise<number> {
  const [row] = await sql<{ count: string }[]>`
    SELECT COUNT(*)::text AS count FROM events WHERE agent_did = ${did}
  `;
  return row ? Number(row.count) : 0;
}
