-- agents: identities. one row per registered agent.
-- did is derived from the public key.

CREATE TABLE IF NOT EXISTS agents (
  did            TEXT PRIMARY KEY,
  public_key     TEXT NOT NULL UNIQUE,
  display_name   TEXT NOT NULL,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_created_at ON agents (created_at DESC);

-- events: signed actions, chained by prev_hash.
-- each row's event_hash is referenced by the next row's prev_hash for the same agent.
-- the first event for any agent uses sha256("logbook:genesis:v1") as prev_hash.

CREATE TABLE IF NOT EXISTS events (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_did      TEXT NOT NULL REFERENCES agents(did) ON DELETE CASCADE,
  seq_num        BIGINT NOT NULL,
  action         TEXT NOT NULL,
  resource       TEXT,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  signature      TEXT NOT NULL,
  prev_hash      TEXT NOT NULL,
  event_hash     TEXT NOT NULL UNIQUE,
  x402_tx_hash   TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT events_seq_unique UNIQUE (agent_did, seq_num)
);

CREATE INDEX IF NOT EXISTS idx_events_agent_did_seq ON events (agent_did, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_events_created_at    ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_event_hash    ON events (event_hash);
