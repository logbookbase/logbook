import {
  didFromPublicKey,
  eventMessage,
  GENESIS_HASH,
  generateKeypair,
  registrationMessage,
  sign,
  type EventPayload,
} from './crypto.js';
import { HttpClient, LogbookError } from './http.js';

const DEFAULT_BASE_URL = 'https://api.logbook.bot';

export type LogbookConfig = {
  did: string;
  privateKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
};

export type Identity = {
  did: string;
  publicKey: string;
  privateKey: string;
};

export type RegisterOptions = {
  displayName: string;
  metadata?: Record<string, unknown>;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
};

export type LogOptions = {
  action: string;
  resource?: string | null;
  metadata?: Record<string, unknown>;
  prevHash?: string;
  seqNum?: number;
};

export type LogResult = {
  id: string;
  seqNum: number;
  eventHash: string;
  prevHash: string;
  createdAt: string;
};

export type VerifyResult =
  | { valid: true; eventId: string; agentDid: string; chainLength: number }
  | { valid: false; reason: string; atSeq?: number; expectedSeq?: number };

export type VerifyOptions = {
  eventId: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
};

export class Logbook {
  private readonly did: string;
  private readonly privateKey: string;
  private readonly http: HttpClient;
  private cachedPrevHash: string | null = null;
  private cachedSeqNum: number | null = null;

  constructor(config: LogbookConfig) {
    if (!/^did:logbook:/.test(config.did)) {
      throw new LogbookError(null, 'invalid_did', 'did must start with did:logbook:');
    }
    if (!/^[0-9a-f]{64}$/.test(config.privateKey)) {
      throw new LogbookError(null, 'invalid_private_key', 'private key must be 64 hex chars');
    }
    this.did = config.did;
    this.privateKey = config.privateKey;
    this.http = new HttpClient({
      baseUrl: config.baseUrl ?? DEFAULT_BASE_URL,
      timeoutMs: config.timeoutMs,
      fetch: config.fetch,
    });
  }

  // register a fresh identity. caller stores the returned privateKey securely.
  static async register(opts: RegisterOptions): Promise<Identity> {
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    const metadata = opts.metadata ?? {};
    const message = registrationMessage({
      public_key: kp.publicKey,
      display_name: opts.displayName,
      metadata,
    });
    const signature = sign(kp.privateKey, message);

    const http = new HttpClient({
      baseUrl: opts.baseUrl ?? DEFAULT_BASE_URL,
      timeoutMs: opts.timeoutMs,
      fetch: opts.fetch,
    });

    await http.post('/agents', {
      public_key: kp.publicKey,
      display_name: opts.displayName,
      metadata,
      signature,
    });

    return { did, publicKey: kp.publicKey, privateKey: kp.privateKey };
  }

  // submit a new event. signs and chains automatically.
  async log(opts: LogOptions): Promise<LogResult> {
    const { prevHash, seqNum } = await this.resolveChainState(opts);

    const payload: EventPayload = {
      agent_did: this.did,
      seq_num: seqNum,
      action: opts.action,
      resource: opts.resource ?? null,
      metadata: opts.metadata ?? {},
      prev_hash: prevHash,
    };

    const signature = sign(this.privateKey, eventMessage(payload));

    const res = await this.http.post<{
      id: string;
      seq_num: number;
      event_hash: string;
      prev_hash: string;
      created_at: string;
    }>('/events', { ...payload, signature });

    // cache for next call
    this.cachedPrevHash = res.event_hash;
    this.cachedSeqNum = res.seq_num;

    return {
      id: res.id,
      seqNum: res.seq_num,
      eventHash: res.event_hash,
      prevHash: res.prev_hash,
      createdAt: res.created_at,
    };
  }

  // anyone can verify any event without credentials.
  static async verify(opts: VerifyOptions): Promise<VerifyResult> {
    const http = new HttpClient({
      baseUrl: opts.baseUrl ?? DEFAULT_BASE_URL,
      timeoutMs: opts.timeoutMs,
      fetch: opts.fetch,
    });
    const res = await http.get<{
      valid: boolean;
      reason?: string;
      event_id?: string;
      agent_did?: string;
      chain_length?: number;
      at_seq?: number;
      expected_seq?: number;
    }>(`/verify/${encodeURIComponent(opts.eventId)}`);

    if (res.valid && res.event_id && res.agent_did && typeof res.chain_length === 'number') {
      return {
        valid: true,
        eventId: res.event_id,
        agentDid: res.agent_did,
        chainLength: res.chain_length,
      };
    }
    return {
      valid: false,
      reason: res.reason ?? 'unknown',
      atSeq: res.at_seq,
      expectedSeq: res.expected_seq,
    };
  }

  private async resolveChainState(
    opts: LogOptions,
  ): Promise<{ prevHash: string; seqNum: number }> {
    // explicit override (power-user path)
    if (opts.prevHash !== undefined && opts.seqNum !== undefined) {
      return { prevHash: opts.prevHash, seqNum: opts.seqNum };
    }

    // local cache from previous log()
    if (this.cachedPrevHash !== null && this.cachedSeqNum !== null) {
      return {
        prevHash: this.cachedPrevHash,
        seqNum: this.cachedSeqNum + 1,
      };
    }

    // fetch from server
    const res = await this.http.get<{
      events: Array<{ seq_num: number; event_hash: string }>;
    }>(`/agents/${encodeURIComponent(this.did)}/events?limit=1`);

    if (res.events.length === 0) {
      return { prevHash: GENESIS_HASH, seqNum: 1 };
    }
    const latest = res.events[0]!;
    return { prevHash: latest.event_hash, seqNum: latest.seq_num + 1 };
  }
}

export { LogbookError } from './http.js';
export {
  generateKeypair,
  didFromPublicKey,
  GENESIS_HASH,
  type EventPayload,
  type Keypair,
} from './crypto.js';
