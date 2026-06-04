import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// the prev_hash of every agent's first event.
// hashed value of a fixed constant string.
export const GENESIS_HASH = bytesToHex(sha256(utf8ToBytes('logbook:genesis:v1')));

// did prefix used in this network.
const DID_PREFIX = 'did:logbook:';

export type Keypair = {
  publicKey: string; // hex
  privateKey: string; // hex
};

export type EventPayload = {
  agent_did: string;
  seq_num: number;
  action: string;
  resource: string | null;
  metadata: Record<string, unknown>;
  prev_hash: string;
};

export function generateKeypair(): Keypair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  };
}

export function sign(privateKeyHex: string, message: string): string {
  const privateKey = hexToBytes(privateKeyHex);
  const msg = utf8ToBytes(message);
  const signature = ed25519.sign(msg, privateKey);
  return bytesToHex(signature);
}

export function verify(
  publicKeyHex: string,
  signatureHex: string,
  message: string,
): boolean {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    const signature = hexToBytes(signatureHex);
    const msg = utf8ToBytes(message);
    return ed25519.verify(signature, msg, publicKey);
  } catch {
    return false;
  }
}

// derive a did from a public key.
// did:logbook:<base58 of public key bytes>
export function didFromPublicKey(publicKeyHex: string): string {
  const publicKey = hexToBytes(publicKeyHex);
  return DID_PREFIX + base58.encode(publicKey);
}

// recover the public key from a did, or null if malformed.
export function publicKeyFromDid(did: string): string | null {
  if (!did.startsWith(DID_PREFIX)) return null;
  try {
    const encoded = did.slice(DID_PREFIX.length);
    const bytes = base58.decode(encoded);
    if (bytes.length !== 32) return null;
    return bytesToHex(bytes);
  } catch {
    return null;
  }
}

// canonical json: sorted keys, no whitespace. needed so hash is deterministic
// across implementations and reorderings of the same payload.
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k]));
  return '{' + parts.join(',') + '}';
}

// the canonical message bytes for an event.
// used both as input to sign() and to hashEvent().
export function eventMessage(payload: EventPayload): string {
  return canonicalize(payload);
}

// content hash of an event payload. used as event_hash, and the next event's prev_hash.
export function hashEvent(payload: EventPayload): string {
  return bytesToHex(sha256(utf8ToBytes(eventMessage(payload))));
}
