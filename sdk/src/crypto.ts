import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

export const GENESIS_HASH = bytesToHex(sha256(utf8ToBytes('logbook:genesis:v1')));

const DID_PREFIX = 'did:logbook:';

export type Keypair = {
  publicKey: string;
  privateKey: string;
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
  return bytesToHex(ed25519.sign(msg, privateKey));
}

export function verify(publicKeyHex: string, signatureHex: string, message: string): boolean {
  try {
    return ed25519.verify(hexToBytes(signatureHex), utf8ToBytes(message), hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

export function didFromPublicKey(publicKeyHex: string): string {
  return DID_PREFIX + base58.encode(hexToBytes(publicKeyHex));
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

export function eventMessage(payload: EventPayload): string {
  return canonicalize(payload);
}

export function hashEvent(payload: EventPayload): string {
  return bytesToHex(sha256(utf8ToBytes(eventMessage(payload))));
}

export function registrationMessage(input: {
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
