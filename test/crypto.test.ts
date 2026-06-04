import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  sign,
  verify,
  didFromPublicKey,
  publicKeyFromDid,
  canonicalize,
  hashEvent,
  eventMessage,
  GENESIS_HASH,
  type EventPayload,
} from '../src/crypto/index.js';

describe('generateKeypair', () => {
  it('produces 32-byte (64 hex) public and private keys', () => {
    const kp = generateKeypair();
    expect(kp.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(kp.privateKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces different keypairs on each call', () => {
    const a = generateKeypair();
    const b = generateKeypair();
    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.privateKey).not.toBe(b.privateKey);
  });
});

describe('sign + verify', () => {
  it('round-trips a signature', () => {
    const kp = generateKeypair();
    const sig = sign(kp.privateKey, 'hello');
    expect(verify(kp.publicKey, sig, 'hello')).toBe(true);
  });

  it('rejects a tampered message', () => {
    const kp = generateKeypair();
    const sig = sign(kp.privateKey, 'hello');
    expect(verify(kp.publicKey, sig, 'hello!')).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const kp = generateKeypair();
    const sig = sign(kp.privateKey, 'hello');
    const bad = sig.slice(0, -2) + (sig.endsWith('0') ? '1' : '0');
    expect(verify(kp.publicKey, bad, 'hello')).toBe(false);
  });

  it('rejects a signature from a different keypair', () => {
    const a = generateKeypair();
    const b = generateKeypair();
    const sig = sign(a.privateKey, 'hello');
    expect(verify(b.publicKey, sig, 'hello')).toBe(false);
  });

  it('returns false on malformed hex without throwing', () => {
    expect(verify('not-hex', 'also-not-hex', 'msg')).toBe(false);
  });
});

describe('did encoding', () => {
  it('round-trips public key to did and back', () => {
    const kp = generateKeypair();
    const did = didFromPublicKey(kp.publicKey);
    expect(did.startsWith('did:logbook:')).toBe(true);
    expect(publicKeyFromDid(did)).toBe(kp.publicKey);
  });

  it('returns null for a did missing the prefix', () => {
    expect(publicKeyFromDid('did:other:abc')).toBeNull();
  });

  it('returns null for a malformed did body', () => {
    expect(publicKeyFromDid('did:logbook:not-base58!!')).toBeNull();
  });

  it('returns null when decoded bytes are wrong length', () => {
    // base58 of "hi" decodes to 1 byte
    expect(publicKeyFromDid('did:logbook:8wH')).toBeNull();
  });
});

describe('canonicalize', () => {
  it('sorts object keys', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('produces identical output for reordered equivalent objects', () => {
    const a = { x: 1, y: { c: 3, b: 2, a: 1 } };
    const b = { y: { a: 1, b: 2, c: 3 }, x: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles nested arrays and objects', () => {
    expect(canonicalize({ a: [{ b: 1, a: 2 }] })).toBe('{"a":[{"a":2,"b":1}]}');
  });

  it('handles primitives', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize('hi')).toBe('"hi"');
    expect(canonicalize(true)).toBe('true');
  });
});

describe('hashEvent', () => {
  const base: EventPayload = {
    agent_did: 'did:logbook:abc',
    seq_num: 1,
    action: 'swap',
    resource: 'ETH-USDC',
    metadata: { amount: 50 },
    prev_hash: GENESIS_HASH,
  };

  it('returns a 64-char hex hash', () => {
    expect(hashEvent(base)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic across key orderings of metadata', () => {
    const a = hashEvent({ ...base, metadata: { amount: 50, slippage: 0.5 } });
    const b = hashEvent({ ...base, metadata: { slippage: 0.5, amount: 50 } });
    expect(a).toBe(b);
  });

  it('changes when any field changes', () => {
    const original = hashEvent(base);
    expect(hashEvent({ ...base, action: 'transfer' })).not.toBe(original);
    expect(hashEvent({ ...base, seq_num: 2 })).not.toBe(original);
    expect(hashEvent({ ...base, prev_hash: 'a'.repeat(64) })).not.toBe(original);
    expect(hashEvent({ ...base, metadata: { amount: 51 } })).not.toBe(original);
  });
});

describe('signing an event payload', () => {
  it('signs the canonical message and verifies', () => {
    const kp = generateKeypair();
    const payload: EventPayload = {
      agent_did: didFromPublicKey(kp.publicKey),
      seq_num: 1,
      action: 'test',
      resource: null,
      metadata: {},
      prev_hash: GENESIS_HASH,
    };
    const msg = eventMessage(payload);
    const sig = sign(kp.privateKey, msg);
    expect(verify(kp.publicKey, sig, msg)).toBe(true);
  });
});

describe('GENESIS_HASH', () => {
  it('is a stable 64-char hex string', () => {
    expect(GENESIS_HASH).toMatch(/^[0-9a-f]{64}$/);
  });
});
