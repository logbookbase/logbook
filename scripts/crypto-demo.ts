import {
  generateKeypair,
  sign,
  verify,
  didFromPublicKey,
  hashEvent,
  eventMessage,
  GENESIS_HASH,
  type EventPayload,
} from '../src/crypto/index.js';

// generate identity
const kp = generateKeypair();
const did = didFromPublicKey(kp.publicKey);

console.log('identity');
console.log('  did:        ', did);
console.log('  public key: ', kp.publicKey);
console.log('  (private key withheld)');
console.log();

// build the first event
const event1: EventPayload = {
  agent_did: did,
  seq_num: 1,
  action: 'swap',
  resource: 'ETH-USDC',
  metadata: { amount: 0.5, slippage_bps: 50 },
  prev_hash: GENESIS_HASH,
};

const msg1 = eventMessage(event1);
const sig1 = sign(kp.privateKey, msg1);
const hash1 = hashEvent(event1);

console.log('event 1');
console.log('  canonical message:', msg1);
console.log('  signature:        ', sig1);
console.log('  event_hash:       ', hash1);
console.log('  verify():         ', verify(kp.publicKey, sig1, msg1));
console.log();

// chain a second event using the first one's hash
const event2: EventPayload = {
  agent_did: did,
  seq_num: 2,
  action: 'transfer',
  resource: '0xabc...',
  metadata: { amount: 10 },
  prev_hash: hash1,
};

const msg2 = eventMessage(event2);
const sig2 = sign(kp.privateKey, msg2);
const hash2 = hashEvent(event2);

console.log('event 2 (chained to event 1)');
console.log('  prev_hash:        ', event2.prev_hash);
console.log('  signature:        ', sig2);
console.log('  event_hash:       ', hash2);
console.log('  verify():         ', verify(kp.publicKey, sig2, msg2));
console.log();

// tamper detection
const tampered = { ...event1, metadata: { amount: 999 } };
const tamperedMsg = eventMessage(tampered);
console.log('tamper detection');
console.log('  original signature verifies tampered event?',
  verify(kp.publicKey, sig1, tamperedMsg));
console.log('  recomputed hash of tampered event matches original?',
  hashEvent(tampered) === hash1);
