#!/usr/bin/env node
// Independent public implementation of the sovereign_ledger format
// verifier, written against SPEC.md only — no shared code with the Rust
// crate. Zero dependencies; node:crypto only.
//
// Usage:
//   node verify.mjs <ledger.jsonl> [--seed S ...]   keyed verification
//   node verify.mjs <ledger.jsonl> --public         key-free verification
//   node verify.mjs --selftest <testvectors-dir>    conformance run
import { createHash, createHmac, createPublicKey, verify as sigVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const ZERO32 = Buffer.alloc(32);
const EVENT_FIELDS = new Set(['v', 'seq', 'ts', 'event_type', 'body', 'epoch', 'prev_hash', 'hash']);
const SEAL_FIELDS = new Set(['segment', 'start_seq', 'end_seq', 'tip_hash', 'merkle_root', 'revealed', 'prev_seal', 'scheme', 'public_key', 'signature', 'payload']);
const SEAL_EVENT = 'sovereign:seal';

class LedgerError extends Error {
  constructor(kind, msg) { super(msg); this.kind = kind; }
  toString() {
    if (this.kind === 'invalid_line') return `invalid ledger line ${this.message}`;
    if (this.kind === 'broken_chain') return `broken hash chain at line ${this.message}`;
    return `verification error: ${this.message}`;
  }
}
const invalid = (line, m) => new LedgerError('invalid_line', `${line}: ${m}`);
const broken = (line) => new LedgerError('broken_chain', line);
const verr = (m) => new LedgerError('verification', m);

const sha256 = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
const hmac256 = (key, ...p) => createHmac('sha256', key).update(Buffer.concat(p)).digest();
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };

function hexBytes(s) {
  if (typeof s !== 'string' || !/^[0-9a-fA-F]{64}$/.test(s)) return null;
  return Buffer.from(s, 'hex');
}

// SPEC §1 — strict field set: anything outside the covered fields is
// unauthenticated data and the line is invalid.
function parseEvent(line, lineNo) {
  let e;
  try { e = JSON.parse(line.trimEnd()); }
  catch (err) { throw invalid(lineNo, String(err.message || err)); }
  if (e === null || typeof e !== 'object' || Array.isArray(e)) throw invalid(lineNo, 'not an event object');
  for (const k of Object.keys(e)) {
    if (!EVENT_FIELDS.has(k)) throw invalid(lineNo, `unknown field \`${k}\``);
  }
  const num = (f, dflt) => {
    const v = e[f] ?? dflt;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) throw invalid(lineNo, `bad ${f}`);
    return v;
  };
  const str = (f) => {
    if (typeof e[f] !== 'string') throw invalid(lineNo, `bad ${f}`);
    return e[f];
  };
  return {
    v: num('v', 1), seq: num('seq'), ts: num('ts'),
    event_type: str('event_type'), body: str('body'),
    epoch: num('epoch', 0), prev_hash: str('prev_hash'), hash: str('hash'),
  };
}

function parseSeal(body, lineNo) {
  let r;
  try { r = JSON.parse(body); }
  catch (err) { throw invalid(lineNo, `malformed seal record: ${err.message || err}`); }
  if (r === null || typeof r !== 'object' || Array.isArray(r)) throw invalid(lineNo, 'malformed seal record');
  for (const k of Object.keys(r)) {
    if (!SEAL_FIELDS.has(k)) throw invalid(lineNo, `unknown seal field \`${k}\``);
  }
  return r;
}

// SPEC §3 — event MACs.
function eventHashV2(prev, seq, ts, type, body, key) {
  const t = Buffer.from(type, 'utf8'), b = Buffer.from(body, 'utf8');
  return hmac256(key, Buffer.from('SL2'), prev, u64le(seq), u64le(ts),
    u32le(t.length), t, u64le(b.length), b);
}
function eventHashV1(prev, seq, ts, type, body, key) {
  return sha256(prev, u64le(seq), u64le(ts), Buffer.from(type, 'utf8'),
    Buffer.from(body, 'utf8'), key);
}
function eventHash(v, prev, seq, ts, type, body, key) {
  if (v === 1) return eventHashV1(prev, seq, ts, type, body, key);
  if (v === 2 || v === 3) return eventHashV2(prev, seq, ts, type, body, key);
  throw verr(`unsupported entry version ${v}`);
}

// SPEC §2 — key schedule.
const baseKey = (seed) => sha256(Buffer.from('SOVEREIGN_LEDGER:'), Buffer.from(seed));
const segmentKey = (base, s) => hmac256(base, Buffer.from('sovereign-segment-v1'), u64le(s));

// SPEC §5 — RFC 6962 Merkle Tree Hash over 32-byte leaves.
function mth(d) {
  if (d.length === 0) return sha256();
  if (d.length === 1) return sha256(Buffer.from([0]), d[0]);
  let k = 1; while (k < d.length) k <<= 1; k >>= 1;
  return sha256(Buffer.from([1]), mth(d.slice(0, k)), mth(d.slice(k)));
}

// SPEC §4.3 — canonical seal payload: sorted keys, ", " / ": " separators.
function canonicalPayload(r) {
  const epochs = Object.keys(r.revealed || {}).sort((a, b) => Number(a) - Number(b));
  const revealed = epochs.map((e) => `"${e}": "${r.revealed[e]}"`).join(', ');
  return `{"end_seq": ${r.end_seq}, "merkle_root": "${r.merkle_root}", "revealed": {${revealed}}, "segment": ${r.segment}, "start_seq": ${r.start_seq}, "tip_hash": "${r.tip_hash}"}`;
}

const b64url = (buf) => buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

// SPEC §4.4 — anchor signatures.
function verifySignature(scheme, publicKey, signature, payload) {
  if (scheme === 'ed25519-file') {
    const pk = Buffer.from(publicKey, 'hex');
    const sig = Buffer.from(signature, 'hex');
    if (pk.length !== 32 || sig.length !== 64) throw verr('bad ed25519 seal material');
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(pk) }, format: 'jwk' });
    return sigVerify(null, Buffer.from(payload, 'utf8'), key, sig);
  }
  if (scheme === 'secure-enclave') {
    const point = Buffer.from(publicKey, 'base64');
    const der = Buffer.from(signature, 'base64');
    // Wrap the SEC1 point in a P-256 SPKI header for node:crypto.
    const spki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), point]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return sigVerify('sha256', Buffer.from(payload, 'utf8'), key, der);
  }
  throw verr(`seal scheme '${scheme}' is not publicly verifiable (symmetric anchor)`);
}

function lines(text) {
  return text.split('\n').map((l, i) => ({ line: l, no: i })).filter((l) => l.line.trim() !== '');
}

// SPEC §6.1 — keyed verification.
export function verifyKeyed(text, seeds) {
  const bases = seeds.map(baseKey);
  let lastHash = ZERO32, seals = 0, seg0legacy = false, expectedSeq = 1;
  for (const { line, no } of lines(text)) {
    const e = parseEvent(line, no);
    const isSeal = e.event_type === SEAL_EVENT;
    if (seals === 0 && e.v < 3) seg0legacy = true;
    if (isSeal) seals += 1;
    const base = bases[e.epoch];
    if (!base) throw verr(`no key supplied for epoch ${e.epoch}`);
    const key = e.v < 3 ? base : segmentKey(base, seals);
    const prev = hexBytes(e.prev_hash);
    if (!prev) throw invalid(no, 'bad prev_hash');
    if (!prev.equals(lastHash) || e.seq !== expectedSeq) throw broken(no);
    expectedSeq += 1;
    const expected = eventHash(e.v, lastHash, e.seq, e.ts, e.event_type, e.body, key);
    if (e.hash !== expected.toString('hex')) throw broken(no);
    lastHash = expected;
    if (isSeal) {
      // Seal reveal-honesty check (keyed-only, SPEC §6.1.5).
      const r = parseSeal(e.body, no);
      for (const [ep, hex] of Object.entries(r.revealed || {})) {
        const b = bases[Number(ep)];
        if (!b) throw verr(`no key supplied for epoch ${ep}`);
        const want = (r.segment === 0 && seg0legacy) ? b : segmentKey(b, r.segment);
        if (hex !== want.toString('hex')) {
          throw verr(`seal at line ${no} reveals a wrong key for epoch ${ep}`);
        }
      }
    }
  }
}

// SPEC §6.2 — public verification, no key material.
export function verifyPublic(text) {
  let sealsSeen = 0, lastHash = ZERO32, buffer = [], segmentStart = 1;
  let sealedEntries = 0, prevSealHash = '', anchorId = null, expectedSeq = 1;

  const fail = (no, m) => { throw verr(`line ${no}: ${m}`); };

  function finishSegment(seal, buf, no) {
    if (seal.segment !== sealsSeen) {
      fail(no, `seal out of order: claims segment ${seal.segment} but ${sealsSeen} seals seen`);
    }
    if ((seal.prev_seal || '') !== prevSealHash) {
      fail(no, 'seal prev_seal does not match the previous seal event');
    }
    if (buf.length === 0 || seal.start_seq !== segmentStart ||
        seal.end_seq !== segmentStart + buf.length - 1) {
      fail(no, `seal covers [${seal.start_seq}..${seal.end_seq}] but segment contains ${buf.length} entries from ${segmentStart}`);
    }
    let prev = hexBytes(buf[0].prev_hash);
    if (!prev) fail(no, 'bad prev_hash');
    let hash = prev;
    const leaves = [];
    for (const e of buf) {
      const keyHex = (seal.revealed || {})[String(e.epoch)];
      if (keyHex === undefined) fail(no, `seal does not reveal a key for epoch ${e.epoch}`);
      const key = hexBytes(keyHex);
      if (!key) fail(no, 'seal reveals a malformed key');
      const expected = eventHash(e.v, prev, e.seq, e.ts, e.event_type, e.body, key);
      if (e.hash !== expected.toString('hex')) fail(no, `entry seq ${e.seq} fails authentication`);
      hash = expected; prev = hash; leaves.push(hash);
    }
    if (mth(leaves).toString('hex') !== seal.merkle_root) {
      fail(no, 'seal merkle_root does not match segment entries');
    }
    if (hash.toString('hex') !== seal.tip_hash) {
      fail(no, 'seal tip_hash does not match segment tip');
    }
    if (anchorId) {
      if (anchorId.scheme !== seal.scheme || anchorId.pk !== seal.public_key) {
        fail(no, 'seal anchor identity changed mid-chain');
      }
    } else {
      anchorId = { scheme: seal.scheme, pk: seal.public_key };
    }
    const canonical = canonicalPayload(seal);
    if (seal.payload && seal.payload !== canonical) {
      fail(no, 'seal payload does not match canonical seal fields');
    }
    if (!verifySignature(seal.scheme, seal.public_key, seal.signature, canonical)) {
      fail(no, 'seal signature invalid');
    }
  }

  for (const { line, no } of lines(text)) {
    const e = parseEvent(line, no);
    const prev = hexBytes(e.prev_hash);
    if (!prev) throw invalid(no, 'bad prev_hash');
    if (!prev.equals(lastHash) || e.seq !== expectedSeq) throw broken(no);
    expectedSeq += 1;
    const h = hexBytes(e.hash);
    if (!h) throw invalid(no, 'bad hash');
    lastHash = h;
    if (e.event_type === SEAL_EVENT) {
      const seal = parseSeal(e.body, no);
      finishSegment(seal, buffer, no);
      sealedEntries += buffer.length;
      buffer = [];
      prevSealHash = e.hash;
      sealsSeen += 1;
      segmentStart = e.seq;
    }
    buffer.push(e);
  }

  return {
    sealed_entries: sealedEntries,
    unsealed_entries: buffer.length,
    segments: sealsSeen,
    scheme: anchorId ? anchorId.scheme : null,
    public_key: anchorId ? anchorId.pk : null,
  };
}

// Conformance runner: consume testvectors/expected.json.
function selftest(dir) {
  const expected = JSON.parse(readFileSync(`${dir}/expected.json`, 'utf8'));
  let pass = 0, failCount = 0;
  for (const v of expected.vectors) {
    const data = readFileSync(`${dir}/${v.file}`, 'utf8');
    const check = (name, res, expect, seg) => {
      let ok;
      if (expect === 'ok') ok = res.ok && (seg === undefined || res.value.segments === seg);
      else if (expect === 'no_seals') ok = res.ok && res.value.segments === 0;
      else if (expect === 'error') ok = !res.ok;
      else ok = !res.ok && String(res.err).includes(expect);
      if (ok) { pass += 1; return; }
      failCount += 1;
      const got = res.ok ? `ok ${JSON.stringify(res.value)}` : String(res.err);
      console.error(`FAIL ${v.file} ${name}: expected '${expect}', got '${got}'`);
    };
    const attempt = (fn) => {
      try { return { ok: true, value: fn() }; }
      catch (e) { return { ok: false, err: e instanceof LedgerError ? e.toString() : String(e) }; }
    };
    if (v.keyed) check('keyed', attempt(() => verifyKeyed(data, v.keyed.seeds)), v.keyed.expect);
    if (v.public) check('public', attempt(() => verifyPublic(data)), v.public.expect, v.public.segments);
  }
  console.log(`${pass} checks passed, ${failCount} failed`);
  process.exit(failCount ? 1 : 0);
}

// CLI.
const args = process.argv.slice(2);
if (args[0] === '--selftest') {
  selftest(args[1] || 'testvectors');
} else {
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('usage: verify.mjs <ledger.jsonl> [--seed S ...] | --public | --selftest <dir>');
    process.exit(2);
  }
  const data = readFileSync(file, 'utf8');
  const seeds = [];
  for (let i = 0; i < args.length; i++) if (args[i] === '--seed' && args[i + 1]) seeds.push(args[++i]);
  try {
    if (args.includes('--public')) {
      const r = verifyPublic(data);
      console.log(`public verification passed: ${r.sealed_entries} sealed entries in ${r.segments} segments, ${r.unsealed_entries} unsealed`);
      if (r.scheme) console.log(`anchor: ${r.scheme} (${r.public_key})`);
    } else {
      verifyKeyed(data, seeds);
      console.log(`chain valid: ${basename(file)} verifies under ${seeds.length} seed(s)`);
    }
  } catch (e) {
    console.error(`INVALID: ${e instanceof LedgerError ? e.toString() : String(e)}`);
    process.exit(1);
  }
}
