/**
 * Read the golden vectors as a second implementation, and disagree loudly.
 *
 * `tests/vectors/*.json` is generated from the Python in `src/ovpoc`, so the
 * Python consumer at `tests/test_vectors.py` pins that implementation against
 * its own future self -- real regression evidence, but a monologue. This file
 * is the other half: an independently written implementation, on a different
 * runtime, reading the same bytes. Where the two agree, the vectors mean
 * something; where they disagree, one of them is wrong and the wire is broken.
 *
 * Nothing here imports from the Python. The blind-signature library is
 * Cloudflare's, written against RFC 9474 with no knowledge of this project;
 * the hashing, Ed25519 and PSS verification are WebCrypto, which is what the
 * browser client will use in stage 1 and the nearest analogue to what Swift
 * will use in stage 3.
 *
 * Unknown schema versions are refused, not skipped -- the same rule the Python
 * consumer follows, and for the same reason: a conformance suite that quietly
 * declines to run is the failure this directory exists to prevent.
 */

import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

const subtle = webcrypto.subtle;
const HERE = dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = join(HERE, '..', '..', 'tests', 'vectors');
const SUPPORTED_SCHEMA_VERSIONS = new Set([1]);

// --------------------------------------------------------------------------
// Helpers.  Each is a claim about the wire format, written from the
// specification rather than translated from the Python.
// --------------------------------------------------------------------------

const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const unb64url = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));

/** Canonical JSON: keys sorted, tight separators, non-ASCII left as UTF-8. */
function canonicalJson(obj: Record<string, unknown>): string {
  const sorted = Object.fromEntries(
    Object.entries(obj).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  return JSON.stringify(sorted);
}

const canonicalBytes = (obj: Record<string, unknown>): Uint8Array =>
  new TextEncoder().encode(canonicalJson(obj));

const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await subtle.digest('SHA-256', data));

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** An Ed25519 seed wrapped as PKCS#8, which is what WebCrypto will import. */
function seedToPkcs8(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error(`seed is ${seed.length} bytes, expected 32`);
  const prefix = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ];
  return new Uint8Array([...prefix, ...seed]);
}

const bytesToBigInt = (b: Uint8Array): bigint =>
  b.length === 0 ? 0n : BigInt('0x' + hex(b));

// --------------------------------------------------------------------------
// Vector loading
// --------------------------------------------------------------------------

interface VectorFile {
  schema_version: number;
  suite: string;
  description?: string;
  vectors?: { name: string; input: any; expected: any }[];
  [key: string]: unknown;
}

function load(suite: string): VectorFile {
  const path = join(VECTOR_DIR, `${suite}.json`);
  const body = JSON.parse(readFileSync(path, 'utf8')) as VectorFile;
  if (!SUPPORTED_SCHEMA_VERSIONS.has(body.schema_version)) {
    throw new Error(
      `${suite}.json declares schema_version ${body.schema_version}, which this ` +
        `consumer does not understand (supported: ` +
        `${[...SUPPORTED_SCHEMA_VERSIONS].join(', ')}). Refusing rather than ` +
        `skipping.`,
    );
  }
  if (body.suite !== suite) {
    throw new Error(`${suite}.json declares suite ${body.suite}`);
  }
  return body;
}

const vectorsOf = (suite: string) => {
  const list = load(suite).vectors;
  if (!list || list.length === 0) throw new Error(`${suite}.json has no vectors`);
  return list;
};

// --------------------------------------------------------------------------
// Result accounting
// --------------------------------------------------------------------------

let passed = 0;
const failures: string[] = [];

function check(condition: boolean, what: string, detail = ''): void {
  if (condition) {
    passed += 1;
  } else {
    failures.push(detail ? `${what}\n      ${detail}` : what);
  }
}

const equal = (got: unknown, want: unknown, what: string): void =>
  check(got === want, what, `got ${String(got)}\n      want ${String(want)}`);

// --------------------------------------------------------------------------
// The groups
// --------------------------------------------------------------------------

async function canonicalJsonGroup(): Promise<void> {
  for (const v of vectorsOf('canonical-json')) {
    const text = canonicalJson(v.input);
    const bytes = new TextEncoder().encode(text);
    equal(text, v.expected.canonical_utf8, `canonical-json/${v.name}: text`);
    equal(b64url(bytes), v.expected.canonical_b64url, `canonical-json/${v.name}: b64url`);
    equal(bytes.length, v.expected.byte_length, `canonical-json/${v.name}: length`);
    equal(hex(await sha256(bytes)), v.expected.sha256, `canonical-json/${v.name}: sha256`);
  }
}

async function payloadsGroup(): Promise<void> {
  for (const v of vectorsOf('payloads')) {
    const i = v.input;
    let obj: Record<string, unknown>;
    switch (i.kind) {
      case 'auth_request':
        obj = { voter_id: i.voter_id, blinded_key: i.blinded_key_b64url };
        break;
      case 'ballot':
        obj = { selection: i.selection, adhoc_public_key: i.adhoc_public_key_b64url };
        break;
      case 'release_query':
        obj = { query: 'token-release', voter_id: i.voter_id };
        break;
      case 'denial':
        obj = { statement: 'no-token-released', voter_id: i.voter_id };
        break;
      default:
        throw new Error(`unknown payload kind ${i.kind}`);
    }
    equal(
      hex(await sha256(canonicalBytes(obj))),
      v.expected.signed_payload_sha256,
      `payloads/${v.name}`,
    );
  }
}

async function ed25519Group(keys: VectorFile): Promise<void> {
  for (const v of vectorsOf('ed25519')) {
    const seedB64 =
      v.input.key === 'wallet'
        ? (keys.ed25519_wallet_seed as string)
        : (keys.ed25519_adhoc_seed as string);
    const priv = await subtle.importKey(
      'pkcs8', seedToPkcs8(unb64url(seedB64)), { name: 'Ed25519' }, true, ['sign'],
    );
    const jwk = await subtle.exportKey('jwk', priv);
    const pub = await subtle.importKey(
      'jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, true, ['verify'],
    );

    // WebCrypto does export raw for Ed25519 public keys; where a runtime does
    // not, the trailing 32 bytes of the SPKI export are the same value, which
    // is checked here so the fallback is pinned too.
    const raw = new Uint8Array(await subtle.exportKey('raw', pub));
    const spki = new Uint8Array(await subtle.exportKey('spki', pub));
    equal(b64url(raw), v.expected.public_key_raw_b64url, `ed25519/${v.name}: raw key`);
    equal(raw.length, v.expected.public_key_raw_length, `ed25519/${v.name}: key length`);
    equal(b64url(spki.slice(-32)), b64url(raw), `ed25519/${v.name}: spki tail == raw`);

    // Ed25519 is deterministic, so the signature itself is a fixed vector.
    const msg = unb64url(v.input.message_b64url);
    const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, msg));
    equal(b64url(sig), v.expected.signature_b64url, `ed25519/${v.name}: signature`);
    check(
      await subtle.verify({ name: 'Ed25519' }, pub, unb64url(v.expected.signature_b64url), msg),
      `ed25519/${v.name}: committed signature verifies`,
    );
  }
}

async function fingerprintGroup(): Promise<void> {
  for (const v of vectorsOf('fingerprint')) {
    const spki = unb64url(v.input.spki_der_b64url);
    equal(hex(await sha256(spki)), v.expected.fingerprint_sha256, `fingerprint/${v.name}`);
  }
}

async function rsabssaGroup(keys: VectorFile): Promise<void> {
  const suite = RSABSSA.SHA384.PSS.Deterministic();
  equal(suite.toString(), 'RSABSSA-SHA384-PSS-Deterministic', 'rsabssa: suite name');

  const pub = await subtle.importKey(
    'spki', unb64url(keys.vro_public_key_spki_der as string),
    { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'],
  );
  const jwk = await subtle.exportKey('jwk', pub);
  const n = bytesToBigInt(unb64url(jwk.n as string));

  for (const v of vectorsOf('rsabssa')) {
    const msg = unb64url(v.input.message_b64url);
    const token = unb64url(v.expected.token_b64url);

    // Unblinding: s = s_c * r^-1 mod n.  Written out rather than taken from
    // the library, because this is the step the voter's device performs and
    // the one place a client could silently differ.
    const sc = bytesToBigInt(unb64url(v.expected.blind_signature_b64url));
    const rInv = BigInt(v.input.r_inv as string);
    const unblinded = ((sc * rInv) % n).toString(16)
      .padStart(v.expected.token_length * 2, '0');
    equal(unblinded, hex(token), `rsabssa/${v.name}: unblinded signature`);

    // The point of RFC 9474: a stock PSS verify, no bespoke code.
    equal(
      await suite.verify(pub, token, msg),
      v.expected.token_verifies,
      `rsabssa/${v.name}: token verifies`,
    );
    const tampered = Uint8Array.from(token);
    tampered[0] ^= 0xff;
    equal(
      await suite.verify(pub, tampered, msg),
      v.expected.tampered_token_verifies,
      `rsabssa/${v.name}: tampered token rejected`,
    );
  }
}

async function ledgerGroup(): Promise<void> {
  for (const v of vectorsOf('ledger')) {
    let prev = new Uint8Array(Buffer.from(v.input.genesis_hex, 'hex'));
    for (let i = 0; i < v.input.payloads.length; i += 1) {
      const index = Buffer.alloc(8);
      index.writeBigUInt64BE(BigInt(i));
      const material = new Uint8Array([
        ...index, ...prev, ...canonicalBytes(v.input.payloads[i]),
      ]);
      const entryHash = await sha256(material);
      equal(hex(prev), v.expected.entries[i].prev_hash_hex, `ledger/${v.name}: prev[${i}]`);
      equal(hex(entryHash), v.expected.entries[i].entry_hash_hex, `ledger/${v.name}: entry[${i}]`);
      prev = entryHash;
    }
    equal(hex(prev), v.expected.head_hex, `ledger/${v.name}: head`);
  }
}

// --------------------------------------------------------------------------

async function main(): Promise<number> {
  const keys = load('keys');
  await canonicalJsonGroup();
  await payloadsGroup();
  await ed25519Group(keys);
  await fingerprintGroup();
  await rsabssaGroup(keys);
  await ledgerGroup();

  if (failures.length > 0) {
    console.error(`\n${failures.length} check(s) failed:\n`);
    for (const f of failures) console.error(`  - ${f}`);
    console.error(
      `\n${passed} passed, ${failures.length} failed.\n` +
        `The two implementations disagree about the wire format. One of them ` +
        `is wrong; the vectors do not say which.`,
    );
    return 1;
  }
  console.log(`TypeScript consumer: ${passed} checks passed against tests/vectors/.`);
  return 0;
}

process.exitCode = await main();
