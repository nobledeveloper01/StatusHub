import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { verifySignature, verifyOrThrow, sign, isTerminal, parseEvent } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(join(here, '..', '..', 'fixtures', 'signature_vectors.json'), 'utf8'),
);

// The test that matters most: this library and the Go server must agree, or
// every customer's handler rejects every delivery. The vectors are produced
// by the server's own signing code, so three implementations agreeing with
// each other but not with the server is not possible.
test('agrees with the server on every signature vector', () => {
  assert.ok(fixtures.vectors.length > 0, 'no vectors found');
  for (const v of fixtures.vectors) {
    const got = verifySignature(v.body, v.signature_header, v.secret, {
      now: v.now_unix,
      toleranceSeconds: v.tolerance_seconds,
    });
    assert.equal(got, v.should_pass, `${v.name}: ${v.description}`);
  }
});

test('names why it rejected, for your logs', () => {
  const byName = Object.fromEntries(fixtures.vectors.map((v) => [v.name, v]));
  const cases = {
    replayed: 'stale',
    tampered_body: 'bad_signature',
    wrong_secret: 'bad_signature',
    no_timestamp: 'malformed',
    no_signature: 'malformed',
    empty_header: 'no_signature',
  };
  for (const [name, reason] of Object.entries(cases)) {
    const v = byName[name];
    assert.ok(v, `fixture ${name} is missing`);
    assert.throws(
      () => verifyOrThrow(v.body, v.signature_header, v.secret, {
        now: v.now_unix, toleranceSeconds: v.tolerance_seconds,
      }),
      (err) => err.reason === reason,
      `${name} should be reported as ${reason}`,
    );
  }
});

test('round-trips its own signatures', () => {
  const body = '{"event_id":"sh_evt_1","status":"success"}';
  const header = sign(body, 'a-secret', 1786511671);
  assert.ok(verifySignature(body, header, 'a-secret', { now: 1786511671 }));
  assert.ok(!verifySignature(body, header, 'another-secret', { now: 1786511671 }));
});

test('tolerates clock drift in both directions', () => {
  // A receiver that only tolerates the past rejects every delivery from a
  // sender running slightly fast.
  const body = '{"x":1}';
  const header = sign(body, 's', 1786511671);
  assert.ok(verifySignature(body, header, 's', { now: 1786511671 - 120 }), 'sender ahead');
  assert.ok(verifySignature(body, header, 's', { now: 1786511671 + 120 }), 'sender behind');
});

test('accepts a header array, as Node gives them', () => {
  const body = '{"x":1}';
  const header = sign(body, 's', 1786511671);
  assert.ok(verifySignature(body, [header], 's', { now: 1786511671 }));
});

test('unknown is not terminal', () => {
  // Not knowing what something is includes not knowing whether it is
  // finished. A handler treating unknown as terminal stops watching a
  // transaction that is still moving.
  assert.equal(isTerminal('unknown'), false);
  assert.equal(isTerminal('pending'), false);
  for (const s of ['success', 'failed', 'reversed', 'abandoned']) {
    assert.equal(isTerminal(s), true, s);
  }
});

test('parses the canonical shape', () => {
  const v = fixtures.vectors.find((x) => x.name === 'genuine');
  const e = parseEvent(v.body);
  assert.equal(e.transaction_ref, 'TXN-2026-08-11-8842');
  assert.equal(e.status, 'success');
  assert.equal(e.amount_minor, 5000000);
  assert.equal(e.currency, 'NGN');
});
