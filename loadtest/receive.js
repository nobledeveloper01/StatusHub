/*
 * The receiver's load profile (§11.9): 10,000 webhooks/sec across six
 * providers, with p99 under 50 ms.
 *
 * The threshold is the test. A load script that reports numbers and passes
 * regardless is a script nobody looks at after the first week — so the SLO is
 * encoded as a threshold, and the run fails when it is missed.
 *
 *   k6 run loadtest/receive.js \
 *     -e BASE_URL=http://localhost:8080 \
 *     -e TENANT=acme \
 *     -e SECRETS='paystack=sk_test_…,stripe=whsec_…'
 *
 * Six providers because one provider's payload exercises one adapter, and the
 * adapters differ in the expensive place: NIBSS and Interswitch parse the
 * body before they can verify it, which is measurably more work than an HMAC
 * over raw bytes. A load test against Paystack alone would flatter the
 * numbers.
 */
import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';
const TENANT = __ENV.TENANT || 'acme';
const ENVIRONMENT = __ENV.ENV || 'test';
const TARGET_RPS = Number(__ENV.RPS || 10000);

// Receiver URLs and secrets, as `provider=token:secret` pairs.
const ENDPOINTS = (__ENV.ENDPOINTS || '')
  .split(',')
  .filter(Boolean)
  .map((pair) => {
    const [provider, rest] = pair.split('=');
    const [token, secret] = rest.split(':');
    return { provider, token, secret };
  });

if (ENDPOINTS.length === 0) {
  throw new Error(
    'ENDPOINTS is required, as provider=token:secret pairs. ' +
      'Get the tokens from `statushubctl endpoints list --tenant <slug>`.',
  );
}

const accepted = new Counter('statushub_accepted');
const rejected = new Counter('statushub_rejected');
const throttled = new Counter('statushub_throttled');
const signing = new Trend('statushub_client_signing_ms', true);

export const options = {
  // p(99) is not in k6's default summary stats, so the SLO the thresholds
  // enforce would be absent from the report a human reads — and a number
  // nobody sees is a number nobody acts on.
  summaryTrendStats: ['avg', 'p(50)', 'p(95)', 'p(99)', 'p(99.9)', 'max'],

  scenarios: {
    // Arrival rate, not virtual users. A VU-based test measures how fast the
    // system can be driven; a rate-based one measures whether it keeps up
    // with a rate somebody actually promised — which is what an SLO is.
    steady: {
      executor: 'constant-arrival-rate',
      rate: TARGET_RPS,
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: Math.ceil(TARGET_RPS / 20),
      maxVUs: Math.ceil(TARGET_RPS / 4),
    },
    // A burst on top, because providers deliver in bursts after their own
    // outages and a receiver that only meets its SLO under smooth load has
    // not met it.
    burst: {
      executor: 'ramping-arrival-rate',
      startTime: '30s',
      startRate: TARGET_RPS,
      timeUnit: '1s',
      preAllocatedVUs: Math.ceil(TARGET_RPS / 10),
      maxVUs: Math.ceil(TARGET_RPS / 2),
      stages: [
        { target: TARGET_RPS * 3, duration: '10s' },
        { target: TARGET_RPS * 3, duration: '20s' },
        { target: TARGET_RPS, duration: '10s' },
      ],
    },
  },

  thresholds: {
    // The SLO from §11.3. This is the assertion; everything else is context.
    'http_req_duration{expected_response:true}': ['p(99)<50', 'p(95)<25'],

    // A provider that gets a 500 may never retry, so a failed request is a
    // potentially lost event — a far worse outcome than a slow one.
    http_req_failed: ['rate<0.0001'],

    // 429s are backpressure working, not failure, but a run that spends its
    // time being throttled has not measured what it set out to.
    statushub_throttled: ['count<100'],
  },
};

function hmacHex(secret, data) {
  return crypto.hmac('sha256', secret, data, 'hex');
}

function hmac512Hex(secret, data) {
  return crypto.hmac('sha512', secret, data, 'hex');
}

// Each provider's real payload and real signing scheme. Simulating them all
// with one HMAC would measure a system that does not exist.
const BUILDERS = {
  paystack: (secret, i) => {
    const body = JSON.stringify({
      event: 'charge.success',
      data: {
        reference: `LOAD-${__VU}-${i}`, status: 'success', amount: 5000000,
        currency: 'NGN', paid_at: new Date().toISOString(),
        customer: { email: `load-${__VU}@example.com` },
      },
    });
    return { body, headers: { 'x-paystack-signature': hmac512Hex(secret, body) } };
  },

  flutterwave: (secret, i) => {
    const body = JSON.stringify({
      event: 'charge.completed',
      data: {
        id: `${__VU}${i}`, tx_ref: `LOAD-${__VU}-${i}`, status: 'successful',
        amount: 8134.55, currency: 'NGN', created_at: new Date().toISOString(),
      },
    });
    // Not a signature: the configured secret hash, echoed. Simulating it as
    // an HMAC would test a scheme Flutterwave does not use.
    return { body, headers: { 'verif-hash': secret } };
  },

  monnify: (secret, i) => {
    const body = JSON.stringify({
      eventType: 'SUCCESSFUL_TRANSACTION',
      eventData: {
        transactionReference: `MNFY|${__VU}|${i}`, paymentReference: `LOAD-${__VU}-${i}`,
        paymentStatus: 'PAID', currency: 'NGN', amountPaid: 50000.0,
        paidOn: new Date().toISOString().replace('T', ' ').replace('Z', ''),
      },
    });
    return { body, headers: { 'monnify-signature': hmac512Hex(secret, body) } };
  },

  nibss: (secret, i) => {
    const session = `9992402608${__VU}${i}`.padEnd(30, '0');
    const ref = `LOAD-${__VU}-${i}`;
    const amount = '50000.00';
    const body = JSON.stringify({
      sessionId: session, paymentReference: ref, amount, responseCode: '00',
      currency: 'NGN',
      transactionDateTime: new Date().toISOString().replace('T', ' ').slice(0, 19),
      originatorAccountName: 'LOAD TEST',
    });
    // Three concatenated fields, not the body. The adapter has to parse the
    // payload before it can verify it, which is the expensive path.
    return { body, headers: { 'x-nibss-signature': hmacHex(secret, session + ref + amount) } };
  },

  interswitch: (secret, i) => {
    const ref = `ISW-${__VU}-${i}`;
    const amount = '5000000';
    const body = JSON.stringify({
      transaction: {
        transactionRef: ref, paymentReference: `LOAD-${__VU}-${i}`, amount,
        responseCode: '00', currencyCode: '566',
        transactionDate: new Date().toISOString().slice(0, 19),
      },
      customer: { customerId: `LOAD-${__VU}` },
    });
    const sig = crypto.hmac('sha256', secret, ref + amount + '00', 'base64');
    return { body, headers: { 'x-interswitch-signature': sig } };
  },

  stripe: (secret, i) => {
    const body = JSON.stringify({
      id: `evt_load_${__VU}_${i}`, type: 'payment_intent.succeeded',
      created: Math.floor(Date.now() / 1000),
      data: {
        object: {
          id: `pi_load_${__VU}_${i}`, amount: 5000000, amount_received: 5000000,
          currency: 'ngn', status: 'succeeded',
          created: Math.floor(Date.now() / 1000),
          metadata: { transaction_ref: `LOAD-${__VU}-${i}` },
        },
      },
    });
    const ts = Math.floor(Date.now() / 1000);
    return {
      body,
      headers: { 'stripe-signature': `t=${ts},v1=${hmacHex(secret, `${ts}.${body}`)}` },
    };
  },
};

export default function () {
  const endpoint = ENDPOINTS[Math.floor(Math.random() * ENDPOINTS.length)];
  const build = BUILDERS[endpoint.provider];
  if (!build) {
    throw new Error(`no payload builder for provider ${endpoint.provider}`);
  }

  const start = Date.now();
  const { body, headers } = build(endpoint.secret, __ITER);
  signing.add(Date.now() - start);

  const url = `${BASE}/v1/hooks/${TENANT}/${endpoint.provider}/${ENVIRONMENT}/${endpoint.token}`;
  const res = http.post(url, body, {
    headers: { 'Content-Type': 'application/json', ...headers },
    tags: { provider: endpoint.provider },
  });

  if (res.status === 200) {
    accepted.add(1);
  } else if (res.status === 429) {
    throttled.add(1);
  } else {
    rejected.add(1);
  }

  check(res, {
    'accepted': (r) => r.status === 200,
    // The claim the SLO is about, asserted per request as well as in
    // aggregate: a p99 that passes while a handful of requests take seconds
    // is a provider timing out and retrying.
    'under 50ms': (r) => r.timings.duration < 50,
  });
}

export function handleSummary(data) {
  // Only successful requests count towards the SLO. A connection refused
  // during a crash has a duration of zero and would otherwise flatter the
  // percentile into looking like the best run ever recorded.
  const p99 =
    data.metrics['http_req_duration{expected_response:true}']?.values?.['p(99)'] ??
    data.metrics.http_req_duration?.values?.['p(99)'] ??
    0;
  const ok = data.metrics.statushub_accepted?.values?.count ?? 0;
  const bad = data.metrics.statushub_rejected?.values?.count ?? 0;
  const slow = data.metrics.statushub_throttled?.values?.count ?? 0;

  const verdict = p99 < 50
    ? `p99 ${p99.toFixed(1)}ms — inside the 50ms budget.`
    : `p99 ${p99.toFixed(1)}ms — OVER the 50ms budget. Providers will begin retrying; ` +
      `check store write latency first (§11.4).`;

  return {
    stdout: `
StatusHub receiver load test
  accepted   ${ok}
  rejected   ${bad}
  throttled  ${slow}   (429s are backpressure working, not failure)

  ${verdict}
`,
    'loadtest/summary.json': JSON.stringify(data, null, 2),
  };
}
