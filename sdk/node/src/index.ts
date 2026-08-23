/**
 * @statushub/node — the StatusHub client library.
 *
 * Deliberately small. The integration StatusHub sells is a URL change, so
 * this library's job is not to be a framework: it is to make the one piece of
 * code you *do* have to write impossible to get wrong.
 *
 * That piece is signature verification. It is the most commonly botched part
 * of any webhook integration — somebody compares two hex strings with `===`,
 * which leaks the position of the first differing byte through timing, and an
 * attacker who can measure that can forge a signature a byte at a time.
 * Nobody notices, because the handler works perfectly.
 *
 * Apache-2.0, so integrating needs no lawyer.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

/** The header StatusHub signs deliveries with. */
export const SIGNATURE_HEADER = 'x-statushub-signature';

/** Headers StatusHub sets on every delivery. */
export const EVENT_ID_HEADER = 'x-statushub-event-id';
export const REPLAY_HEADER = 'x-statushub-replay';
export const SCHEMA_VERSION_HEADER = 'x-statushub-schema-version';
export const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';

/**
 * How far a delivery's timestamp may be from now, in seconds.
 *
 * Five minutes each way. Symmetric, because clocks drift in both directions
 * and a receiver that only tolerates the past rejects every delivery from a
 * sender running slightly fast.
 */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/** Why a signature was rejected. Distinguished for your logs; the response to
 *  the caller should be a bare 401 either way. */
export type VerifyFailure =
  | 'no_signature'
  | 'malformed'
  | 'stale'
  | 'bad_signature';

export class VerificationError extends Error {
  readonly reason: VerifyFailure;
  constructor(reason: VerifyFailure, message: string) {
    super(message);
    this.name = 'VerificationError';
    this.reason = reason;
  }
}

export interface VerifyOptions {
  /** Seconds of clock tolerance. Defaults to five minutes. */
  toleranceSeconds?: number;
  /** Unix seconds to treat as "now". For tests. */
  now?: number;
}

/**
 * Verify a delivery's signature, returning true or false.
 *
 * Pass the **raw** request body, before any JSON parsing. A round trip
 * through a parser changes the bytes — reordered keys, different whitespace,
 * numbers reformatted — and the signature covers the bytes that were sent.
 * In Express that means `express.raw({ type: 'application/json' })`, not
 * `express.json()`.
 */
export function verifySignature(
  body: string | Buffer,
  header: string | string[] | undefined,
  secret: string,
  options: VerifyOptions = {},
): boolean {
  try {
    verifyOrThrow(body, header, secret, options);
    return true;
  } catch {
    return false;
  }
}

/** Verify, throwing a VerificationError that names the reason. */
export function verifyOrThrow(
  body: string | Buffer,
  header: string | string[] | undefined,
  secret: string,
  options: VerifyOptions = {},
): void {
  const raw = Array.isArray(header) ? header[0] : header;
  if (!raw || raw.trim() === '') {
    throw new VerificationError('no_signature', 'no signature header');
  }

  let timestamp = 0;
  const signatures: string[] = [];
  for (const part of raw.split(',')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key === 't') {
      const parsed = Number.parseInt(value, 10);
      if (!Number.isFinite(parsed)) {
        throw new VerificationError('malformed', `timestamp "${value}" is not an integer`);
      }
      timestamp = parsed;
    } else if (key === 'v1' && value !== '') {
      signatures.push(value);
    }
    // Unknown elements are ignored rather than rejected. StatusHub may add
    // one, and a handler that refuses an unfamiliar element stops working the
    // day it does.
  }

  if (timestamp === 0) throw new VerificationError('malformed', 'no timestamp in the header');
  if (signatures.length === 0) throw new VerificationError('malformed', 'no v1 signature in the header');

  // Checked before the digest. A captured delivery replayed tomorrow carries
  // a genuine signature; only the window stops it.
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (Math.abs(now - timestamp) > tolerance) {
    throw new VerificationError('stale', `signature is ${Math.abs(now - timestamp)}s away from now`);
  }

  const payload = Buffer.concat([
    Buffer.from(`${timestamp}.`, 'utf8'),
    // The separator matters: without it, timestamp 1754903662 with body "x"
    // and timestamp 175490366 with body "2x" sign identically.
    typeof body === 'string' ? Buffer.from(body, 'utf8') : body,
  ]);
  const expected = createHmac('sha256', secret).update(payload).digest();

  // Several v1 values appear during a secret rotation, and any one matching
  // is enough — that is what lets you rotate on your own schedule.
  for (const candidate of signatures) {
    let presented: Buffer;
    try {
      presented = Buffer.from(candidate.toLowerCase(), 'hex');
    } catch {
      continue;
    }
    // timingSafeEqual throws on a length mismatch, which would itself leak
    // whether the length was right — so the length is checked separately and
    // the comparison only runs on equal-length buffers.
    if (presented.length === expected.length && timingSafeEqual(presented, expected)) {
      return;
    }
  }
  throw new VerificationError('bad_signature', 'no signature in the header matched the body');
}

/** The canonical outcome. A closed set of six. */
export type Status =
  | 'pending'
  | 'success'
  | 'failed'
  | 'reversed'
  | 'abandoned'
  /**
   * StatusHub did not recognise the provider's value and refused to guess.
   *
   * Handle it explicitly. The tempting shortcut is to treat it as a failure,
   * which is exactly the mistake this value exists to prevent: an unmapped
   * SUCCESS treated as a failure reverses a payment that completed.
   * `unmapped_status` carries the provider's own string.
   */
  | 'unknown';

/** The canonical event. One shape, whichever provider sent it. */
export interface StatusHubEvent {
  event_id: string;
  event_type: string;
  provider: string;
  provider_event_id?: string;
  transaction_ref: string;
  status: Status;

  /**
   * Always integer minor units, in the currency's own exponent — kobo for
   * NGN, cents for USD, yen for JPY. Never a float, never a decimal string,
   * never a unit you have to look up.
   */
  amount_minor: number;
  currency?: string;

  occurred_at: string;
  received_at: string;

  /** Pseudonymised. There is no name, email or phone here and there never
   *  will be. */
  customer?: { ref_hash: string };

  /** Every field StatusHub did not map, so you are never blocked waiting for
   *  them to add one. */
  provider_extra?: Record<string, unknown>;

  /** False when StatusHub was unsure about a field. Worth branching on. */
  mapping_complete: boolean;

  unmapped_status?: string;
  redacted?: boolean;
  raw?: unknown;
}

/** Whether a transaction can still change. `unknown` is not terminal: not
 *  knowing what something is includes not knowing whether it is finished. */
export function isTerminal(status: Status): boolean {
  return status !== 'pending' && status !== 'unknown';
}

/** Parse a delivery body. */
export function parseEvent(body: string | Buffer): StatusHubEvent {
  return JSON.parse(typeof body === 'string' ? body : body.toString('utf8')) as StatusHubEvent;
}

/**
 * Sign a body. Exported for your own tests: it is how you build a request
 * your handler will accept, without needing StatusHub running.
 */
export function sign(body: string | Buffer, secret: string, atUnix?: number): string {
  const timestamp = atUnix ?? Math.floor(Date.now() / 1000);
  const payload = Buffer.concat([
    Buffer.from(`${timestamp}.`, 'utf8'),
    typeof body === 'string' ? Buffer.from(body, 'utf8') : body,
  ]);
  const digest = createHmac('sha256', secret).update(payload).digest('hex');
  return `t=${timestamp},v1=${digest}`;
}
