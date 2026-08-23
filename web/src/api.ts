// The API client.
//
// The dashboard is served by the StatusHub binary itself, from the same
// origin, so every request here is a relative path. That is deliberate: a
// dashboard on another origin would need CORS opened on an API that can
// replay payments and read every raw provider payload, and would put the
// credential through a cross-origin request. Same origin means neither.

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const KEY_STORAGE = "statushub.key";

export function storedKey(): string | null {
  return sessionStorage.getItem(KEY_STORAGE);
}

export function storeKey(key: string): void {
  // sessionStorage, not localStorage: the key is gone when the tab closes. A
  // key that outlives the session on a shared machine is a credential left
  // lying around, and this one reads every event a tenant has and can replay
  // any of them.
  sessionStorage.setItem(KEY_STORAGE, key);
}

export function clearKey(): void {
  sessionStorage.removeItem(KEY_STORAGE);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = storedKey();
  if (!key) throw new ApiError(401, "connect with an API key first");

  const resp = await fetch(path, {
    ...init,
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });

  if (resp.status === 204) return undefined as T;

  // The server's 401 is deliberately opaque — it does not say whether the key
  // is unknown, revoked, expired or for the wrong environment, because that
  // would tell a caller which of their stolen keys are real. The dashboard
  // says the one useful thing instead: the key is not being accepted.
  if (resp.status === 401) throw new ApiError(401, "the API key was not accepted");
  if (resp.status === 403) {
    throw new ApiError(403, "this key's role is not sufficient for that");
  }

  const body = await resp.json().catch(() => null);
  if (!resp.ok) {
    throw new ApiError(resp.status, body?.error ?? `${resp.status} from ${path}`);
  }
  return body as T;
}

export const get = <T>(path: string) => request<T>(path);
export const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });

// --- the shapes the API returns ---------------------------------------------

/** The canonical event, exactly as a destination receives it. */
export interface Event {
  event_id: string;
  event_type: string;
  provider: string;
  provider_event_id?: string;
  transaction_ref: string;
  status: Status;
  amount_minor: number;
  currency?: string;
  occurred_at: string;
  received_at: string;
  customer?: { ref_hash: string };
  provider_extra?: Record<string, unknown>;
  mapping_complete: boolean;
  unmapped_status?: string;
  redacted?: boolean;
}

export type Status = "pending" | "success" | "failed" | "reversed" | "abandoned" | "unknown";

export interface Delivery {
  id: number;
  destination_id: string;
  attempt: number;
  status: string;
  response_code?: number;
  response_body?: string;
  error?: string;
  duration_ms?: number;
  is_replay: boolean;
  next_retry_at?: string;
  created_at: string;
}

export interface UnknownStatus {
  provider: string;
  raw_value: string;
  count: number;
  first_seen: string;
  last_seen: string;
  sample_event_id: string;
}

export interface Endpoint {
  id: string;
  provider: string;
  environment: string;
  adapter: string;
  enabled: boolean;
  receiver_url: string;
  secret_ref: string;
  warning?: string;
  created_at: string;
  rotated_at?: string;
}

export interface Destination {
  id: string;
  name?: string;
  url: string;
  signing_secret_ref: string;
  filter: Record<string, unknown>;
  retry_schedule: string[];
  include_raw: boolean;
  schema_version: string;
  enabled: boolean;
}

export interface AdapterDescription {
  name: string;
  display_name: string;
  signature_scheme: string;
  signature_header?: string;
  known_statuses: Record<string, string>;
  supplies_event_id: boolean;
  supplies_currency: boolean;
  amount_unit: string;
  notes?: string;
  error?: string;
}

export interface AuditRecord {
  id: string;
  event_type: string;
  recorded_at: string;
  actor: { type: string; id?: string; ip?: string };
  subject: { type: string; id: string };
  corrects?: string;
}

export interface ChainProof {
  records: number;
  head_hash: string;
  intact: boolean;
  broken_at?: string;
  reason?: string;
  verified_at: string;
}

export interface ListenSession {
  id: string;
  forward?: string;
  started_at: string;
  last_seen: string;
  delivered: number;
  failed: number;
}

// --- the calls ---------------------------------------------------------------

export const events = (query: string) =>
  get<{ events: Event[]; next_cursor?: string }>(`/v1/events?${query}`);

export const event = (id: string) =>
  get<{ event: Event; raw_event_id: string; deliveries: Delivery[]; delivery_count: number }>(
    `/v1/events/${encodeURIComponent(id)}`,
  );

export const replay = (id: string) => post(`/v1/events/${encodeURIComponent(id)}/replay`);

export const unknownStatuses = () =>
  get<{ unknown_statuses: UnknownStatus[] | null; since: string }>("/v1/unknown-statuses");

export const deadLetters = () =>
  get<{ deliveries: Delivery[] | null }>("/v1/deliveries?status=dead_letter&limit=100");

export const retryDelivery = (id: number) => post(`/v1/deliveries/${id}/retry`);

export const endpoints = () => get<{ endpoints: Endpoint[] | null }>("/v1/endpoints");

export const destinations = () => get<{ destinations: Destination[] | null }>("/v1/destinations");

export const adapters = () =>
  get<{ adapters: { built_in?: boolean; description: AdapterDescription }[] }>("/v1/adapters");

export const listening = () => get<{ sessions: ListenSession[] | null }>("/v1/listen");

export const audit = () => get<{ records: AuditRecord[] | null }>("/v1/audit?limit=100");

/**
 * The chain proof.
 *
 * A broken chain is a 409, not a 200 with a flag — so anything polling it
 * sees a failure without parsing the body. That means this call has to read
 * the body on a non-2xx rather than treating it as an error, which is the one
 * place in this client where a 4xx carries the answer.
 */
export async function auditVerify(): Promise<ChainProof> {
  const key = storedKey();
  if (!key) throw new ApiError(401, "connect with an API key first");

  const resp = await fetch("/v1/audit/verify", { headers: { Authorization: `Bearer ${key}` } });
  if (resp.status === 401 || resp.status === 403) {
    throw new ApiError(resp.status, "not permitted to verify the audit chain");
  }
  return (await resp.json()) as ChainProof;
}
