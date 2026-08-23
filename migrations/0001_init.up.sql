-- StatusHub initial schema (§5).
--
-- Three things here are load-bearing and worth reading before changing:
--
--   1. raw_events is range-partitioned by month. It is the fastest-growing
--      table in the system and the only one whose rows cannot be regenerated
--      from anywhere else. Partitioning makes retention a DROP PARTITION
--      instead of a DELETE that leaves the table bloated and the autovacuum
--      running for a week.
--
--   2. Row Level Security is on every tenant-owned table. It is the third
--      layer of §8.1 and exists precisely for the query that forgets to
--      scope: with RLS on, that query returns nothing instead of returning
--      someone else's payments.
--
--   3. audit_records has no UPDATE and no DELETE path. Not by convention —
--      by a trigger that raises regardless of role, and by grants that do not
--      include them.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- tenants --

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The slug appears in every receiver URL, so it has to survive being typed
-- into a provider's dashboard by hand: lower case, no spaces, no surprises.
ALTER TABLE tenants ADD CONSTRAINT tenants_slug_shape
    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$');

-- -------------------------------------------------------------- endpoints --

CREATE TABLE endpoints (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    environment          TEXT NOT NULL CHECK (environment IN ('test','live')),
    receiver_token       TEXT NOT NULL UNIQUE,
    secret_ref           TEXT NOT NULL,
    adapter_name         TEXT NOT NULL,
    adapter_config       JSONB,
    allowed_source_cidrs TEXT[] NOT NULL DEFAULT '{}',
    enabled              BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at           TIMESTAMPTZ
);

-- One live endpoint per provider per tenant. Two would mean two receiver URLs
-- for the same provider, and an operator with no way to tell which one the
-- provider is actually calling.
CREATE UNIQUE INDEX idx_endpoints_tenant_provider_env
    ON endpoints (tenant_id, provider, environment);

-- The receiver's hot lookup. Covering, so resolving a URL is an index-only
-- scan and the 50 ms budget is spent on the insert instead.
CREATE INDEX idx_endpoints_token ON endpoints (receiver_token) INCLUDE (tenant_id, provider, environment, enabled);

-- ----------------------------------------------------------- destinations --

CREATE TABLE destinations (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT NOT NULL DEFAULT '',
    url                 TEXT NOT NULL,
    signing_secret_ref  TEXT NOT NULL,
    filter              JSONB NOT NULL DEFAULT '{}',
    retry_policy        JSONB NOT NULL DEFAULT '{}',
    include_raw         BOOLEAN NOT NULL DEFAULT false,
    -- Empty means the destination predates versioning and receives the
    -- original shape. Never defaulted to the newest: silently moving an
    -- existing handler onto a new payload is what versioning prevents.
    schema_version      TEXT NOT NULL DEFAULT '',
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_destinations_tenant ON destinations (tenant_id) WHERE enabled;

-- HTTPS is enforced in the database as well as in the application. The
-- application check is the one that produces a good error message; this one is
-- the one that holds when a future code path forgets to call it.
ALTER TABLE destinations ADD CONSTRAINT destinations_https_only
    CHECK (url LIKE 'https://%');

-- ------------------------------------------------------------- raw events --

CREATE TABLE raw_events (
    id               TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    endpoint_id      TEXT NOT NULL,
    provider         TEXT NOT NULL,
    headers          JSONB NOT NULL DEFAULT '{}',
    body             BYTEA NOT NULL,
    body_sha256      TEXT NOT NULL,
    source_ip        INET,
    signature_valid  BOOLEAN NOT NULL,
    signature_error  TEXT NOT NULL DEFAULT '',
    -- True when card data was found and replaced before storage (§8.4). The
    -- body_sha256 above still covers the bytes that arrived, so what was
    -- received is provable even though it is not retained.
    redacted         BOOLEAN NOT NULL DEFAULT false,
    redaction_note   TEXT NOT NULL DEFAULT '',
    normalised_at    TIMESTAMPTZ,
    canonical_id     TEXT,
    failure_reason   TEXT,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The partition key has to be in the primary key. Sorting on id first
    -- keeps it useful as a lookup key regardless.
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

CREATE INDEX idx_raw_tenant_time ON raw_events (tenant_id, received_at DESC);

-- The normaliser's work queue. A partial index rather than a full one: the
-- pending set is tiny and transient, and indexing the whole table to find it
-- would cost a write on every event to serve a query that matches almost none
-- of them.
CREATE INDEX idx_raw_pending ON raw_events (received_at)
    WHERE signature_valid AND normalised_at IS NULL AND failure_reason IS NULL;

CREATE INDEX idx_raw_signature_failures ON raw_events (tenant_id, endpoint_id, received_at DESC)
    WHERE NOT signature_valid;

CREATE INDEX idx_raw_body_hash ON raw_events (tenant_id, provider, body_sha256);

-- A default partition catches anything outside the ranges created ahead of
-- time. It exists so that a missed partition-creation job degrades into a
-- slow query rather than into refusing to store a provider's event — the one
-- failure this system is built to never have.
CREATE TABLE raw_events_default PARTITION OF raw_events DEFAULT;

-- ------------------------------------------------------- canonical events --

CREATE TABLE canonical_events (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    raw_event_id       TEXT NOT NULL,
    provider           TEXT NOT NULL,
    provider_event_id  TEXT,
    event_type         TEXT NOT NULL,
    transaction_ref    TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('pending','success','failed','reversed','abandoned','unknown')),
    amount_minor       BIGINT,
    currency           CHAR(3),
    customer_ref_hash  TEXT,
    provider_extra     JSONB NOT NULL DEFAULT '{}',
    unmapped_status    TEXT NOT NULL DEFAULT '',
    occurred_at        TIMESTAMPTZ NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL,
    normalised_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    mapping_complete   BOOLEAN NOT NULL DEFAULT true
);

-- Provider-level deduplication, enforced by the database rather than by a
-- check-then-insert in the application. Two receiver replicas processing a
-- provider's retry at the same moment would both pass a check and both write;
-- a unique index is the only version of this that is actually correct.
--
-- NULLS NOT DISTINCT would collapse every event from a provider that supplies
-- no event ID into one row, so the constraint deliberately only binds when an
-- ID is present. Providers without one dedupe on the body hash instead.
CREATE UNIQUE INDEX idx_canon_provider_event
    ON canonical_events (tenant_id, provider, provider_event_id)
    WHERE provider_event_id IS NOT NULL;

CREATE INDEX idx_canon_txnref  ON canonical_events (tenant_id, transaction_ref, occurred_at);
CREATE INDEX idx_canon_status  ON canonical_events (tenant_id, status, occurred_at DESC);
CREATE INDEX idx_canon_recent  ON canonical_events (tenant_id, id DESC);
CREATE INDEX idx_canon_raw     ON canonical_events (raw_event_id);

-- Backs the "unknown statuses awaiting mapping" view. Partial, because the
-- rows it wants are a rounding error against the whole table.
CREATE INDEX idx_canon_unmapped ON canonical_events (tenant_id, provider, unmapped_status, normalised_at DESC)
    WHERE unmapped_status <> '';

CREATE INDEX idx_canon_incomplete ON canonical_events (tenant_id, normalised_at DESC)
    WHERE NOT mapping_complete;

-- ------------------------------------------------------------- deliveries --

CREATE TABLE deliveries (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    event_id        TEXT NOT NULL REFERENCES canonical_events(id) ON DELETE CASCADE,
    destination_id  TEXT NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
    transaction_ref TEXT NOT NULL,
    shard           INTEGER NOT NULL,
    sequence        BIGINT NOT NULL,
    attempt         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL CHECK (status IN ('pending','in_flight','succeeded','failed','dead_letter')),
    response_code   INTEGER,
    response_body   TEXT,
    error           TEXT,
    duration_ms     INTEGER,
    is_replay       BOOLEAN NOT NULL DEFAULT false,
    next_retry_at   TIMESTAMPTZ,
    leased_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The dispatcher's claim query. Partial on the non-terminal states, ordered
-- the way the claim reads it, so leasing work is an index range scan rather
-- than a scan of every delivery ever made.
CREATE INDEX idx_deliveries_due ON deliveries (shard, next_retry_at, sequence)
    WHERE status IN ('pending','failed','in_flight');

CREATE INDEX idx_deliveries_event  ON deliveries (tenant_id, event_id);
CREATE INDEX idx_deliveries_dlq    ON deliveries (tenant_id, created_at DESC) WHERE status = 'dead_letter';
CREATE INDEX idx_deliveries_dest   ON deliveries (tenant_id, destination_id, created_at DESC);

-- Ordering within a transaction reference. Allocated at enqueue so a retry
-- cannot be overtaken by an event queued after it.
CREATE TABLE delivery_sequences (
    tenant_id       TEXT NOT NULL,
    transaction_ref TEXT NOT NULL,
    last_sequence   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, transaction_ref)
);

-- ---------------------------------------------------------------- audit ----

CREATE TABLE audit_records (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor        JSONB NOT NULL DEFAULT '{}',
    subject      JSONB NOT NULL DEFAULT '{}',
    payload      JSONB NOT NULL DEFAULT '{}',
    corrects     TEXT,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL,

    -- Sequence is per tenant and gapless, so a missing record is detectable
    -- even before the hash chain is walked.
    seq          BIGINT NOT NULL
);

CREATE UNIQUE INDEX idx_audit_tenant_seq ON audit_records (tenant_id, seq);
CREATE INDEX idx_audit_tenant_time ON audit_records (tenant_id, recorded_at DESC);
CREATE INDEX idx_audit_subject ON audit_records (tenant_id, (subject->>'id'));

-- Immutability, enforced (§8.3). The application role is not granted UPDATE
-- or DELETE on this table, and this trigger refuses them anyway — including
-- for a superuser, whose mistakes are the ones nothing else catches.
CREATE OR REPLACE FUNCTION audit_records_are_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only: % on % is refused', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Corrections are appended with a corrects reference, never applied in place.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_records_no_update
    BEFORE UPDATE OR DELETE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_are_append_only();

CREATE TABLE audit_checkpoints (
    tenant_id     TEXT NOT NULL,
    checkpointed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    through_seq   BIGINT NOT NULL,
    head_hash     TEXT NOT NULL,
    signature     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, through_seq)
);

-- ---------------------------------------------------------- row security --

-- Layer three of §8.1. The session variable is set from the authenticated
-- tenant on every connection checkout; a query that forgets its WHERE clause
-- returns nothing rather than returning everything.
ALTER TABLE endpoints        ENABLE ROW LEVEL SECURITY;
ALTER TABLE destinations     ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_events       ENABLE ROW LEVEL SECURITY;
ALTER TABLE canonical_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE deliveries       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_records    ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION current_tenant() RETURNS TEXT AS $$
    SELECT nullif(current_setting('statushub.tenant_id', true), '');
$$ LANGUAGE sql STABLE;

-- Each policy allows a row when it belongs to the session's tenant, or when
-- no tenant is set at all. The second case is for the dispatcher and the
-- normaliser, which legitimately work across tenants and connect as a role
-- that never has the variable set — expressing that as an explicit branch is
-- clearer than two sets of policies.
CREATE POLICY tenant_isolation ON endpoints
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON destinations
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON raw_events
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON canonical_events
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON deliveries
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());
CREATE POLICY tenant_isolation ON audit_records
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());

INSERT INTO schema_migrations (version) VALUES ('0001_init')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
