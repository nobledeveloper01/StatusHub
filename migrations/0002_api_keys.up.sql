-- API keys, persisted (§8.2).
--
-- Until now keys lived in process memory, which meant a key issued by the CLI
-- did not exist to the server, and every key vanished on restart. Both are
-- the kind of gap that only shows up the first time somebody tries to use the
-- thing end to end.
--
-- What is stored here is deliberately useless to anyone who obtains it: an
-- Argon2id hash with its parameters, and a short plaintext prefix that exists
-- only so a presented key can be looked up in one index scan rather than by
-- hashing against every row.

BEGIN;

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The lookup key. Unique, because two keys sharing a prefix would make
    -- resolution ambiguous — with 120 bits of entropy after the prefix that
    -- is effectively impossible, and "effectively impossible" is not a reason
    -- to resolve it wrongly if it happens.
    prefix       TEXT NOT NULL UNIQUE,

    -- Argon2id, with the cost parameters encoded alongside so they can be
    -- raised later without invalidating every key already issued.
    hash         TEXT NOT NULL,

    environment  TEXT NOT NULL CHECK (environment IN ('test','live')),
    role         TEXT NOT NULL CHECK (role IN ('owner','engineer','support','read_only')),
    name         TEXT NOT NULL DEFAULT '',

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_tenant ON api_keys (tenant_id, created_at DESC);

-- Revocation must take effect immediately, so the live set is what the
-- authentication path reads.
CREATE INDEX idx_api_keys_live ON api_keys (prefix) WHERE revoked_at IS NULL;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Authentication resolves a key *before* a tenant is known, so the lookup
-- runs as a role with no session tenant set — which the policy's NULL branch
-- permits. Once authenticated, every other query is scoped.
CREATE POLICY tenant_isolation ON api_keys
    USING (current_tenant() IS NULL OR tenant_id = current_tenant());

INSERT INTO schema_migrations (version) VALUES ('0002_api_keys')
    ON CONFLICT (version) DO NOTHING;

COMMIT;
