BEGIN;

DROP TABLE IF EXISTS audit_checkpoints;
DROP TRIGGER IF EXISTS audit_records_no_update ON audit_records;
DROP TABLE IF EXISTS audit_records;
DROP FUNCTION IF EXISTS audit_records_are_append_only();
DROP TABLE IF EXISTS delivery_sequences;
DROP TABLE IF EXISTS deliveries;
DROP TABLE IF EXISTS canonical_events;
DROP TABLE IF EXISTS raw_events;
DROP TABLE IF EXISTS destinations;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS tenants;
DROP FUNCTION IF EXISTS current_tenant();

DELETE FROM schema_migrations WHERE version = '0001_init';

COMMIT;
