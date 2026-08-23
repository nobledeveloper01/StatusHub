BEGIN;
DROP TABLE IF EXISTS api_keys;
DELETE FROM schema_migrations WHERE version = '0002_api_keys';
COMMIT;
