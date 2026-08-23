# Migrations

The files here are the source of truth. They are copied into
`internal/migrate/sql/` at build preparation time and embedded into the
binary, so the schema a binary expects and the schema it can create are always
the same artefact — a container shipped without its migrations directory would
otherwise start, connect, and fail on its first query.

Run `make sync-migrations` after adding or editing one.

Every change comes in a pair: `NNNN_name.up.sql` and `NNNN_name.down.sql`.
A down that does not exist is a change that cannot be rolled back, which is a
decision worth making deliberately rather than by omission.

Migrations are reviewed as a separate artefact from code (§11.8) and applied
before the new binary rolls out, which means every migration must leave the
*previous* version of the code still working. In practice: add columns
nullable or with defaults, add indexes concurrently in production, and split a
rename into add-write-both-backfill-drop across two releases.
