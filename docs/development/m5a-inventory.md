# M5a inventory and job read contract

A01 adds `job list`, `job inspect JOB_UUID`, and `inventory check` using the configured storage root. These commands open the existing inventory read-only: they do not create directories or databases, migrate a schema, sweep jobs, load keys, or contact PostgreSQL. Job reads first run SQLite's structural integrity check, so a damaged index is not reported as an absent job; job fingerprints must be valid and match the bound source. Before reporting a missing job, inspection also validates the other job rows. The binding is read from the inventory itself; it is not authenticated by this operation. A copied inventory can therefore be inspected without the source server or keys. Schema v1 has no job table: job reads fail rather than migrate it. The inventory is an index, not proof that an artifact exists or is trustworthy.

## JSON and ordering

`--output json job list` returns `{"jobs":[...],"audit_recorded":false}` in ascending `started_at_utc`, then ascending `job_id` order. `job inspect` returns `{"job":{...},"audit_recorded":false}`. Each job has `job_id`, `backup_id` (UUID or `null`), `source_fingerprint`, `profile_fingerprint`, `state` (`running`, `staged`, `complete`, `failed`, or `interrupted`), `started_at_utc`, `updated_at_utc`, and `operation`. Schema v2 does not store operation type, so `operation` is `null`; this must not be guessed from an artifact or event. For example:

```json
{"jobs":[{"job_id":"00000000-0000-4000-8000-000000000001","backup_id":null,"source_fingerprint":"0123456789abcdef","profile_fingerprint":"0123456789abcdef","state":"running","started_at_utc":"2026-01-01T00:00:00Z","updated_at_utc":"2026-01-01T00:00:00Z","operation":null}],"audit_recorded":false}
```

`inventory check` runs SQLite `integrity_check` and returns `{"valid":true,"schema_version":2,"source_fingerprint":"0123456789abcdef","problems":[],"audit_recorded":false}` when clean. If SQLite reports structural problems, `valid` is false, `problems` contains its diagnostics, and the command exits 1 after printing the report. A clean structural check does not authenticate rows, artifacts, or their estate provenance. These read commands do not write audit events.

## Errors and exit codes

Successful commands exit 0. Inventory-related failures exit 1, use the existing stderr `error:` cause-chain format, and include one stable category: `INVENTORY_OPEN_FAILED` for missing, inaccessible, invalid or unsupported inventory; `INVENTORY_READ_FAILED` for a failed job query or integrity check; and `JOB_NOT_FOUND` when a valid inventory has no requested job. Structural problems found by a completed check exit 1 with `INVENTORY_CORRUPT`. Configuration errors retain the existing error format; invalid CLI arguments, including malformed UUIDs, remain Clap errors with exit 2. Failures do not create or modify the inventory. Schema v1 can be structurally checked but cannot supply jobs without a separately authorized writable migration.
