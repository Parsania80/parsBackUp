# Fixture HTTP API

The API serves PostgreSQL fixtures under `/api/v1`. Use the
[OpenAPI contract](../api/openapi-v1.json) for request and response fields.
The [API design](../development/p01-api-contract.md) defines permissions,
confirmation, retry and cancellation semantics.

The listener binds to loopback. For local development, run
`backup-api --read-only /absolute/path/api.toml`. This mode authenticates requests
and serves reads. It can create and revoke browser sessions, and it refuses job
mutations with `503 CONTAINMENT_UNAVAILABLE`. The
[systemd service](../../deploy/systemd/backup-api.service) runs
`backup-api --supervise /etc/backupctl/api.toml` and admits jobs once it verifies
containment. A system deployment requires a service-owned configuration and state
directory. P03 validation used a transient service on a fixture host.

An example API configuration is below. Point `reader_config` and `writer_config`
at existing writable fixture configurations with `access = "reader"` and
`access = "writer"`, respectively. Both must select the same store and source
estate when configured with a source. Store the API config, core configs and
credential registry as mode 0600, with protected ancestors. Create the API
control database's parent first with mode 0700. Keep control state and the registry
outside the artifact and key directories.

```toml
format = "api-config-v1"
listen = "127.0.0.1:8090"
public_origin = "http://127.0.0.1:8090"
development_http = true
control_database = "/absolute/path/state/control.sqlite"
credential_registry = "/absolute/path/credentials.json"

[[profiles]]
id = "default"
display_name = "Fixture"
writer_config = "/absolute/path/writer.toml"
reader_config = "/absolute/path/reader.toml"
operations = [
  "backup", "inspection", "verification", "restore_plan", "restore",
  "retention_preview", "retention_run", "artifact_protection",
]
```

The operator generates each credential from 32 random bytes and distributes the
base64url encoding without padding. Put the lowercase SHA-256 digest of the
**original bytes** in the registry's `token_sha256`, along with the actor UUID,
credential UUID, roles, revision and active flag. Only the clear token is sent as
`Authorization: Bearer <token>`. For browser access, the same-origin session
endpoint exchanges it for a cookie. The returned CSRF token and exact Origin are
required on cookie-authenticated mutations.

For proxied access set `development_http = false` and configure the exact HTTPS
public origin. The reverse proxy terminates TLS and preserves the public Host when
forwarding to the loopback backend. Forwarding headers do not confer identity or
affect rate limits. Login limits use the proxy's direct peer address. The browser
cookie uses `__Host-backupctl` and the Secure attribute in this mode.

Use authenticated `GET /api/v1/health` to distinguish reads from job admission.
Readiness checks the protected API configuration and its default profile binding.
Named profiles are checked on submission. The queue depth is reported separately.
A new or still-running submission returns 202 and a job URL in `Location`.
A retry of the same terminal job returns 200. Use the job URL to read its state and
result. The artifact listing exposes unverified public discovery, so confirm the
artifact through verification before using it. The admin metrics endpoint counts
durable jobs by state and reports rejected requests since listener startup.

The opt-in [HTTP drill](../../tests/p03_http_drill.py) uses the same fixture
requirements as the [worker drill](../../tests/p02_worker_drill.py): Docker, a
running user systemd manager and a C compiler. Build the two binaries with
`cargo build --locked --offline -p backup-api -p backupctl`, then run
`python3 tests/p03_http_drill.py`. The drill starts its own loopback listeners and
disposable PostgreSQL 17 fixture.
