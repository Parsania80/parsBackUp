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

### API v1 acceptance and recovery

Follow `Location` until the job reaches a terminal state. Keep the original
`Idempotency-Key` and request body when retrying a submission after a timeout
or restart. A new key is a new attempt. Restore and retention intents are
consumed at job admission. An interrupted job's consumed intent cannot be
submitted again with a new key.

Use the terminal state, `effects` and `core_job_id` together when reviewing a job.
A partial restore can leave a target that needs operator inspection. A partial
retention receipt separates completed, deleting and pending candidates. The core
recovery command handles started deletion work. Pending candidates need a new
preview and confirmation. An interrupted job with unknown effects needs
inspection before a new attempt. A failed verification can record a failure
observation in inventory, which is reported in its effects.

The [acceptance drill](../../tests/p04_api_acceptance.py) uses the built binaries,
the P03 fixture requirements and Python's `jsonschema` in the verification
environment. Run `python3 tests/p04_api_acceptance.py` to check live responses
against OpenAPI, compare API and core results, and exercise revocation, expiry,
queue, cancellation, partial effects and restart. See the
[API v1 threat review](../security/api-v1-review.md) for scope and limitations.

### Fixture operator console

Build the static console from the repository root using Node 22.23.2 and
npm 10.9.8. The build checks generated types against the committed OpenAPI
file before packaging the assets.

```bash
npm --prefix ui ci
npm --prefix ui run build
```

Serve `ui/dist` at the root of the configured HTTPS origin. Forward
`/api/v1/` to the loopback API with the public Host, Origin and session
headers intact. Preserve the upstream response status, cookie, Location
and Retry-After headers. Serve static assets directly and disable proxy
caching for API traffic. Keep sign-in request bodies and credential headers
out of proxy logs. The Node toolchain is used to build and test the console.

The [browser drill](../../tests/u02_console_drill.py) uses the built assets,
the P03 fixture requirements, OpenSSL and Chromium. Install the browser with
`cd ui && npx playwright install chromium`, or set `PARSBACKUP_BROWSER` to a
local Chromium or Chrome binary. From the repository root run
`python3 tests/u02_console_drill.py`. It starts its own HTTPS proxy, creates
disposable accounts and a backup, and checks the restored PostgreSQL row.

Open **Profiles** to see the configured profiles and the operations the API
allows for your session. To start a backup, select an eligible profile and
confirm that the data is synthetic. The console opens the job receipt when
the API accepts it. A successful receipt links to the new artifact. If a
submission loses its response, use **Retry same submission** to recover the
receipt with the original profile and idempotency key.
