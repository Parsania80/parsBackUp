# API v1 fixture threat review

[OpenAPI v1](../api/openapi-v1.json) exposes the existing backup core through
the [HTTP API](../operations/http-api.md). This review covers the fixture
listener, private control database and operation worker. The
[core threat model](threat-model.md) covers artifact custody and native execution.

| Boundary | Control | Evidence |
|---|---|---|
| Browser and machine identity | Protected token registry with fixed-length hash comparison. A browser gets an expiring HttpOnly cookie. The SQLite session row holds the cookie hash. Exact Host and Origin checks and a session-bound CSRF token guard browser mutations. | P03 live login, logout, restart, Origin, cookie and rate checks. P04 revokes a registry entry and checks both login modes and an admitted job. |
| Roles and object ownership | Current role permissions gate submission and reads. The original actor owns the restore or retention intent. A second administrator cannot execute it. | P03 job and intent read isolation. P04 exercises cross-actor execution refusal. |
| Destructive confirmation | Admission binds the confirmation to its actor, store, profile revision, exact plan and expiry. The worker checks the binding again and core consumes the same plan digest. Admission rejection does not consume an intent. | P02 digest drift. P04 target, digest, ownership, expiry and same-key replay checks plus real restore and deletion effects. |
| Bounded execution | Body, request, actor, discovery and queue bounds apply before work is admitted. The worker uses a separate process and verifies current credential authority. systemd owns hard stops. | P03 transport and discovery bounds. P02 receipt cap and escaped-process drill. P04 queue saturation and revocation before dispatch. |
| Ambiguous effects | API receipts are durable. Cancellation and crashes preserve the safest supported effect report and do not trigger automatic re-execution. | P04 verifies a partial restore's actual target, a post-unlink deletion partition and interrupted active and queued receipts after a supervisor crash. |
| Response data | Public listings show only unverified discovery facts. Private results require scoped permission. Errors carry fixed codes, and stdout, stderr, tokens and filesystem paths stay out of responses. | P04 validates live envelopes against OpenAPI and checks a native diagnostic canary and fixture paths and tokens. |

The worker shares the service account's custody and PostgreSQL access. The registry,
store and control database sit within that trusted local operator boundary. A stolen
operator token confers its roles until revoked. A role change or token rotation
requires the registry revision to advance. A revocation blocks queued work at
dispatch. An operator must cancel work that has already started.

The proxy terminates HTTPS and preserves the configured public Host. Its access
logging must redact credentials and cookies. The loopback drill exercises the
proxy-facing Host, Origin and cookie policy. Package installation and TLS proxy
deployment on supported hosts remain part of integrated release validation.

Recovery tests exercise the documented interruption points using disposable
PostgreSQL and SQLite state. They cover a crash after durable acceptance and
during a live operation, along with the P02 case where completion cannot be
trusted until the worker's descendants are gone. Core effects and API receipts
are separate transactions, so a crash can leave an interrupted API job whose
effects need operator inspection. Idempotency survives that restart for the
retained control database.
