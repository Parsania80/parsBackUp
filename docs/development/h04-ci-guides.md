# H04 CI and operating reference contract

Recorded before implementation on 2026-11-16, after reviewed H03 checkpoint `cb34f5e`. This increment adds CI definitions/tooling and current-behavior references. It changes no runtime/artifact/plan/schema, operating flow or production authorization. H05 readability review and V01–V03 remain required.

## CI ownership

Three GitHub-hosted Ubuntu 24.04 jobs cover fast checks, existing native suites and the H03 package drill. Fast checks run on pull requests/push/manual dispatch. Native suites and privileged package tests run only on main push/manual dispatch using disposable hosted runners, never self-hosted machines or pull_request_target. Tokens are contents-read only; checkout credentials are not persisted; actions use verified commit SHAs. Logs/artifacts contain synthetic fixtures only and have a short retention. No release upload, deployment or secret is configured.

Pin the existing Rust version, action revisions, actionlint/rage tool versions and PostgreSQL/base images in a reviewed input manifest. Pull digest-qualified images then tag them to the existing harness names, preserving every harness's actual assertions and all-major loops. H03 receives the pinned base images through Docker build arguments and reuses its existing --reuse-images entry point. Apt and hosted-runner patch packages remain upstream-resolved and recorded; this is not full hermetic/reproducible CI. Registry/tool provisioning failure fails the job, with no mutable-tag fallback. Pin updates require explicit review and rerun affected suites.

`ci/run.sh` is the same entry point locally and in CI. Fast mode checks formatting, strict Clippy, workspace tests, documentation/embedded syntax, current report examples against actual CLI output and workflow lint. Native mode selects only an enumerated existing test script, each in its own job/checkout so builds cannot overlap shared binaries; all supported-major loops remain intact. Package mode builds isolated pinned-base test images then invokes the actual H03 release/package/service drill. Cargo fetch is explicit provisioning before locked/offline gates. Capture input digests before and after execution and preserve logs/checksums without archiving private fixture directories or keys. Hosted GitHub status cannot be claimed until the workflows are pushed and run; local execution/lint is separate evidence.

## Operating references

New references describe delivered fixture installation/invocation, versioned config/access/resource limits, reports/errors and effects, native matching/auth, independent verifier/recovery-key custody, timer opt-in/stop/deadlines, preservation on removal, stale-backup policy, consistent store/inventory copying and isolated recovery validation. Use clear reference tables and illustrative commands, not a new authoritative flow. Existing controlled operating documents remain unchanged.

Show complete structural reader/inventory examples and real envelope examples, with command-data ownership links and report limitations. Configuration check is structural only. Versioned writable offline backup/retention commands still refuse; do not present a writer/read-only toggle as an access workaround. Discovery/signature/checksum/archive levels and restored-row checks have distinct meanings. Never claim native restore success alone proves data correctness, read-only media proves copy consistency, or an SQLite-only copy proves a consistent artifact store.

A consistent live-store backup/export operation is not implemented. Reference copying only after all writers/manual/service/native owners are stopped and the entire store is quiescent; preserve inventory, lifecycle/history, markers and complete signed components together. A read-only snapshot must be independently consistent and have private external scratch for decryption. Crashed scratch may contain plaintext; operator inspection precedes explicit maintenance. Recovery uses a fresh isolated target and identity/verifier without signer, maintenance DB after source loss, exact target/plan confirmation and independent row/schema/security validation. No automatic destructive cleanup or retry, new alerting daemon, remote copy workflow or off-host guarantee is added.

## Acceptance

Review/lint all workflows and scripts; run fast checks with the pinned toolchain, meaningful actual-CLI report examples and documentation/syntax checks. Run a representative existing native all-major suite through the new wrapper, and exercise the package wrapper on both target userspaces. Record which old suite results remain historical and which jobs have not run on GitHub. Verify frozen inputs, preservation of existing flows/runtime/format/production guard and append-only audit. Completion does not resolve H03's observed selective-public restore conflict, production command/plan availability, least-privilege content matrix or release licensing/security decisions.

Primary CI references: [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [secure use](https://docs.github.com/en/actions/reference/security/secure-use), [actionlint usage](https://github.com/rhysd/actionlint/blob/v1.7.7/docs/usage.md). Actual local/hosted acceptance is recorded in the roadmap, not inferred from these references.

## CI invocation reference

Local prerequisites are Linux amd64, a non-root operator with Docker access, Rustup, Python 3.11+, Bash/Git and Go for actionlint provisioning. Native syscall/crash suites additionally require strace; signing interoperability requires stock rage and rage-keygen 0.12.1. Package acceptance requires Docker private writable cgroup namespaces/privileged isolated containers and the local registry/toolchain mounts consumed by H03. These commands only operate fixture/test resources and ignored target output. Do not run them on a shared self-hosted CI runner carrying secrets or unrelated deployment authority.

| Reference command | Meaning/precondition |
|---|---|
| `rustup toolchain install 1.97.1 --profile minimal --component rustfmt --component clippy` | Provision exact product toolchain/components; rust-toolchain.toml selects it. |
| `cargo fetch --locked` | Explicit network/cache provisioning before offline tests. |
| `python3 ci/prepare.py lint` | Build actionlint v1.7.7 under target/ci-tools through Go module checksum verification. Host Go compiler is a build prerequisite, not a product dependency. |
| `bash ci/run.sh fast` | Format/strict-Clippy/workspace/reference/report/workflow checks with locked/offline Cargo. |
| `python3 ci/prepare.py native` | Pull only recorded digest-qualified PG16/17/18, retag for unchanged harnesses. |
| `cargo install rage --version 0.12.1 --locked` | Stock signing interoperability tool provisioning, needed for m4b_docker_smoke only; not artifact-reader compatibility. |
| `bash ci/run.sh native h02_cancellation_drill` | Selected enumerated suite with its complete all-major loop; matrix lists the other existing suite names. Bootstrap drill is host-only. |
| `python3 ci/prepare.py package` | Pull pinned target bases and build isolated Ubuntu/Debian fixture images using existing H03 Dockerfile. Apt patch resolutions remain recorded dynamic inputs. |
| `bash ci/run.sh package` | H03 locked release build, repeated-byte package and actual two-target manager/lifecycle/recovery drill. |

GitHub-hosted Ubuntu24.04/Python/Go/Docker/apt patches evolve; input pins constrain Rust/actions/tool release versions/base images, not the entire hosted machine. Each job's logs and source input digests are under target/ci-logs; successful package output/checksum is under target/packages. Upload actions retain these paths seven days and never include temporary fixture roots. These are CI evidence artifacts, not approved releases. Verify recorded checksum against trusted job provenance; downloading a checksum beside an untrusted .deb does not authenticate it. Input manifests record source-file digests before/after each invocation; documentation-only handoff edits afterward do not invalidate unchanged runtime tests and must receive their own reference audit.

The three jobs have contents-read tokens and no persisted checkout credentials. Native/package execute only on main push or explicit workflow_dispatch and use fresh hosted workers; fast PR jobs receive no repository secret. Job cancellation is bounded by disposable runner ownership. No workflow is pushed, dispatched or marked green by merely creating these files. Review pin changes and rerun affected evidence before updating acceptance; no mutable image fallback is provided.
