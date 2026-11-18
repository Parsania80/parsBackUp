# U01 fixture operator console

The console lets an operator find a backup, inspect its verification result,
plan a fixture restore and follow the job to a terminal receipt. The starting
point is P04 checkpoint `86e96c5030d58b3e81f060a1dc6d668428c3b1fe` and the
[OpenAPI 3.1.2 contract](../api/openapi-v1.json), version `1.0.0-fixture`.
U01 records the design. U02 implements the first screens.

## Stack decision

| Option | Fit | Tradeoff |
|---|---|---|
| React, TypeScript and Vite | Selected. Local component state fits the restore form, job receipts and session boundary. A static build fits the existing reverse proxy. | Own a small navigation and polling layer. |
| Vue, TypeScript and Vite | Single-file components and reactive forms offer a similar static deployment. | A separate template model with no project-specific advantage at this scope. |
| TypeScript and native DOM | Smallest runtime and direct HTML control. | Manual rendering, event cleanup and focus transitions across job and form states. |
| Full-stack UI framework | Built-in routing and richer rendering options. | Additional conventions and dependencies for an authenticated console that already has a backend. |

Use React and React DOM for rendering, strict TypeScript, Vite and plain CSS.
Use browser navigation and fetch with a small typed API module. Generate
compile-time types from the committed contract with `openapi-typescript`.
U02 records exact package versions, the npm lockfile and the toolchain once the
actual dependency graph passes build, license and advisory checks. Node is a
build dependency. Deploy the static assets with the existing API as a separate
service. References: [React client application setup](https://react.dev/learn/build-a-react-app-from-scratch),
[Vite static deployment](https://vite.dev/guide/static-deploy.html),
[Vue quick start](https://vuejs.org/guide/quick-start.html),
[TypeScript strict mode](https://www.typescriptlang.org/tsconfig/strict.html),
[OpenAPI type generation](https://openapi-ts.dev/introduction).

## Layout and scope

Use a compact, responsive console. The header carries the product name,
session status and a visible fixture label. The application navigation leads
to Overview, Artifacts and Jobs. On a narrow screen, navigation wraps above the
content and tables allow horizontal scrolling. Use text status labels with
color as a secondary cue. Give the data table or confirmation panel the main
content area and keep action buttons next to the records they affect.

| Screen | What the operator sees and does | API operations |
|---|---|---|
| Sign in | Enter an operator token. On return, reopen a previously selected job if it is visible to the current actor. | `createSession`, `getSession`, `deleteSession` |
| Overview | API readiness, whether jobs can be submitted, and queue depth. Show degraded or read-only operation explicitly. | `getHealth`, `listProfiles` |
| Artifacts | UUID, format and unverified header status. Load another page using the server cursor. Start inspection or a signature, checksum or archive verification when allowed. Show results as job observations. | `listArtifacts`, `getArtifact`, `createInspection`, `createVerification` |
| Jobs | Paginated work with timestamps, state and terminal receipts. The API pages in UUID order, so label any sort as applying to the loaded page. Cancellation keeps the job visible through its final outcome. | `listJobs`, `getJob`, `cancelJob` |
| Restore | Select a signed artifact, choose a fresh fixture target and options, review the saved plan, then confirm its exact target. Monitor the restore job. | `createRestorePlan`, `getIntent`, `createRestore`, `getJob` |
| Profiles and backup | Read the configured profiles and permitted operations. Offer starting a backup where the operator has permission and the selected profile supports it. | U03: `listProfiles`, `createBackup` |

U02 covers the first five screens and reads profile capabilities for its action
controls. U03 adds the profile and backup screen. Retention and protection already
have API endpoints, but their operator UI is deferred so the first release of the
console can focus on restore. Schedule editing, key status and key management
require corresponding API support before they get views or controls. The launch
scope uses only [delivered API operations](../operations/http-api.md).
Controls reflect session permissions, profile operations and admission status.
Cancel is offered for owned nonterminal jobs with cancel and operation
permissions, or to administrators with the corresponding all-jobs permission.
The API makes the final authorization decision for every call.

## Restore interaction

1. From the artifact detail, open a restore form. Default to portable security
   and full sections. Present the supported section choices and constrain
   section-limited restores to portable. The operator provides a fresh fixture
   database name and explicitly confirms synthetic operation. Describe the
   additional role, ownership and privilege effects for full disaster recovery.
2. Submit the planning job and show its progress. Planning success opens a review
   panel with artifact UUID, target, security, sections, expiry, snapshot
   acknowledgement and the saved intent identifier. A planning failure shows the
   API's safe code. The current API does not expose a dedicated older-snapshot
   failure code. Offer an explicit acknowledgement choice with its meaning,
   and leave any new planning attempt to the operator.
3. Re-read the saved intent before showing confirmation for a resumed panel.
   Require an exact typed target and a deliberate confirm action. Send only the
   intent UUID, its returned digest, exact target and synthetic confirmation.
   Use the server's expiry and consumed state. If a plan expires or changes,
   return to planning with an explanation.
4. On acceptance, show the linked job and say it was queued. On completion, show
   the target and receipt. For a partial restore, report that the target or
   related database state may have changed and show the job ID. For interruption
   with unknown effects, direct the operator to inspect the existing job and
   target before trying again. Keep these states visible after reload.

The review panel replaces the editable form at step 3. Returning to edit
requires a new planning request. Do not reuse a confirmation payload after
changing its inputs. The backend enforces the plan, target and role rules.

## Client and deployment boundary

- Serve the console and `/api/v1` from the same HTTPS origin. The reverse proxy
  forwards API traffic to loopback and preserves the exact public Host and Origin
  policy. Development browser integration uses the same topology with a local
  test HTTPS proxy. A dev server on another port would send a different Origin,
  and development HTTP mode binds the accepted origin to the API listener.
- Enter the token only in the sign-in form. Clear it after submission and keep
  the returned CSRF token in memory. Let the browser manage the HttpOnly cookie.
  Fetch with same-origin credentials and use `X-CSRF-Token` on browser mutations.
  Session loss clears private views and aborts polling. Use fixed relative API
  paths and validate any `Location` against the response's canonical job UUID
  before navigating. Disable redirect following for API requests.
- Generate request and response types from the committed OpenAPI file. Keep
  page components behind typed API functions. Check the envelope, API version,
  expected status and values used for navigation or confirmation at runtime.
  Unknown errors get a generic message and a validated request ID. Render server
  strings as text. No token, private response cache or plan payload goes into
  browser storage, URLs or client logs. References: [Fetch standard](https://fetch.spec.whatwg.org/),
  [API threat review](../security/api-v1-review.md).
- A submission owns a key and request body until it has a receipt or a known
  refusal. Retry an ambiguous submission only after explicit operator action
  with the identical key and body in memory and the same actor. A reload clears
  the pending submission. After reload, check Jobs before offering a new attempt.
  `202` means accepted and `200` can return a terminal replay. `409` and `410`
  require handling the reported conflict or expiry. `429` honors `Retry-After`.
- Poll the selected nonterminal job without overlapping requests. Start at the
  API's two-second retry hint and back off to ten seconds under repeated polls.
  Honor a longer retry hint. Pause on tab hide, abort on navigation or sign-out
  and stop at terminal state. Use cursor pagination for list views and refresh
  on demand. Keep linkage between artifact and job visible without adding an
  inferred verification state to discovery rows.

The jobs screen uses all eight states from the schema: queued, running,
cancellation requested, succeeded, failed, partial, cancelled and interrupted.
Show reported effects independently of state. Label archive verification as an
archive check and display a successful restore as its own result.

## U02 and U04 acceptance targets

U02 builds the static console, verifies type generation against the committed
contract and exercises sign-in, artifact inspection, restore planning,
confirmation and job polling with the real fixture API. U04 adds the browser
checks for session expiry, unavailable admission, retry without duplicate work,
partial and interrupted jobs, invalid text and complete keyboard navigation.
Use semantic forms, associated field errors, visible focus, readable contrast
and discrete announcements for state changes. Target WCAG 2.2 AA and test
keyboard behavior and narrow viewport layout. [WCAG 2.2](https://www.w3.org/TR/WCAG22/).

U01 checks that every operation named above exists in the committed schema and
that local document references resolve. Browser behavior and dependency lock
checks require the U02 implementation.
