import type { components } from "./openapi";

type Schema = components["schemas"];
export type Session = Schema["Session"];
export type Health = Schema["Health"];
export type Profile = Schema["Profile"];
export type Artifact = Schema["Artifact"];
export type Job = Schema["Job"];
export type Intent = Schema["RestoreIntent"];
export type Permission = Schema["Permission"];
export type Operation = Schema["Operation"];
export type Level = Schema["VerificationRequest"]["level"];
export type RestoreDraft = Schema["RestorePlanRequest"];
export type Page<T> = { items: T[]; next_after: string | null };

export const jobStates = {
  queued: "Queued", running: "Running", cancel_requested: "Cancellation requested",
  succeeded: "Succeeded", failed: "Failed", partial: "Partial",
  cancelled: "Cancelled", interrupted: "Interrupted",
} satisfies Record<Schema["JobState"], string>;

export const effects = {
  none: "No effects reported",
  preparation_only: "Preparation or cleanup may have occurred",
  artifact_may_be_published: "An artifact may have been published",
  database_may_be_modified: "Database state may have changed",
  artifacts_may_be_deleted: "Artifacts may have been deleted",
  inventory_may_be_modified: "Inventory may have changed",
  unknown: "Effects unknown",
} satisfies Record<Schema["Effects"], string>;

export const operations = {
  backup: "Backup", inspection: "Inspection", verification: "Verification",
  restore_plan: "Restore plan", restore: "Restore", retention_preview: "Retention preview",
  retention_run: "Retention run", artifact_protection: "Artifact protection",
} satisfies Record<Operation, string>;

export const permissions = {
  backup: "backup.create", inspection: "artifact.inspect", verification: "artifact.verify",
  restore_plan: "restore.plan", restore: "restore.run", retention_preview: "retention.preview",
  retention_run: "retention.run", artifact_protection: "artifact.protect",
} satisfies Record<Operation, Permission>;

export type Submission =
  | { operation: "backup"; body: Schema["BackupRequest"] }
  | { operation: "inspection"; body: Schema["ArtifactRequest"] }
  | { operation: "verification"; body: Schema["VerificationRequest"] }
  | { operation: "restore_plan"; body: RestoreDraft }
  | { operation: "restore"; body: Schema["RestoreRequest"] }
  | { operation: "cancel"; jobId: string; body: Schema["CancelRequest"] };

export type Controls = {
  busy: boolean;
  can: (operation: Operation, profileId?: string) => boolean;
  invalidIntent?: string;
  submit: (input: Submission) => void;
};

const paths = {
  backup: "/backups",
  inspection: "/inspections", verification: "/verifications",
  restore_plan: "/restore-plans", restore: "/restores",
} as const;

export const uuid = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
export const targetName = (value: unknown): value is string =>
  typeof value === "string" && value.length <= 63 && /^backupctl_fixture_[a-z0-9_]+$/.test(value);
const digest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const time = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 8.64e15;
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const has = (value: unknown, names: object) => typeof value === "string" && Object.hasOwn(names, value);
const choice = (value: unknown, options: readonly string[]) => typeof value === "string" && options.includes(value);
const idPath = (value: string) => {
  if (!uuid(value)) throw protocol();
  return value;
};

export const terminal = (job: Job) => !choice(job.state, ["queued", "running", "cancel_requested"]);
const artifact = (x: unknown): x is Artifact => object(x) && uuid(x.artifact_id) &&
  typeof x.format === "string" && x.format.length <= 128 && x.header_status === "unverified";
const session = (x: unknown): x is Session => object(x) && uuid(x.actor_id) && time(x.expires_unix_ms) &&
  typeof x.csrf_token === "string" && /^[A-Za-z0-9_-]{43}$/.test(x.csrf_token) &&
  Array.isArray(x.permissions) && x.permissions.every(p => typeof p === "string");
const health = (x: unknown): x is Health => object(x) && typeof x.ready === "boolean" &&
  x.mode === "fixture" && x.production_enabled === false && typeof x.job_admission === "boolean" &&
  typeof x.containment_verified === "boolean" && Number.isInteger(x.queue_depth) &&
  typeof x.queue_depth === "number" && x.queue_depth >= 0 && x.queue_depth <= 16;
const profile = (x: unknown): x is Profile => object(x) && typeof x.id === "string" &&
  /^[a-z][a-z0-9_-]{0,63}$/.test(x.id) &&
  typeof x.display_name === "string" && x.display_name.length > 0 && Array.from(x.display_name).length <= 128 &&
  Array.isArray(x.operations) && x.operations.length <= 8 && x.operations.every(op => has(op, operations));
const profiles = (x: unknown): x is Schema["Profiles"] => object(x) && Array.isArray(x.items) &&
  x.items.length <= 256 && x.items.every(profile) &&
  new Set(x.items.map(item => item.id)).size === x.items.length;
const safeError = (x: unknown) => object(x) && typeof x.code === "string" && typeof x.retryable === "boolean";

function restoreIntent(x: unknown): x is Intent {
  if (!object(x) || x.kind !== "restore" || !uuid(x.id) || !uuid(x.actor_id) ||
    !uuid(x.planning_job_id) || !uuid(x.core_plan_id) || !uuid(x.store_instance_id) ||
    !digest(x.digest) || !digest(x.config_revision) || !digest(x.core_plan_digest) ||
    !time(x.created_unix_ms) || !time(x.expires_unix_ms) ||
    !(x.consumed_by_job_id === null || uuid(x.consumed_by_job_id)) || !object(x.confirmation)) return false;
  const c = x.confirmation;
  return uuid(c.artifact_id) && targetName(c.target_database) && choice(c.security, ["portable", "dr_full"]) &&
    choice(c.sections, ["full", "pre_data", "pre_data_data"]) &&
    (c.sections === "full" || c.security === "portable") && typeof c.acknowledge_older_snapshot === "boolean";
}

function receipt(x: Record<string, unknown>) {
  switch (x.kind) {
    case "backup": return uuid(x.artifact_id);
    case "inspection": return uuid(x.artifact_id) && typeof x.database === "string" &&
      [16, 17, 18].includes(x.source_major as number) &&
      (x.scope === null || typeof x.scope === "string") && time(x.created_unix_ms);
    case "verification": return uuid(x.artifact_id) && choice(x.level, ["signature", "checksum", "archive"]) &&
      typeof x.passed === "boolean" && typeof x.inventory_recorded === "boolean";
    case "restore_plan": return restoreIntent(x.intent);
    case "restore": return uuid(x.artifact_id) && targetName(x.target_database) &&
      x.verification_level === "none" && typeof x.recorded_in_artifact === "boolean";
    case "retention_preview": return true; // U02 only labels this job kind.
    case "retention_run": return [x.completed, x.deleting, x.pending].every(ids =>
      Array.isArray(ids) && ids.every(uuid)) && typeof x.audit_recorded === "boolean";
    case "artifact_protection": return uuid(x.artifact_id) && typeof x.protected === "boolean";
    default: return false;
  }
}

const job = (x: unknown): x is Job => object(x) && uuid(x.id) && uuid(x.actor_id) &&
  has(x.operation, operations) && has(x.state, jobStates) && has(x.effects, effects) &&
  x.url === `/api/v1/jobs/${x.id}` && time(x.created_unix_ms) && time(x.updated_unix_ms) &&
  (x.core_job_id === null || uuid(x.core_job_id)) && (x.error === null || safeError(x.error)) &&
  (x.result === null || (object(x.result) && x.result.kind === x.operation && receipt(x.result))) &&
  (x.state !== "succeeded" || (x.result !== null && x.error === null));

function page<T>(item: (x: unknown) => x is T) {
  return (x: unknown): x is Page<T> => object(x) && Array.isArray(x.items) &&
    x.items.length <= 100 && x.items.every(item) && (x.next_after === null || uuid(x.next_after));
}

const messages: Partial<Record<Schema["SafeCode"], string>> = {
  AUTH_REQUIRED: "Sign in to continue.",
  ACCESS_DENIED: "Your session does not permit this action.",
  NOT_FOUND: "This item is unavailable or you do not have permission to see it.",
  POLICY_REFUSED: "The API refused this operation for the configured profile.",
  CONFIG_CHANGED: "The configured profile changed. Refresh readiness and try again.",
  CONTAINMENT_UNAVAILABLE: "This listener can read data. Job submission requires supervision.",
  NOT_READY: "The API is not ready to accept work.",
  CONTROL_CAPACITY: "The API has reached its receipt capacity.",
  DISCOVERY_LIMIT: "The artifact directory exceeds the API discovery limit.",
  INTENT_EXPIRED: "The restore plan expired. Create a fresh plan.",
  INTENT_CONFLICT: "The plan changed or was already consumed. Check Jobs before planning again.",
  IDEMPOTENCY_CONFLICT: "This submission conflicts with an existing receipt. Check Jobs.",
  QUEUE_FULL: "The job queue is full. Try again after it has room.",
  RATE_LIMIT: "The API is receiving too many requests. Wait before trying again.",
  INVALID_REQUEST: "The API did not accept these inputs.",
  OPERATION_CANCELLED: "The operation was cancelled.",
  OPERATION_FAILED: "The operation failed. Review the effects and job receipt.",
  OPERATION_INTERRUPTED: "The operation was interrupted. Inspect its effects before trying again.",
};

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, readonly requestId?: string,
    readonly retryAfter?: number, message?: string) {
    super(message ?? (Object.hasOwn(messages, code) ? messages[code as Schema["SafeCode"]] : undefined) ??
      "The API could not complete this request.");
  }

  get ambiguous() {
    return this.status === 0 || this.status >= 500 &&
      !choice(this.code, ["NOT_READY", "CONTAINMENT_UNAVAILABLE", "CONTROL_CAPACITY"]);
  }
}

function protocol() {
  return new ApiError(0, "PROTOCOL", undefined, undefined, "The API returned an unexpected response.");
}

function retryDelay(value: string | null) {
  if (value === null || !/^\d+$/.test(value)) return undefined;
  const ms = Number(value) * 1000;
  return Number.isSafeInteger(ms) && ms <= 2_147_483_647 ? ms : undefined;
}

function query(after?: string) {
  return after ? `?after=${idPath(after)}` : "";
}

export class Api {
  constructor(private readonly scope: AbortSignal, private readonly csrf?: string | null,
    private readonly onUnauthorized?: () => void) {}

  private async request<T>(path: string, accepts: number[], check: (x: unknown) => x is T,
    init: RequestInit = {}, signal?: AbortSignal) {
    const owners = signal ? AbortSignal.any([this.scope, signal]) : this.scope;
    const timeout = AbortSignal.timeout(15_000);
    const requestSignal = AbortSignal.any([owners, timeout]);
    let response: Response;
    try {
      response = await fetch(`/api/v1${path}`, {
        ...init, signal: requestSignal, credentials: "same-origin", redirect: "error", cache: "no-store",
      });
    } catch (error) {
      if (owners.aborted) throw error;
      if (timeout.aborted) throw new ApiError(0, "TIMEOUT", undefined, undefined, "The API request timed out.");
      throw new ApiError(0, "NETWORK", undefined, undefined, "The connection to the API was lost.");
    }
    const retryAfter = retryDelay(response.headers.get("Retry-After"));
    if (response.status === 401) this.onUnauthorized?.();
    const raw: unknown = await response.json().catch(() => null);
    if (!object(raw) || raw.api_version !== "backupctl-api-v1" || !uuid(raw.request_id)) throw protocol();
    if (!response.ok) {
      if (!object(raw.error) || typeof raw.error.code !== "string") throw protocol();
      throw new ApiError(response.status, raw.error.code, raw.request_id, retryAfter);
    }
    if (!accepts.includes(response.status) || !check(raw.data)) throw protocol();
    return { data: raw.data, response, retryAfter };
  }

  private mutation(method: "POST" | "DELETE", body?: object, key?: string): RequestInit {
    const headers = new Headers();
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (this.csrf) headers.set("X-CSRF-Token", this.csrf);
    if (key) headers.set("Idempotency-Key", idPath(key));
    return { method, headers, body: body === undefined ? undefined : JSON.stringify(body) };
  }

  async login(token: string) {
    return (await this.request("/session", [201], session, this.mutation("POST", { token }))).data;
  }
  async session(signal?: AbortSignal) {
    return (await this.request("/session", [200], session, {}, signal)).data;
  }
  async logout() {
    const revoked = (x: unknown): x is Schema["SessionRevoked"] => object(x) && x.revoked === true;
    await this.request("/session", [200], revoked, this.mutation("DELETE"));
  }
  async health(signal: AbortSignal) {
    return (await this.request("/health", [200], health, {}, signal)).data;
  }
  async profiles(signal: AbortSignal) {
    return (await this.request("/profiles", [200], profiles, {}, signal)).data.items;
  }
  async artifacts(signal: AbortSignal, after?: string) {
    return (await this.request(`/artifacts${query(after)}`, [200], page(artifact), {}, signal)).data;
  }
  async artifact(id: string, signal: AbortSignal) {
    const value = (await this.request(`/artifacts/${idPath(id)}`, [200], artifact, {}, signal)).data;
    if (value.artifact_id !== id) throw protocol();
    return value;
  }
  async jobs(signal: AbortSignal, after?: string) {
    return (await this.request(`/jobs${query(after)}`, [200], page(job), {}, signal)).data;
  }
  async job(id: string, signal: AbortSignal) {
    const value = await this.request(`/jobs/${idPath(id)}`, [200], job, {}, signal);
    if (value.data.id !== id) throw protocol();
    return value;
  }
  async intent(id: string, signal: AbortSignal) {
    const value = (await this.request(`/intents/${idPath(id)}`, [200], restoreIntent, {}, signal)).data;
    if (value.id !== id) throw protocol();
    return value;
  }

  async submit(input: Submission, key: string) {
    if (!this.csrf) throw new ApiError(403, "ACCESS_DENIED");
    const path = input.operation === "cancel"
      ? `/jobs/${idPath(input.jobId)}/cancel` : paths[input.operation];
    const result = await this.request(path, input.operation === "cancel" ? [200] : [200, 202],
      job, this.mutation("POST", input.body, key));
    const { data, response } = result;
    if (input.operation === "cancel" ? data.id !== input.jobId
      : data.operation !== input.operation || (response.status === 202
        ? terminal(data) || response.headers.get("Location") !== data.url
        : !terminal(data))) throw protocol();
    return result;
  }
}
