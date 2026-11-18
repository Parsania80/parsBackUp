import { useCallback, useState } from "react";
import type { ReactNode } from "react";
import type { Api, Artifact, Controls, Health, Job, Level, Session } from "./api";
import { ApiError, effects, operations, permissions, terminal } from "./api";
import { date, Failure, Facts, Heading, Message, Pager, Status } from "./components";
import { ConfirmRestore } from "./restore";
import { useJob, usePage, useResource } from "./state";
import type { Accepted } from "./state";

export function Overview({ health, loading, refresh, error }:
  { health?: Health; loading: boolean; refresh: () => void; error?: ApiError }) {
  return <>
    <Heading title="Overview"><button className="secondary" onClick={refresh}>Refresh</button></Heading>
    {loading && <Message>Checking API status…</Message>}
    {error && <Failure error={error} />}
    {health && <>
      <div className="stat-grid">
        <section className="panel stat"><h2>API status</h2>
          <p className={health.ready ? "stat-value green" : "stat-value amber"}>{health.ready ? "Ready" : "Degraded"}</p>
        </section>
        <section className="panel stat"><h2>Job admission</h2>
          <p className={health.job_admission ? "stat-value green" : "stat-value amber"}>{health.job_admission ? "Available" : "Unavailable"}</p>
          <p className="metadata">{health.containment_verified ? "Supervised listener" : "Read-only listener"}</p>
        </section>
        <section className="panel stat"><h2>Queued jobs</h2>
          <p className="stat-value">{health.queue_depth} <span className="metadata">/ 16</span></p>
        </section>
      </div>
      <div className="overview-links">
        <a className="panel jump" href="#/artifacts"><strong>Browse artifacts</strong><span>Inspect and verify backups</span><b aria-hidden="true">→</b></a>
        <a className="panel jump" href="#/jobs"><strong>View jobs</strong><span>Track work and review receipts</span><b aria-hidden="true">→</b></a>
      </div>
    </>}
  </>;
}

export function Artifacts({ api }: { api: Api }) {
  const load = useCallback((signal: AbortSignal, after?: string) => api.artifacts(signal, after), [api]);
  const page = usePage(load);
  return <>
    <Heading title="Artifacts"><button className="secondary" onClick={page.refresh}>Refresh</button></Heading>
    {page.loading && <Message>Loading artifacts…</Message>}
    {page.error && <Failure error={page.error} />}
    {page.value && <section className="panel listing">
      {page.value.items.length === 0 ? <Message>No artifacts on this page.</Message> :
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Artifact table"><table>
          <caption className="sr-only">Artifact discovery</caption>
          <thead><tr><th scope="col">Artifact ID</th><th scope="col">Format</th><th scope="col">Header status</th></tr></thead>
          <tbody>{page.value.items.map(row => <tr key={row.artifact_id}>
            <td><a className="code-link" href={`#/artifacts/${row.artifact_id}`}>{row.artifact_id}</a></td>
            <td>{row.format}</td><td><span className="status">Unverified</span></td>
          </tr>)}</tbody>
        </table></div>}
      <Pager {...page} canNext={!!page.value.next_after} />
    </section>}
  </>;
}

export function ArtifactDetail({ api, id, controls }: { api: Api; id: string; controls: Controls }) {
  const load = useCallback((signal: AbortSignal) => api.artifact(id, signal), [api, id]);
  const resource = useResource(load);
  return <>
    <a className="back" href="#/artifacts">← Artifacts</a>
    <Heading title="Artifact details" />
    {resource.loading && <Message>Loading artifact…</Message>}
    {resource.error && <Failure error={resource.error} />}
    {resource.value && <ArtifactActions artifact={resource.value} controls={controls} />}
  </>;
}

function ArtifactActions({ artifact, controls }: { artifact: Artifact; controls: Controls }) {
  const id = artifact.artifact_id;
  const [level, setLevel] = useState<Level>("archive");
  const signed = /^signed-artifact-v[12]$/.test(artifact.format);
  const inspectAllowed = signed && controls.can("inspection");
  const verifyAllowed = signed && controls.can("verification");
  const restoreAllowed = signed && controls.can("restore_plan");
  return <section className="panel form-panel">
    <Facts rows={[["Artifact", <code>{id}</code>], ["Format", artifact.format],
      ["Public header", <span className="status">Unverified</span>]]} />
    {!(inspectAllowed || verifyAllowed || restoreAllowed)
      ? <p className="metadata">Job actions are unavailable for this artifact or session.</p>
      : <div className="artifact-actions">
        {inspectAllowed && <button className="secondary" disabled={controls.busy} onClick={() =>
          controls.submit({ operation: "inspection", body: { artifact_id: id } })}>Inspect artifact</button>}
        {restoreAllowed && <a className="button" href={`#/restore/${id}`}>Plan a restore</a>}
        {verifyAllowed && <form onSubmit={e => {
          e.preventDefault();
          if (!controls.busy) controls.submit({ operation: "verification", body: { artifact_id: id, level } });
        }}>
          <label htmlFor="verification-level">Verification level</label>
          <div className="button-row">
            <select id="verification-level" value={level} onChange={e => setLevel(e.target.value as Level)}>
              <option value="signature">Signature</option><option value="checksum">Checksum</option>
              <option value="archive">Archive</option>
            </select>
            <button className="secondary" disabled={controls.busy}>Verify artifact</button>
          </div>
        </form>}
      </div>}
  </section>;
}

export function Jobs({ api }: { api: Api }) {
  const load = useCallback((signal: AbortSignal, after?: string) => api.jobs(signal, after), [api]);
  const page = usePage(load);
  return <>
    <Heading title="Jobs"><button className="secondary" onClick={page.refresh}>Refresh</button></Heading>
    {page.loading && <Message>Loading jobs…</Message>}
    {page.error && <Failure error={page.error} />}
    {page.value && <section className="panel listing">
      {page.value.items.length === 0 ? <Message>No jobs on this page.</Message> :
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Job table"><table>
          <caption className="sr-only">Jobs in identifier order</caption>
          <thead><tr><th scope="col">Job ID</th><th scope="col">Operation</th><th scope="col">State</th><th scope="col">Updated</th></tr></thead>
          <tbody>{page.value.items.map(job => <tr key={job.id}>
            <td><a className="code-link" href={`#/jobs/${job.id}`}>{job.id}</a></td>
            <td>{operations[job.operation]}</td><td><Status value={job.state} /></td>
            <td>{date(job.updated_unix_ms)}</td>
          </tr>)}</tbody>
        </table></div>}
      <Pager {...page} canNext={!!page.value.next_after} />
    </section>}
  </>;
}

export function JobDetail({ api, id, accepted, controls, session, admission }:
  { api: Api; id: string; accepted?: Accepted; controls: Controls; session: Session; admission: boolean }) {
  const resource = useJob(api, id, accepted);
  const job = resource.value;
  const permitted = job && session.permissions.includes(permissions[job.operation]) &&
    (session.permissions.includes("job.cancel_all") ||
      job.actor_id === session.actor_id && session.permissions.includes("job.cancel_own"));
  const facts: [string, ReactNode][] = job ? [
    ["Job ID", <code>{job.id}</code>], ["Created", date(job.created_unix_ms)],
    ["Updated", date(job.updated_unix_ms)], ["Effects", effects[job.effects]],
  ] : [];
  if (job?.core_job_id) facts.push(["Core job ID", <code>{job.core_job_id}</code>]);
  return <>
    <a className="back" href="#/jobs">← Jobs</a>
    <Heading title={job ? `${operations[job.operation]} job` : "Job details"}>
      <button className="secondary" onClick={resource.refresh}>Refresh</button>
    </Heading>
    {resource.loading && <Message>Loading job…</Message>}
    {resource.error && <Failure error={resource.error} />}
    {job && <>
      <section className="panel form-panel">
        <div className="receipt-top">
          <div role="status" aria-live="polite"><Status value={job.state} /></div>
          {!resource.error && !terminal(job) && job.state !== "cancel_requested" && permitted && admission &&
            <button className="secondary" disabled={controls.busy} onClick={() =>
              controls.submit({ operation: "cancel", jobId: id, body: {} })}>Request cancellation</button>}
        </div>
        {job.state === "queued" && <p>Accepted by the API and waiting for a worker.</p>}
        {job.state === "cancel_requested" && <p>Cancellation requested. Wait for the final receipt.</p>}
        {job.state === "partial" && <p className="caution">Work ended with possible effects. Inspect them before starting a new attempt.</p>}
        {job.state === "interrupted" && <p className="caution">Work was interrupted. Inspect the job and any target before starting a new attempt.</p>}
        {job.error && <Failure error={new ApiError(0, job.error.code)} />}
        <Facts rows={facts} />
      </section>
      {job.result && <ResultDetails result={job.result} />}
      {job.state === "succeeded" && job.result?.kind === "restore_plan" &&
        <ConfirmRestore api={api} id={job.result.intent.id} session={session} controls={controls} />}
    </>}
  </>;
}

function ResultDetails({ result }: { result: NonNullable<Job["result"]> }) {
  switch (result.kind) {
    case "inspection":
      return <section className="panel form-panel"><h2>Inspection result</h2>
        <Facts rows={[["Artifact", <ArtifactLink id={result.artifact_id} />], ["Source database", result.database],
          ["PostgreSQL", result.source_major], ["Scope", result.scope ?? "Whole database"],
          ["Artifact created", date(result.created_unix_ms)]]} />
      </section>;
    case "verification":
      return <section className="panel form-panel"><h2>Verification result</h2>
        <Facts rows={[["Artifact", <ArtifactLink id={result.artifact_id} />],
          ["Check", `${result.level[0]?.toUpperCase()}${result.level.slice(1)} check`],
          ["Outcome", result.passed ? "Passed" : "Failed"],
          ["Inventory observation", result.inventory_recorded ? "Recorded" : "Not recorded"]]} />
      </section>;
    case "restore":
      return <section className="panel form-panel"><h2>Restore result</h2>
        <Facts rows={[["Artifact", <ArtifactLink id={result.artifact_id} />],
          ["Target database", <code>{result.target_database}</code>]]} />
      </section>;
    case "backup":
      return <section className="panel form-panel"><h2>Backup result</h2>
        <ArtifactLink id={result.artifact_id} />
      </section>;
    case "artifact_protection":
      return <section className="panel form-panel"><h2>Protection result</h2>
        <Facts rows={[["Artifact", <ArtifactLink id={result.artifact_id} />],
          ["Protected", result.protected ? "Yes" : "No"]]} />
      </section>;
    case "retention_run":
      return <section className="panel form-panel"><h2>Retention receipt</h2>
        <Facts rows={[["Completed", idList(result.completed)], ["Deleting", idList(result.deleting)],
          ["Pending", idList(result.pending)]]} />
      </section>;
    case "retention_preview":
    case "restore_plan":
      return null;
  }
}

function ArtifactLink({ id }: { id: string }) {
  return <a className="code-link" href={`#/artifacts/${id}`}>{id}</a>;
}

function idList(ids: string[]) {
  return ids.length ? <ul className="id-list">{ids.map(id => <li key={id}><code>{id}</code></li>)}</ul> : "None";
}
