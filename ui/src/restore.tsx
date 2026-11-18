import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import type { Api, Controls, Intent, RestoreDraft, Session } from "./api";
import { targetName } from "./api";
import { date, Failure, Facts, Heading, Message } from "./components";
import { useResource } from "./state";

const sectionLabels = {
  full: "All sections", pre_data: "Pre-data", pre_data_data: "Pre-data and data",
} satisfies Record<RestoreDraft["sections"], string>;
const securityLabels = {
  portable: "Portable", dr_full: "Full disaster recovery",
} satisfies Record<RestoreDraft["security"], string>;

export function PlanRestore({ artifactId, api, controls }:
  { artifactId: string; api: Api; controls: Controls }) {
  const load = useCallback((signal: AbortSignal) => api.artifact(artifactId, signal), [api, artifactId]);
  const resource = useResource(load);
  const [target, setTarget] = useState("");
  const [sections, setSections] = useState<RestoreDraft["sections"]>("full");
  const [security, setSecurity] = useState<RestoreDraft["security"]>("portable");
  const [older, setOlder] = useState(false);
  const [synthetic, setSynthetic] = useState(false);
  const [error, setError] = useState(false);
  const signed = !!resource.value?.format.match(/^signed-artifact-v[12]$/);
  const allowed = signed && controls.can("restore_plan");

  function plan(event: FormEvent) {
    event.preventDefault();
    if (!allowed || controls.busy || !synthetic) return;
    if (!targetName(target)) { setError(true); return; }
    controls.submit({ operation: "restore_plan", body: {
      artifact_id: artifactId, target_database: target, security, sections,
      acknowledge_older_snapshot: older, confirm_synthetic: true,
    } });
  }

  return <>
    <a className="back" href={`#/artifacts/${artifactId}`}>← Artifact details</a>
    <Heading title="Plan a restore" />
    {resource.loading && <Message>Loading artifact…</Message>}
    {resource.error && <Failure error={resource.error} />}
    {resource.value && <section className="panel form-panel">
      <Facts rows={[["Artifact", <code>{artifactId}</code>], ["Format", resource.value.format]]} />
      <form onSubmit={plan} noValidate>
        <label htmlFor="target">Target database</label>
        <input id="target" value={target} autoComplete="off" spellCheck={false} maxLength={63}
          placeholder="backupctl_fixture_" aria-describedby="target-help" aria-invalid={error}
          onChange={e => { setTarget(e.target.value); setError(false); }} />
        <p id="target-help" className={error ? "field-error" : "metadata"}>
          {error ? "Enter a fixture database name using lowercase letters, numbers or underscores."
            : "Choose a fresh database name beginning with backupctl_fixture_."}
        </p>
        <div className="field-grid">
          <div><label htmlFor="sections">Sections</label>
            <select id="sections" value={sections} onChange={e => {
              const value = e.target.value as RestoreDraft["sections"];
              setSections(value);
              if (value !== "full") setSecurity("portable");
            }}>
              {Object.entries(sectionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </div>
          <div><label htmlFor="security">Security</label>
            <select id="security" value={security} onChange={e => setSecurity(e.target.value as RestoreDraft["security"])}>
              <option value="portable">Portable</option>
              <option value="dr_full" disabled={sections !== "full"}>Full disaster recovery</option>
            </select>
          </div>
        </div>
        {security === "dr_full" && <Message>Full disaster recovery can replay roles, ownership and privileges.</Message>}
        <label className="check"><input type="checkbox" checked={older}
          onChange={e => setOlder(e.target.checked)} /> Acknowledge an older snapshot if required</label>
        <label className="check"><input type="checkbox" checked={synthetic}
          onChange={e => setSynthetic(e.target.checked)} /> I confirm this is a synthetic fixture</label>
        {!allowed && <p className="metadata">Restore planning is unavailable for this artifact or session.</p>}
        <button disabled={!allowed || !synthetic || controls.busy}>Create restore plan</button>
      </form>
    </section>}
  </>;
}

export function ConfirmRestore({ api, id, session, controls }:
  { api: Api; id: string; session: Session; controls: Controls }) {
  const load = useCallback((signal: AbortSignal) => api.intent(id, signal), [api, id]);
  const resource = useResource(load);
  if (resource.loading) return <Message>Loading saved restore plan…</Message>;
  if (resource.error) return <Failure error={resource.error} />;
  return resource.value && <RestoreReview intent={resource.value} session={session} controls={controls} />;
}

function RestoreReview({ intent, session, controls }:
  { intent: Intent; session: Session; controls: Controls }) {
  const [typed, setTyped] = useState("");
  const [now, setNow] = useState(Date.now);
  const plan = intent.confirmation;
  const active = now >= intent.created_unix_ms && now < intent.expires_unix_ms;
  const owned = intent.actor_id === session.actor_id;
  const invalid = controls.invalidIntent === intent.id;
  const allowed = active && !invalid && owned && controls.can("restore") && !intent.consumed_by_job_id;
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  function confirm(event: FormEvent) {
    event.preventDefault();
    if (!allowed || typed !== plan.target_database || controls.busy || Date.now() >= intent.expires_unix_ms) return;
    controls.submit({ operation: "restore", body: {
      intent_id: intent.id, confirm_digest: intent.digest, confirm_target: typed, confirm_synthetic: true,
    } });
  }
  return <section className="panel form-panel restore-review" aria-labelledby="review-title">
    <h2 id="review-title">Review restore plan</h2>
    <Facts rows={[
      ["Artifact", <code>{plan.artifact_id}</code>], ["Target", <code>{plan.target_database}</code>],
      ["Security", securityLabels[plan.security]], ["Sections", sectionLabels[plan.sections]],
      ["Expires", date(intent.expires_unix_ms)], ["Older snapshot", plan.acknowledge_older_snapshot ? "Acknowledged" : "Not acknowledged"],
      ["Plan ID", <code>{intent.id}</code>],
    ]} />
    {intent.consumed_by_job_id ? <p>Plan already submitted. <a href={`#/jobs/${intent.consumed_by_job_id}`}>View restore job</a></p>
      : !active || invalid ? <p>Plan unavailable or expired. <a href={`#/restore/${plan.artifact_id}`}>Create a fresh plan</a></p>
      : !owned ? <p>This plan belongs to another operator.</p>
      : !controls.can("restore") ? <p>Your session or the API cannot run this restore.</p>
      : <form onSubmit={confirm}>
        <p>This creates the target database shown above.</p>
        <label htmlFor="confirm-target">Type the exact target database</label>
        <input id="confirm-target" value={typed} autoComplete="off" spellCheck={false} maxLength={63}
          onChange={e => setTyped(e.target.value)} />
        <div className="button-row">
          <button className="danger" disabled={typed !== plan.target_database || controls.busy}>Confirm restore</button>
          <a href={`#/restore/${plan.artifact_id}`}>Edit and replan</a>
        </div>
      </form>}
  </section>;
}
