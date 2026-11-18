import { useState } from "react";
import type { FormEvent } from "react";
import { operations } from "./api";
import type { Controls, Health, Profile } from "./api";
import { Failure, Heading, Message } from "./components";
import type { Resource } from "./state";

export function Profiles({ profiles, health, backupPermission, controls, refresh }:
  { profiles: Resource<Profile[]>; health: Resource<Health>; backupPermission: boolean;
    controls: Controls; refresh: () => void }) {
  const items = profiles.value;
  const backupProfiles = items?.filter(profile => profile.operations.includes("backup")) ?? [];

  return <>
    <Heading title="Profiles"><button className="secondary" onClick={refresh}>Refresh</button></Heading>
    {profiles.loading && <Message>Loading profiles…</Message>}
    {profiles.error && <Failure error={profiles.error} />}
    {items && <div className="profile-layout">
      <section className="panel listing" aria-labelledby="configured-profiles">
        <h2 id="configured-profiles">Configured profiles</h2>
        {items.length === 0 ? <Message>No profiles are available.</Message> :
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Profile table">
            <table>
              <caption className="sr-only">Configured profiles and allowed operations</caption>
              <thead><tr><th scope="col">Profile</th><th scope="col">Allowed operations</th></tr></thead>
              <tbody>{items.map(profile => <tr key={profile.id}>
                <td><strong>{profile.display_name}</strong><br /><code>{profile.id}</code></td>
                <td>{profile.operations.length === 0 ? "None" :
                  <ul className="operation-list">
                    {profile.operations.map(op => <li key={op} className="status">{operations[op]}</li>)}
                  </ul>}
                </td>
              </tr>)}</tbody>
            </table>
          </div>}
      </section>
      <section className="panel form-panel backup-panel" aria-labelledby="backup-title">
        <h2 id="backup-title">Start a backup</h2>
        {!backupPermission ? <p>Your session cannot start backups.</p> :
          backupProfiles.length === 0 ? <p>No profiles allow backup for this session.</p> :
            <BackupForm profiles={backupProfiles} health={health} controls={controls} />}
      </section>
    </div>}
  </>;
}

function BackupForm({ profiles, health, controls }:
  { profiles: Profile[]; health: Resource<Health>; controls: Controls }) {
  const [profileId, setProfileId] = useState("");
  const [synthetic, setSynthetic] = useState(false);
  const selected = profiles.find(profile => profile.id === profileId);
  const allowed = !!selected && controls.can("backup", selected.id);

  function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || !allowed || !synthetic || controls.busy) return;
    controls.submit({ operation: "backup", body: {
      profile_id: selected.id === "default" ? null : selected.id,
      confirm_synthetic: true,
    } });
  }

  return <>
    {health.error ? <Failure error={health.error} /> :
      health.loading ? <Message>Checking job admission…</Message> :
        !health.value?.job_admission && <Message>The API is currently refusing new jobs.</Message>}
    <form onSubmit={start}>
      <label htmlFor="backup-profile">Backup profile</label>
      <select id="backup-profile" value={selected?.id ?? ""} disabled={controls.busy}
        onChange={event => { setProfileId(event.target.value); setSynthetic(false); }}>
        <option value="" disabled>Choose a profile</option>
        {profiles.map(profile =>
          <option key={profile.id} value={profile.id}>{profile.display_name} ({profile.id})</option>)}
      </select>
      <label className="check"><input type="checkbox" checked={synthetic} disabled={!selected || controls.busy}
        onChange={event => setSynthetic(event.target.checked)} /> I confirm this is a synthetic fixture</label>
      <button disabled={!allowed || !synthetic || controls.busy}>Start backup</button>
    </form>
  </>;
}
