//! Retention snapshots, immutable plans and marker-first deletion under maintenance ownership.
use crate::layout::{ARTIFACTS_DIR, INVENTORY_FILE, PLANS_DIR};
use crate::reconcile::{directory, entries_for_hash, open_at};
use crate::{LocalReconciler, LocalStore, hash_file, open_regular};
use anyhow::{Context, Result, ensure};
use backup_application::{RetentionPlanner, RetentionPreview};
use backup_domain::{
    ArtifactSnapshot, Config, DELETION_FILES, DELETION_PLAN_FORMAT, DELETION_PLAN_MAX_BYTES,
    DELETION_PLAN_TTL_MS, DeletionPlan, FileSnapshot, Protection, RetentionExclusion,
    RetentionMember, RetentionOperation, RetentionRequest, RetentionSelection, SavedDeletionPlan,
    profile_fingerprint, select_retention,
};
use backup_inventory::{ActivityLock, Inventory, ResourceLock, SCHEMA_VERSION, Shape, State};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct LocalRetention(pub Config);

struct Snapshot {
    source: String,
    profile: String,
    inventory_sha256: String,
    selection: RetentionSelection,
    // Keep artifact claims inside maintenance ownership through the complete save/check.
    _resources: Vec<ResourceLock>,
    _activity: Option<ActivityLock>,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn quiet(root: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        match fs::symlink_metadata(root.join(format!("{INVENTORY_FILE}{suffix}"))) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!(
                "RETENTION_INVENTORY_INVALID: SQLite sidecar or scan failure; recover explicitly"
            ),
        }
    }
    Ok(())
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() },
        "RETENTION_PLAN_INVALID: plan storage must be private and owned by this user"
    );
    Ok(())
}
fn plan_dir(root: &Path, create: bool) -> Result<File> {
    let path = root.join(PLANS_DIR);
    if create {
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => directory(root)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let dir = directory(&path)?;
    private(&dir)?;
    Ok(dir)
}
fn descriptor_path(dir: &File) -> PathBuf {
    // shortcut: Linux procfs anchors relative reads to an already-held no-follow directory.
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

impl LocalRetention {
    fn snapshot(
        &self,
        request: &RetentionRequest,
        expected: Option<&DeletionPlan>,
    ) -> Result<Snapshot> {
        let activity = maintenance(&self.0.storage.root)?;
        let mut snapshot = self.snapshot_claimed(request, expected, &activity)?;
        snapshot._activity = Some(activity);
        Ok(snapshot)
    }

    fn snapshot_claimed(
        &self,
        request: &RetentionRequest,
        expected: Option<&DeletionPlan>,
        activity: &ActivityLock,
    ) -> Result<Snapshot> {
        let root = &self.0.storage.root;
        let root_fd = directory(root).context("RETENTION_INVENTORY_INVALID")?;
        quiet(root)?;
        let index = root.join(INVENTORY_FILE);
        let inventory =
            Inventory::open_read_only_bound(&index).context("RETENTION_INVENTORY_INVALID")?;
        ensure!(
            inventory.schema_version()? == SCHEMA_VERSION
                && inventory.integrity_problems()?.is_empty(),
            "RETENTION_INVENTORY_INVALID: current healthy schema required; no implicit migration"
        );
        let rows = inventory
            .artifacts()
            .context("RETENTION_INVENTORY_INVALID")?;
        let index_hash = hash_file(&index).context("RETENTION_INVENTORY_INVALID")?.1;
        if let Some(plan) = expected {
            ensure!(
                index_hash == plan.inventory_sha256,
                "RETENTION_PLAN_STALE: inventory changed; prepare a new preview"
            );
        }
        let profile = match request {
            RetentionRequest::Prune {
                profile_fingerprint,
                keep_last,
            } => {
                ensure!(
                    *keep_last > 0,
                    "RETENTION_PLAN_INVALID: keep-last must be positive"
                );
                profile_fingerprint.clone()
            }
            RetentionRequest::Delete { backup_id } => {
                let row = rows
                    .iter()
                    .find(|r| r.backup_id == *backup_id)
                    .context("RETENTION_SCOPE_UNKNOWN: target is not registered")?;
                ensure!(
                    row.shape == Shape::V1Signed
                        && row.state == State::Registered
                        && row.completed_at_utc.is_some()
                        && !inventory.is_provisional(*backup_id)?,
                    "RETENTION_SCOPE_UNKNOWN: target scope, time or provenance is unconfirmed"
                );
                row.profile_fingerprint
                    .clone()
                    .context("RETENTION_SCOPE_UNKNOWN: target profile is unknown")?
            }
        };
        let mut pinned = BTreeSet::new();
        for job in inventory.jobs().context("RETENTION_INVENTORY_INVALID")? {
            let operation = inventory
                .job_operation(job.job_id)
                .context("RETENTION_INVENTORY_INVALID")?;
            if !job.state.is_terminal() {
                ensure!(
                    operation.is_some(),
                    "RETENTION_JOB_DEPENDENCY: open job dependencies are unknown; recover explicitly"
                );
                if let Some(id) = job.backup_id {
                    pinned.insert(id);
                } else {
                    let intent = (|| -> Result<_> {
                        let intent = inventory.deletion_job_for_job(job.job_id)?;
                        let saved = load_plan(root, intent.plan_id)?;
                        intent.validate(&saved)?;
                        Ok(intent)
                    })()
                    .context(
                        "RETENTION_JOB_DEPENDENCY: exact open-job evidence is missing or invalid",
                    )?;
                    pinned.extend(intent.dependencies.into_iter().map(|d| d.backup_id));
                }
            }
        }
        let mut valid = Vec::new();
        let mut excluded = Vec::new();
        for row in &rows {
            let protection = inventory
                .protection(row.backup_id)
                .context("RETENTION_INVENTORY_INVALID")?;
            let scoped = row.profile_fingerprint.as_deref() == Some(profile.as_str());
            ensure!(
                !scoped || protection.is_some(),
                "RETENTION_PROTECTION_UNKNOWN: establish protection for every known scope member"
            );
            let mut reasons = Vec::new();
            match &row.profile_fingerprint {
                None => reasons.push("unknown_profile"),
                Some(_) if !scoped => reasons.push("outside_scope"),
                _ => {}
            }
            if row.completed_at_utc.is_none() {
                reasons.push("unknown_time");
            }
            if row.shape != Shape::V1Signed {
                reasons.push("unsigned");
            }
            if inventory
                .is_provisional(row.backup_id)
                .context("RETENTION_INVENTORY_INVALID")?
            {
                reasons.push("unconfirmed");
            }
            match row.state {
                State::Missing => reasons.push("missing"),
                State::Conflict => reasons.push("conflict"),
                State::Registered => {}
                State::Deleting => reasons.push("deleting"),
                State::Deleted => reasons.push("deleted"),
            }
            let event = if scoped && reasons.is_empty() {
                inventory
                    .current_archive_event(
                        row.backup_id,
                        row.payload_sha256.as_deref().unwrap(),
                        row.manifest_sha256.as_deref().unwrap(),
                    )
                    .context("RETENTION_INVENTORY_INVALID")?
            } else {
                None
            };
            if scoped && reasons.is_empty() && event.is_none() {
                reasons.push("verification_required");
            }
            if reasons.is_empty() {
                valid.push(RetentionMember {
                    snapshot: ArtifactSnapshot {
                        backup_id: row.backup_id,
                        completed_at_utc: row.completed_at_utc.clone().unwrap(),
                        signer_id: row.signer_id.clone().unwrap(),
                        protection: if protection == Some(true) {
                            Protection::Protected
                        } else {
                            Protection::Unprotected
                        },
                        verification_event_id: event.unwrap(),
                        files: vec![],
                    },
                    job_dependency: pinned.contains(&row.backup_id),
                });
            } else {
                if matches!(request, RetentionRequest::Delete { backup_id } if *backup_id == row.backup_id)
                {
                    ensure!(
                        !reasons.contains(&"verification_required"),
                        "RETENTION_VERIFICATION_REQUIRED: target needs a current matching archive observation"
                    );
                    anyhow::bail!("RETENTION_SCOPE_UNKNOWN: target is not known valid");
                }
                excluded.push(RetentionExclusion::new(Some(row.backup_id), &reasons));
            }
        }
        let mut selection = select_retention(request, valid)?;
        let candidates: BTreeSet<_> = selection.candidates.iter().map(|a| a.backup_id).collect();
        let ids: BTreeSet<_> = selection
            .candidates
            .iter()
            .chain(&selection.retained)
            .map(|a| a.backup_id)
            .collect();
        let mut resources = Vec::new();
        for id in ids {
            resources.push(
                ResourceLock::artifact(root, id, candidates.contains(&id))
                    .context("RETENTION_BUSY: unsafe artifact claim")?
                    .context("RETENTION_BUSY: needed artifact is in use")?,
            );
        }
        let (entries, _) =
            LocalReconciler(root.clone())
                .scan_files(&rows)
                .context(if expected.is_some() {
                    "RETENTION_PLAN_STALE: complete scan failed"
                } else {
                    "RETENTION_ARTIFACT_INVALID: complete scan failed"
                })?;
        let observed: BTreeMap<_, _> = entries
            .iter()
            .filter_map(|e| e.backup_id.map(|id| (id, e.status)))
            .collect();
        for e in &entries {
            if e.backup_id.is_none() || !rows.iter().any(|r| Some(r.backup_id) == e.backup_id) {
                excluded.push(RetentionExclusion::new(e.backup_id, &[e.status]));
            }
        }
        let keys = (|| -> Result<_> {
            let encryption = self
                .0
                .encryption
                .as_ref()
                .context("missing reader identity")?;
            let signing = self
                .0
                .signing
                .as_ref()
                .context("missing trusted verifier")?;
            LocalStore::reader_keys(&encryption.identity_file, &signing.verifying_key_file)
        })()
        .map_err(|_| {
            anyhow::anyhow!(
                "RETENTION_ARTIFACT_INVALID: reader identity and trusted verifier are required"
            )
        })?;
        let store = LocalStore {
            root: root.clone(),
            keys: Some(keys),
        };
        let artifacts =
            open_at(&root_fd, ARTIFACTS_DIR, true).context("RETENTION_ARTIFACT_INVALID")?;
        for a in selection
            .candidates
            .iter_mut()
            .chain(&mut selection.retained)
        {
            let authenticated = (|| -> Result<Vec<FileSnapshot>> {
                ensure!(
                    observed.get(&a.backup_id) == Some(&"registered"),
                    "needed files changed"
                );
                let dir = open_at(&artifacts, &a.backup_id.to_string(), true)?;
                let path = descriptor_path(&dir);
                let before = file_snapshot(&dir)?;
                let signed = store.open_signed_claimed(a.backup_id, &path, activity)?;
                let row = rows.iter().find(|r| r.backup_id == a.backup_id).unwrap();
                ensure!(
                    signed.manifest.source_fingerprint == inventory.estate().source_fingerprint
                        && profile_fingerprint(&signed.manifest.profile_snapshot.name) == profile
                        && signed.manifest.completed_at_utc == a.completed_at_utc
                        && row.matches_header(&signed.header),
                    "authenticated facts disagree"
                );
                let mut names = DELETION_FILES.to_vec();
                if signed.globals.is_some() {
                    names.push("globals.age");
                    names.sort_unstable();
                }
                ensure!(
                    before.iter().map(|f| f.name.as_str()).collect::<Vec<_>>() == names,
                    "unexpected artifact file set"
                );
                ensure!(
                    before == file_snapshot(&dir)?,
                    "files changed during authentication"
                );
                Ok(before)
            })();
            a.files = authenticated.map_err(|_| {
                anyhow::anyhow!(if expected.is_some() {
                    "RETENTION_PLAN_STALE: needed artifact no longer matches; prepare a new preview"
                } else {
                    "RETENTION_ARTIFACT_INVALID: needed artifact files or authentication disagree"
                })
            })?;
            a.validate().map_err(|_| {
                anyhow::anyhow!("RETENTION_ARTIFACT_INVALID: invalid authenticated file snapshot")
            })?;
        }
        selection.excluded.extend(excluded);
        selection.excluded.sort_by(|a, b| {
            (a.backup_id.is_none(), a.backup_id, &a.reasons).cmp(&(
                b.backup_id.is_none(),
                b.backup_id,
                &b.reasons,
            ))
        });
        quiet(root)?;
        ensure!(
            hash_file(&index)?.1 == index_hash,
            "RETENTION_PLAN_STALE: inventory changed during preview"
        );
        if let Some(plan) = expected {
            ensure!(
                plan.source_fingerprint == inventory.estate().source_fingerprint
                    && plan.profile_fingerprint == profile
                    && plan.candidates == selection.candidates
                    && plan.retained == selection.retained,
                "RETENTION_PLAN_STALE: exact selection or files changed"
            );
        }
        Ok(Snapshot {
            source: inventory.estate().source_fingerprint.clone(),
            profile,
            inventory_sha256: index_hash,
            selection,
            _resources: resources,
            _activity: None,
        })
    }

    fn save(&self, saved: &SavedDeletionPlan) -> Result<()> {
        saved.validate(saved.plan.plan_id, saved.plan.operation, now()?)?;
        let bytes = serde_json::to_vec_pretty(saved)?;
        ensure!(
            bytes.len() <= DELETION_PLAN_MAX_BYTES,
            "RETENTION_PLAN_TOO_LARGE: exact envelope exceeds 64 KiB"
        );
        let dir = plan_dir(&self.0.storage.root, true).context("RETENTION_PLAN_INVALID")?;
        let path = descriptor_path(&dir).join(format!("deletion-{}.json", saved.plan.plan_id));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .context("RETENTION_PLAN_INVALID: cannot create plan")?;
        let result = (|| -> Result<()> {
            private(&file)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            dir.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
            let _ = dir.sync_all();
        }
        result.context("RETENTION_PLAN_INVALID: plan was not durably saved")
    }

    /// Checks saved intent only; execution revalidates under its own held claims.
    pub fn check_saved_plan(
        &self,
        id: Uuid,
        operation: RetentionOperation,
        confirmation: &str,
    ) -> Result<DeletionPlan> {
        let saved = load_plan(&self.0.storage.root, id)?;
        saved.validate(id, operation, now()?)?;
        ensure!(
            confirmation == saved.digest,
            "RETENTION_CONFIRMATION_MISMATCH: full lowercase digest required"
        );
        let request = match operation {
            RetentionOperation::Prune => RetentionRequest::Prune {
                keep_last: saved.plan.keep_last.unwrap(),
                profile_fingerprint: saved.plan.profile_fingerprint.clone(),
            },
            RetentionOperation::Delete => RetentionRequest::Delete {
                backup_id: saved.plan.candidates[0].backup_id,
            },
        };
        let _snapshot = self.snapshot(&request, Some(&saved.plan))?;
        saved.plan.validate(now()?)?;
        Ok(saved.plan)
    }
}

fn file_snapshot(dir: &File) -> Result<Vec<FileSnapshot>> {
    let path = descriptor_path(dir);
    let mut names = entries_for_hash(dir)?;
    names.sort();
    ensure!(
        names
            .iter()
            .all(|n| DELETION_FILES.contains(&n.as_str()) || n == "globals.age"),
        "unexpected artifact component"
    );
    names
        .into_iter()
        .map(|name| {
            let (bytes, sha256) = hash_file(&path.join(&name))?;
            Ok(FileSnapshot {
                name,
                bytes,
                sha256,
            })
        })
        .collect()
}

impl RetentionPlanner for LocalRetention {
    fn preview(&self, request: &RetentionRequest) -> Result<RetentionPreview> {
        let snapshot = self.snapshot(request, None)?;
        let mut report = RetentionPreview {
            operation: request.operation(),
            source_fingerprint: snapshot.source.clone(),
            profile_fingerprint: snapshot.profile.clone(),
            keep_last: request.keep_last(),
            candidates: snapshot
                .selection
                .candidates
                .iter()
                .map(|a| a.backup_id)
                .collect(),
            retained: snapshot
                .selection
                .retained
                .iter()
                .map(|a| a.backup_id)
                .collect(),
            excluded: snapshot.selection.excluded.clone(),
            plan_id: None,
            digest: None,
            expires_unix_ms: None,
            audit_recorded: false,
        };
        if !report.candidates.is_empty() {
            let created = now()?;
            let plan = DeletionPlan {
                format: DELETION_PLAN_FORMAT.to_string(),
                plan_id: Uuid::new_v4(),
                operation: request.operation(),
                source_fingerprint: snapshot.source.clone(),
                profile_fingerprint: snapshot.profile.clone(),
                keep_last: request.keep_last(),
                created_unix_ms: created,
                expires_unix_ms: created
                    .checked_add(DELETION_PLAN_TTL_MS)
                    .context("RETENTION_PLAN_INVALID: expiry overflow")?,
                inventory_sha256: snapshot.inventory_sha256.clone(),
                candidates: snapshot.selection.candidates.clone(),
                retained: snapshot.selection.retained.clone(),
            };
            let saved = SavedDeletionPlan {
                digest: plan.digest()?,
                plan,
            };
            self.save(&saved)?;
            report.plan_id = Some(saved.plan.plan_id);
            report.digest = Some(saved.digest);
            report.expires_unix_ms = Some(saved.plan.expires_unix_ms);
        }
        Ok(report)
    }
}

fn maintenance(root: &Path) -> Result<ActivityLock> {
    directory(root).context("RETENTION_INVENTORY_INVALID")?;
    ActivityLock::hold_maintenance(root)
        .context("RETENTION_BUSY: unsafe maintenance claim")?
        .context("RETENTION_BUSY: store has active work")
}
fn load_plan(root: &Path, id: Uuid) -> Result<SavedDeletionPlan> {
    ensure!(
        id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122,
        "RETENTION_PLAN_INVALID: expected UUIDv4"
    );
    let dir = plan_dir(root, false).context("RETENTION_PLAN_INVALID")?;
    let file = open_regular(&descriptor_path(&dir).join(format!("deletion-{id}.json")))
        .context("RETENTION_PLAN_INVALID")?;
    private(&file)?;
    ensure!(
        file.metadata()?.len() <= DELETION_PLAN_MAX_BYTES as u64,
        "RETENTION_PLAN_TOO_LARGE: envelope exceeds 64 KiB"
    );
    let mut bytes = Vec::new();
    file.take(DELETION_PLAN_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("RETENTION_PLAN_INVALID")?;
    ensure!(
        bytes.len() <= DELETION_PLAN_MAX_BYTES,
        "RETENTION_PLAN_TOO_LARGE: envelope exceeds 64 KiB"
    );
    let saved: SavedDeletionPlan = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("RETENTION_PLAN_INVALID: malformed envelope"))?;
    saved.validate_structure(id, saved.plan.operation)?;
    Ok(saved)
}
fn partition(
    saved: &SavedDeletionPlan,
    job: &backup_inventory::DeletionJob,
    audit_recorded: bool,
) -> Result<backup_application::DeletionOutcome> {
    job.validate(saved)?;
    let mut result = backup_application::DeletionResult {
        operation: saved.plan.operation,
        plan_id: saved.plan.plan_id,
        digest: saved.digest.clone(),
        job_id: job.job.job_id,
        outcome: "partial",
        completed: Vec::new(),
        deleting: Vec::new(),
        pending: Vec::new(),
        audit_recorded,
    };
    for d in job.dependencies.iter().filter(|d| d.role == "candidate") {
        match d.progress.as_str() {
            "pending" => result.pending.push(d.backup_id),
            "deleting" => result.deleting.push(d.backup_id),
            "deleted" => result.completed.push(d.backup_id),
            _ => anyhow::bail!("DELETION_RECOVERY_REQUIRED: invalid progress"),
        }
    }
    let error = if job.job.state == backup_inventory::JobState::Complete {
        result.outcome = "complete";
        None
    } else {
        Some("DELETION_RECOVERY_REQUIRED")
    };
    Ok(backup_application::DeletionOutcome { result, error })
}
impl backup_application::DeletionExecutor for LocalRetention {
    /// A receipt is checked before expiry or files; a failed job can never resume pending IDs.
    fn run(
        &self,
        id: Uuid,
        operation: RetentionOperation,
        confirmation: &str,
    ) -> Result<backup_application::DeletionOutcome> {
        let root = &self.0.storage.root;
        let saved = load_plan(root, id)?;
        saved.validate_structure(id, operation)?;
        ensure!(
            confirmation == saved.digest,
            "RETENTION_CONFIRMATION_MISMATCH: full lowercase digest required"
        );
        let activity = maintenance(root)?;
        quiet(root)?;
        let path = root.join(INVENTORY_FILE);
        let inventory =
            Inventory::open_read_only_bound(&path).context("RETENTION_INVENTORY_INVALID")?;
        ensure!(
            inventory.schema_version()? == SCHEMA_VERSION
                && inventory.integrity_problems()?.is_empty(),
            "RETENTION_INVENTORY_INVALID: current healthy schema required"
        );
        if let Some(job) = inventory.deletion_job(id)? {
            return partition(&saved, &job, false);
        }
        drop(inventory);
        saved.plan.validate(now()?)?;
        let request = match operation {
            RetentionOperation::Prune => RetentionRequest::Prune {
                keep_last: saved.plan.keep_last.unwrap(),
                profile_fingerprint: saved.plan.profile_fingerprint.clone(),
            },
            RetentionOperation::Delete => RetentionRequest::Delete {
                backup_id: saved.plan.candidates[0].backup_id,
            },
        };
        let _snapshot = self.snapshot_claimed(&request, Some(&saved.plan), &activity)?;
        saved.plan.validate(now()?)?;
        let estate = backup_inventory::Estate::new(saved.plan.source_fingerprint.clone())?;
        let inventory = Inventory::open_existing_current(&path, &estate)
            .context("RETENTION_INVENTORY_INVALID")?;
        let job_id = inventory.begin_deletion(&saved)?;
        let execution = (|| -> Result<()> {
            for candidate in &saved.plan.candidates {
                inventory.mark_deleting(job_id, candidate.backup_id)?;
                remove_candidate(root, candidate, false)?;
                inventory.mark_deleted(job_id, candidate.backup_id)?;
            }
            inventory.finish_deletion(job_id, true)
        })();
        if execution.is_err() {
            // Keep failure details out of the keyless ledger and expose the durable partition.
            let _ = inventory.finish_deletion(job_id, false);
        }
        let job = inventory
            .deletion_job(id)?
            .context("DELETION_RECOVERY_REQUIRED: missing started intent")?;
        partition(&saved, &job, true)
    }
}

fn unlink(dir: &File, name: &str, directory: bool) -> Result<()> {
    let name = std::ffi::CString::new(name)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Recovery accepts only a matching subset of the exact fixed files. Never recursively remove.
fn remove_candidate(root: &Path, candidate: &ArtifactSnapshot, recovering: bool) -> Result<()> {
    let root = directory(root)?;
    let parent = open_at(&root, ARTIFACTS_DIR, true)?;
    let name = candidate.backup_id.to_string();
    let dir = match open_at(&parent, &name, true) {
        Ok(dir) => dir,
        Err(e) if recovering && e.kind() == std::io::ErrorKind::NotFound => {
            parent.sync_all()?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let remaining = file_snapshot(&dir)?;
    ensure!(
        (recovering || remaining == candidate.files)
            && remaining.iter().all(|file| candidate.files.contains(file)),
        "DELETION_RECOVERY_REQUIRED: remaining files disagree with confirmed intent"
    );
    if remaining.iter().any(|f| f.name == "complete") {
        unlink(&dir, "complete", false)?;
    }
    // A durable absent marker precedes every content unlink, including an interrupted retry.
    dir.sync_all()?;
    for file in &remaining {
        if file.name != "complete" {
            unlink(&dir, &file.name, false)?;
        }
    }
    dir.sync_all()?;
    let current = open_at(&parent, &name, true)?;
    ensure!(
        dir.metadata()?.ino() == current.metadata()?.ino()
            && dir.metadata()?.dev() == current.metadata()?.dev(),
        "DELETION_RECOVERY_REQUIRED: artifact directory changed"
    );
    unlink(&parent, &name, true)?;
    parent.sync_all()?;
    Ok(())
}

/// Called only by the existing exclusive maintenance pass, never by ordinary opens.
pub(crate) fn recover_deletions(
    root: &Path,
    inventory: &Inventory,
    _activity: &ActivityLock,
) -> Result<Vec<Uuid>> {
    let mut jobs = Vec::new();
    let mut started = BTreeSet::new();
    for id in inventory.deletion_recovery_ids()? {
        let job = inventory
            .deletion_job(id)?
            .context("DELETION_RECOVERY_REQUIRED: missing intent")?;
        for d in job
            .dependencies
            .iter()
            .filter(|d| d.role == "candidate" && d.progress == "deleting")
        {
            started.insert(d.backup_id);
        }
        if job.dependencies.iter().any(|d| d.progress == "deleting") {
            jobs.push(job);
        }
    }
    ensure!(
        inventory
            .artifacts()?
            .iter()
            .filter(|a| a.state == State::Deleting)
            .all(|a| started.contains(&a.backup_id)),
        "DELETION_RECOVERY_REQUIRED: deleting artifact has no intact job evidence"
    );
    let mut completed = Vec::new();
    for job in jobs {
        let saved = load_plan(root, job.plan_id)
            .context("DELETION_RECOVERY_REQUIRED: missing or invalid saved intent")?;
        job.validate(&saved)?;
        let mut resources = Vec::new();
        for d in &job.dependencies {
            resources.push(
                ResourceLock::artifact(root, d.backup_id, d.role == "candidate")?
                    .context("RETENTION_BUSY: recovery artifact is in use")?,
            );
        }
        for candidate in &saved.plan.candidates {
            if job
                .dependencies
                .iter()
                .any(|d| d.backup_id == candidate.backup_id && d.progress == "deleting")
            {
                remove_candidate(root, candidate, true)
                    .context("DELETION_RECOVERY_REQUIRED: cannot finish started deletion")?;
                inventory.mark_deleted(job.job.job_id, candidate.backup_id)?;
                completed.push(candidate.backup_id);
            }
        }
    }
    completed.sort_unstable();
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn save_refuses_overwrite_and_oversize_without_leaving_an_incomplete_plan() {
        let root = std::env::temp_dir().join(format!("backupctl-plan-bound-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let config = Config {
            source: backup_domain::Source {
                host: "127.0.0.1".into(),
                port: 5432,
                user: "postgres".into(),
                database: "backupctl_fixture_plan".into(),
                client_bin_dir: "/nonexistent".into(),
                password_file: None,
            },
            storage: backup_domain::Storage { root: root.clone() },
            encryption: None,
            signing: None,
            profiles: vec![],
            export_globals: false,
            timeout_seconds: 30,
        };
        let planner = LocalRetention(config);
        let body = include_str!("../../../docs/development/m5b-retention.md")
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        let mut plan: DeletionPlan = serde_json::from_str(body).unwrap();
        plan.created_unix_ms = now().unwrap();
        plan.expires_unix_ms = plan.created_unix_ms + DELETION_PLAN_TTL_MS;
        let saved = SavedDeletionPlan {
            digest: plan.digest().unwrap(),
            plan: plan.clone(),
        };
        planner.save(&saved).unwrap();
        let path = root
            .join("plans")
            .join(format!("deletion-{}.json", plan.plan_id));
        let original = fs::read(&path).unwrap();
        assert!(
            planner
                .save(&saved)
                .unwrap_err()
                .to_string()
                .contains("RETENTION_PLAN_INVALID")
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        let duplicate = plan.retained[0].clone();
        for n in 3..100 {
            let mut member = duplicate.clone();
            member.backup_id = Uuid::from_u128(0x20000000000040008000000000000000 + n);
            plan.retained.push(member);
        }
        plan.plan_id = Uuid::new_v4();
        let oversized = SavedDeletionPlan {
            digest: plan.digest().unwrap(),
            plan,
        };
        assert!(
            planner
                .save(&oversized)
                .unwrap_err()
                .to_string()
                .contains("RETENTION_PLAN_TOO_LARGE")
        );
        assert_eq!(fs::read_dir(root.join("plans")).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
