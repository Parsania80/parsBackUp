//! Explicit reconciliation of disk observations with the local inventory.
use crate::layout::*;
use anyhow::{Context, Result, ensure};
use backup_application::{DiscoveryEntry, ReconcileReport, Reconciler};
use backup_domain::{
    AGE_FORMAT, DEV_FORMAT, DevelopmentManifest, MAX_PUBLIC_JSON_BYTES, PublicHeader,
};
use backup_inventory::{ActivityLock, ArtifactRow, Estate, Inventory, Shape, State};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct LocalReconciler(pub PathBuf);

type StateChanges = Vec<(Uuid, State, State)>;

// Open relative to the already-held directory descriptor, never following a final symlink.
fn open_at(dir: &File, name: &str, directory: bool) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?)
}

fn entries(dir: &File) -> Result<fs::ReadDir> {
    // shortcut: requires Linux procfs, use descriptor-based directory iteration for other targets.
    Ok(fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?)
}

fn entries_for_hash(dir: &File) -> Result<Vec<String>> {
    entries(dir)?
        .map(|entry| {
            let name = entry?.file_name();
            name.into_string()
                .map_err(|_| anyhow::anyhow!("artifact has a non-UTF-8 component"))
        })
        .collect()
}

#[derive(Debug)]
enum Problem {
    Missing,
    Invalid,
    Io(io::Error),
}
impl From<io::Error> for Problem {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            Self::Missing
        } else if matches!(
            e.raw_os_error(),
            Some(libc::ELOOP | libc::ENOTDIR | libc::ENXIO | libc::ENODEV)
        ) {
            Self::Invalid
        } else {
            Self::Io(e)
        }
    }
}

fn component(dir: &File, name: &str) -> std::result::Result<File, Problem> {
    let file = open_at(dir, name, false)?;
    if !file.metadata()?.is_file() {
        return Err(Problem::Invalid);
    }
    Ok(file)
}

fn bytes(dir: &File, name: &str, max: u64) -> std::result::Result<Vec<u8>, Problem> {
    let file = component(dir, name)?;
    let mut out = Vec::new();
    file.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(Problem::Invalid);
    }
    Ok(out)
}

fn absent(dir: &File, name: &str) -> std::result::Result<(), Problem> {
    match open_at(dir, name, false) {
        Ok(_) => Err(Problem::Invalid),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn digest(
    dir: &File,
    name: &str,
    expected_size: u64,
    expected_digest: &str,
) -> std::result::Result<bool, Problem> {
    let file = component(dir, name)?;
    if file.metadata()?.len() != expected_size {
        return Ok(false);
    }
    let mut reader = file.take(expected_size.saturating_add(1));
    let mut hash = Sha256::new();
    let count = io::copy(&mut reader, &mut hash)?;
    Ok(count == expected_size && format!("{:x}", hash.finalize()) == expected_digest)
}

fn observe(
    dir: &File,
    id: Uuid,
    row: Option<&backup_inventory::ArtifactRow>,
) -> std::result::Result<(&'static str, bool), Problem> {
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        if !entry?.file_type()?.is_file() {
            return Err(Problem::Invalid);
        }
    }
    component(dir, COMPLETE_MARKER)?;
    let public = match bytes(dir, PUBLIC_FILE, MAX_PUBLIC_JSON_BYTES as u64) {
        Ok(data) => Some(data),
        Err(Problem::Missing) => None,
        Err(e) => return Err(e),
    };
    if let Some(public) = public {
        let text = std::str::from_utf8(&public).map_err(|_| Problem::Invalid)?;
        let header = PublicHeader::from_json(text).map_err(|_| Problem::Invalid)?;
        if header.backup_id != id {
            return Err(Problem::Invalid);
        }
        if component(dir, SIGNATURE_FILE)?.metadata()?.len()
            != backup_crypto::protocol::HYBRID_SIGNATURE_BYTES as u64
        {
            return Err(Problem::Invalid);
        }
        let manifest_ok = digest(
            dir,
            AGE_MANIFEST_FILE,
            header.manifest_ciphertext_bytes,
            &header.manifest_sha256,
        )?;
        let payload_ok = digest(
            dir,
            AGE_PAYLOAD_FILE,
            header.payload_ciphertext_bytes,
            &header.payload_sha256,
        )?;
        let agrees = row.is_none_or(|r| {
            r.shape == Shape::V1Signed
                && r.payload_sha256.as_deref() == Some(&header.payload_sha256)
                && r.manifest_sha256.as_deref() == Some(&header.manifest_sha256)
                && r.payload_bytes == Some(header.payload_ciphertext_bytes)
                && r.manifest_bytes == Some(header.manifest_ciphertext_bytes)
                && r.signer_id.as_deref() == Some(&header.signer_id)
                && r.recipient_id.as_deref() == Some(&header.recipient_id)
                && r.recipient_suite.as_deref() == Some(&header.recipient_suite)
                && r.signature_suite.as_deref() == Some(&header.signature_suite)
        });
        for name in [MANIFEST_FILE, PAYLOAD_FILE, GLOBALS_FILE] {
            absent(dir, name)?;
        }
        Ok(("v1-signed", manifest_ok && payload_ok && agrees))
    } else {
        let manifest = bytes(dir, MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
        let manifest: DevelopmentManifest =
            serde_json::from_slice(&manifest).map_err(|_| Problem::Invalid)?;
        manifest.validate_shape().map_err(|_| Problem::Invalid)?;
        if manifest.id != id {
            return Err(Problem::Invalid);
        }
        let (shape, payload) = match manifest.format.as_str() {
            DEV_FORMAT => ("plaintext-dev", PAYLOAD_FILE),
            AGE_FORMAT => ("age-unsigned", AGE_PAYLOAD_FILE),
            _ => return Err(Problem::Invalid),
        };
        for name in [AGE_MANIFEST_FILE, SIGNATURE_FILE] {
            absent(dir, name)?;
        }
        let (unused_payload, globals, unused_globals) = if manifest.format == AGE_FORMAT {
            (PAYLOAD_FILE, AGE_GLOBALS_FILE, GLOBALS_FILE)
        } else {
            (AGE_PAYLOAD_FILE, GLOBALS_FILE, AGE_GLOBALS_FILE)
        };
        absent(dir, unused_payload)?;
        absent(dir, unused_globals)?;
        let payload_ok = digest(dir, payload, manifest.size_bytes, &manifest.sha256)?;
        let globals_ok = if manifest.security_globals {
            digest(
                dir,
                globals,
                manifest.globals_size_bytes.ok_or(Problem::Invalid)?,
                manifest.globals_sha256.as_deref().ok_or(Problem::Invalid)?,
            )?
        } else {
            absent(dir, globals)?;
            true
        };
        let shape_ok = row.is_none_or(|r| r.shape.as_str() == shape);
        Ok((shape, shape_ok && payload_ok && globals_ok))
    }
}

impl Reconciler for LocalReconciler {
    fn discover(&self) -> Result<ReconcileReport> {
        self.scan(false)
    }

    fn reconcile(&self) -> Result<ReconcileReport> {
        self.scan(true)
    }
}

impl LocalReconciler {
    fn rebuild_digest(&self, estate: &Estate) -> Result<(ReconcileReport, String)> {
        let (entries, _) = self.scan_files(&[])?;
        ensure!(
            entries.iter().all(|e| e.status == "unregistered"),
            "artifact scan contains invalid, incomplete, or conflicting entries"
        );
        let root = directory(&self.0)?;
        let artifacts = open_at(&root, ARTIFACTS_DIR, true)?;
        let mut hash = Sha256::new();
        hash.update(b"backupctl-rebuild-plan-v1\0");
        hash.update(estate.source_fingerprint.as_bytes());
        hash.update((entries.len() as u64).to_be_bytes());
        for entry in &entries {
            let id = entry.backup_id.context("artifact name is invalid")?;
            self.candidate(id, estate)?;
            hash.update(id.as_bytes());
            let dir = open_at(&artifacts, &id.to_string(), true)?;
            let mut names = entries_for_hash(&dir)?;
            names.sort();
            hash.update((names.len() as u64).to_be_bytes());
            for name in names {
                hash.update((name.len() as u64).to_be_bytes());
                hash.update(name.as_bytes());
                let mut file = component(&dir, &name)
                    .map_err(|_| anyhow::anyhow!("artifact changed while preparing rebuild"))?;
                let size = file.metadata()?.len();
                hash.update(size.to_be_bytes());
                ensure!(
                    io::copy(&mut file, &mut hash)? == size,
                    "artifact changed while preparing rebuild"
                );
            }
        }
        match open_at(&root, INVENTORY_FILE, false) {
            Ok(mut file) => {
                ensure!(
                    file.metadata()?.is_file(),
                    "inventory is not a regular file"
                );
                hash.update(b"inventory-present\0");
                let size = file.metadata()?.len();
                hash.update(size.to_be_bytes());
                ensure!(
                    io::copy(&mut file, &mut hash)? == size,
                    "inventory changed while preparing rebuild"
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                hash.update(b"inventory-absent\0")
            }
            Err(error) => return Err(error.into()),
        }
        Ok((
            ReconcileReport {
                entries,
                audit_recorded: false,
            },
            format!("{:x}", hash.finalize()),
        ))
    }

    pub fn prepare_rebuild(&self, source_fingerprint: &str) -> Result<(Uuid, ReconcileReport)> {
        let estate = Estate::new(source_fingerprint.to_owned())?;
        let _claim = ActivityLock::hold_maintenance(&self.0)?
            .context("RECONCILE_BUSY: store has active work")?;
        let (report, digest) = self.rebuild_digest(&estate)?;
        let id = Uuid::new_v4();
        let path = self.0.join(format!(".inventory-rebuild-plan-{id}.json"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        serde_json::to_writer(
            &mut file,
            &serde_json::json!({"version": 1, "source_fingerprint": source_fingerprint, "digest": digest}),
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        directory(&self.0)?.sync_all()?;
        Ok((id, report))
    }
    fn candidate(&self, id: Uuid, estate: &Estate) -> Result<ArtifactRow> {
        let root = directory(&self.0)?;
        let artifacts = open_at(&root, ARTIFACTS_DIR, true)?;
        let dir = open_at(&artifacts, &id.to_string(), true)?;
        let public = match bytes(&dir, PUBLIC_FILE, MAX_PUBLIC_JSON_BYTES as u64) {
            Ok(data) => Some(data),
            Err(Problem::Missing) => None,
            Err(_) => anyhow::bail!("invalid artifact discovery record"),
        };
        let mut row = ArtifactRow {
            backup_id: id,
            source_fingerprint: estate.source_fingerprint.clone(),
            profile_fingerprint: None,
            shape: Shape::PlaintextDev,
            signer_id: None,
            recipient_id: None,
            payload_sha256: None,
            manifest_sha256: None,
            recipient_suite: None,
            signature_suite: None,
            payload_bytes: None,
            manifest_bytes: None,
            completed_at_utc: None,
            state: State::Registered,
        };
        if let Some(public) = public {
            let header = PublicHeader::from_json(std::str::from_utf8(&public)?)?;
            ensure!(header.backup_id == id, "artifact ID mismatch");
            row.shape = Shape::V1Signed;
            row.signer_id = Some(header.signer_id);
            row.recipient_id = Some(header.recipient_id);
            row.payload_sha256 = Some(header.payload_sha256);
            row.manifest_sha256 = Some(header.manifest_sha256);
            row.recipient_suite = Some(header.recipient_suite);
            row.signature_suite = Some(header.signature_suite);
            row.payload_bytes = Some(header.payload_ciphertext_bytes);
            row.manifest_bytes = Some(header.manifest_ciphertext_bytes);
        } else {
            let manifest = bytes(&dir, MANIFEST_FILE, MAX_MANIFEST_BYTES)
                .map_err(|_| anyhow::anyhow!("invalid development manifest"))?;
            let manifest: DevelopmentManifest = serde_json::from_slice(&manifest)?;
            row.shape = match manifest.format.as_str() {
                DEV_FORMAT => Shape::PlaintextDev,
                AGE_FORMAT => Shape::AgeUnsigned,
                _ => anyhow::bail!("unknown development format"),
            };
        }
        match observe(&dir, id, Some(&row)) {
            Ok((_, true)) => Ok(row),
            Ok(_) | Err(Problem::Missing | Problem::Invalid) => {
                anyhow::bail!("artifact is incomplete or conflicting")
            }
            Err(Problem::Io(error)) => Err(error.into()),
        }
    }

    pub fn adopt(&self, id: Uuid, source_fingerprint: &str) -> Result<()> {
        let estate = Estate::new(source_fingerprint.to_owned())?;
        let _claim = ActivityLock::hold_maintenance(&self.0)?
            .context("RECONCILE_BUSY: store has active work")?;
        let path = self.0.join(INVENTORY_FILE);
        let inventory = Inventory::open_read_only(&path, &estate)?;
        ensure!(
            inventory.integrity_problems()?.is_empty(),
            "inventory is corrupt"
        );
        let (entries, _) = self.scan_files(&inventory.artifacts()?)?;
        ensure!(
            entries
                .iter()
                .any(|entry| entry.backup_id == Some(id) && entry.status == "unregistered"),
            "artifact is absent, registered, incomplete, or invalid"
        );
        let row = self.candidate(id, &estate)?;
        drop(inventory);
        Inventory::open_existing_upgrade(&path, &estate)?.adopt(&row)
    }

    /// Rebuild a disposable index while retaining any old index under a unique name.
    pub fn rebuild(
        &self,
        source_fingerprint: &str,
        plan_id: Uuid,
    ) -> Result<(ReconcileReport, Option<PathBuf>)> {
        let estate = Estate::new(source_fingerprint.to_owned())?;
        let _claim = ActivityLock::hold_maintenance(&self.0)?
            .context("RECONCILE_BUSY: store has active work")?;
        let root_fd = directory(&self.0)?;
        let plan_name = format!(".inventory-rebuild-plan-{plan_id}.json");
        let plan_bytes = bytes(&root_fd, &plan_name, 4096)
            .map_err(|_| anyhow::anyhow!("cannot read rebuild plan"))?;
        let plan: serde_json::Value = serde_json::from_slice(&plan_bytes)?;
        ensure!(
            plan["version"] == 1 && plan["source_fingerprint"] == source_fingerprint,
            "rebuild plan does not match the requested source"
        );
        let (_, digest) = self.rebuild_digest(&estate)?;
        ensure!(
            plan["digest"].as_str() == Some(digest.as_str()),
            "rebuild plan is stale; prepare a new plan"
        );
        let path = self.0.join(INVENTORY_FILE);
        for suffix in ["-journal", "-wal", "-shm"] {
            let sidecar = self.0.join(format!("{INVENTORY_FILE}{suffix}"));
            match fs::symlink_metadata(sidecar) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    anyhow::bail!("inventory has a SQLite sidecar; recover it before rebuilding")
                }
                Err(error) => return Err(error.into()),
            }
        }
        let old_exists = match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink(),
                    "inventory is not a regular file"
                );
                if let Ok(version) = Inventory::probe_version(&path) {
                    ensure!(
                        version <= backup_inventory::SCHEMA_VERSION,
                        "inventory schema is newer than this build"
                    );
                }
                if let Ok(inventory) = Inventory::open_read_only_bound(&path) {
                    ensure!(inventory.estate() == &estate, "inventory estate mismatch");
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let (mut entries, _) = self.scan_files(&[])?;
        ensure!(
            entries.iter().all(|entry| entry.status == "unregistered"),
            "artifact scan contains invalid, incomplete, or conflicting entries"
        );
        let rows = entries
            .iter()
            .map(|entry| self.candidate(entry.backup_id.expect("validated ID"), &estate))
            .collect::<Result<Vec<_>>>()?;
        let stage = self
            .0
            .join(format!(".inventory-rebuild-{}.db", Uuid::new_v4()));
        let result = (|| -> Result<Option<PathBuf>> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&stage)?;
            drop(file);
            let staged = Inventory::initialize_staged(&stage, &estate)?;
            for row in &rows {
                staged.adopt(row)?;
            }
            staged.record_rebuild()?;
            ensure!(
                staged.integrity_problems()?.is_empty(),
                "staged inventory is corrupt"
            );
            ensure!(
                staged.artifacts()? == rows,
                "staged inventory does not match the scan"
            );
            drop(staged);
            File::open(&stage)?.sync_all()?;
            let backup = if old_exists {
                let backup = self
                    .0
                    .join(format!("inventory.db.previous-{}", Uuid::new_v4()));
                fs::hard_link(&path, &backup)?;
                root_fd.sync_all()?;
                Some(backup)
            } else {
                None
            };
            fs::rename(&stage, &path)?;
            root_fd
                .sync_all()
                .context("replacement installed, but syncing the store directory failed")?;
            Ok(backup)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&stage);
        }
        let backup = result?;
        for entry in &mut entries {
            entry.status = "registered";
            entry.provenance = Some("unconfirmed");
        }
        Ok((
            ReconcileReport {
                entries,
                audit_recorded: true,
            },
            backup,
        ))
    }
    fn scan(&self, write: bool) -> Result<ReconcileReport> {
        let root = &self.0;
        let _claim = if write {
            Some(
                ActivityLock::hold_maintenance(root)?
                    .context("RECONCILE_BUSY: store has active work")?,
            )
        } else {
            None
        };
        let path = root.join(INVENTORY_FILE);
        let inventory = Inventory::open_read_only_bound(&path).context("INVENTORY_OPEN_FAILED")?;
        ensure!(
            !write || inventory.schema_version()? == backup_inventory::SCHEMA_VERSION,
            "INVENTORY_OPEN_FAILED: upgrade the inventory before reconciliation"
        );
        ensure!(
            inventory.integrity_problems()?.is_empty(),
            "INVENTORY_READ_FAILED: inventory is corrupt"
        );
        let snapshot = inventory.artifacts()?;
        let estate = inventory.estate().clone();
        let (mut output, changes) = self.scan_files(&snapshot)?;
        if inventory.schema_version()? >= 3 {
            for entry in &mut output {
                if let Some(id) = entry.backup_id
                    && inventory.is_provisional(id)?
                {
                    entry.provenance = Some("unconfirmed");
                }
            }
        }
        if write && !changes.is_empty() {
            drop(inventory);
            let inventory = Inventory::open_existing_current(&path, &estate)
                .context("INVENTORY_OPEN_FAILED: cannot reopen inventory")?;
            inventory.reconcile_states(&snapshot, &changes)?;
        }
        Ok(ReconcileReport {
            entries: output,
            audit_recorded: write && !changes.is_empty(),
        })
    }

    /// Observe artifact files without requiring an inventory or loading keys.
    pub fn preview_rebuild(&self, source_fingerprint: &str) -> Result<ReconcileReport> {
        backup_inventory::Estate::new(source_fingerprint.to_owned())?;
        let (entries, _) = self.scan_files(&[])?;
        Ok(ReconcileReport {
            entries,
            audit_recorded: false,
        })
    }

    fn scan_files(
        &self,
        snapshot: &[backup_inventory::ArtifactRow],
    ) -> Result<(Vec<DiscoveryEntry>, StateChanges)> {
        let root = &self.0;
        let mut rows: BTreeMap<_, _> = snapshot.iter().cloned().map(|r| (r.backup_id, r)).collect();
        let root_fd = directory(root)?;
        let artifacts =
            open_at(&root_fd, ARTIFACTS_DIR, true).context("scan artifacts directory")?;
        let mut output = Vec::new();
        let mut changes = Vec::new();
        let disk_entries = entries(&artifacts)?.collect::<io::Result<Vec<_>>>()?;
        let aliases: BTreeSet<Uuid> = disk_entries
            .iter()
            .filter_map(|item| {
                let name = item.file_name();
                let name = name.to_str()?;
                let id = Uuid::parse_str(name).ok()?;
                (id.to_string() != name).then_some(id)
            })
            .collect();
        for item in disk_entries {
            let name = item.file_name();
            let Some(name) = name.to_str() else {
                output.push(DiscoveryEntry {
                    backup_id: None,
                    shape: None,
                    status: "invalid",
                    reason: Some("invalid_name"),
                    provenance: None,
                });
                continue;
            };
            let id = match Uuid::parse_str(name) {
                Ok(id) if id.to_string() == name => id,
                _ => {
                    output.push(DiscoveryEntry {
                        backup_id: None,
                        shape: None,
                        status: "invalid",
                        reason: Some("invalid_name"),
                        provenance: None,
                    });
                    continue;
                }
            };
            let row = rows.remove(&id);
            let observed = if aliases.contains(&id) {
                Err(Problem::Invalid)
            } else {
                match open_at(&artifacts, name, true) {
                    Ok(dir) => observe(&dir, id, row.as_ref()),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Err(e).context("artifact changed during scan");
                    }
                    Err(e) => Err(e.into()),
                }
            };
            let (shape, status, reason) = match observed {
                Ok((shape, true)) => (
                    Some(shape),
                    if row.is_some() {
                        "registered"
                    } else {
                        "unregistered"
                    },
                    None,
                ),
                Ok((shape, false)) => (Some(shape), "conflict", Some("facts_mismatch")),
                Err(Problem::Missing) => (
                    None,
                    if row.is_some() {
                        "conflict"
                    } else {
                        "incomplete"
                    },
                    Some("missing_component"),
                ),
                Err(Problem::Invalid) => (
                    None,
                    if row.is_some() { "conflict" } else { "invalid" },
                    Some("invalid_component"),
                ),
                Err(Problem::Io(e)) => return Err(e).context("artifact scan failed"),
            };
            if let Some(row) = row {
                let to = if status == "registered" {
                    State::Registered
                } else {
                    State::Conflict
                };
                if row.state != to {
                    changes.push((id, row.state, to));
                }
            }
            output.push(DiscoveryEntry {
                backup_id: Some(id),
                shape,
                status,
                reason,
                provenance: None,
            });
        }
        for (id, row) in rows {
            let to = if aliases.contains(&id) {
                State::Conflict
            } else {
                State::Missing
            };
            if row.state != to {
                changes.push((id, row.state, to));
            }
            output.push(DiscoveryEntry {
                backup_id: Some(id),
                shape: Some(row.shape.as_str()),
                status: if to == State::Missing {
                    "missing"
                } else {
                    "conflict"
                },
                reason: (to == State::Conflict).then_some("invalid_name"),
                provenance: None,
            });
        }
        output.sort_by_key(|e| (e.backup_id.is_none(), e.backup_id));
        Ok((output, changes))
    }
}
