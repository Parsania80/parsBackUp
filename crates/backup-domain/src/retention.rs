//! Exact retention intent; eligibility is established by the authenticated storage reader.
use crate::is_utc_timestamp;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const DELETION_PLAN_FORMAT: &str = "backupctl-deletion-plan-v1";
pub const DELETION_PLAN_TTL_MS: u64 = 900_000;
pub const DELETION_PLAN_MAX_BYTES: usize = 64 * 1024;
pub const DELETION_FILES: [&str; 5] = [
    "complete",
    "manifest.age",
    "payload.age",
    "public.json",
    "signature.hybrid",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RetentionOperation {
    Prune,
    Delete,
}

#[derive(Clone, Debug)]
pub enum RetentionRequest {
    Prune {
        keep_last: u64,
        profile_fingerprint: String,
    },
    Delete {
        backup_id: Uuid,
    },
}
impl RetentionRequest {
    pub fn operation(&self) -> RetentionOperation {
        match self {
            Self::Prune { .. } => RetentionOperation::Prune,
            Self::Delete { .. } => RetentionOperation::Delete,
        }
    }
    pub fn keep_last(&self) -> Option<u64> {
        match self {
            Self::Prune { keep_last, .. } => Some(*keep_last),
            Self::Delete { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    Protected,
    Unprotected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSnapshot {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSnapshot {
    #[serde(deserialize_with = "canonical_uuid")]
    pub backup_id: Uuid,
    pub completed_at_utc: String,
    pub signer_id: String,
    pub protection: Protection,
    pub verification_event_id: i64,
    pub files: Vec<FileSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionPlan {
    pub format: String,
    #[serde(deserialize_with = "canonical_uuid")]
    pub plan_id: Uuid,
    pub operation: RetentionOperation,
    pub source_fingerprint: String,
    pub profile_fingerprint: String,
    #[serde(deserialize_with = "required_nullable")]
    pub keep_last: Option<u64>,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub inventory_sha256: String,
    pub candidates: Vec<ArtifactSnapshot>,
    pub retained: Vec<ArtifactSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedDeletionPlan {
    pub plan: DeletionPlan,
    pub digest: String,
}

fn required_nullable<'de, D: Deserializer<'de>>(
    de: D,
) -> std::result::Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(de)
}
fn canonical_uuid<'de, D: Deserializer<'de>>(de: D) -> std::result::Result<Uuid, D::Error> {
    let text = String::deserialize(de)?;
    let id = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
    if text != id.to_string()
        || id.get_version_num() != 4
        || id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(serde::de::Error::custom("expected canonical UUIDv4"));
    }
    Ok(id)
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl DeletionPlan {
    pub fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_structure()?;
        ensure!(
            now >= self.created_unix_ms && now < self.expires_unix_ms,
            "RETENTION_PLAN_EXPIRED: prepare a new preview"
        );
        Ok(())
    }

    pub fn validate_structure(&self) -> Result<()> {
        ensure!(
            self.format == DELETION_PLAN_FORMAT
                && self.plan_id.get_version_num() == 4
                && self.plan_id.get_variant() == uuid::Variant::RFC4122
                && hex(&self.source_fingerprint, 16)
                && hex(&self.profile_fingerprint, 16)
                && hex(&self.inventory_sha256, 64),
            "RETENTION_PLAN_INVALID: invalid format, identity or scope"
        );
        ensure!(
            self.created_unix_ms.checked_add(DELETION_PLAN_TTL_MS) == Some(self.expires_unix_ms),
            "RETENTION_PLAN_INVALID: invalid expiry interval"
        );
        ensure!(
            !self.candidates.is_empty() && !self.retained.is_empty(),
            "RETENTION_PLAN_INVALID: empty exact set"
        );
        match self.operation {
            RetentionOperation::Prune => {
                let n = self
                    .keep_last
                    .context("RETENTION_PLAN_INVALID: missing quota")?;
                ensure!(
                    n > 0
                        && self.retained.len() as u64
                            >= n.min((self.retained.len() + self.candidates.len()) as u64),
                    "RETENTION_PLAN_INVALID: invalid quota"
                );
                let mut all: Vec<_> = self.candidates.iter().chain(&self.retained).collect();
                all.sort_by(|a, b| {
                    b.completed_at_utc
                        .cmp(&a.completed_at_utc)
                        .then(a.backup_id.cmp(&b.backup_id))
                });
                ensure!(
                    all.iter()
                        .take(usize::try_from(n).unwrap_or(usize::MAX))
                        .all(|a| self.retained.iter().any(|r| r.backup_id == a.backup_id)),
                    "RETENTION_PLAN_INVALID: newest quota is not retained"
                );
            }
            RetentionOperation::Delete => ensure!(
                self.keep_last.is_none() && self.candidates.len() == 1,
                "RETENTION_PLAN_INVALID: invalid delete set"
            ),
        }
        let mut ids = BTreeSet::new();
        for set in [&self.candidates, &self.retained] {
            ensure!(
                set.windows(2).all(|w| w[0].backup_id < w[1].backup_id),
                "RETENTION_PLAN_INVALID: IDs are not sorted and unique"
            );
            for artifact in set {
                ensure!(
                    ids.insert(artifact.backup_id),
                    "RETENTION_PLAN_INVALID: overlapping IDs"
                );
                artifact.validate()?;
            }
        }
        ensure!(
            self.candidates
                .iter()
                .all(|a| a.protection == Protection::Unprotected),
            "RETENTION_PLAN_INVALID: protected candidate"
        );
        Ok(())
    }
}
impl ArtifactSnapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.backup_id.get_version_num() == 4
                && self.backup_id.get_variant() == uuid::Variant::RFC4122
                && is_utc_timestamp(&self.completed_at_utc)
                && hex(&self.signer_id, 16)
                && self.verification_event_id > 0,
            "RETENTION_PLAN_INVALID: invalid artifact facts"
        );
        ensure!(
            self.files.windows(2).all(|w| w[0].name < w[1].name),
            "RETENTION_PLAN_INVALID: file names are not sorted and unique"
        );
        let names: Vec<_> = self.files.iter().map(|f| f.name.as_str()).collect();
        let mut expected = DELETION_FILES.to_vec();
        if names.contains(&"globals.age") {
            expected.push("globals.age");
            expected.sort_unstable();
        }
        ensure!(
            names == expected && self.files.iter().all(|f| hex(&f.sha256, 64)),
            "RETENTION_PLAN_INVALID: invalid file set"
        );
        for f in &self.files {
            ensure!(
                match f.name.as_str() {
                    "complete" => f.bytes == 0 && f.sha256 == format!("{:x}", Sha256::digest([])),
                    "signature.hybrid" => f.bytes == 3373,
                    "public.json" => f.bytes > 0 && f.bytes <= crate::MAX_PUBLIC_JSON_BYTES as u64,
                    _ => f.bytes > 0,
                },
                "RETENTION_PLAN_INVALID: invalid file size or marker"
            );
        }
        Ok(())
    }
}
impl SavedDeletionPlan {
    pub fn validate(&self, id: Uuid, operation: RetentionOperation, now: u64) -> Result<()> {
        self.plan.validate(now)?;
        self.validate_structure(id, operation)
    }

    pub fn validate_structure(&self, id: Uuid, operation: RetentionOperation) -> Result<()> {
        self.plan.validate_structure()?;
        ensure!(
            self.plan.plan_id == id
                && self.plan.operation == operation
                && hex(&self.digest, 64)
                && self.plan.digest()? == self.digest,
            "RETENTION_PLAN_INVALID: identity, operation or digest mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetentionExclusion {
    pub backup_id: Option<Uuid>,
    pub reasons: Vec<String>,
}
impl RetentionExclusion {
    pub fn new(backup_id: Option<Uuid>, reasons: &[&str]) -> Self {
        let mut reasons: Vec<_> = reasons.iter().map(|r| r.to_string()).collect();
        reasons.sort();
        reasons.dedup();
        Self { backup_id, reasons }
    }
}
pub struct RetentionMember {
    pub snapshot: ArtifactSnapshot,
    pub job_dependency: bool,
}
pub struct RetentionSelection {
    pub candidates: Vec<ArtifactSnapshot>,
    pub retained: Vec<ArtifactSnapshot>,
    pub excluded: Vec<RetentionExclusion>,
}

pub fn select_retention(
    request: &RetentionRequest,
    mut valid: Vec<RetentionMember>,
) -> Result<RetentionSelection> {
    ensure!(
        !valid.is_empty(),
        "RETENTION_SCOPE_UNKNOWN: no known valid copy in scope"
    );
    ensure!(
        request.keep_last().is_none_or(|n| n > 0),
        "RETENTION_PLAN_INVALID: keep-last must be positive"
    );
    valid.sort_by(|a, b| {
        b.snapshot
            .completed_at_utc
            .cmp(&a.snapshot.completed_at_utc)
            .then(a.snapshot.backup_id.cmp(&b.snapshot.backup_id))
    });
    if let RetentionRequest::Delete { backup_id } = request {
        let target = valid
            .iter()
            .find(|a| a.snapshot.backup_id == *backup_id)
            .context("RETENTION_SCOPE_UNKNOWN: target is not known valid")?;
        ensure!(
            target.snapshot.protection != Protection::Protected,
            "RETENTION_PROTECTED: target is protected"
        );
        ensure!(
            !target.job_dependency,
            "RETENTION_JOB_DEPENDENCY: target is referenced by open work"
        );
        ensure!(
            valid.len() > 1,
            "RETENTION_LAST_VALID: another valid copy in this scope must survive"
        );
    }
    let mut selection = RetentionSelection {
        candidates: vec![],
        retained: vec![],
        excluded: vec![],
    };
    for (i, member) in valid.into_iter().enumerate() {
        let id = member.snapshot.backup_id;
        let mut reasons = Vec::new();
        if request.keep_last().is_some_and(|n| (i as u64) < n) {
            reasons.push("keep_last");
        }
        if member.snapshot.protection == Protection::Protected {
            reasons.push("protected");
        }
        if member.job_dependency {
            reasons.push("job_dependency");
        }
        let selected = match request {
            RetentionRequest::Prune { .. } => true,
            RetentionRequest::Delete { backup_id } => id == *backup_id,
        };
        if selected && reasons.is_empty() {
            selection.candidates.push(member.snapshot);
        } else {
            selection.retained.push(member.snapshot);
        }
        if !reasons.is_empty() {
            selection
                .excluded
                .push(RetentionExclusion::new(Some(id), &reasons));
        }
    }
    selection.candidates.sort_by_key(|a| a.backup_id);
    selection.retained.sort_by_key(|a| a.backup_id);
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector() -> (&'static str, DeletionPlan) {
        let body = include_str!("../../../docs/development/m5b-retention.md")
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        (body, serde_json::from_str(body).unwrap())
    }
    fn member(id: u128, time: &str, protected: bool, job: bool) -> RetentionMember {
        let mut snapshot = vector().1.candidates.remove(0);
        snapshot.backup_id = Uuid::from_u128(0x20000000000040008000000000000000 + id);
        snapshot.completed_at_utc = time.to_string();
        snapshot.protection = if protected {
            Protection::Protected
        } else {
            Protection::Unprotected
        };
        RetentionMember {
            snapshot,
            job_dependency: job,
        }
    }
    fn prune(n: u64) -> RetentionRequest {
        RetentionRequest::Prune {
            keep_last: n,
            profile_fingerprint: "1".repeat(16),
        }
    }
    #[test]
    fn canonical_vector_and_expiry_are_exact() {
        let (body, plan) = vector();
        assert_eq!(serde_json::to_string(&plan).unwrap(), body);
        assert_eq!(
            plan.digest().unwrap(),
            "b5198a0748f35d01db177f4af9f31890203755278185ef341c2bb8749c4b370a"
        );
        assert_eq!(backup_crypto::protocol::HYBRID_SIGNATURE_BYTES, 3373);
        plan.validate(plan.created_unix_ms).unwrap();
        plan.validate(plan.expires_unix_ms - 1).unwrap();
        for time in [plan.created_unix_ms - 1, plan.expires_unix_ms, u64::MAX] {
            assert!(
                plan.validate(time)
                    .unwrap_err()
                    .to_string()
                    .contains("EXPIRED")
            );
        }
        let mut overflow = plan.clone();
        overflow.created_unix_ms = u64::MAX;
        overflow.expires_unix_ms = 0;
        assert!(overflow.validate(0).is_err());
    }
    #[test]
    fn selection_counts_only_the_supplied_valid_scope_and_keeps_exclusions_in_addition() {
        let oldest = "2026-11-10T00:00:00Z";
        let newest = "2026-11-12T00:00:00Z";
        let result = select_retention(
            &prune(1),
            vec![
                member(3, oldest, true, false),
                member(2, oldest, false, false),
                member(1, newest, false, false),
            ],
        )
        .unwrap();
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|a| a.backup_id.as_u128() & 255)
                .collect::<Vec<_>>(),
            [2]
        );
        assert_eq!(result.retained.len(), 2);
        let tied = select_retention(
            &prune(1),
            vec![
                member(2, newest, false, false),
                member(1, newest, false, false),
            ],
        )
        .unwrap();
        assert_eq!(tied.candidates[0].backup_id.as_u128() & 255, 2);
        let pinned = select_retention(
            &prune(1),
            vec![
                member(1, newest, false, false),
                member(2, oldest, false, true),
            ],
        )
        .unwrap();
        assert!(pinned.candidates.is_empty());
        assert_eq!(pinned.retained.len(), 2);
        assert!(
            select_retention(&prune(1), vec![member(1, newest, false, false)])
                .unwrap()
                .candidates
                .is_empty()
        );
        assert!(select_retention(&prune(1), vec![]).is_err());
        assert!(select_retention(&prune(0), vec![member(1, newest, false, false)]).is_err());
        assert!(
            select_retention(&prune(u64::MAX), vec![member(1, newest, false, false)])
                .unwrap()
                .candidates
                .is_empty()
        );
    }
    #[test]
    fn explicit_delete_preserves_another_copy_and_refuses_pins() {
        let time = "2026-11-12T00:00:00Z";
        let id = member(1, time, false, false).snapshot.backup_id;
        let request = RetentionRequest::Delete { backup_id: id };
        for (protected, job, code) in [
            (true, false, "RETENTION_PROTECTED"),
            (false, true, "RETENTION_JOB_DEPENDENCY"),
        ] {
            let e = select_retention(
                &request,
                vec![
                    member(1, time, protected, job),
                    member(2, time, false, false),
                ],
            )
            .err()
            .unwrap();
            assert!(e.to_string().contains(code));
        }
        assert!(
            select_retention(&request, vec![member(1, time, false, false)])
                .err()
                .unwrap()
                .to_string()
                .contains("RETENTION_LAST_VALID")
        );
        let r = select_retention(
            &request,
            vec![member(1, time, false, false), member(2, time, false, false)],
        )
        .unwrap();
        assert_eq!(r.candidates[0].backup_id, id);
        assert_eq!(r.retained.len(), 1);
    }
    #[test]
    fn strict_parser_and_semantics_reject_mutated_intent() {
        let (body, plan) = vector();
        for altered in [
            body.replacen("{", "{\"extra\":0,", 1),
            body.replacen("\"keep_last\":null,", "", 1),
            body.replacen("{", "{\"format\":\"backupctl-deletion-plan-v1\",", 1),
            body.replacen(
                "10000000-0000-4000-8000-000000000001",
                "10000000000040008000000000000001",
                1,
            ),
            body.replacen("\"delete\"", "\"execute\"", 1),
        ] {
            assert!(
                serde_json::from_str::<DeletionPlan>(&altered).is_err(),
                "accepted {altered}"
            );
        }
        let mut cases = Vec::new();
        let mut p = plan.clone();
        p.retained = p.candidates.clone();
        cases.push(p);
        let mut p = plan.clone();
        p.candidates[0].files.swap(0, 1);
        cases.push(p);
        let mut p = plan.clone();
        let duplicate = p.candidates[0].files[0].clone();
        p.candidates[0].files.push(duplicate);
        cases.push(p);
        let mut p = plan.clone();
        p.candidates[0].verification_event_id = 0;
        cases.push(p);
        let mut p = plan.clone();
        p.candidates[0].protection = Protection::Protected;
        cases.push(p);
        let mut p = plan.clone();
        p.candidates[0].files[1].name = "../payload.age".into();
        cases.push(p);
        let mut p = plan.clone();
        p.retained.clear();
        cases.push(p);
        let mut p = plan.clone();
        p.operation = RetentionOperation::Prune;
        p.keep_last = Some(2);
        cases.push(p);
        let mut p = plan.clone();
        p.inventory_sha256 = "A".repeat(64);
        cases.push(p);
        for p in cases {
            assert!(p.validate(p.created_unix_ms).is_err());
            assert_ne!(p.digest().unwrap(), plan.digest().unwrap());
        }
        let saved = SavedDeletionPlan {
            plan: plan.clone(),
            digest: plan.digest().unwrap(),
        };
        saved
            .validate(plan.plan_id, plan.operation, plan.created_unix_ms)
            .unwrap();
        assert!(
            saved
                .validate(Uuid::new_v4(), plan.operation, plan.created_unix_ms)
                .is_err()
        );
        assert!(
            saved
                .validate(
                    plan.plan_id,
                    RetentionOperation::Prune,
                    plan.created_unix_ms
                )
                .is_err()
        );
    }
}
