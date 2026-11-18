//! Compose the synchronous core inside the isolated worker.
use crate::{
    Config,
    config::Selection,
    control::{self, Work},
    model::*,
};
use anyhow::{Context, Result, ensure};
use backup_application::{
    ArtifactStore, BackupService, InventoryService, Record, RestoreService, SignedArtifactHandle,
    VerifyService,
    control::{self as core_control, ExecutionFailure},
    execute_deletion, preview_retention,
};
use backup_domain::{
    Config as CoreConfig, ConfigV1, Encryption, RestoreSections, RestoreSecurityPolicy,
    RetentionRequest, Signing, Source,
};
use backup_local::{
    KeyUse, LocalProtection, ProtectedRetention, ProtectedRoot, open_protected_store,
};
use backup_postgres::PostgresAdapter;
use std::{ffi::CString, time::Duration};
use uuid::Uuid;

pub(crate) fn check_core_plan(config: &ConfigV1, intent: &Intent) -> Result<()> {
    let check = || -> Result<()> {
        let root = ProtectedRoot::open(config, false)?;
        let bound = &intent.bound;
        match &bound.confirmation {
            Confirmation::Restore(c) => {
                let plan = root
                    .saved_restore_plan(bound.core_plan_id)?
                    .context(ErrorCode::IntentConflict)?;
                plan.validate(now()?.into())?;
                ensure!(
                    plan.digest() == bound.core_plan_digest
                        && plan.target_database == c.target_database
                        && plan.artifact_id == c.artifact_id
                        && plan.security == security(c.security)
                        && plan.sections == sections(c.sections),
                    ErrorCode::IntentConflict
                );
            }
            Confirmation::Retention(_) => {
                ProtectedRetention::bound_plan(&root, bound.core_plan_id, &bound.core_plan_digest)?;
            }
        }
        Ok(())
    };
    check().context(ErrorCode::IntentConflict)
}

fn security(value: Security) -> RestoreSecurityPolicy {
    match value {
        Security::Portable => RestoreSecurityPolicy::portable(),
        Security::DrFull => RestoreSecurityPolicy::dr_full(),
    }
}

fn sections(value: Sections) -> RestoreSections {
    RestoreSections {
        pre_data: true,
        data: value != Sections::PreData,
        post_data: value == Sections::Full,
    }
}

fn service_config(config: &ConfigV1, native: bool, writer: bool) -> Result<CoreConfig> {
    let source = if native {
        let source = config.source.as_ref().context(ErrorCode::PolicyRefused)?;
        Source {
            host: source.host.clone(),
            port: source.port,
            user: source.user.clone(),
            database: source.database.clone(),
            password_file: source.password_file.clone(),
            client_bin_dir: config
                .tools
                .as_ref()
                .context(ErrorCode::PolicyRefused)?
                .client_bin_dir
                .clone(),
        }
    } else {
        Source {
            host: "/unused".into(),
            port: 1,
            user: "unused".into(),
            database: "unused".into(),
            password_file: None,
            client_bin_dir: config
                .tools
                .as_ref()
                .map_or_else(|| "/unused".into(), |tools| tools.client_bin_dir.clone()),
        }
    };
    let (encryption, signing) = if writer {
        let enc = config
            .encryption
            .as_ref()
            .context(ErrorCode::PolicyRefused)?;
        let sig = config.signing.as_ref().context(ErrorCode::PolicyRefused)?;
        (
            Some(Encryption {
                identity_file: enc
                    .identity_file
                    .clone()
                    .context(ErrorCode::PolicyRefused)?,
                recipient_file: enc
                    .recipient_file
                    .clone()
                    .context(ErrorCode::PolicyRefused)?,
            }),
            Some(Signing {
                signing_key_file: sig.signing_key_file.clone(),
                verifying_key_file: sig
                    .verifying_key_file
                    .clone()
                    .context(ErrorCode::PolicyRefused)?,
            }),
        )
    } else {
        (None, None)
    };
    Ok(CoreConfig {
        source,
        storage: config.storage.clone(),
        encryption,
        signing,
        export_globals: writer && config.export_globals,
        profiles: config.profiles.clone(),
        timeout_seconds: config.timeout_seconds,
    })
}

struct Execution {
    job: Job,
    work: Work,
    intent: Option<Intent>,
    instance: Uuid,
    selected: Selection,
}

fn execute(config: &Config, id: Uuid) -> Result<Outcome> {
    let (job, work, intent, instance) = control::load_worker(config, id, std::process::id())?;
    let selected = config.select(&work.profile, job.operation)?;
    ensure!(selected.revision == work.revision, ErrorCode::ConfigChanged);
    if let Some(intent) = &intent {
        check_core_plan(&selected.config, intent)?;
    }
    core_control::check()?;
    Execution {
        job,
        work,
        intent,
        instance,
        selected,
    }
    .run()
}

impl Execution {
    fn make_intent(
        &self,
        confirmation: Confirmation,
        core_plan_id: Uuid,
        core_plan_digest: String,
        core_expiry: u64,
    ) -> Result<Box<Intent>> {
        let created = now()?;
        ensure!(
            created >= self.job.created_unix_ms && created < core_expiry,
            ErrorCode::IntentExpired
        );
        let kind = match confirmation {
            Confirmation::Restore(_) => IntentKind::Restore,
            Confirmation::Retention(_) => IntentKind::Retention,
        };
        let bound = IntentBinding {
            id: Uuid::new_v4(),
            actor_id: self.job.actor_id,
            planning_job_id: self.job.id,
            kind,
            store_instance_id: self.instance,
            config_revision: self.work.revision.clone(),
            core_plan_id,
            core_plan_digest,
            created_unix_ms: created,
            expires_unix_ms: core_expiry.min(created + 900_000),
            confirmation,
        };
        Ok(Box::new(Intent {
            digest: binding("backupctl-api-intent-v1", &bound)?,
            bound,
            consumed_by_job_id: None,
        }))
    }

    fn run(&self) -> Result<Outcome> {
        let config = &self.selected.config;
        let completed = |result| Ok(Outcome::success(result, None, Effects::None));
        match &self.work.request {
            Request::Backup { .. } => {
                let source = service_config(config, true, true)?;
                let engine = PostgresAdapter::configured(config)?;
                let store = open_protected_store(config, KeyUse::Writer)?;
                let recovery = match store.recover() {
                    Ok(recovery) => recovery,
                    // Recovery can have already finalized a deletion or
                    // changed inventory before the error ended the pass.
                    Err(_) => {
                        return Ok(Outcome::error(
                            State::Interrupted,
                            ErrorCode::OperationInterrupted,
                            Effects::Unknown,
                        ));
                    }
                };
                let (created, job_id) = match BackupService::new(engine, store)
                    .create_with_job(&source, self.selected.core_profile.as_deref())
                {
                    Ok(result) => result,
                    Err(error) => {
                        let mut outcome = failure(&error);
                        if matches!(outcome.effects, Effects::None | Effects::PreparationOnly) {
                            if !recovery.deleted.is_empty() {
                                outcome.effects = Effects::ArtifactsMayBeDeleted;
                                outcome.state = State::Partial;
                            } else if !recovery.interrupted.is_empty() {
                                outcome.effects = Effects::InventoryMayBeModified;
                                outcome.state = State::Partial;
                            } else if !recovery.removed.is_empty() {
                                outcome.effects = Effects::PreparationOnly;
                            }
                        }
                        return Ok(outcome);
                    }
                };
                Ok(Outcome::success(
                    JobResult::Backup {
                        artifact_id: created.id(),
                    },
                    job_id,
                    Effects::ArtifactMayBePublished,
                ))
            }
            Request::Inspection { artifact_id } => {
                let store = open_protected_store(config, KeyUse::Reader)?;
                let Record::Signed(manifest) =
                    BackupService::new(PostgresAdapter, store).inspect(*artifact_id)?
                else {
                    anyhow::bail!(ErrorCode::PolicyRefused);
                };
                let scope = &manifest.profile_snapshot.name;
                completed(JobResult::Inspection {
                    artifact_id: *artifact_id,
                    database: manifest.profile_snapshot.database.clone(),
                    source_major: manifest.source_server_major,
                    scope: (scope != backup_domain::WHOLE_DATABASE_PROFILE).then(|| scope.clone()),
                    created_unix_ms: timestamp(&manifest.started_at_utc)?,
                })
            }
            Request::Verification { artifact_id, level } => {
                let usage = if *level == VerifyLevel::Signature {
                    KeyUse::Signature
                } else {
                    KeyUse::Reader
                };
                let store = open_protected_store(config, usage)?;
                let engine = if *level == VerifyLevel::Archive {
                    let major = store
                        .open_signed(*artifact_id)?
                        .manifest()
                        .source_server_major;
                    let tools = config.tools.as_ref().context(ErrorCode::PolicyRefused)?;
                    PostgresAdapter::offline_for_major(
                        &tools.client_bin_dir,
                        major,
                        Duration::from_secs(config.timeout_seconds),
                    )?
                } else {
                    PostgresAdapter
                };
                let result = VerifyService::new(engine, store).verify(
                    &service_config(config, false, false)?,
                    *artifact_id,
                    level.as_str(),
                )?;
                Ok(Outcome::success(
                    JobResult::Verification {
                        artifact_id: *artifact_id,
                        level: *level,
                        passed: true,
                        inventory_recorded: result.audit_recorded,
                    },
                    None,
                    if result.audit_recorded {
                        Effects::InventoryMayBeModified
                    } else {
                        Effects::None
                    },
                ))
            }
            Request::RestorePlan {
                artifact_id,
                target_database,
                security: policy,
                sections: part,
                acknowledge_older_snapshot,
                ..
            } => {
                let source = service_config(config, true, false)?;
                let service = RestoreService::new(
                    PostgresAdapter::configured_for_restore(config)?,
                    open_protected_store(config, KeyUse::Reader)?,
                );
                let plan = service.plan_with_acknowledgement(
                    &source,
                    *artifact_id,
                    target_database,
                    security(*policy),
                    sections(*part),
                    *acknowledge_older_snapshot,
                )?;
                let confirmation = Confirmation::Restore(RestoreConfirmation {
                    target_database: target_database.clone(),
                    artifact_id: *artifact_id,
                    security: *policy,
                    sections: *part,
                    acknowledge_older_snapshot: *acknowledge_older_snapshot,
                });
                let intent = self.make_intent(
                    confirmation,
                    plan.id,
                    plan.digest(),
                    plan.expires_unix_ms.try_into()?,
                )?;
                Ok(Outcome::success(
                    JobResult::RestorePlan { intent },
                    None,
                    Effects::PreparationOnly,
                ))
            }
            Request::Restore { confirm_target, .. } => {
                let source = service_config(config, true, false)?;
                let bound = &self
                    .intent
                    .as_ref()
                    .context(ErrorCode::IntentConflict)?
                    .bound;
                let service = RestoreService::new(
                    PostgresAdapter::configured_for_restore(config)?,
                    open_protected_store(config, KeyUse::Reader)?,
                );
                let result = service.run_bound(
                    &source,
                    bound.core_plan_id,
                    confirm_target,
                    Some(&bound.core_plan_digest),
                )?;
                Ok(Outcome::success(
                    JobResult::Restore {
                        artifact_id: result.plan.artifact_id,
                        target_database: result.plan.target_database,
                        verification_level: result.verification_level,
                        recorded_in_artifact: result.recorded_in_artifact,
                    },
                    result.job_id,
                    Effects::DatabaseMayBeModified,
                ))
            }
            Request::RetentionPreview { selection } => self.preview(selection),
            Request::RetentionRun { .. } => self.delete(),
            Request::ArtifactProtection {
                artifact_id,
                protected,
                ..
            } => {
                let root = ProtectedRoot::open(config, false)?;
                let result = InventoryService::new(LocalProtection(root.path().to_owned()))
                    .set_protection(*artifact_id, *protected)?;
                let effects = if result.changed {
                    Effects::InventoryMayBeModified
                } else {
                    Effects::None
                };
                Ok(Outcome::success(
                    JobResult::ArtifactProtection {
                        artifact_id: *artifact_id,
                        protected: result.protected,
                    },
                    None,
                    effects,
                ))
            }
        }
    }

    fn preview(&self, selection: &RetentionSelection) -> Result<Outcome> {
        let request = match selection {
            RetentionSelection::Prune { keep_last, .. } => RetentionRequest::Prune {
                keep_last: *keep_last,
                profile_fingerprint: backup_domain::profile_fingerprint(
                    self.selected
                        .core_profile
                        .as_deref()
                        .unwrap_or(backup_domain::WHOLE_DATABASE_PROFILE),
                ),
            },
            RetentionSelection::Delete { artifact_id } => RetentionRequest::Delete {
                backup_id: *artifact_id,
            },
        };
        let store = open_protected_store(&self.selected.config, KeyUse::Reader)?;
        let preview = preview_retention(&ProtectedRetention::new(store)?, &request)?;
        let intent = match (preview.plan_id, preview.digest, preview.expires_unix_ms) {
            (Some(id), Some(digest), Some(expiry)) => {
                let mut candidates = preview.candidates;
                let mut retained = preview.retained;
                candidates.sort_unstable();
                retained.sort_unstable();
                Some(self.make_intent(
                    Confirmation::Retention(RetentionConfirmation {
                        candidates,
                        retained,
                    }),
                    id,
                    digest,
                    expiry,
                )?)
            }
            (None, None, None) => None,
            _ => anyhow::bail!(ErrorCode::OperationFailed),
        };
        let effects = if intent.is_some() {
            Effects::PreparationOnly
        } else {
            Effects::None
        };
        let excluded = preview
            .excluded
            .into_iter()
            .map(|e| Exclusion {
                artifact_id: e.backup_id,
                reasons: e.reasons,
            })
            .collect();
        Ok(Outcome::success(
            JobResult::RetentionPreview { intent, excluded },
            None,
            effects,
        ))
    }

    fn delete(&self) -> Result<Outcome> {
        let bound = &self
            .intent
            .as_ref()
            .context(ErrorCode::IntentConflict)?
            .bound;
        let config = &self.selected.config;
        let root = ProtectedRoot::open(config, false)?;
        let plan =
            ProtectedRetention::bound_plan(&root, bound.core_plan_id, &bound.core_plan_digest)?;
        let service = ProtectedRetention::new(open_protected_store(config, KeyUse::Reader)?)?;
        core_control::check()?;
        let outcome = match execute_deletion(
            &service,
            plan.plan_id,
            plan.operation,
            &bound.core_plan_digest,
        ) {
            Ok(outcome) => outcome,
            // An error without a partition cannot establish whether a marker moved.
            Err(_) => {
                return Ok(Outcome::error(
                    State::Interrupted,
                    ErrorCode::OperationInterrupted,
                    Effects::Unknown,
                ));
            }
        };
        let r = outcome.result;
        let effects = if r.completed.is_empty() && r.deleting.is_empty() {
            Effects::PreparationOnly
        } else {
            Effects::ArtifactsMayBeDeleted
        };
        let result = JobResult::RetentionRun {
            completed: r.completed,
            deleting: r.deleting,
            pending: r.pending,
            audit_recorded: r.audit_recorded,
        };
        let mut receipt = Outcome::success(result, Some(r.job_id), effects);
        if outcome.error.is_some() {
            receipt.state = if effects == Effects::PreparationOnly {
                State::Failed
            } else {
                State::Partial
            };
            receipt.error = Some(ErrorCode::OperationFailed.into());
        }
        Ok(receipt)
    }
}

fn timestamp(value: &str) -> Result<u64> {
    ensure!(backup_domain::is_utc_timestamp(value), "INVALID_TIMESTAMP");
    let text = CString::new(value)?;
    // SAFETY: tm is a zero-initializable C POD. The format and input are valid C strings.
    let seconds = unsafe {
        let mut tm = std::mem::zeroed();
        ensure!(
            !libc::strptime(text.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm).is_null(),
            "INVALID_TIMESTAMP"
        );
        libc::timegm(&mut tm)
    };
    let seconds = u64::try_from(seconds)?;
    ensure!(seconds <= MAX_TIME / 1000, "INVALID_TIMESTAMP");
    Ok(seconds * 1000)
}

pub(crate) fn run(config: &Config, id: Uuid) -> Outcome {
    match execute(config, id) {
        Ok(result) => result,
        Err(error) => failure(&error),
    }
}

fn failure(error: &anyhow::Error) -> Outcome {
    let receipt = error.downcast_ref::<ExecutionFailure>();
    let effects = match receipt.map(|e| e.effects) {
        None => Effects::None,
        Some("preparation_only") => Effects::PreparationOnly,
        Some("artifact_may_be_published") => Effects::ArtifactMayBePublished,
        Some("database_may_be_modified") => Effects::DatabaseMayBeModified,
        Some(_) => Effects::Unknown,
    };
    let cancelled = error.downcast_ref::<ErrorCode>() == Some(&ErrorCode::OperationCancelled)
        || error
            .chain()
            .any(|e| e.to_string() == "OPERATION_CANCELLED");
    let state = match effects {
        Effects::Unknown => State::Interrupted,
        Effects::ArtifactMayBePublished | Effects::DatabaseMayBeModified => State::Partial,
        _ if cancelled => State::Cancelled,
        _ => State::Failed,
    };
    let code = if cancelled {
        ErrorCode::OperationCancelled
    } else {
        error
            .downcast_ref::<ErrorCode>()
            .copied()
            .unwrap_or(ErrorCode::OperationFailed)
    };
    let mut outcome = Outcome::error(state, code, effects);
    outcome.core_job_id = receipt.and_then(|e| e.job_id);
    outcome
}
