//! The outer drill runs this test binary as the main PID of a real systemd unit.
use anyhow::{Context, Result, ensure};
use backup_api::{
    Actor, Config, Effects, ErrorCode, Job, JobResult, Request, RetentionSelection, Sections,
    Security, State, Supervisor, VerifyLevel,
};
use std::{path::Path, time::Duration};
use uuid::Uuid;

#[tokio::test(flavor = "current_thread")]
#[ignore = "run via tests/p02_worker_drill.py under a dedicated systemd unit"]
async fn supervised_worker() -> Result<()> {
    let dir =
        std::path::PathBuf::from(std::env::var_os("P02_FIXTURE").context("fixture directory")?);
    let actor: Actor = serde_json::from_slice(&std::fs::read(dir.join("actor.json"))?)?;
    let binary = Path::new(env!("CARGO_BIN_EXE_backup-api")).to_owned();
    let mut supervisor = Supervisor::open(Config::load(&dir.join("api.toml"))?, binary).await?;
    let control = supervisor.control();
    let duplicate = Supervisor::open(
        Config::load(&dir.join("api.toml"))?,
        Path::new(env!("CARGO_BIN_EXE_backup-api")).to_owned(),
    )
    .await;
    ensure!(
        matches!(duplicate, Err(ref error) if error.to_string() == "CONTROL_ALREADY_OWNED"),
        "a second supervisor did not encounter the control lock"
    );

    if dir.join("crash.json").exists() {
        let (key, active, queued): (Uuid, Uuid, Uuid) =
            serde_json::from_slice(&std::fs::read(dir.join("crash.json"))?)?;
        let job = control.submit(actor, key, backup())?;
        assert_eq!(job.id, active);
        assert_eq!(job.state, State::Interrupted);
        assert_eq!(job.effects, Effects::Unknown);
        let job = control.job(actor, queued)?;
        assert_eq!(job.state, State::Interrupted);
        assert_eq!(job.effects, Effects::None);
        assert!(!supervisor.run_next().await?);
        println!("interrupted active/queued jobs preserved; retry did not replay");
        return Ok(());
    }

    // Refusal and replay change neither queue capacity nor the referenced job.
    let key = Uuid::new_v4();
    let first = control.submit(actor, key, backup())?;
    assert_eq!(control.submit(actor, key, backup())?.id, first.id);
    assert!(
        control
            .submit(
                actor,
                key,
                Request::Backup {
                    profile_id: Some("other".into()),
                    confirm_synthetic: true,
                }
            )
            .unwrap_err()
            .downcast_ref::<ErrorCode>()
            == Some(&ErrorCode::IdempotencyConflict)
    );
    let mut queued = Vec::new();
    for _ in 0..15 {
        queued.push(control.submit(actor, Uuid::new_v4(), missing_inspection())?);
    }
    assert_eq!(
        control
            .submit(actor, Uuid::new_v4(), backup())
            .unwrap_err()
            .downcast_ref::<ErrorCode>(),
        Some(&ErrorCode::QueueFull)
    );
    let db = rusqlite::Connection::open(dir.join("state/control.sqlite"))?;
    // Seed receipt history against the existing admitted job. Keep its original
    // receipt and job row intact so the drill still dispatches that job.
    db.execute(
        "WITH RECURSIVE sequence(n) AS (
             SELECT 1 UNION ALL SELECT n+1 FROM sequence WHERE n < 100000
         ) INSERT INTO receipts
         SELECT ?, '/fixture-capacity', printf('00000000-0000-4000-8000-%012x', n), '', ?
         FROM sequence",
        [actor.actor_id.to_string(), first.id.to_string()],
    )?;
    assert_eq!(
        control
            .submit(actor, Uuid::new_v4(), backup())
            .unwrap_err()
            .downcast_ref::<ErrorCode>(),
        Some(&ErrorCode::ControlCapacity)
    );
    for job in queued {
        let key = Uuid::new_v4();
        assert_eq!(control.cancel(actor, job.id, key)?.state, State::Cancelled);
        assert_eq!(control.cancel(actor, job.id, key)?.state, State::Cancelled);
    }
    db.execute("DELETE FROM receipts WHERE route='/fixture-capacity'", [])?;
    drop(db);
    assert!(supervisor.run_next().await?);
    let job = control.job(actor, first.id)?;
    assert_eq!(job.state, State::Succeeded, "{job:?}");
    assert!(job.core_job_id.is_some());
    let Some(JobResult::Backup { artifact_id }) = job.result else {
        anyhow::bail!("missing backup receipt")
    };

    // A second successful backup supplies an independently verified retained copy.
    let next = run(&mut supervisor, actor, backup()).await?;
    let Some(JobResult::Backup {
        artifact_id: retained,
    }) = next.result
    else {
        anyhow::bail!("missing retained copy")
    };
    assert!(matches!(
        run(&mut supervisor, actor, Request::Inspection { artifact_id })
            .await?
            .result,
        Some(JobResult::Inspection {
            source_major: 17,
            ..
        })
    ));
    for id in [artifact_id, retained] {
        let verification = run(
            &mut supervisor,
            actor,
            Request::Verification {
                artifact_id: id,
                level: VerifyLevel::Archive,
            },
        )
        .await?;
        assert!(
            matches!(
                verification.result,
                Some(JobResult::Verification {
                    passed: true,
                    inventory_recorded: true,
                    ..
                })
            ),
            "{verification:?}"
        );
    }

    let target = "backupctl_fixture_p02_restore".to_owned();
    let plan = run(
        &mut supervisor,
        actor,
        Request::RestorePlan {
            artifact_id: retained,
            target_database: target.clone(),
            security: Security::Portable,
            sections: Sections::Full,
            acknowledge_older_snapshot: false,
            confirm_synthetic: true,
        },
    )
    .await?;
    let Some(JobResult::RestorePlan { intent }) = plan.result else {
        anyhow::bail!("missing restore intent: {plan:?}")
    };
    let request = Request::Restore {
        intent_id: intent.bound.id,
        confirm_digest: intent.digest.clone(),
        confirm_target: target,
        confirm_synthetic: true,
    };
    let key = Uuid::new_v4();
    let saved = dir.join(format!("store/plans/{}.json", intent.bound.core_plan_id));
    let original = std::fs::read(&saved)?;
    let mut altered: serde_json::Value = serde_json::from_slice(&original)?;
    altered["client_version"] = serde_json::json!("pg_restore (PostgreSQL) 17.1");
    std::fs::write(&saved, serde_json::to_vec(&altered)?)?;
    assert_eq!(
        control
            .submit(actor, key, request.clone())
            .unwrap_err()
            .downcast_ref::<ErrorCode>(),
        Some(&ErrorCode::IntentConflict)
    );
    assert!(
        control
            .intent(actor, intent.bound.id)?
            .consumed_by_job_id
            .is_none()
    );
    std::fs::write(saved, original)?;
    let job = control.submit(actor, key, request.clone())?;
    assert_eq!(
        control.intent(actor, intent.bound.id)?.consumed_by_job_id,
        Some(job.id)
    );
    assert_eq!(
        control
            .submit(actor, Uuid::new_v4(), request.clone())
            .unwrap_err()
            .downcast_ref::<ErrorCode>(),
        Some(&ErrorCode::IntentConflict)
    );
    supervisor.run_next().await?;
    let restored = control.submit(actor, key, request)?;
    assert_eq!(restored.id, job.id);
    assert_eq!(restored.state, State::Succeeded, "{restored:?}");
    assert!(restored.core_job_id.is_some());

    let preview = run(
        &mut supervisor,
        actor,
        Request::RetentionPreview {
            selection: RetentionSelection::Delete { artifact_id },
        },
    )
    .await?;
    let Some(JobResult::RetentionPreview {
        intent: Some(intent),
        ..
    }) = preview.result
    else {
        anyhow::bail!("missing retention intent: {preview:?}");
    };
    let deleted = run(
        &mut supervisor,
        actor,
        Request::RetentionRun {
            intent_id: intent.bound.id,
            confirm_digest: intent.digest.clone(),
        },
    )
    .await?;
    assert!(
        matches!(deleted.result, Some(JobResult::RetentionRun { ref completed, .. }) if completed == &[artifact_id]),
        "{deleted:?}"
    );
    assert!(deleted.core_job_id.is_some());

    // Signals must kill the owned native process and leave the next worker's
    // fresh cancellation flag unaffected. The tool marks actual dump entry.
    std::fs::write(dir.join("tool-mode"), "cancel")?;
    let cancelled = control.submit(actor, Uuid::new_v4(), backup())?;
    let (dispatch, cancellation) = tokio::join!(supervisor.run_next(), async {
        wait_for(&dir.join("native-started")).await?;
        assert_eq!(
            control.cancel(actor, cancelled.id, Uuid::new_v4())?.state,
            State::CancelRequested
        );
        Ok::<_, anyhow::Error>(())
    });
    dispatch?;
    cancellation?;
    let job = control.job(actor, cancelled.id)?;
    assert_eq!(job.state, State::Cancelled, "{job:?}");
    std::fs::remove_file(dir.join("native-started"))?;
    std::fs::remove_file(dir.join("tool-mode"))?;
    assert_eq!(
        run(&mut supervisor, actor, backup()).await?.state,
        State::Succeeded
    );

    // A recovery error without a receipt cannot establish what changed.
    let inventory = dir.join("store/inventory.db");
    let db = rusqlite::Connection::open(&inventory)?;
    let version: u32 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    db.pragma_update(None, "user_version", version + 1)?;
    drop(db);
    let failed = control.submit(actor, Uuid::new_v4(), backup())?;
    assert!(supervisor.run_next().await?);
    let failed = control.job(actor, failed.id)?;
    rusqlite::Connection::open(inventory)?.pragma_update(None, "user_version", version)?;
    assert_eq!(failed.state, State::Interrupted, "{failed:?}");
    assert_eq!(failed.effects, Effects::Unknown);

    // The fixture now leaves a descendant in a new session after a normal dump
    // and no inherited IPC descriptors. Only the unit boundary can stop it.
    let key = Uuid::new_v4();
    let active = control.submit(actor, key, backup())?;
    let queued = control.submit(actor, Uuid::new_v4(), missing_inspection())?;
    std::fs::write(
        dir.join("crash.json"),
        serde_json::to_vec(&(key, active.id, queued.id))?,
    )?;
    std::fs::write(dir.join("tool-mode"), "orphan")?;
    supervisor.run_next().await?;
    anyhow::bail!("supervisor accepted a receipt despite a live descendant")
}

fn backup() -> Request {
    Request::Backup {
        profile_id: None,
        confirm_synthetic: true,
    }
}

fn missing_inspection() -> Request {
    Request::Inspection {
        artifact_id: Uuid::new_v4(),
    }
}

async fn run(supervisor: &mut Supervisor, actor: Actor, request: Request) -> Result<Job> {
    let control = supervisor.control();
    let job = control.submit(actor, Uuid::new_v4(), request)?;
    ensure!(supervisor.run_next().await?, "nothing dispatched");
    let job = control.job(actor, job.id)?;
    ensure!(job.state == State::Succeeded, "job failed: {job:?}");
    Ok(job)
}

async fn wait_for(path: &Path) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    Ok(())
}
