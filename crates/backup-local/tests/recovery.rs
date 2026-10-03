//! The maintenance pass, on its own: what it may remove, what it refuses to touch, and what a busy
//! store makes it skip.
//!
//! `crates/backupctl/tests/store_concurrency.rs` proves the same rule from outside with two real
//! processes and a live dump. These ask the narrower questions a process scene cannot isolate — one
//! symlinked entry, one name this tool would never write, one second pass over a store that is
//! already clean, one stage that is being written right now.

mod common;

use backup_application::{ArtifactStore, WriteOptions};
use backup_local::LocalStore;
use common::temp_root;
use std::fs;
use uuid::Uuid;

/// A stage that is live is not a leftover, and the pass cannot tell otherwise: it is refused the
/// exclusive claim, and being refused means removing nothing rather than waiting until the dump
/// ends and then deleting its work.
#[test]
fn a_live_stage_makes_the_pass_skip_the_whole_store() {
    let base = temp_root("recovery-live");
    let root = base.join("data");
    let store = LocalStore::new(root.clone()).unwrap();
    let id = Uuid::new_v4();
    let stage = store
        .begin(
            id,
            &WriteOptions {
                with_globals: false,
            },
        )
        .unwrap();
    let dir = root.join("staging").join(id.to_string());
    assert!(dir.is_dir());

    let recovery = store.recover().unwrap();
    assert!(
        !recovery.claimed,
        "a maintenance pass claimed a store one of its stages was using"
    );
    assert!(recovery.removed.is_empty(), "{recovery:?}");
    assert!(dir.is_dir(), "the pass removed a live stage anyway");
    assert!(
        fs::read_dir(root.join("scratch")).is_err(),
        "a plaintext store has no scratch directory to sweep"
    );

    drop(stage);
    assert!(!dir.exists(), "the stage outlived the guard that owned it");
    // Released, and the same pass now runs: the store is clean, so it reports doing nothing,
    // which is the ordinary outcome and is not a failure.
    let quiet = store.recover().unwrap();
    assert!(quiet.claimed);
    assert!(quiet.removed.is_empty());
    assert!(quiet.interrupted.is_empty());
    fs::remove_dir_all(base).unwrap();
}

/// The shapes under `staging/`, each with its own answer. A UUID-named directory is the only thing
/// this tool writes there, so only that is treated as a leftover; everything else is reported and
/// left alone, because an operator's own file in a backup store must never be the thing a backup
/// tool deletes.
#[test]
fn the_pass_removes_leftovers_and_refuses_everything_else_it_finds() {
    let base = temp_root("recovery-shapes");
    let root = base.join("data");
    let store = LocalStore::new(root.clone()).unwrap();
    let staging = root.join("staging");

    let abandoned = staging.join(Uuid::new_v4().to_string());
    fs::create_dir_all(&abandoned).unwrap();
    fs::write(abandoned.join("payload.dump"), b"left behind mid-dump").unwrap();
    // A directory with a name this tool would never write.
    let kept = staging.join("my-files");
    fs::create_dir_all(&kept).unwrap();
    // The same, but a plain file rather than a directory.
    let plain = staging.join(Uuid::new_v4().to_string());
    fs::write(&plain, b"").unwrap();
    // And the worst case: a UUID-named *symlink* out of the store. Following it would turn a
    // cleanup into a deletion of something the store never held.
    let elsewhere = base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(elsewhere.join("precious.txt"), b"not a backup").unwrap();
    let link = staging.join(Uuid::new_v4().to_string());
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

    let recovery = store.recover().unwrap();
    assert!(recovery.claimed);
    assert_eq!(recovery.removed, vec![abandoned]);
    for path in [kept, plain, link] {
        assert!(
            recovery.refused.contains(&path),
            "{path:?} was neither removed nor refused: {recovery:?}"
        );
        assert!(
            fs::symlink_metadata(&path).is_ok(),
            "{path:?} was removed anyway"
        );
    }
    assert!(
        elsewhere.join("precious.txt").is_file(),
        "a symlinked entry was followed out of the store"
    );

    // A second pass over what is left reports the same refusals and removes nothing: it is the
    // names that disqualify them, not their age, so the pass is idempotent by construction.
    let again = store.recover().unwrap();
    assert!(again.claimed);
    assert!(again.removed.is_empty(), "{again:?}");
    assert_eq!(again.refused.len(), 3, "{again:?}");
    fs::remove_dir_all(base).unwrap();
}
