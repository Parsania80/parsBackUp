mod common;

use backup_application::{ArtifactStore, BackupService, Created, Reconciler};
use backup_inventory::{ActivityLock, Estate, INVENTORY_FILE, Inventory, State};
use backup_local::{LocalReconciler, LocalStore};
use common::{Capture, Keys, StubEngine, config, signing_block, temp_root};
use std::fs;
use uuid::Uuid;

#[test]
fn adoption_and_rebuild_preserve_history_and_refuse_foreign_authenticated_source() {
    let base = temp_root("rebuild");
    let root = base.join("data");
    let keys = Keys::generate(&base.join("keys"));
    let capture = Capture::default();
    let signed = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::with_signing_keys(
            root.clone(),
            &keys.identity,
            &keys.recipient,
            &keys.signing,
            &keys.verifying,
        )
        .unwrap(),
    )
    .create(
        &config(
            &root,
            Some((keys.identity.clone(), keys.recipient.clone())),
            Some(signing_block(&keys)),
        ),
        None,
    )
    .unwrap();
    let Created::Signed { manifest, .. } = signed else {
        panic!()
    };
    let id = manifest.backup_id;
    let expected = &manifest.source_fingerprint;
    let scanner = LocalReconciler(root.clone());
    let db = root.join(INVENTORY_FILE);
    let published = Inventory::open_read_only_bound(&db).unwrap();
    assert_eq!(published.protection(id).unwrap(), Some(false));
    drop(published);
    backup_application::InventoryService::new(backup_local::LocalProtection(root.clone()))
        .set_protection(id, true)
        .unwrap();
    let original = fs::read(&db).unwrap();
    let (wrong_plan, _) = scanner.prepare_rebuild("0000000000000000").unwrap();
    assert!(scanner.rebuild("0000000000000000", wrong_plan).is_err());
    assert_eq!(fs::read(&db).unwrap(), original);
    let (plan, _) = scanner.prepare_rebuild(expected).unwrap();
    let mut changed_index = original.clone();
    changed_index.extend_from_slice(b"changed");
    fs::write(&db, changed_index).unwrap();
    assert!(format!("{:#}", scanner.rebuild(expected, plan).err().unwrap()).contains("stale"));
    fs::write(&db, &original).unwrap();
    let claim = ActivityLock::hold(&root).unwrap();
    assert!(scanner.rebuild(expected, plan).is_err());
    drop(claim);
    let (report, previous) = scanner.rebuild(expected, plan).unwrap();
    assert!(report.audit_recorded);
    let previous = previous.unwrap();
    assert_eq!(fs::read(&previous).unwrap(), original);
    let recovered = Inventory::open_read_only_bound(&previous).unwrap();
    assert_eq!(
        recovered.artifact(id).unwrap().unwrap().profile_fingerprint,
        Some(backup_domain::profile_fingerprint(
            &manifest.profile_snapshot.name
        ))
    );
    assert!(!recovered.is_provisional(id).unwrap());
    assert_eq!(recovered.protection(id).unwrap(), Some(true));
    drop(recovered);
    let inventory = Inventory::open_read_only_bound(&db).unwrap();
    let row = inventory.artifact(id).unwrap().unwrap();
    assert!(inventory.is_provisional(id).unwrap());
    assert_eq!(inventory.protection(id).unwrap(), None);
    assert_eq!(row.profile_fingerprint, None);
    assert_eq!(row.completed_at_utc, None);
    drop(inventory);
    assert!(scanner.rebuild(expected, plan).is_err());
    fs::remove_file(&db).unwrap();
    fs::rename(base.join("keys"), base.join("offline-keys")).unwrap();
    let (loss_plan, _) = scanner.prepare_rebuild(expected).unwrap();
    let (_, previous) = scanner.rebuild(expected, loss_plan).unwrap();
    assert!(previous.is_none());
    fs::rename(base.join("offline-keys"), base.join("keys")).unwrap();
    let reader = LocalStore::for_reading(root.clone(), &keys.identity, &keys.verifying).unwrap();
    assert!(reader.open_signed(id).is_ok());
    assert_eq!(
        Inventory::open_read_only_bound(&db)
            .unwrap()
            .protection(id)
            .unwrap(),
        None
    );
    assert!(scanner.adopt(id, expected).is_err());
    fs::remove_file(&db).unwrap();
    let foreign = Estate::new("0000000000000000".into()).unwrap();
    drop(Inventory::open(&db, &foreign).unwrap());
    scanner.adopt(id, &foreign.source_fingerprint).unwrap();
    assert!(
        format!("{:#}", reader.open_signed(id).err().unwrap())
            .contains("provisional inventory estate")
    );
    let before = fs::read(&db).unwrap();
    assert!(
        scanner
            .adopt(Uuid::new_v4(), &foreign.source_fingerprint)
            .is_err()
    );
    assert_eq!(fs::read(&db).unwrap(), before);
    drop(reader);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn mixed_store_reconciles_without_adoption_or_losing_facts() {
    let base = temp_root("reconcile");
    let root = base.join("data");
    let keys = Keys::generate(&base.join("keys"));
    let capture = Capture::default();
    let plain = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::new(root.clone()).unwrap(),
    )
    .create(&config(&root, None, None), None)
    .unwrap();
    let encrypted = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::with_keys(root.clone(), &keys.identity, &keys.recipient).unwrap(),
    )
    .create(
        &config(
            &root,
            Some((keys.identity.clone(), keys.recipient.clone())),
            None,
        ),
        None,
    )
    .unwrap();
    let signed = BackupService::new(
        StubEngine { capture: &capture },
        LocalStore::with_signing_keys(
            root.clone(),
            &keys.identity,
            &keys.recipient,
            &keys.signing,
            &keys.verifying,
        )
        .unwrap(),
    )
    .create(
        &config(
            &root,
            Some((keys.identity.clone(), keys.recipient.clone())),
            Some(signing_block(&keys)),
        ),
        None,
    )
    .unwrap();
    let Created::Development(plain) = plain else {
        panic!()
    };
    let Created::Development(encrypted) = encrypted else {
        panic!()
    };
    let Created::Signed { manifest, .. } = signed else {
        panic!()
    };
    let id = manifest.backup_id;
    backup_application::InventoryService::new(backup_local::LocalProtection(root.clone()))
        .set_protection(id, true)
        .unwrap();
    let inventory = Inventory::open_read_only_bound(&root.join(INVENTORY_FILE)).unwrap();
    let original = inventory.artifact(id).unwrap().unwrap();
    let events = inventory.audit_events().unwrap().len();
    drop(inventory);
    let reconcile = LocalReconciler(root.clone());
    let inventory_path = root.join(INVENTORY_FILE);
    let saved_inventory = base.join("saved-inventory.db");
    fs::rename(&inventory_path, &saved_inventory).unwrap();
    fs::rename(base.join("keys"), base.join("offline-keys")).unwrap();
    let keyless = reconcile
        .preview_rebuild(&original.source_fingerprint)
        .unwrap();
    assert!(reconcile.preview_rebuild("invalid").is_err());
    for (id, shape) in [
        (plain.id, "plaintext-dev"),
        (encrypted.id, "age-unsigned"),
        (id, "v1-signed"),
    ] {
        let item = keyless
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap();
        assert_eq!((item.shape, item.status), (Some(shape), "unregistered"));
    }
    assert!(!keyless.audit_recorded);
    assert!(!inventory_path.exists());
    fs::rename(&saved_inventory, &inventory_path).unwrap();
    fs::rename(base.join("offline-keys"), base.join("keys")).unwrap();
    let claim = ActivityLock::hold(&root).unwrap();
    assert!(format!("{:#}", reconcile.reconcile().err().unwrap()).contains("RECONCILE_BUSY"));
    drop(claim);
    let initial = reconcile.reconcile().unwrap();
    assert!(!initial.audit_recorded);
    for (id, shape, state) in [
        (plain.id, "plaintext-dev", "unregistered"),
        (encrypted.id, "age-unsigned", "unregistered"),
        (id, "v1-signed", "registered"),
    ] {
        let item = initial
            .entries
            .iter()
            .find(|item| item.backup_id == Some(id))
            .unwrap();
        assert_eq!((item.shape, item.status), (Some(shape), state));
    }
    let dir = root.join("artifacts").join(id.to_string());
    let payload = dir.join("payload.age");
    let original_payload = fs::read(&payload).unwrap();
    let mut changed = original_payload.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    fs::write(&payload, changed).unwrap();
    let result = reconcile.reconcile().unwrap();
    assert!(result.audit_recorded);
    assert_eq!(
        result
            .entries
            .iter()
            .find(|entry| entry.backup_id == Some(id))
            .unwrap()
            .status,
        "conflict"
    );
    let inventory = Inventory::open_read_only_bound(&root.join(INVENTORY_FILE)).unwrap();
    let conflict = inventory.artifact(id).unwrap().unwrap();
    assert_eq!(conflict.state, State::Conflict);
    assert_eq!(inventory.protection(id).unwrap(), Some(true));
    assert_eq!(conflict.profile_fingerprint, original.profile_fingerprint);
    assert_eq!(conflict.completed_at_utc, original.completed_at_utc);
    assert_eq!(inventory.audit_events().unwrap().len(), events + 1);
    drop(inventory);
    assert!(!reconcile.reconcile().unwrap().audit_recorded);
    fs::write(&payload, original_payload).unwrap();
    assert!(reconcile.reconcile().unwrap().audit_recorded);
    let public_path = dir.join("public.json");
    let public_original = fs::read(&public_path).unwrap();
    let mut header: serde_json::Value = serde_json::from_slice(&public_original).unwrap();
    header["signer_id"] = serde_json::json!("aaaaaaaaaaaaaaaa");
    fs::write(&public_path, serde_json::to_vec(&header).unwrap()).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "conflict"
    );
    fs::write(&public_path, public_original).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "registered"
    );
    let moved = base.join("outside");
    fs::rename(&dir, &moved).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "missing"
    );
    fs::rename(&moved, &dir).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "registered"
    );
    let alias = root.join("artifacts").join(id.to_string().to_uppercase());
    fs::create_dir(&alias).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "conflict"
    );
    fs::remove_dir(alias).unwrap();
    assert_eq!(
        reconcile
            .reconcile()
            .unwrap()
            .entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "registered"
    );
    let invalid = Uuid::new_v4();
    std::os::unix::fs::symlink(&dir, root.join("artifacts").join(invalid.to_string())).unwrap();
    let incomplete = Uuid::new_v4();
    fs::create_dir(root.join("artifacts").join(incomplete.to_string())).unwrap();
    let oversized = Uuid::new_v4();
    let oversized_dir = root.join("artifacts").join(oversized.to_string());
    fs::create_dir(&oversized_dir).unwrap();
    fs::write(oversized_dir.join("complete"), []).unwrap();
    fs::write(oversized_dir.join("public.json"), vec![b' '; 4097]).unwrap();
    let inner_link = Uuid::new_v4();
    let inner_dir = root.join("artifacts").join(inner_link.to_string());
    fs::create_dir(&inner_dir).unwrap();
    std::os::unix::fs::symlink(&payload, inner_dir.join("unexpected")).unwrap();
    let socket_id = Uuid::new_v4();
    let socket_dir = root.join("artifacts").join(socket_id.to_string());
    fs::create_dir(&socket_dir).unwrap();
    let fifo = std::ffi::CString::new(socket_dir.join("unexpected").as_os_str().as_encoded_bytes())
        .unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let entries = reconcile.reconcile().unwrap().entries;
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(invalid))
            .unwrap()
            .status,
        "invalid"
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(socket_id))
            .unwrap()
            .status,
        "invalid"
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(incomplete))
            .unwrap()
            .status,
        "incomplete"
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(oversized))
            .unwrap()
            .status,
        "invalid"
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(inner_link))
            .unwrap()
            .status,
        "invalid"
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e.backup_id == Some(id))
            .unwrap()
            .status,
        "registered"
    );
    assert_eq!(
        Inventory::open_read_only_bound(&root.join(INVENTORY_FILE))
            .unwrap()
            .artifacts()
            .unwrap()
            .len(),
        1
    );
    fs::remove_dir_all(base).unwrap();
}
