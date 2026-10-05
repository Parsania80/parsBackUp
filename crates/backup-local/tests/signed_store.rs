//! The signed v1 shape in `backup-local`: the writer's file order, and a reader that
//! authenticates before it decrypts.
//!
//! These tests are store-level on purpose. The property under test is that an artifact in a
//! signed store cannot be read without its signature having been checked against the
//! configured verifying key, and that is a fact about the files on disk — not about
//! `pg_dump`, `age`, or the CLI.

mod common;

use anyhow::Result;
use backup_application::{ArtifactStore, PlaintextView, SignedArtifactHandle, WriteOptions};
use backup_crypto::protocol::HYBRID_SIGNATURE_BYTES;
use backup_crypto::signing::signature_tuple;
use backup_domain::{
    AGE_FORMAT, ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, ArtifactManifest, BACKUP_STATUS,
    DevelopmentManifest, GLOBALS_POLICY_EXPORTED, GLOBALS_POLICY_SKIPPED, ID_HEX_LEN,
    MAX_PUBLIC_JSON_BYTES, Profile, RECIPIENT_SUITES, RequestedSelection, ResolvedSelection,
    SIGNATURE_SUITES, SUBSCRIPTION_POLICY_DROPPED, SelectionMode, VERIFICATION_NONE, format_utc,
};
use backup_local::LocalStore;
use common::{Keys, artifact_dir, failure};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// A temporary directory that removes itself. These tests create plaintext by design, so
/// leaving it behind in a shared `/tmp` would defeat the point of the store's rules.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("backupctl-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn signed_store(root: &Path, keys: &Keys) -> LocalStore {
    LocalStore::with_signing_keys(
        root.to_path_buf(),
        &keys.identity,
        &keys.recipient,
        &keys.signing,
        &keys.verifying,
    )
    .unwrap()
}

fn read_only_store(root: &Path, keys: &Keys) -> LocalStore {
    LocalStore::for_reading(root.to_path_buf(), &keys.identity, &keys.verifying).unwrap()
}

const PAYLOAD_LEN: usize = 4096;
const GLOBALS_SQL: &[u8] = b"CREATE ROLE backupctl_fixture_alice LOGIN;";

fn payload_bytes(seed: u8) -> Vec<u8> {
    vec![seed; PAYLOAD_LEN]
}

type Stage = <LocalStore as ArtifactStore>::Stage;

/// What a staged file measures to: ciphertext bytes, and their SHA-256 in lowercase hex.
type Measured = (u64, String);

/// Stages a synthetic dump the way the write path does: a payload stream, plus a globals
/// stream when the artifact declares one. Returns the stage with each file's ciphertext size
/// and digest, which is what a manifest has to record.
fn stage_dump(
    store: &LocalStore,
    id: Uuid,
    payload: &[u8],
    globals: Option<&[u8]>,
) -> Result<(Stage, Measured, Option<Measured>)> {
    let stage = store.begin(
        id,
        &WriteOptions {
            with_globals: globals.is_some(),
        },
    )?;
    let mut sink = store.payload_sink(&stage)?;
    sink.write_all(payload)?;
    sink.finish()?;
    drop(sink);
    let measured = store.measure(&stage)?;
    let mut globals_measured = None;
    if let Some(bytes) = globals {
        let mut sink = store.globals_sink(&stage)?;
        sink.write_all(bytes)?;
        sink.finish()?;
        drop(sink);
        globals_measured = Some(store.measure_globals(&stage)?);
    }
    Ok((stage, measured, globals_measured))
}

fn profile() -> Profile {
    Profile {
        name: "app-only".to_string(),
        database: "backupctl_fixture_m4b".to_string(),
        mode: SelectionMode::SchemaAndData,
        schemas: vec!["app".to_string()],
        exclude_schemas: Vec::new(),
        tables: Vec::new(),
        exclude_tables: Vec::new(),
        exclude_extensions: Vec::new(),
        large_objects: false,
    }
}

/// The manifest of one staged artifact, with the two key ids spelled out. They are written
/// literally here rather than derived because a test needs to be able to get one wrong.
fn manifest_with(
    id: Uuid,
    recipient_id: &str,
    signer_id: &str,
    payload: &Measured,
    plaintext_bytes: u64,
    globals: Option<&Measured>,
) -> ArtifactManifest {
    let profile = profile();
    ArtifactManifest {
        format_version: 1,
        backup_id: id,
        engine: "postgresql".to_string(),
        source_server_major: 16,
        source_server_version: "160004".to_string(),
        dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
        application_version: "0.1.0".to_string(),
        recipient_id: recipient_id.to_string(),
        signer_id: signer_id.to_string(),
        recipient_suite: RECIPIENT_SUITES[0].to_string(),
        signature_suite: SIGNATURE_SUITES[0].to_string(),
        started_at_utc: format_utc(1_759_000_000_000).expect("a fixture timestamp"),
        completed_at_utc: format_utc(1_759_000_060_000).expect("a fixture timestamp"),
        source_fingerprint: "c".repeat(ID_HEX_LEN),
        requested_selection: RequestedSelection::from_profile(&profile),
        profile_snapshot: profile,
        resolved_selection: ResolvedSelection {
            whole_database: false,
            schemas: vec!["app".to_string()],
            exclude_schemas: Vec::new(),
            tables: Vec::new(),
            exclude_tables: Vec::new(),
            dangling: Vec::new(),
            extension_members: Vec::new(),
        },
        archive_format: ARCHIVE_FORMAT.to_string(),
        compression: ARCHIVE_COMPRESSION.to_string(),
        subscription_policy: SUBSCRIPTION_POLICY_DROPPED.to_string(),
        globals_policy: match globals {
            Some(_) => GLOBALS_POLICY_EXPORTED.to_string(),
            None => GLOBALS_POLICY_SKIPPED.to_string(),
        },
        globals_sha256: globals.map(|(_, digest)| digest.clone()),
        globals_ciphertext_bytes: globals.map(|(bytes, _)| *bytes),
        payload_ciphertext_sha256: payload.1.clone(),
        payload_ciphertext_bytes: payload.0,
        archive_plaintext_bytes: plaintext_bytes,
        archive_toc_sha256: None,
        verification_level: VERIFICATION_NONE.to_string(),
        compatibility_notes: Vec::new(),
    }
}

/// The same manifest, with the ids this store's own key files derive — the way the service
/// will build it once the application layer learns about v1.
fn manifest_for(
    store: &LocalStore,
    id: Uuid,
    payload: &Measured,
    plaintext_bytes: u64,
    globals: Option<&Measured>,
) -> Result<ArtifactManifest> {
    let facts = store.signed_key_facts()?;
    let (recipient_id, signer_id) = (facts.recipient_id, facts.signer_id);
    Ok(manifest_with(
        id,
        &recipient_id,
        &signer_id,
        payload,
        plaintext_bytes,
        globals,
    ))
}

fn legacy_manifest(id: Uuid, payload: &Measured, plaintext_bytes: u64) -> DevelopmentManifest {
    DevelopmentManifest {
        format: AGE_FORMAT.to_string(),
        id,
        synthetic_only: true,
        database: "backupctl_fixture_m4b".to_string(),
        source_major: 16,
        source_version: "160004".to_string(),
        dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
        application_version: "0.1.0".to_string(),
        archive_format: ARCHIVE_FORMAT.to_string(),
        compression: ARCHIVE_COMPRESSION.to_string(),
        created_unix_ms: 1_759_000_000_000,
        size_bytes: payload.0,
        sha256: payload.1.clone(),
        status: BACKUP_STATUS.to_string(),
        security_globals: false,
        globals_sha256: None,
        globals_size_bytes: None,
        verification_level: None,
        verified_unix_ms: None,
        scope: None,
        toc_sha256: None,
        recipient_suite: Some(RECIPIENT_SUITES[0].to_string()),
        payload_plaintext_bytes: Some(plaintext_bytes),
    }
}

/// Publishes one signed artifact and returns its id.
fn publish_one(store: &LocalStore, seed: u8, globals: bool) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let payload = payload_bytes(seed);
    let (stage, measured, globals_measured) = stage_dump(
        store,
        id,
        &payload,
        match globals {
            true => Some(GLOBALS_SQL),
            false => None,
        },
    )?;
    let manifest = manifest_for(
        store,
        id,
        &measured,
        payload.len() as u64,
        globals_measured.as_ref(),
    )?;
    store.publish_signed(stage, &manifest)?;
    Ok(id)
}

#[test]
fn a_signed_artifact_is_written_in_the_contracts_order_and_reads_back() -> Result<()> {
    let root = Scratch::new("v1-order");
    let keydir = Scratch::new("v1-order-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = Uuid::new_v4();
    let payload = payload_bytes(7);
    let (stage, measured, globals_measured) = stage_dump(&store, id, &payload, Some(GLOBALS_SQL))?;
    let manifest = manifest_for(
        &store,
        id,
        &measured,
        payload.len() as u64,
        globals_measured.as_ref(),
    )?;
    let header = store.publish_signed(stage, &manifest)?;
    let dir = artifact_dir(root.path(), id);

    // The contract's writer order, each file present and none of them the older shape.
    for name in [
        "payload.age",
        "globals.age",
        "manifest.age",
        "signature.hybrid",
        "public.json",
        "complete",
    ] {
        assert!(dir.join(name).is_file(), "{name} was not published");
    }
    assert!(!dir.join("manifest.json").exists());
    assert_eq!(
        fs::metadata(dir.join("signature.hybrid"))?.len(),
        u64::try_from(HYBRID_SIGNATURE_BYTES).expect("3373 bytes"),
        "signature.hybrid is exactly the hybrid suite's width"
    );
    let public = fs::read(dir.join("public.json"))?;
    assert!(public.len() <= MAX_PUBLIC_JSON_BYTES);
    assert_eq!(public, header.to_json()?.into_bytes());
    assert!(
        fs::read_dir(root.path().join("staging"))?.next().is_none(),
        "a published stage leaves nothing behind in staging/"
    );

    let artifact = store.open_signed(id)?;
    assert_eq!(artifact.manifest().backup_id, id);
    assert_eq!(artifact.header().backup_id, id);
    assert_eq!(artifact.manifest().globals_policy, GLOBALS_POLICY_EXPORTED);
    assert_eq!(artifact.globals_path().unwrap(), dir.join("globals.age"));

    // Reading on a host that holds no signing key and no recipient: the DR shape.
    let reader = read_only_store(root.path(), &keys);
    let artifact = reader.open_signed(id)?;
    let view = reader.payload_plaintext(&artifact)?;
    assert_eq!(fs::read(view.path())?, payload);
    let globals_view = reader.globals_plaintext(&artifact)?;
    assert_eq!(fs::read(globals_view.path())?, GLOBALS_SQL);
    drop(view);
    drop(globals_view);
    assert!(
        fs::read_dir(root.path().join("scratch"))?.next().is_none(),
        "a dropped plaintext view leaves no decrypted file behind"
    );
    Ok(())
}

#[test]
fn listing_needs_no_keys_and_hides_no_unsigned_artifact() -> Result<()> {
    // An artifact written before [signing] was configured, in a store that now has it: a
    // key-free listing has to say it exists rather than show an empty store.
    let root = Scratch::new("v1-list");
    let keydir = Scratch::new("v1-list-keys");
    let keys = Keys::generate(keydir.path());
    let unsigned =
        LocalStore::with_keys(root.path().to_path_buf(), &keys.identity, &keys.recipient).unwrap();
    let legacy_id = Uuid::new_v4();
    let payload = payload_bytes(3);
    let (stage, measured, _) = stage_dump(&unsigned, legacy_id, &payload, None)?;
    unsigned.publish(
        stage,
        &legacy_manifest(legacy_id, &measured, payload.len() as u64),
    )?;
    drop(unsigned);

    let store = signed_store(root.path(), &keys);
    let signed_id = publish_one(&store, 5, false)?;
    let listing = store.list_signed()?;
    assert_eq!(listing.signed.len(), 1);
    assert_eq!(listing.signed[0].backup_id, signed_id);
    assert_eq!(listing.unsigned, vec![legacy_id]);
    // The pre-v1 artifact is still readable by the manifest reader it belongs to, and the
    // signed one refuses to be read by it.
    assert!(store.inspect(legacy_id).is_ok());
    let error = store.inspect(signed_id).unwrap_err().to_string();
    assert!(error.contains("signed v1 artifact"), "{error}");
    Ok(())
}

#[test]
fn a_signed_store_refuses_to_publish_unsigned() -> Result<()> {
    let root = Scratch::new("v1-unsigned");
    let keydir = Scratch::new("v1-unsigned-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = Uuid::new_v4();
    let payload = payload_bytes(1);
    let (stage, measured, _) = stage_dump(&store, id, &payload, None)?;
    let error =
        failure(store.publish(stage, &legacy_manifest(id, &measured, payload.len() as u64)));
    assert!(
        error.contains("publishes only signed v1 artifacts"),
        "{error}"
    );
    assert!(!artifact_dir(root.path(), id).exists());
    Ok(())
}

#[test]
fn a_read_only_host_can_verify_but_cannot_write() -> Result<()> {
    let root = Scratch::new("v1-readonly");
    let keydir = Scratch::new("v1-readonly-keys");
    let keys = Keys::generate(keydir.path());
    let writer = signed_store(root.path(), &keys);
    let id = publish_one(&writer, 9, false)?;
    drop(writer);

    let reader = read_only_store(root.path(), &keys);
    assert!(reader.open_signed(id).is_ok());
    let stage = reader.begin(
        Uuid::new_v4(),
        &WriteOptions {
            with_globals: false,
        },
    )?;
    let error = failure(reader.payload_sink(&stage));
    assert!(error.contains("no recipient file"), "{error}");
    let manifest = manifest_with(
        Uuid::nil(),
        &"a".repeat(ID_HEX_LEN),
        &"b".repeat(ID_HEX_LEN),
        &(1, "f".repeat(64)),
        1,
        None,
    );
    let error = failure(reader.publish_signed(stage, &manifest));
    assert!(error.contains("no signing key"), "{error}");
    Ok(())
}

#[test]
fn a_changed_payload_is_refused_before_anything_is_decrypted() -> Result<()> {
    let root = Scratch::new("v1-payload");
    let keydir = Scratch::new("v1-payload-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 4, false)?;
    fs::write(
        artifact_dir(root.path(), id).join("payload.age"),
        payload_bytes(5),
    )?;
    let error = failure(store.open_signed(id));
    assert!(
        error.contains("payload.age is not the ciphertext public.json describes"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_changed_manifest_is_refused_by_its_ciphertext_digest() -> Result<()> {
    let root = Scratch::new("v1-manifest");
    let keydir = Scratch::new("v1-manifest-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 6, false)?;
    fs::write(
        artifact_dir(root.path(), id).join("manifest.age"),
        b"-> not an age stream".as_slice(),
    )?;
    let error = failure(store.open_signed(id));
    // The digest catches it, so the reader never learns that the file is not an age stream:
    // a tampered sealed manifest is a checksum failure, not a parse failure.
    assert!(
        error.contains("manifest.age is not the ciphertext public.json describes"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_signature_made_by_another_key_is_refused() -> Result<()> {
    let root = Scratch::new("v1-forge");
    let keydir = Scratch::new("v1-forge-keys");
    let otherdir = Scratch::new("v1-forge-other");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 8, false)?;
    let dir = artifact_dir(root.path(), id);

    // Two artifacts, one signature moved between them: public.json and both ciphertexts
    // still agree, so only the signature can catch this — and it catches it before the
    // sealed manifest is opened.
    let other = publish_one(&store, 9, false)?;
    fs::copy(
        artifact_dir(root.path(), other).join("signature.hybrid"),
        dir.join("signature.hybrid"),
    )?;
    let error = failure(store.open_signed(id));
    assert!(
        error.contains("origin signature of artifact"),
        "a moved signature must fail as a signature failure, not a decrypt failure: {error}"
    );
    assert!(!error.contains("age stream"), "{error}");

    // A host that trusts a different verifying key refuses the same bytes.
    let other_keys = Keys::generate(otherdir.path());
    let stranger = read_only_store(root.path(), &other_keys);
    let error = failure(stranger.open_signed(other));
    assert!(error.contains("does not verify"), "{error}");
    Ok(())
}

#[test]
fn a_signature_of_the_wrong_width_is_refused() -> Result<()> {
    let root = Scratch::new("v1-width");
    let keydir = Scratch::new("v1-width-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 10, false)?;
    let path = artifact_dir(root.path(), id).join("signature.hybrid");
    let bytes = fs::read(&path)?;
    fs::write(&path, &bytes[..HYBRID_SIGNATURE_BYTES - 1])?;
    let error = failure(store.open_signed(id));
    assert!(
        error.contains(&format!("must be exactly {HYBRID_SIGNATURE_BYTES} bytes")),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_swapped_globals_file_is_caught_through_the_signed_manifest() -> Result<()> {
    let root = Scratch::new("v1-globals");
    let keydir = Scratch::new("v1-globals-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 11, true)?;
    let dir = artifact_dir(root.path(), id);
    // Overwritten with its own plaintext, so the file is no longer even an age stream and
    // the only thing that could catch it is the digest inside the authenticated manifest.
    fs::write(dir.join("globals.age"), GLOBALS_SQL)?;
    let error = failure(store.open_signed(id));
    assert!(
        error.contains("globals.age does not match the digest inside the signed manifest"),
        "{error}"
    );
    Ok(())
}

#[test]
fn two_manifests_for_one_id_are_refused() -> Result<()> {
    let root = Scratch::new("v1-split");
    let keydir = Scratch::new("v1-split-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 13, false)?;
    fs::write(
        artifact_dir(root.path(), id).join("manifest.json"),
        b"{}\n".as_slice(),
    )?;
    let errors = [failure(store.open_signed(id)), failure(store.inspect(id))];
    for error in errors {
        assert!(
            error.contains("both manifest.json and manifest.age"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn an_oversized_public_json_is_refused_before_it_is_parsed() -> Result<()> {
    let root = Scratch::new("v1-cap");
    let keydir = Scratch::new("v1-cap-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 14, false)?;
    fs::write(
        artifact_dir(root.path(), id).join("public.json"),
        " ".repeat(MAX_PUBLIC_JSON_BYTES + 1),
    )?;
    for error in [failure(store.open_signed(id)), failure(store.list_signed())] {
        assert!(
            error.contains(&format!("over the {MAX_PUBLIC_JSON_BYTES} byte cap")),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn a_manifest_that_disagrees_with_the_staged_bytes_is_refused() -> Result<()> {
    let root = Scratch::new("v1-drift");
    let keydir = Scratch::new("v1-drift-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = Uuid::new_v4();
    let (stage, measured, _) = stage_dump(&store, id, &payload_bytes(15), None)?;
    let mut manifest = manifest_for(&store, id, &measured, PAYLOAD_LEN as u64, None)?;
    manifest.payload_ciphertext_bytes += 1;
    let error = failure(store.publish_signed(stage, &manifest));
    assert!(
        error.contains("staged payload changed, or the manifest was not built from it"),
        "{error}"
    );
    Ok(())
}

#[test]
fn the_two_ids_are_derived_from_the_key_files_and_not_from_config() -> Result<()> {
    let root = Scratch::new("v1-ids");
    let keydir = Scratch::new("v1-ids-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let facts = store.signed_key_facts()?;
    let (recipient_id, signer_id) = (facts.recipient_id, facts.signer_id);
    assert_eq!(recipient_id.len(), ID_HEX_LEN);
    assert_ne!(recipient_id, signer_id);

    let id = Uuid::new_v4();
    let (stage, measured, _) = stage_dump(&store, id, &payload_bytes(16), None)?;
    let mut manifest = manifest_for(&store, id, &measured, PAYLOAD_LEN as u64, None)?;
    manifest.recipient_id = "f".repeat(ID_HEX_LEN);
    let error = failure(store.publish_signed(stage, &manifest));
    assert!(
        error.contains(&format!("the configured recipient derives {recipient_id}")),
        "{error}"
    );
    // Nothing was published and the stage is gone: a v1 store has no visible state in which
    // an unsigned artifact exists.
    assert!(!artifact_dir(root.path(), id).exists());
    assert!(store.list_signed()?.signed.is_empty());
    Ok(())
}

#[test]
fn a_signed_artifacts_plaintext_is_bounded_by_the_manifest_it_was_signed_with() -> Result<()> {
    let root = Scratch::new("v1-bound");
    let keydir = Scratch::new("v1-bound-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = Uuid::new_v4();
    let payload = payload_bytes(17);
    let (stage, measured, _) = stage_dump(&store, id, &payload, None)?;
    // Recorded short on purpose: the signature makes this number authoritative, so the
    // decryption that trusts it has to be the thing that stops.
    let manifest = manifest_for(&store, id, &measured, 16, None)?;
    store.publish_signed(stage, &manifest)?;
    let artifact = store.open_signed(id)?;
    let error = failure(store.payload_plaintext(&artifact));
    assert!(error.contains("byte plaintext limit"), "{error}");
    assert!(
        fs::read_dir(root.path().join("scratch"))?.next().is_none(),
        "a refused decryption must not leave a half-written plaintext file"
    );
    Ok(())
}

#[test]
fn a_signature_that_covers_a_different_backup_id_is_refused() -> Result<()> {
    // The signed tuple binds the backup id, so an artifact copied into a second directory
    // with its own `public.json` cannot present someone else's bytes as its own.
    let root = Scratch::new("v1-relocate");
    let keydir = Scratch::new("v1-relocate-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 18, false)?;
    let copy = Uuid::new_v4();
    fs::create_dir_all(artifact_dir(root.path(), copy))?;
    for name in [
        "payload.age",
        "manifest.age",
        "signature.hybrid",
        "public.json",
        "complete",
    ] {
        fs::copy(
            artifact_dir(root.path(), id).join(name),
            artifact_dir(root.path(), copy).join(name),
        )?;
    }
    let error = failure(store.open_signed(copy));
    assert!(
        error.contains("public.json records backup id"),
        "the id the signature covers is checked against the directory: {error}"
    );
    Ok(())
}

#[test]
fn the_signed_tuple_is_the_documented_width() {
    let digest = [0u8; 32];
    let tuple = signature_tuple(Uuid::nil().as_bytes(), &digest, &digest);
    assert_eq!(tuple.as_bytes().len(), 22 + 16 + 32 + 32);
}

#[test]
fn signed_views_refuse_ciphertext_replaced_after_opening() -> Result<()> {
    let root = Scratch::new("v1-replaced-after-open");
    let keydir = Scratch::new("v1-replaced-after-open-keys");
    let keys = Keys::generate(keydir.path());
    let store = signed_store(root.path(), &keys);
    let id = publish_one(&store, 1, true)?;
    let artifact = store.open_signed(id)?;
    let recipient = backup_crypto::keystore::KeyFile::load(
        &keys.recipient,
        backup_crypto::keystore::KeyRole::Recipient,
    )?;
    for (name, bytes) in [
        ("payload.age", payload_bytes(9)),
        ("globals.age", GLOBALS_SQL.to_vec()),
    ] {
        let mut forged = Vec::new();
        backup_crypto::stream::encrypt(recipient.recipient(), bytes.as_slice(), &mut forged)?;
        // Test both replacing the pathname and changing the existing inode.
        for rename in [true, false] {
            let path = artifact_dir(root.path(), id).join(name);
            if rename {
                let replacement = path.with_extension("replacement");
                fs::write(&replacement, &forged)?;
                fs::rename(replacement, &path)?;
            } else {
                fs::write(&path, &forged)?;
            }
            let result = if name == "payload.age" {
                store.payload_plaintext(&artifact)
            } else {
                store.globals_plaintext(&artifact)
            };
            let error = failure(result);
            assert!(
                error.contains("ciphertext changed after authentication")
                    || error.contains("failed to decrypt completely"),
                "{error}"
            );
            assert_eq!(fs::read_dir(root.path().join("scratch"))?.count(), 0);
        }
    }
    Ok(())
}
