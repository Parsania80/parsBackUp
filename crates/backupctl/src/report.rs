//! Human-readable reporting. Every line here is what an operator (and the
//! Docker smoke scripts) reads, so this module is the single place those
//! strings live; the JSON path stays in `run` because it serializes the domain
//! types directly.

use backup_application::{Created, Inventory, Record, RestoreOutcome, VerifyReport};
use backup_domain::{
    ArtifactManifest, DevelopmentManifest, Profile, ResolvedSelection, RestorePlan,
    VERIFICATION_NONE,
};
use backup_local::{KeyStatus, Recovery, SigningKeyStatus, SigningRole};

fn print_list(label: &str, values: &[String]) {
    if !values.is_empty() {
        println!("{label}: {}", values.join(", "));
    }
}

/// Both key files, plus the public recipient they share. Reaching the same recipient
/// from an identity file and a recipient file is how an operator proves a pair belongs
/// together, and this is the only key material that is safe to print.
pub(crate) fn print_keys(identity: &KeyStatus, recipient: &KeyStatus) {
    println!("suite: {}", identity.suite);
    println!(
        "identity: {} (mode {:04o})",
        identity.path.display(),
        identity.mode
    );
    println!(
        "recipient: {} (mode {:04o})",
        recipient.path.display(),
        recipient.mode
    );
    // The seed is never printed, and the recipient is: it is the public half both files
    // carry, and the value an operator copies to a host that may only write backups. It
    // is shown as a fingerprint because a 1216-byte key is a file to move, not a line to
    // read; `--output json` carries it whole.
    let fingerprint = identity
        .recipient_hex
        .chars()
        .take(identity.recipient_hex.len().min(32))
        .collect::<String>();
    println!(
        "recipient key: {fingerprint}… ({} hex characters, --output json for the full value)",
        identity.recipient_hex.len()
    );
}

/// The signing pair, the same way [`print_keys`] reports the encryption pair: paths, modes,
/// and the public signer id both files derive. A verifying-only host reports one row, because
/// holding no signing secret is the point of that configuration.
pub(crate) fn print_signing_keys(statuses: &[SigningKeyStatus]) {
    for status in statuses {
        let role = match status.role {
            SigningRole::Signing => "signing",
            SigningRole::Verifying => "verifying",
        };
        println!(
            "{role}: {} (mode {:04o}, suite {})",
            status.path.display(),
            status.mode,
            status.suite
        );
    }
    if let Some(first) = statuses.first() {
        println!("signer key: {}", first.signer_id);
    }
}

pub(crate) fn print_selection(selection: &ResolvedSelection) {
    if selection.whole_database {
        println!("scope: whole database");
        return;
    }
    print_list("schemas", &selection.schemas);
    print_list("relations", &selection.tables);
    print_list("excluded schemas", &selection.exclude_schemas);
    print_list("excluded relations", &selection.exclude_tables);
    print_list("extension members", &selection.extension_members);
}

pub(crate) fn print_profile_scope(profile: &Profile) {
    println!("profile: {}", profile.name);
    println!("database: {}", profile.database);
    let mode = serde_json::to_value(profile.mode).unwrap_or_default();
    println!("mode: {}", mode.as_str().unwrap_or_default());
    print_list("requested schemas", &profile.schemas);
    print_list("requested tables", &profile.tables);
    print_list("excluded schemas", &profile.exclude_schemas);
    print_list("excluded tables", &profile.exclude_tables);
    print_list("excluded extensions", &profile.exclude_extensions);
    println!("large objects: {}", profile.large_objects);
}

/// What ADR 0004's maintenance pass did before this backup ran, in the one case an operator has to
/// know about: that it *didn't*. A quiet store with nothing to clear prints nothing here, so a normal
/// nightly backup stays as silent as it was.
pub(crate) fn print_recovery(recovery: &Recovery) {
    if !recovery.claimed {
        eprintln!(
            "warning: another command is using this store's working directories, so nothing was \
             cleared and no abandoned job was marked interrupted"
        );
        return;
    }
    for path in &recovery.refused {
        eprintln!(
            "warning: {} is not a directory this tool writes, so it was left alone",
            path.display()
        );
    }
    if recovery.removed.is_empty() && recovery.interrupted.is_empty() {
        return;
    }
    eprintln!(
        "cleared {} abandoned working directory(s), marked {} job(s) interrupted",
        recovery.removed.len(),
        recovery.interrupted.len()
    );
}

pub(crate) fn print_backup_created(created: &Created) {
    match created {
        Created::Development(manifest) => print_development_created(manifest),
        Created::Signed { manifest, .. } => print_signed_created(manifest),
    }
}

fn print_development_created(manifest: &DevelopmentManifest) {
    println!("created synthetic development backup {}", manifest.id);
    println!("database: {}", manifest.database);
    println!("bytes: {}", manifest.size_bytes);
    // Which of the two payload shapes was written is the first thing an operator
    // needs to know before deciding where to copy the artifact.
    match &manifest.recipient_suite {
        Some(suite) => println!("payload: encrypted with {suite}"),
        None => println!("payload: plaintext"),
    }
    if let Some(scope) = &manifest.scope {
        println!("profile: {}", scope.profile);
        println!("resolved schemas: {}", scope.resolved_schemas.join(", "));
        println!("resolved relations: {}", scope.resolved_tables.join(", "));
        if scope.large_objects {
            println!("large objects: every one in the database");
        }
    }
    println!(
        "security metadata: {}",
        if manifest.security_globals {
            let name = if manifest.recipient_suite.is_some() {
                "globals.age"
            } else {
                "globals.sql"
            };
            format!("{name} (roles and memberships, no password verifiers)")
        } else {
            "none".to_string()
        }
    );
}

/// What a v1 write published.
///
/// The record is reported from the manifest that was just sealed and signed, so every line
/// here is a claim the operator's own key has now attested to — including the two id
/// fingerprints, which name the keys an artifact can be opened and trusted by.
fn print_signed_created(manifest: &ArtifactManifest) {
    println!("created signed artifact v1 {}", manifest.backup_id);
    println!("source database: {}", manifest.profile_snapshot.database);
    println!("profile: {}", manifest.profile_snapshot.name);
    println!(
        "payload: {} bytes of ciphertext {}, {} of archive",
        manifest.payload_ciphertext_bytes,
        manifest.payload_ciphertext_sha256,
        manifest.archive_plaintext_bytes
    );
    println!(
        "sealed: {} to recipient {}",
        manifest.recipient_suite, manifest.recipient_id
    );
    println!(
        "signed: {} by signer {}",
        manifest.signature_suite, manifest.signer_id
    );
    println!(
        "security metadata: {}",
        if manifest.globals_policy == backup_domain::GLOBALS_POLICY_EXPORTED {
            "globals.age (roles and memberships, no password verifiers)"
        } else {
            "none"
        }
    );
    println!(
        "verification: {}; the manifest is signed, so later checks are reported by \
         backup verify rather than written into the artifact",
        manifest.verification_level
    );
}

/// One artifact's record, printed from whichever of the two files describes it. A signed
/// artifact's detail is only readable by a host holding the decryption identity, which is
/// precisely why `backup inspect` on such a store needs keys and `backup list` does not.
pub(crate) fn print_inspect(record: &Record) {
    match record {
        Record::Development(manifest) => print_development_inspect(manifest),
        Record::Signed(manifest) => print_signed_inspect(manifest),
    }
}

fn print_development_inspect(manifest: &DevelopmentManifest) {
    println!("id: {}", manifest.id);
    println!("format: {}", manifest.format);
    println!("database: {}", manifest.database);
    println!("source major: {}", manifest.source_major);
    println!("client: {}", manifest.dump_client_version);
    println!("bytes: {}", manifest.size_bytes);
    println!(
        "recipient suite: {}",
        manifest
            .recipient_suite
            .as_deref()
            .unwrap_or("none (plaintext payload)")
    );
    if let Some(plaintext_bytes) = manifest.payload_plaintext_bytes {
        println!("plaintext bytes: {plaintext_bytes}");
    }
    println!("sha256: {}", manifest.sha256);
    println!("security globals: {}", manifest.security_globals);
    if let Some(scope) = &manifest.scope {
        println!("profile: {}", scope.profile);
        println!("whole database: {}", scope.whole_database);
        println!("resolved schemas: {}", scope.resolved_schemas.join(", "));
        println!("resolved relations: {}", scope.resolved_tables.join(", "));
        println!("extension members: {}", scope.extension_members.join(", "));
    }
    println!(
        "table of contents: {}",
        manifest
            .toc_sha256
            .clone()
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "verification: {}",
        manifest
            .verification_level
            .clone()
            .unwrap_or_else(|| VERIFICATION_NONE.to_string())
    );
}

fn print_signed_inspect(manifest: &ArtifactManifest) {
    println!("id: {}", manifest.backup_id);
    println!("format: signed artifact v1");
    println!(
        "engine: {} major {}",
        manifest.engine, manifest.source_server_major
    );
    println!("source server: {}", manifest.source_server_version);
    println!("client: {}", manifest.dump_client_version);
    println!(
        "written: {} to {}",
        manifest.started_at_utc, manifest.completed_at_utc
    );
    println!("source fingerprint: {}", manifest.source_fingerprint);
    println!("profile: {}", manifest.profile_snapshot.name);
    println!("source database: {}", manifest.profile_snapshot.database);
    println!(
        "scope: {}",
        if manifest.resolved_selection.whole_database {
            "whole database".to_string()
        } else {
            format!(
                "{} schemas, {} relations",
                manifest.resolved_selection.schemas.len(),
                manifest.resolved_selection.tables.len()
            )
        }
    );
    print_list("resolved schemas", &manifest.resolved_selection.schemas);
    print_list("resolved relations", &manifest.resolved_selection.tables);
    print_list(
        "extension members",
        &manifest.resolved_selection.extension_members,
    );
    println!(
        "payload: {} bytes of ciphertext {}, {} of archive",
        manifest.payload_ciphertext_bytes,
        manifest.payload_ciphertext_sha256,
        manifest.archive_plaintext_bytes
    );
    println!(
        "globals: {}",
        match (manifest.globals_policy.as_str(), &manifest.globals_sha256) {
            (backup_domain::GLOBALS_POLICY_EXPORTED, Some(sha)) => format!(
                "{} bytes {}",
                manifest.globals_ciphertext_bytes.unwrap_or_default(),
                sha
            ),
            (backup_domain::GLOBALS_POLICY_SKIPPED, None) => "skipped".to_string(),
            _ => "declared inconsistently".to_string(),
        }
    );
    println!(
        "sealed: {} to recipient {}, signed: {} by signer {}",
        manifest.recipient_suite,
        manifest.recipient_id,
        manifest.signature_suite,
        manifest.signer_id
    );
    println!(
        "table of contents: {}",
        manifest
            .archive_toc_sha256
            .clone()
            .unwrap_or_else(|| "recorded by verify --level archive".to_string())
    );
    println!("verification: {}", manifest.verification_level);
}

/// What the store holds, in the shape it can be listed.
///
/// A signed store's listing is unauthenticated by design — these are candidates to verify,
/// not facts — and the pre-v1 artifacts it cannot describe are named by id so that nothing in
/// the store is hidden from the operator who has to decide what to restore.
pub(crate) fn print_inventory(inventory: &Inventory) {
    match inventory {
        Inventory::Development(manifests) => {
            for item in manifests {
                println!("{}  {}  {} bytes", item.id, item.database, item.size_bytes);
            }
        }
        Inventory::Public(listing) => {
            for header in &listing.signed {
                println!(
                    "{}  {} bytes  signed v1 (signer {})",
                    header.backup_id, header.payload_ciphertext_bytes, header.signer_id
                );
            }
            for id in &listing.unsigned {
                println!("{id}  unsigned development artifact; no record without keys");
            }
            if listing.signed.is_empty() && listing.unsigned.is_empty() {
                println!("no artifacts");
            }
        }
    }
}

pub(crate) fn print_verify(report: &VerifyReport) {
    println!(
        "artifact {} verified at level {}",
        report.artifact_id, report.level
    );
    println!(
        "payload: {} bytes {}",
        report.payload_size_bytes, report.payload_sha256
    );
    if let (Some(size), Some(sha)) = (report.globals_size_bytes, &report.globals_sha256) {
        println!("globals: {size} bytes {sha}");
    }
    if let Some(origin) = &report.origin {
        println!(
            "origin: {} signature by signer {}, sealed to recipient {}",
            origin.signature_suite, origin.signer_id, origin.recipient_id
        );
    }
    if report.level == backup_domain::VERIFY_SIGNATURE {
        println!("nothing was decrypted to produce this report");
    }
}

pub(crate) fn print_plan(plan: &RestorePlan) {
    println!("restore plan {} (digest {})", plan.id, plan.digest());
    println!(
        "artifact: {} ({})",
        plan.artifact_id, plan.artifact_database
    );
    if let Some(profile) = &plan.artifact_scope {
        println!("backup profile scope: {profile}");
    }
    println!("target: {} (new database)", plan.target_database);
    println!(
        "security: roles={} ownership={} privileges={}",
        plan.security.roles, plan.security.ownership, plan.security.privileges
    );
    println!(
        "sections: pre-data={} data={} post-data={}",
        plan.sections.pre_data, plan.sections.data, plan.sections.post_data
    );
    println!(
        "expires in {} minutes; run with --confirm-target {}",
        backup_domain::PLAN_TTL_SECONDS / 60,
        plan.target_database
    );
}

pub(crate) fn print_restore(executed: &RestoreOutcome) {
    println!(
        "restored {} into {}",
        executed.plan.artifact_id, executed.plan.target_database
    );
    println!("verification level: {}", executed.verification_level);
    if !executed.recorded_in_artifact {
        println!(
            "note: this run did not change what the artifact itself records about verification"
        );
    }
    if !executed.plan.sections.is_full() {
        println!(
            "warning: only part of the archive was replayed, so this run does not prove the artifact restores completely"
        );
    }
}
