//! Human-readable reporting. Every line here is what an operator (and the
//! Docker smoke scripts) reads, so this module is the single place those
//! strings live; the JSON path stays in `run` because it serializes the domain
//! types directly.

use backup_application::{RestoreOutcome, VerifyReport};
use backup_domain::{
    DevelopmentManifest, Profile, ResolvedSelection, RestorePlan, VERIFICATION_NONE,
};
use backup_local::KeyStatus;

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

pub(crate) fn print_backup_created(manifest: &DevelopmentManifest) {
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

pub(crate) fn print_inspect(manifest: DevelopmentManifest) {
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
        manifest.toc_sha256.unwrap_or_else(|| "none".to_string())
    );
    println!(
        "verification: {}",
        manifest
            .verification_level
            .unwrap_or_else(|| VERIFICATION_NONE.to_string())
    );
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
    if !executed.plan.sections.is_full() {
        println!(
            "warning: only part of the archive was replayed, so this run does not prove the artifact restores completely"
        );
    }
}
