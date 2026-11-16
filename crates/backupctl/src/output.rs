//! One invocation owns one machine result. Legacy JSON is printed at the old result
//! boundary; v1 waits for the final outcome so partial work is never reported as success.
use crate::cli::Output;
use anyhow::Result;
use serde_json::{Value, json};
use std::process::ExitCode;

#[derive(Debug)]
pub(crate) struct Refusal(pub &'static str);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Refusal {}
pub(crate) fn refuse<T>(code: &'static str) -> Result<T> {
    Err(Refusal(code).into())
}

pub(crate) struct Reporter {
    output: Output,
    operation: &'static str,
    data: Option<Value>,
    partial: bool,
}
impl Reporter {
    pub(crate) fn new(output: Output, operation: &'static str) -> Self {
        Self {
            output,
            operation,
            data: None,
            partial: false,
        }
    }
    pub(crate) fn is_json(&self) -> bool {
        !matches!(self.output, Output::Human)
    }
    pub(crate) fn data(&mut self, value: Value) -> Result<()> {
        if matches!(self.output, Output::Json) {
            if self.operation == "config.check" {
                println!("{value}");
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
        }
        self.data = Some(value);
        Ok(())
    }
    pub(crate) fn partial(&mut self) {
        self.partial = true;
    }
    pub(crate) fn finish(self, result: Result<()>) -> ExitCode {
        let failure = result
            .as_ref()
            .err()
            .map(|e| safe_failure(e, self.operation));
        if matches!(self.output, Output::JsonV1) {
            let envelope = json!({
                "format": "backupctl-cli-report-v1", "operation": self.operation,
                "status": if failure.is_none() { "ok" } else if self.partial { "partial" } else { "error" },
                "data": self.data,
                "error": failure.as_ref().map(|(code, message)| json!({"code": code, "message": message})),
            });
            println!("{envelope}");
        } else if let Some((code, message)) = &failure {
            eprintln!("error: {code}: {message}");
        }
        if failure.is_none() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

/// Only generated messages and enumerated codes may leave this boundary. Never forward
/// a parser excerpt, a path-bearing cause or native stderr, even through anyhow context.
fn safe_failure(error: &anyhow::Error, operation: &str) -> (&'static str, &'static str) {
    if let Some(refusal) = error.downcast_ref::<Refusal>() {
        return (refusal.0, message(refusal.0));
    }
    const CODES: &[&str] = &[
        "CONFIG_INVALID",
        "FILESYSTEM_UNSAFE",
        "SNAPSHOT_UNSAFE",
        "SCRATCH_REQUIRED",
        "RESOURCE_LIMIT",
        "DISK_RESERVE_LOW",
        "KEY_UNSAFE",
        "KEY_INVALID",
        "KEY_OCCUPIED",
        "KEY_BUSY",
        "KEY_OPERATION_FAILED",
        "KEY_PARTIAL",
        "NATIVE_CONTEXT_MISMATCH",
        "RETENTION_JOB_DEPENDENCY",
        "RETENTION_LAST_VALID",
        "RETENTION_PLAN_EXPIRED",
        "RETENTION_PLAN_INVALID",
        "RETENTION_PROTECTED",
        "RETENTION_SCOPE_UNKNOWN",
        "RETENTION_PLAN_STALE",
        "RETENTION_ARTIFACT_INVALID",
        "RETENTION_BUSY",
        "RETENTION_INVENTORY_INVALID",
        "RETENTION_CONFIRMATION_MISMATCH",
        "RETENTION_PLAN_TOO_LARGE",
        "RETENTION_PROTECTION_UNKNOWN",
        "RETENTION_VERIFICATION_REQUIRED",
        "OLDER_SNAPSHOT_ACK_NOT_APPLICABLE",
        "OLDER_SNAPSHOT_ACK_REQUIRED",
        "OLDER_SNAPSHOT_REPLAN_REQUIRED",
        "INVENTORY_CORRUPT",
        "INVENTORY_OPEN_FAILED",
        "INVENTORY_READ_FAILED",
        "JOB_NOT_FOUND",
        "RECONCILE_BUSY",
        "RESTORE_BUSY",
        "DELETION_RECOVERY_REQUIRED",
    ];
    for cause in error.chain() {
        let text = cause.to_string();
        let prefix = text.split_once(':').map_or(text.as_str(), |(code, _)| code);
        if let Some(code) = CODES.iter().find(|code| **code == prefix) {
            return (code, diagnostic(error).unwrap_or(message(code)));
        }
    }
    // Established uncoded legacy concurrency diagnostics have fixed safe equivalents.
    if error
        .chain()
        .any(|c| c.to_string().contains("already running"))
    {
        return ("OPERATION_BUSY", "This operation is already running.");
    }
    if error.chain().any(|c| c.to_string().contains("stale")) {
        return ("PLAN_STALE", "The saved plan is stale; prepare a new plan.");
    }
    if matches!(
        operation,
        "backup.create" | "profile.validate" | "backup.verify" | "restore.plan" | "restore.run"
    ) {
        (
            "NATIVE_OPERATION_FAILED",
            diagnostic(error).unwrap_or("The operation failed; the target may be partially modified. Inspect durable jobs before retrying."),
        )
    } else {
        (
            "OPERATION_FAILED",
            diagnostic(error).unwrap_or("The operation failed. Inspect the configured resources and durable jobs before retrying."),
        )
    }
}
fn message(code: &str) -> &'static str {
    match code {
        "NATIVE_CONTEXT_MISMATCH" => {
            "The restore plan connection context changed; create a new plan."
        }
        "KEY_UNSAFE" => "A required key resource or its ancestry is missing, unsafe or aliased.",
        "KEY_INVALID" => {
            "Required key material is missing, invalid or does not match its public half."
        }
        "KEY_OCCUPIED" => "A key destination is occupied; existing material was preserved.",
        "KEY_BUSY" => "A required key directory is in use by another key operation.",
        "KEY_OPERATION_FAILED" => {
            "Key staging or publication failed; inspect key custody before retrying."
        }
        "KEY_PARTIAL" => {
            "Some key files were published and retained; inspect the receipt and key custody before recovery."
        }
        "SNAPSHOT_UNSAFE" => {
            "The snapshot is unsafe, unsupported or requires quiescent SQLite state."
        }
        "SCRATCH_REQUIRED" => {
            "Authenticated snapshot reads require explicit protected external scratch."
        }
        "FILESYSTEM_UNSAFE" => {
            "The store or required filesystem resource is missing, unsafe or aliases protected key storage."
        }
        "RESOURCE_LIMIT" => {
            "The configured resource limit was exceeded; publication or plaintext release was refused."
        }
        "DISK_RESERVE_LOW" => {
            "The destination filesystem cannot preserve the configured free-space reserve."
        }
        "CONFIG_INVALID" => "invalid configuration; check the documented fields and safety rules.",
        "CONFIG_VERSION_UNSUPPORTED" => "This configuration version is not supported.",
        "CREDENTIAL_UNSAFE" => "The configuration file or its ancestry is not protected.",
        "ACCESS_DENIED" => "The configured access role does not permit this command.",
        "READ_ONLY" => "The command is not permitted by read-only configuration.",
        "PRODUCTION_NOT_ENABLED" => "Production operations are not enabled in this build.",
        "OUTPUT_FORMAT_UNSUPPORTED" => "Production machine output requires json-v1.",
        "CAPABILITY_NOT_ENABLED" => "This versioned capability requires a later H02 increment.",
        "RECONCILE_BUSY" => {
            "The store is busy or the saved plan is stale; prepare a new plan when quiescent."
        }
        "RESTORE_BUSY" => "The restore target is already in use.",
        "INVENTORY_CORRUPT" => "Inventory structural integrity checks failed.",
        "INVENTORY_OPEN_FAILED" => "The inventory could not be opened safely.",
        "INVENTORY_READ_FAILED" => "The inventory could not be read safely.",
        "DELETION_RECOVERY_REQUIRED" => {
            "Inspect deleting/deleted artifact state, durable jobs and saved intent before retrying."
        }
        "JOB_NOT_FOUND" => "The requested job is not recorded.",
        "OLDER_SNAPSHOT_ACK_NOT_APPLICABLE" => {
            "No known older-snapshot warning can be acknowledged."
        }
        "OLDER_SNAPSHOT_ACK_REQUIRED" => {
            "The selected older snapshot requires explicit acknowledgement in a new plan."
        }
        "OLDER_SNAPSHOT_REPLAN_REQUIRED" => {
            "Snapshot history or selection changed; prepare a new restore plan."
        }
        _ => {
            "The operation was refused or interrupted. Inspect durable jobs and saved intent before retrying."
        }
    }
}

/// Compatibility phrases used by the established fixture diagnostics. Matching selects
/// a wholly static explanation, never an excerpt or interpolated value. The longest recognized phrase
/// selects the most specific category. This is a bridge for existing untyped adapter errors.
fn diagnostic(error: &anyhow::Error) -> Option<&'static str> {
    const SAFE: &[(&str, &str)] = &[
        (
            "a [signing] block requires an [encryption] block",
            "a [signing] block requires an [encryption] block.",
        ),
        (
            "encryption key files must live outside the artifact store",
            "encryption key files must live outside the artifact store.",
        ),
        (
            "signing key files must live outside the artifact store",
            "signing key files must live outside the artifact store.",
        ),
        (
            "must not name the same file",
            "key paths must not name the same file.",
        ),
        (
            "must live outside the artifact store",
            "key files must live outside the artifact store.",
        ),
        (
            "refusing to overwrite the existing key file",
            "refusing to overwrite the existing key file; use a new generation.",
        ),
        (
            "is not the recipient of identity key file",
            "recipient key file is not the recipient of identity key file.",
        ),
        (
            "payload.age is not the ciphertext public.json describes",
            "payload.age is not the ciphertext public.json describes.",
        ),
        (
            "manifest.age is not the ciphertext public.json describes",
            "manifest.age is not the ciphertext public.json describes.",
        ),
        (
            "payload checksum or size mismatch",
            "payload checksum or size mismatch.",
        ),
        ("globals checksum", "globals checksum mismatch."),
        (
            "origin signature of artifact",
            "origin signature of artifact does not verify; signature check failed.",
        ),
        (
            "found under directory",
            "public backup ID does not match the ID found under directory.",
        ),
        (
            "invalid public.json",
            "invalid public.json; no artifact details were trusted.",
        ),
        (
            "over the 4096 byte cap",
            "public.json is over the 4096 byte cap.",
        ),
        (
            "expected a regular non-symlink file",
            "expected a regular non-symlink file.",
        ),
        (
            "no such file",
            "required artifact or key file: no such file or not a directory.",
        ),
        (
            "not a directory",
            "required artifact or key file: no such file or not a directory.",
        ),
        (
            "configures no signing_key_file",
            "this host configures no signing_key_file; key publication was refused.",
        ),
        (
            "no recipient file",
            "no recipient file is held; this reader cannot seal artifacts.",
        ),
        (
            "cannot seal",
            "this reader cannot seal artifacts; no recipient file is held.",
        ),
        (
            "dumped from a different source than the configured one",
            "artifact was dumped from a different source than the configured one.",
        ),
        (
            "must be mode 0600 or stricter",
            "secret key file must be mode 0600 or stricter.",
        ),
        (
            "inspect recipient key file",
            "cannot inspect recipient key file.",
        ),
        ("load signing key file", "cannot load signing key file."),
        ("load verifying key file", "cannot load verifying key file."),
        (
            "identity key file",
            "cannot use the configured identity key file.",
        ),
        (
            "recipient key file",
            "cannot use the configured recipient key file.",
        ),
        (
            "verifying key file",
            "cannot use the configured verifying key file.",
        ),
        (
            "already exist",
            "the target or required object already exists; no overwrite is permitted.",
        ),
        (
            "every large object",
            "this selection does not include every large object; review large objects explicitly.",
        ),
        (
            "large objects",
            "large objects are not supported by this selection.",
        ),
        ("match nothing", "configured selectors match nothing."),
        (
            "postgresql 17",
            "this selection requires PostgreSQL 17 or later.",
        ),
        (
            "table of contents",
            "archive table of contents does not match the recorded scope.",
        ),
        (
            "pre-data",
            "section selection must start with pre-data and be contiguous.",
        ),
        (
            "cannot reconstruct",
            "this partial restore cannot reconstruct the declared security state.",
        ),
        (
            "published and restorable",
            "backup bytes may be published and restorable; inspect inventory before retrying.",
        ),
        (
            "clearing this store",
            "active or saved history prevents clearing this store.",
        ),
        (
            "schema version",
            "unsupported inventory schema version; use a compatible build.",
        ),
        (
            "confirmation target",
            "confirmation target does not match the planned database.",
        ),
        (
            "artifact scan contains",
            "artifact scan contains invalid, incomplete, or conflicting entries.",
        ),
        (
            "refusing to merge two estates",
            "refusing to merge two estates into one index.",
        ),
        (
            "estate mismatch",
            "inventory estate mismatch; use the recorded estate.",
        ),
        (
            "schema is newer",
            "inventory schema is newer than this build.",
        ),
        (
            "artifact is absent, registered, incomplete, or invalid",
            "artifact is absent, registered, incomplete, or invalid.",
        ),
        (
            "output withheld",
            "native operation failed (output withheld); resources may be partially modified. Inspect durable jobs before retrying.",
        ),
        (
            "decrypt",
            "cannot decrypt the artifact with the configured identity.",
        ),
        (
            "could not be opened with this identity",
            "artifact could not be opened with this identity; decryption refused.",
        ),
        (
            "not a readable age stream",
            "artifact is not a readable age stream; decryption refused.",
        ),
        ("signature", "artifact signature validation failed."),
        (
            "foreign key target",
            "selection depends on an out-of-scope foreign key target.",
        ),
        (
            "parent relation",
            "selection depends on an out-of-scope parent relation.",
        ),
        (
            "sequence default",
            "selection depends on an out-of-scope sequence default.",
        ),
        (
            "view base relation",
            "selection depends on an out-of-scope view base relation.",
        ),
        (
            "column type",
            "selection depends on an out-of-scope column type.",
        ),
        (
            "unknown public.json format version 2",
            "unknown public.json format version 2; this build accepts version 1.",
        ),
        (
            "disagree on signature_suite",
            "signed manifest and public header disagree on signature_suite.",
        ),
    ];
    let causes: Vec<_> = error
        .chain()
        .map(|c| c.to_string().to_lowercase())
        .collect();
    SAFE.iter()
        .filter(|(needle, _)| causes.iter().any(|c| c.contains(needle)))
        .max_by_key(|(needle, _)| needle.len())
        .map(|(_, text)| *text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_emit_only_allowlisted_codes_and_static_text() {
        let secret = "SECRET_SENTINEL_/private/path/password";
        for error in [
            anyhow::anyhow!("invalid input {secret}"),
            anyhow::anyhow!("MALICIOUS_CODE: {secret}"),
            anyhow::anyhow!("cannot decrypt {secret}"),
            anyhow::anyhow!("RETENTION_PLAN_STALE: {secret}"),
            anyhow::anyhow!("{secret}").context("INVENTORY_OPEN_FAILED"),
        ] {
            let (code, text) = safe_failure(&error, "backup.inspect");
            assert!(!text.contains(secret));
            assert!(text.len() <= 512);
            assert_ne!(code, "MALICIOUS_CODE");
        }
        let identity = anyhow::anyhow!("opaque failure {secret}")
            .context("artifact could not be opened with this identity");
        let (_, text) = safe_failure(&identity, "backup.verify");
        assert!(text.contains("identity"));
        assert!(!text.contains(secret));
    }

    #[test]
    fn remaining_inventory_matrix_refusals_keep_their_safe_distinctions() {
        // Source error templates and externally asserted diagnostics from the M5a/B06
        // native contracts, including code-bearing context and private interpolated data.
        for (cause, expected) in [
            (
                "artifact is absent, registered, incomplete, or invalid",
                "artifact is absent, registered, incomplete, or invalid",
            ),
            (
                "confirmation target does not match the planned database",
                "confirmation target",
            ),
            (
                "artifact scan contains invalid, incomplete, or conflicting entries",
                "artifact scan contains",
            ),
            (
                "inventory SECRET belongs to source SECRET; refusing to merge two estates into one index",
                "refusing to merge two estates",
            ),
            ("inventory estate mismatch", "estate mismatch"),
            ("inventory schema is newer than this build", "newer"),
            (
                "inventory schema version SECRET not supported",
                "schema version",
            ),
            (
                "backup SECRET is published and restorable; only its inventory row failed",
                "published and restorable",
            ),
            (
                "another command is clearing this store's working directories",
                "clearing this store",
            ),
        ] {
            let error = anyhow::anyhow!("{cause}").context("INVENTORY_OPEN_FAILED");
            let (code, text) = safe_failure(&error, "restore.run");
            assert_eq!(code, "INVENTORY_OPEN_FAILED");
            assert!(text.contains(expected), "{expected}: {text}");
            assert!(!text.contains("SECRET"));
        }
        let deleted =
            anyhow::anyhow!("DELETION_RECOVERY_REQUIRED: artifact is deleting or deleted");
        let (code, text) = safe_failure(&deleted, "backup.inspect");
        assert_eq!(code, "DELETION_RECOVERY_REQUIRED");
        assert!(text.contains("deleted"));
    }
}
