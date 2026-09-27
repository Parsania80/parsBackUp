use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::path::PathBuf;
use uuid::Uuid;

pub const DEV_FORMAT: &str = "m1-development-plaintext";
pub const FIXTURE_PREFIX: &str = "backupctl_fixture_";
pub const PLAN_FORMAT: &str = "m3-restore-plan";
pub const VERIFY_CHECKSUM: &str = "checksum";
pub const VERIFY_ARCHIVE: &str = "archive";
pub const VERIFY_RESTORE_TESTED: &str = "restore-tested";
pub const SECTION_PRE_DATA: &str = "pre-data";
pub const SECTION_DATA: &str = "data";
pub const SECTION_POST_DATA: &str = "post-data";
/// `pg_dump --exclude-extension` arrived after PostgreSQL 16.
pub const MIN_MAJOR_EXCLUDE_EXTENSION: u32 = 17;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Source,
    pub storage: Storage,
    #[serde(default)]
    pub export_globals: bool,
    /// Configured with `[[profile]]` blocks in the service TOML.
    #[serde(default, rename = "profile")]
    pub profiles: Vec<Profile>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
    pub client_bin_dir: PathBuf,
    pub password_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub root: PathBuf,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.source.host.as_str(), "localhost" | "127.0.0.1" | "::1")
            && !self.source.host.starts_with('/')
        {
            bail!("only local PostgreSQL connections are permitted");
        }
        if self.source.port == 0 || self.source.user.is_empty() {
            bail!("source port and user are required");
        }
        if !self.source.database.starts_with(FIXTURE_PREFIX) {
            bail!("database name must start with {FIXTURE_PREFIX}");
        }
        if !self.source.client_bin_dir.is_absolute() || !self.storage.root.is_absolute() {
            bail!("client_bin_dir and storage.root must be absolute paths");
        }
        if let Some(path) = &self.source.password_file
            && !path.is_absolute()
        {
            bail!("password_file must be an absolute path");
        }
        if !(1..=3600).contains(&self.timeout_seconds) {
            bail!("timeout_seconds must be between 1 and 3600");
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            profile.validate()?;
            if names.contains(&profile.name.as_str()) {
                bail!("duplicate profile name {}", profile.name);
            }
            names.push(&profile.name);
            if profile.database != self.source.database {
                bail!(
                    "profile {} targets database {} but only {} is configured",
                    profile.name,
                    profile.database,
                    self.source.database
                );
            }
        }
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|profile| profile.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown profile {name}; configured profiles: {}",
                    if self.profiles.is_empty() {
                        "none".to_string()
                    } else {
                        self.profiles
                            .iter()
                            .map(|profile| profile.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                )
            })
    }
}

/// What a profile asks `pg_dump` to write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionMode {
    #[default]
    SchemaAndData,
    SchemaOnly,
    DataOnly,
}

/// Exact, non-pattern object names. `pg_dump` treats its own filters as
/// patterns with case folding, so accepting wildcards or mixed case here would
/// let a profile name objects the resolver cannot match one-to-one.
fn is_valid_schema_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_lowercase())
        && chars.all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit() || c == '$')
}

fn is_valid_table_name(name: &str) -> bool {
    let Some((schema, table)) = name.split_once('.') else {
        return false;
    };
    !table.contains('.') && is_valid_schema_name(schema) && is_valid_schema_name(table)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub database: String,
    #[serde(default)]
    pub mode: SelectionMode,
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(default)]
    pub exclude_schemas: Vec<String>,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub exclude_tables: Vec<String>,
    #[serde(default)]
    pub exclude_extensions: Vec<String>,
    #[serde(default)]
    pub large_objects: bool,
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.chars().any(char::is_whitespace) {
            bail!("profile name must be non-empty and contain no whitespace");
        }
        if !self.database.starts_with(FIXTURE_PREFIX) {
            bail!(
                "profile {} must target a {FIXTURE_PREFIX} database",
                self.name
            );
        }
        for list in [&self.schemas, &self.exclude_schemas] {
            for schema in list {
                if !is_valid_schema_name(schema) {
                    bail!(
                        "profile {}: schema {schema:?} must be an exact lower-case identifier without wildcards",
                        self.name
                    );
                }
                if starts_with_system_prefix(schema) {
                    bail!(
                        "profile {}: system schema {schema:?} cannot be selected",
                        self.name
                    );
                }
            }
        }
        for table in &self.tables {
            if !is_valid_table_name(table) {
                bail!(
                    "profile {}: table {table:?} must be an exact schema.table identifier without wildcards",
                    self.name
                );
            }
        }
        for table in &self.exclude_tables {
            if !is_valid_table_name(table) {
                bail!(
                    "profile {}: excluded table {table:?} must be an exact schema.table identifier",
                    self.name
                );
            }
        }
        for extension in &self.exclude_extensions {
            if !is_valid_schema_name(extension) {
                bail!(
                    "profile {}: excluded extension {extension:?} must be an exact lower-case name",
                    self.name
                );
            }
        }
        for (list, what) in [
            (&self.schemas, "schema"),
            (&self.tables, "table"),
            (&self.exclude_tables, "table"),
        ] {
            if let Some(duplicate) = first_duplicate(list) {
                bail!("profile {} lists {} {duplicate} twice", self.name, what);
            }
        }
        if let Some(duplicate) = first_duplicate(&self.exclude_schemas) {
            bail!("profile {} excludes schema {duplicate} twice", self.name);
        }
        if !self.tables.is_empty() && (!self.schemas.is_empty() || !self.exclude_schemas.is_empty())
        {
            bail!(
                "profile {} mixes tables with schema filters: pg_dump ignores --schema/--exclude-schema when --table is given; select one kind",
                self.name
            );
        }
        if self.mode == SelectionMode::SchemaOnly && self.large_objects {
            bail!(
                "profile {} requests large objects but a schema-only dump contains no object bytes",
                self.name
            );
        }
        Ok(())
    }

    pub fn is_whole_database(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty()
    }
}

fn starts_with_system_prefix(name: &str) -> bool {
    name.starts_with("pg_") || name == "information_schema"
}

/// Names the restore path may issue `CREATE SCHEMA` for: the same exact
/// lower-case identifier shape a profile may select, and never a system
/// namespace.
pub fn is_safe_created_schema_name(name: &str) -> bool {
    is_valid_schema_name(name) && !starts_with_system_prefix(name)
}

fn first_duplicate(list: &[String]) -> Option<&String> {
    let mut sorted: Vec<&String> = list.iter().collect();
    sorted.sort_unstable();
    sorted
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| pair[0])
}

/// A reference from an object inside the selection to an object outside it.
/// `pg_dump` does not follow these, so a selective artifact cannot be assumed
/// to restore into a clean database on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DanglingReference {
    pub dependent: String,
    pub referenced: String,
    pub kind: String,
}

/// The concrete object set a selection resolved to, produced by reading the
/// live catalog before any dump runs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSelection {
    pub whole_database: bool,
    pub schemas: Vec<String>,
    pub exclude_schemas: Vec<String>,
    pub tables: Vec<String>,
    pub exclude_tables: Vec<String>,
    pub dangling: Vec<DanglingReference>,
    /// Extensions owning objects inside the selection, recorded so a restore
    /// operator can see that member objects came from an extension.
    pub extension_members: Vec<String>,
}

impl ResolvedSelection {
    pub fn is_filtered(&self) -> bool {
        !self.whole_database
    }
}

/// The exact scope an artifact was built from, as recorded in its manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScope {
    pub profile: String,
    pub mode: SelectionMode,
    pub requested_schemas: Vec<String>,
    pub requested_tables: Vec<String>,
    pub exclude_schemas: Vec<String>,
    pub exclude_tables: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub resolved_schemas: Vec<String>,
    pub resolved_tables: Vec<String>,
    pub large_objects: bool,
    pub whole_database: bool,
    pub extension_members: Vec<String>,
}

impl ArtifactScope {
    pub fn from_profile(profile: &Profile, resolved: &ResolvedSelection) -> Self {
        Self {
            profile: profile.name.clone(),
            mode: profile.mode,
            requested_schemas: profile.schemas.clone(),
            requested_tables: profile.tables.clone(),
            exclude_schemas: profile.exclude_schemas.clone(),
            exclude_tables: profile.exclude_tables.clone(),
            exclude_extensions: profile.exclude_extensions.clone(),
            resolved_schemas: resolved.schemas.clone(),
            resolved_tables: resolved.tables.clone(),
            large_objects: profile.large_objects,
            whole_database: resolved.whole_database,
            extension_members: resolved.extension_members.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.profile.is_empty() {
            bail!("manifest scope requires a profile name");
        }
        if self.whole_database
            && (!self.resolved_schemas.is_empty() || !self.resolved_tables.is_empty())
        {
            bail!("a whole-database scope must not list resolved objects");
        }
        if !self.whole_database
            && self.resolved_schemas.is_empty()
            && self.resolved_tables.is_empty()
        {
            bail!("a filtered scope must list the objects it resolved to");
        }
        if !self.requested_schemas.is_empty() && !self.requested_tables.is_empty() {
            bail!("manifest scope cannot request both schemas and tables");
        }
        Ok(())
    }

    /// The namespaces a restore target must hold even though the archive does
    /// not create them: `pg_dump --table` selections carry no `CREATE SCHEMA`
    /// entries, while schema selections (and whole-database dumps) do.
    pub fn restore_required_schemas(&self) -> Vec<String> {
        if !self.resolved_schemas.is_empty() || self.resolved_tables.is_empty() {
            return Vec::new();
        }
        let mut schemas: Vec<String> = self
            .resolved_tables
            .iter()
            .filter_map(|table| table.split_once('.').map(|(schema, _)| schema.to_string()))
            .collect();
        schemas.sort();
        schemas.dedup();
        schemas
    }
}

/// Everything the dump step needs, resolved before the tool runs.
#[derive(Clone, Debug)]
pub struct DumpOptions<'a> {
    pub major: u32,
    pub mode: SelectionMode,
    pub selection: &'a ResolvedSelection,
    /// `None` leaves large-object handling to the native default, which is the
    /// profile-less whole-database path.
    pub large_objects: Option<bool>,
    pub exclude_extensions: &'a [String],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSections {
    pub pre_data: bool,
    pub data: bool,
    pub post_data: bool,
}

impl Default for RestoreSections {
    fn default() -> Self {
        Self::full()
    }
}

impl RestoreSections {
    pub fn full() -> Self {
        Self {
            pre_data: true,
            data: true,
            post_data: true,
        }
    }

    pub fn is_full(&self) -> bool {
        self.pre_data && self.data && self.post_data
    }

    pub fn validate(&self) -> Result<()> {
        if !(self.pre_data || self.data || self.post_data) {
            bail!("restore sections must select at least one of pre-data, data, post-data");
        }
        // M3 restores only into a database it creates, so a section set that
        // skips an earlier section would run against objects that do not exist
        // yet. pg_restore cannot be made to prove otherwise.
        if !self.pre_data && (self.data || self.post_data) {
            bail!(
                "restoring into a new database requires the pre-data section; select pre-data plus the sections after it"
            );
        }
        if self.pre_data && !self.data && self.post_data {
            bail!(
                "post-data without data skips the rows its indexes, constraints, and triggers would apply to; select data as well or drop post-data"
            );
        }
        Ok(())
    }

    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::new();
        if self.pre_data {
            argv.push(format!("--section={SECTION_PRE_DATA}"));
        }
        if self.data {
            argv.push(format!("--section={SECTION_DATA}"));
        }
        if self.post_data {
            argv.push(format!("--section={SECTION_POST_DATA}"));
        }
        argv
    }

    /// Pure input check, kept separate so a service can run it before any
    /// environment probing: a partial restore cannot rebuild what it skips.
    pub fn check_security(&self, security: &RestoreSecurityPolicy) -> Result<()> {
        if !self.is_full() && (security.roles || security.ownership || security.privileges) {
            bail!(
                "a section-limited restore cannot reconstruct roles, ownership, or privileges; use the portable policy or restore every section"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentManifest {
    pub format: String,
    pub id: Uuid,
    pub synthetic_only: bool,
    pub database: String,
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
    pub application_version: String,
    pub archive_format: String,
    pub compression: String,
    pub created_unix_ms: u128,
    pub size_bytes: u64,
    pub sha256: String,
    pub status: String,
    pub security_globals: bool,
    pub globals_sha256: Option<String>,
    pub globals_size_bytes: Option<u64>,
    pub verification_level: Option<String>,
    pub verified_unix_ms: Option<u128>,
    /// Absent means an unfiltered whole-database dump, which is what every
    /// pre-M3 artifact is.
    pub scope: Option<ArtifactScope>,
    pub toc_sha256: Option<String>,
}

impl DevelopmentManifest {
    pub fn validate_shape(&self) -> Result<()> {
        if self.format != DEV_FORMAT
            || !self.synthetic_only
            || !self.database.starts_with(FIXTURE_PREFIX)
            || !matches!(self.source_major, 16..=18)
            || self.archive_format != "custom"
            || self.compression != "gzip"
            || self.status != "complete"
            || self.size_bytes == 0
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid development manifest");
        }
        let globals_present = self.globals_sha256.is_some() || self.globals_size_bytes.is_some();
        if self.security_globals != globals_present {
            bail!("manifest globals fields must be present exactly when security_globals is set");
        }
        if let Some(sha) = &self.globals_sha256
            && (sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid manifest globals checksum");
        }
        if let Some(size) = self.globals_size_bytes
            && size == 0
        {
            bail!("manifest globals file must not be empty");
        }
        if let Some(level) = &self.verification_level
            && !matches!(level.as_str(), VERIFY_ARCHIVE | VERIFY_RESTORE_TESTED)
        {
            bail!("invalid manifest verification level");
        }
        if self.verified_unix_ms.is_some() != self.verification_level.is_some() {
            bail!("manifest verification fields must appear together");
        }
        if let Some(scope) = &self.scope {
            scope.validate()?;
        }
        if let Some(digest) = &self.toc_sha256
            && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("invalid manifest table-of-contents checksum");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSecurityPolicy {
    pub roles: bool,
    pub ownership: bool,
    pub privileges: bool,
}

impl RestoreSecurityPolicy {
    pub fn dr_full() -> Self {
        Self {
            roles: true,
            ownership: true,
            privileges: true,
        }
    }

    pub fn portable() -> Self {
        Self {
            roles: false,
            ownership: false,
            privileges: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub format: String,
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_database: String,
    pub source_major: u32,
    pub client_version: String,
    pub target_database: String,
    pub security: RestoreSecurityPolicy,
    pub sections: RestoreSections,
    /// The profile name the artifact was recorded with, when selective.
    pub artifact_scope: Option<String>,
    pub created_unix_ms: u128,
    pub expires_unix_ms: u128,
}

impl RestorePlan {
    pub fn validate(&self, now_unix_ms: u128) -> Result<()> {
        if self.format != PLAN_FORMAT {
            bail!("unrecognized restore plan format");
        }
        if !self.target_database.starts_with(FIXTURE_PREFIX) {
            bail!("restore target must be a synthetic fixture database");
        }
        if self.target_database == self.artifact_database {
            bail!("restore target must differ from the backup source database");
        }
        if self.expires_unix_ms <= self.created_unix_ms {
            bail!("restore plan expiry must be after its creation");
        }
        self.sections.validate()?;
        self.sections.check_security(&self.security)?;
        if now_unix_ms >= self.expires_unix_ms {
            bail!("restore plan has expired; create a new plan");
        }
        Ok(())
    }

    pub fn is_expired(&self, now_unix_ms: u128) -> bool {
        now_unix_ms >= self.expires_unix_ms
    }

    pub fn digest(&self) -> String {
        // Canonical serialization: fixed struct field order plus serde_json
        // keeps this stable, and any content change alters the digest.
        let bytes = serde_json::to_vec(self).expect("plan serializes");
        format!("{:x}", sha2::Sha256::digest(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(database: &str) -> Config {
        Config {
            source: Source {
                host: "127.0.0.1".to_string(),
                port: 5432,
                user: "fixture".to_string(),
                database: database.to_string(),
                client_bin_dir: PathBuf::from("/usr/lib/postgresql/16/bin"),
                password_file: None,
            },
            storage: Storage {
                root: PathBuf::from("/tmp/backupctl-fixture-test"),
            },
            export_globals: false,
            timeout_seconds: 30,
            profiles: Vec::new(),
        }
    }

    #[test]
    fn only_local_fixture_sources_are_accepted() {
        assert!(config("backupctl_fixture_m1").validate().is_ok());
        assert!(config("production").validate().is_err());
        let mut remote = config("backupctl_fixture_m1");
        remote.source.host = "db.example.invalid".to_string();
        assert!(remote.validate().is_err());
    }

    fn plan(target: &str, policy: RestoreSecurityPolicy) -> RestorePlan {
        RestorePlan {
            format: PLAN_FORMAT.to_string(),
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            artifact_database: "backupctl_fixture_m1".to_string(),
            source_major: 16,
            client_version: "pg_restore (PostgreSQL) 16.4".to_string(),
            target_database: target.to_string(),
            security: policy,
            sections: RestoreSections::full(),
            artifact_scope: None,
            created_unix_ms: 1_000,
            expires_unix_ms: 2_000,
        }
    }

    #[test]
    fn plan_digest_binds_security_policy_and_target() {
        let base = plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        let digest = base.digest();
        assert_eq!(digest.len(), 64);
        assert_eq!(base.digest(), digest);

        let mut flipped = plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        flipped.id = base.id;
        flipped.artifact_id = base.artifact_id;
        flipped.created_unix_ms = base.created_unix_ms;
        flipped.expires_unix_ms = base.expires_unix_ms;
        assert_ne!(flipped.digest(), digest);

        let mut retargeted = base.clone();
        retargeted.target_database = "backupctl_fixture_other".to_string();
        assert_ne!(retargeted.digest(), digest);
    }

    #[test]
    fn plan_rejects_source_target_and_expiry_violations() {
        let dr = plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        assert!(dr.validate(1_500).is_ok());
        let same = plan("backupctl_fixture_m1", RestoreSecurityPolicy::dr_full());
        assert!(same.validate(1_500).is_err());
        assert!(dr.validate(2_000).is_err());
        assert!(dr.validate(2_500).is_err());
        assert!(dr.is_expired(2_000));
        assert!(!dr.is_expired(1_999));
    }

    fn manifest_fixture() -> DevelopmentManifest {
        DevelopmentManifest {
            format: DEV_FORMAT.to_string(),
            id: Uuid::new_v4(),
            synthetic_only: true,
            database: "backupctl_fixture_m1".to_string(),
            source_major: 16,
            source_version: "160004".to_string(),
            dump_client_version: "pg_dump (PostgreSQL) 16.4".to_string(),
            application_version: "0.1.0".to_string(),
            archive_format: "custom".to_string(),
            compression: "gzip".to_string(),
            created_unix_ms: 1,
            size_bytes: 10,
            sha256: "a".repeat(64),
            status: "complete".to_string(),
            security_globals: false,
            globals_sha256: None,
            globals_size_bytes: None,
            verification_level: None,
            verified_unix_ms: None,
            scope: None,
            toc_sha256: None,
        }
    }

    #[test]
    fn manifest_globals_and_verification_fields_are_consistent() {
        let mut manifest = manifest_fixture();
        assert!(manifest.validate_shape().is_ok());
        manifest.security_globals = true;
        assert!(manifest.validate_shape().is_err());
        manifest.globals_sha256 = Some("b".repeat(64));
        manifest.globals_size_bytes = Some(5);
        assert!(manifest.validate_shape().is_ok());
        manifest.verification_level = Some(VERIFY_RESTORE_TESTED.to_string());
        assert!(manifest.validate_shape().is_err());
        manifest.verified_unix_ms = Some(2);
        assert!(manifest.validate_shape().is_ok());
    }

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            database: "backupctl_fixture_m1".to_string(),
            mode: SelectionMode::SchemaAndData,
            schemas: vec!["app".to_string()],
            exclude_schemas: Vec::new(),
            tables: Vec::new(),
            exclude_tables: Vec::new(),
            exclude_extensions: Vec::new(),
            large_objects: false,
        }
    }

    #[test]
    fn profiles_are_exact_names_and_single_kind_of_selection() {
        assert!(profile("app-only").validate().is_ok());

        let mut wildcard = profile("wildcard");
        wildcard.schemas = vec!["app*".to_string()];
        assert!(wildcard.validate().is_err());

        let mut quoted = profile("quoted");
        quoted.schemas = vec!["App".to_string()];
        assert!(quoted.validate().is_err());

        let mut system = profile("system");
        system.schemas = vec!["pg_catalog".to_string()];
        assert!(system.validate().is_err());

        let mut mixed = profile("mixed");
        mixed.tables = vec!["app.accounts".to_string()];
        assert!(mixed.validate().is_err());

        let mut bad_table = profile("bad-table");
        bad_table.schemas = Vec::new();
        bad_table.tables = vec!["accounts".to_string()];
        assert!(bad_table.validate().is_err());

        let mut duplicate = profile("duplicate");
        duplicate.schemas = vec!["app".to_string(), "app".to_string()];
        assert!(duplicate.validate().is_err());

        let mut schema_only_objects = profile("schema-only-los");
        schema_only_objects.mode = SelectionMode::SchemaOnly;
        schema_only_objects.large_objects = true;
        assert!(schema_only_objects.validate().is_err());

        let mut whole = profile("whole");
        whole.schemas = Vec::new();
        assert!(whole.is_whole_database());
        assert!(!profile("app-only").is_whole_database());
    }

    #[test]
    fn configuration_requires_known_profiles_and_a_matching_database() {
        let mut base = config("backupctl_fixture_m1");
        base.profiles = vec![profile("app-only")];
        assert!(base.validate().is_ok());
        assert_eq!(base.profile("app-only").unwrap().name, "app-only");
        assert!(base.profile("missing").is_err());

        let mut duplicated = config("backupctl_fixture_m1");
        duplicated.profiles = vec![profile("app-only"), profile("app-only")];
        assert!(duplicated.validate().is_err());

        let mut other_database = config("backupctl_fixture_m1");
        let mut misplaced = profile("app-only");
        misplaced.database = "backupctl_fixture_other".to_string();
        other_database.profiles = vec![misplaced];
        assert!(other_database.validate().is_err());
    }

    #[test]
    fn sections_must_start_at_pre_data_and_cannot_skip_data() {
        assert!(RestoreSections::full().validate().is_ok());
        assert!(RestoreSections::full().is_full());
        assert!(
            RestoreSections {
                pre_data: true,
                data: true,
                post_data: false,
            }
            .validate()
            .is_ok()
        );
        assert!(
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: false,
            }
            .validate()
            .is_ok()
        );
        for skipped in [
            RestoreSections {
                pre_data: false,
                data: true,
                post_data: false,
            },
            RestoreSections {
                pre_data: false,
                data: false,
                post_data: true,
            },
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: true,
            },
            RestoreSections {
                pre_data: false,
                data: false,
                post_data: false,
            },
        ] {
            assert!(skipped.validate().is_err());
        }
        assert_eq!(
            RestoreSections {
                pre_data: true,
                data: false,
                post_data: false,
            }
            .argv(),
            vec![format!("--section={SECTION_PRE_DATA}")]
        );
        assert_eq!(RestoreSections::full().argv().len(), 3);
    }

    #[test]
    fn a_partial_section_plan_cannot_claim_security_or_be_expired() {
        let mut partial = plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        partial.sections = RestoreSections {
            pre_data: true,
            data: true,
            post_data: false,
        };
        assert!(partial.validate(1_500).is_ok());

        let mut dr_partial = plan("backupctl_fixture_dr", RestoreSecurityPolicy::dr_full());
        dr_partial.sections = partial.sections;
        assert!(dr_partial.validate(1_500).is_err());

        // The digest covers the section set, so a plan cannot be reinterpreted.
        let mut other_sections = plan("backupctl_fixture_dr", RestoreSecurityPolicy::portable());
        other_sections.id = partial.id;
        other_sections.artifact_id = partial.artifact_id;
        other_sections.created_unix_ms = partial.created_unix_ms;
        other_sections.expires_unix_ms = partial.expires_unix_ms;
        assert_ne!(other_sections.digest(), partial.digest());
    }

    #[test]
    fn manifest_scope_records_requested_and_resolved_names() {
        let profile = profile("app-only");
        let resolved = ResolvedSelection {
            whole_database: false,
            schemas: vec!["app".to_string()],
            exclude_schemas: Vec::new(),
            tables: Vec::new(),
            exclude_tables: Vec::new(),
            dangling: Vec::new(),
            extension_members: vec!["hstore".to_string()],
        };
        let scope = ArtifactScope::from_profile(&profile, &resolved);
        assert_eq!(scope.requested_schemas, vec!["app".to_string()]);
        assert_eq!(scope.resolved_schemas, vec!["app".to_string()]);
        assert_eq!(scope.extension_members, vec!["hstore".to_string()]);
        assert!(scope.validate().is_ok());
        // A schema-based scope carries its own CREATE SCHEMA in the archive.
        assert!(scope.restore_required_schemas().is_empty());

        // A table-based scope names namespaces the restore must prepare.
        let table_scope = ArtifactScope {
            requested_tables: vec!["app.partitioned_events".to_string()],
            requested_schemas: Vec::new(),
            resolved_schemas: Vec::new(),
            resolved_tables: vec![
                "app.partitioned_events".to_string(),
                "app.partitioned_events_2025".to_string(),
                "aux.other".to_string(),
            ],
            ..scope.clone()
        };
        assert_eq!(
            table_scope.restore_required_schemas(),
            vec!["app".to_string(), "aux".to_string()]
        );
        assert!(is_safe_created_schema_name("app"));
        assert!(!is_safe_created_schema_name("pg_catalog"));
        assert!(!is_safe_created_schema_name("App"));
        assert!(!is_safe_created_schema_name("a*"));

        let empty = ArtifactScope {
            profile: "nothing".to_string(),
            mode: SelectionMode::SchemaAndData,
            requested_schemas: vec!["app".to_string()],
            requested_tables: Vec::new(),
            exclude_schemas: Vec::new(),
            exclude_tables: Vec::new(),
            exclude_extensions: Vec::new(),
            resolved_schemas: Vec::new(),
            resolved_tables: Vec::new(),
            large_objects: false,
            whole_database: false,
            extension_members: Vec::new(),
        };
        assert!(empty.validate().is_err());

        let both = ArtifactScope {
            whole_database: true,
            resolved_schemas: vec!["app".to_string()],
            ..empty.clone()
        };
        assert!(both.validate().is_err());

        let mut manifest = DevelopmentManifest {
            scope: Some(scope.clone()),
            toc_sha256: Some("c".repeat(64)),
            ..manifest_fixture()
        };
        assert!(manifest.validate_shape().is_ok());
        manifest.toc_sha256 = Some("not-hex".to_string());
        assert!(manifest.validate_shape().is_err());
    }
}
