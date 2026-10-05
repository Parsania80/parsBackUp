use anyhow::{Context, Result, bail};
use backup_domain::{
    AGE_FORMAT, ARCHIVE_COMPRESSION, ARCHIVE_FORMAT, ARTIFACT_FORMAT_VERSION, ArtifactManifest,
    ArtifactScope, BACKUP_STATUS, Config, DEV_FORMAT, DevelopmentManifest, DumpOptions,
    ENGINE_POSTGRESQL, GLOBALS_POLICY_EXPORTED, GLOBALS_POLICY_SKIPPED, Profile, PublicHeader,
    RequestedSelection, ResolvedSelection, RestorePlan, RestoreSections, RestoreSecurityPolicy,
    SUBSCRIPTION_POLICY_DROPPED, SelectionMode, Source, VERIFICATION_NONE, VERIFY_ARCHIVE,
    VERIFY_CHECKSUM, VERIFY_RESTORE_TESTED, VERIFY_SIGNATURE, WHOLE_DATABASE_PROFILE, format_utc,
    source_fingerprint,
};
use sha2::Digest as _;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const PLAN_TTL: Duration = Duration::from_secs(backup_domain::PLAN_TTL_SECONDS);

#[derive(Clone, Debug)]
pub struct EngineInfo {
    pub source_major: u32,
    pub source_version: String,
    pub dump_client_version: String,
}

pub trait DatabaseAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo>;
    /// Read the live catalog and turn a profile's requested names into the
    /// exact object set a dump would write, including anything it references
    /// from outside that set.
    fn resolve_selection(
        &self,
        source: &Source,
        profile: &Profile,
        timeout: Duration,
    ) -> Result<ResolvedSelection>;
    /// Runs `pg_dump` and hands its standard output to `consume`.
    ///
    /// There is deliberately no output path here: the adapter that talks to
    /// PostgreSQL does not get to decide whether plaintext reaches a disk, and the
    /// only way to make that a property of the tool rather than of each call site is
    /// to keep the bytes in a stream the caller owns. A dump that fails or warns
    /// returns an error before `consume` has been given anything to finish.
    fn dump_stream(
        &self,
        source: &Source,
        options: &DumpOptions,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()>;
    /// The `pg_dumpall` equivalent of [`DatabaseAdapter::dump_stream`], for the
    /// cluster role metadata.
    fn dump_globals_stream(
        &self,
        source: &Source,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()>;
    /// Returns the archive table of contents, one entry per line.
    fn inspect_archive(
        &self,
        source: &Source,
        archive: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>>;
    fn database_exists(&self, source: &Source, database: &str, timeout: Duration) -> Result<bool>;
    fn role_conflicts(
        &self,
        source: &Source,
        globals: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>>;
    fn apply_globals(&self, source: &Source, globals: &Path, timeout: Duration) -> Result<()>;
    fn create_database(&self, source: &Source, database: &str, timeout: Duration) -> Result<()>;
    /// Create namespaces the archive assumes to exist (table-selected dumps
    /// carry no CREATE SCHEMA entries). Implementations must validate every
    /// name before issuing DDL.
    fn create_schemas(
        &self,
        source: &Source,
        database: &str,
        schemas: &[String],
        timeout: Duration,
    ) -> Result<()>;
    fn restore_to_database(
        &self,
        source: &Source,
        database: &str,
        archive: &Path,
        security: RestoreSecurityPolicy,
        sections: RestoreSections,
        timeout: Duration,
    ) -> Result<()>;
}

pub struct WriteOptions {
    pub with_globals: bool,
}

/// The scope one operation claims, in the words its caller has: the fingerprint of the source it
/// resolved, the profile *name* it was configured with, and the artifact id it is about to write.
///
/// The store, not the service, turns this into what it records. Name-to-digest is the store's
/// business because the name is operator configuration and the row lands in the one file an
/// operator copies off-site without copying a key — and because a service that digested it here
/// would have to know a key-free index exists, which is exactly the dependency this layer avoids.
pub struct JobRequest {
    pub source_fingerprint: String,
    pub profile_name: String,
    pub backup_id: Uuid,
}

/// One operation the store is recording, seen from the caller's side.
///
/// Two moves and no reads, because the service has no business knowing the rest of the state
/// machine: `staged` says every stream this operation sealed is finished, `complete` says the
/// artifact is published. Every other way a row ends — `failed` when a command returns an error,
/// `interrupted` when a process was killed — is decided below this trait, by the store and the
/// kernel, because a command that dies cannot be trusted to report it.
pub trait JobHandle {
    fn staged(&self) -> Result<()>;
    fn complete(&self) -> Result<()>;
}

pub trait StageHandle {
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

/// What one staged file holds once its writer is finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedBytes {
    /// Plaintext bytes absorbed, which for an encrypted file is not the number of
    /// bytes published.
    pub plaintext_bytes: u64,
    /// The recipient suite the bytes were sealed under, or `None` when the store
    /// published them as plaintext.
    pub recipient_suite: Option<&'static str>,
}

/// The writer for one staged file.
///
/// The store, not the service, decides whether the bytes land as plaintext or as an
/// authenticated ciphertext, because the store is what an attacker can read. This is
/// the only place the two cases differ, and both must be finished before publication:
/// a stream that was never completed leaves nothing publishable behind.
pub trait PayloadSink: Write {
    /// Completes the stream and reports what was staged. Publishing a stage whose
    /// sink was not finished must fail.
    fn finish(&mut self) -> Result<StagedBytes>;
}

/// A file a PostgreSQL client tool may be pointed at, as plaintext.
///
/// The implementor owns any temporary decrypted copy behind that path and removes it
/// on drop, so a restore cannot leave plaintext in the artifact store.
pub trait PlaintextView {
    fn path(&self) -> &Path;
}

pub trait ArtifactHandle {
    fn id(&self) -> Uuid;
    fn manifest(&self) -> &DevelopmentManifest;
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

/// A v1 artifact whose origin signature has been checked.
///
/// The handle is separate from [`ArtifactHandle`] rather than an extra method on it, because
/// what it takes to read one is different in kind: an unsigned artifact's manifest is a file
/// beside the payload, while a signed artifact's manifest only exists after two ciphertext
/// digests have been recomputed and a signature over them has verified. Reaching this type
/// therefore means the reader already did the authentication, and every field read off
/// [`SignedArtifactHandle::manifest`] is a claim by whoever holds the signing key.
pub trait SignedArtifactHandle {
    /// `public.json`, now known to describe the bytes it was read beside.
    fn header(&self) -> &PublicHeader;
    fn manifest(&self) -> &ArtifactManifest;
    fn payload_path(&self) -> &Path;
    fn globals_path(&self) -> Option<&Path>;
}

/// What a key-free listing of a store holds.
///
/// The two lists are separate because they mean different things: a signed entry has been
/// *found* (its discovery record parsed), not verified, while an unsigned entry is an
/// artifact from before v1 that this listing can name but never describe. Reporting the
/// unsigned ids is the point — a signature-first `backup list` that hides them hides the
/// store's own history.
#[derive(Debug)]
pub struct StoreListing {
    pub signed: Vec<PublicHeader>,
    pub unsigned: Vec<Uuid>,
}

/// The key facts a v1 manifest must record, computed by the store from its own key files.
///
/// An id the operator could type is an id that could lie about which key opened this
/// artifact, so neither number is read from the configuration: both are derived here, from
/// key bytes, and the writer refuses a manifest that disagrees.
#[derive(Clone, Debug)]
pub struct SignedKeyFacts {
    pub recipient_id: String,
    pub signer_id: String,
    /// The signature suite the store's signing key belongs to, which is what the manifest
    /// and `public.json` both have to name.
    pub signature_suite: &'static str,
}

pub trait ArtifactStore {
    type Stage: StageHandle;
    type Artifact: ArtifactHandle;
    type Plaintext: PlaintextView;

    fn begin(&self, id: Uuid, options: &WriteOptions) -> Result<Self::Stage>;
    /// Claims one scope for the duration of the returned handle, and records the operation that
    /// holds it.
    ///
    /// A store that keeps no index still has to answer for the lock: "two dumps of one scope must
    /// not run at once" is not a feature of the inventory, and the inventory is only where the
    /// refusal becomes visible afterwards. Dropping the handle ends the claim.
    fn begin_job(&self, request: &JobRequest) -> Result<Box<dyn JobHandle>>;
    /// The writer for the staged payload file.
    ///
    /// `'a` is shared between the store and the stage: sealing a stream also marks the
    /// stage publishable, so the sink has to outlive the call while the stage does.
    fn payload_sink<'a>(&'a self, stage: &'a Self::Stage) -> Result<Box<dyn PayloadSink + 'a>>;
    /// The writer for the staged globals file, when the stage declares one.
    fn globals_sink<'a>(&'a self, stage: &'a Self::Stage) -> Result<Box<dyn PayloadSink + 'a>>;
    fn measure(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn measure_globals(&self, stage: &Self::Stage) -> Result<(u64, String)>;
    fn publish(&self, stage: Self::Stage, manifest: &DevelopmentManifest) -> Result<()>;
    fn list(&self) -> Result<Vec<DevelopmentManifest>>;
    fn inspect(&self, id: Uuid) -> Result<DevelopmentManifest>;
    fn open(&self, id: Uuid) -> Result<Self::Artifact>;
    /// The payload as a plaintext file, decrypting it into private storage when the
    /// artifact is an age ciphertext.
    fn plaintext_payload(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext>;
    /// The staged payload as plaintext, for the table-of-contents digest taken before
    /// publication. A stage holds no manifest yet, so the caller's own recorded
    /// plaintext size is the only bound available; this view is bounded by the
    /// format's own limit instead.
    fn plaintext_staged_payload(&self, stage: &Self::Stage) -> Result<Self::Plaintext>;
    /// The globals file as plaintext, same contract as
    /// [`ArtifactStore::plaintext_payload`].
    fn plaintext_globals(&self, artifact: &Self::Artifact) -> Result<Self::Plaintext>;
    fn rewrite_manifest(
        &self,
        artifact: &Self::Artifact,
        manifest: &DevelopmentManifest,
    ) -> Result<()>;
    fn save_plan(&self, plan: &RestorePlan) -> Result<()>;
    fn load_plan(&self, id: Uuid) -> Result<Option<RestorePlan>>;

    /// A v1 artifact the store has authenticated, ready to read.
    type Signed: SignedArtifactHandle;

    /// Whether the artifacts this store holds are the signed v1 shape.
    ///
    /// This is a property of the key files the store was opened with, never of a flag on the
    /// call: a store configured to sign writes v1 and reads v1, and one that is not writes
    /// and reads the development shapes.
    fn is_signed(&self) -> bool;

    /// The key facts a v1 manifest records, derived from this store's own key files.
    fn signed_key_facts(&self) -> Result<SignedKeyFacts>;

    /// Publishes a staged dump as a signed v1 artifact and returns the discovery record it
    /// wrote.
    ///
    /// The signature is written and verified before the artifact becomes visible, so a store
    /// has no reachable state in which a v1 artifact exists without one.
    fn publish_signed(
        &self,
        stage: Self::Stage,
        manifest: &ArtifactManifest,
    ) -> Result<PublicHeader>;

    /// The reader's first three steps only: parse `public.json`, recompute both ciphertext
    /// digests from the files on disk, and verify `signature.hybrid`.
    ///
    /// Nothing is decrypted here and no plaintext manifest is read, so this works on a host
    /// that holds a verifying key and no decryption identity. The returned header is
    /// authenticated, which is why its digests can be reported.
    fn verify_signed(&self, id: Uuid) -> Result<PublicHeader>;

    /// The full reader order: [`ArtifactStore::verify_signed`], then decrypt `manifest.age`
    /// and compare it field by field with the header, then bind `globals.age` through the
    /// digest inside that signed manifest.
    fn open_signed(&self, id: Uuid) -> Result<Self::Signed>;

    /// Discovery from `public.json` alone, with no key material and nothing decrypted.
    fn list_signed(&self) -> Result<StoreListing>;

    /// An authenticated payload as plaintext, decrypted into private storage.
    fn payload_plaintext(&self, artifact: &Self::Signed) -> Result<Self::Plaintext>;

    /// An authenticated globals file as plaintext.
    fn globals_plaintext(&self, artifact: &Self::Signed) -> Result<Self::Plaintext>;
}

/// One artifact, open, in whichever shape its store keeps it.
///
/// The two shapes differ in exactly one way that matters to a service: how the metadata it
/// is about to trust became trustworthy. Everything after that — the payload a restore
/// replays, the globals it applies, the source it came from — is the same work, so it is
/// written once here instead of once per service per shape.
enum Opened<S: ArtifactStore> {
    Development(S::Artifact),
    Signed(S::Signed),
}

/// What a restore needs from an artifact, in the one form both manifests can give.
struct ArtifactFacts {
    database: String,
    source_major: u32,
    has_globals: bool,
    required_schemas: Vec<String>,
    profile: Option<String>,
    verification_level: Option<String>,
    /// The v1 manifest's digest of the source it was dumped from. `None` for a development
    /// artifact, whose manifest predates the field, so a plan cannot bind what was never
    /// recorded.
    source_fingerprint: Option<String>,
}

impl<S: ArtifactStore> Opened<S> {
    /// Opens an artifact the way its store can be trusted to: a signed store authenticates
    /// before it decrypts, and refuses a v1 artifact to the manifest-file reader rather than
    /// reporting a missing file.
    fn open(store: &S, id: Uuid) -> Result<Self> {
        if store.is_signed() {
            Ok(Self::Signed(store.open_signed(id)?))
        } else {
            Ok(Self::Development(store.open(id)?))
        }
    }

    fn facts(&self) -> ArtifactFacts {
        match self {
            Self::Development(artifact) => {
                let manifest = artifact.manifest();
                ArtifactFacts {
                    database: manifest.database.clone(),
                    source_major: manifest.source_major,
                    has_globals: manifest.security_globals,
                    required_schemas: manifest
                        .scope
                        .as_ref()
                        .map_or_else(Vec::new, ArtifactScope::restore_required_schemas),
                    profile: manifest.scope.as_ref().map(|scope| scope.profile.clone()),
                    verification_level: manifest.verification_level.clone(),
                    source_fingerprint: None,
                }
            }
            Self::Signed(artifact) => {
                let manifest = artifact.manifest();
                ArtifactFacts {
                    // A v1 manifest carries no separate database field: the profile snapshot
                    // it was written from names the database the dump came out of.
                    database: manifest.profile_snapshot.database.clone(),
                    source_major: manifest.source_server_major,
                    has_globals: manifest.globals_policy == GLOBALS_POLICY_EXPORTED,
                    required_schemas: manifest.resolved_selection.restore_required_schemas(),
                    profile: Some(manifest.profile_snapshot.name.clone()),
                    verification_level: Some(manifest.verification_level.clone()),
                    source_fingerprint: Some(manifest.source_fingerprint.clone()),
                }
            }
        }
    }

    /// The payload as plaintext a PostgreSQL tool may read, with any decrypted copy owned by
    /// the returned view.
    fn payload(&self, store: &S) -> Result<S::Plaintext> {
        match self {
            Self::Development(artifact) => store.plaintext_payload(artifact),
            Self::Signed(artifact) => store.payload_plaintext(artifact),
        }
    }

    fn globals(&self, store: &S) -> Result<S::Plaintext> {
        match self {
            Self::Development(artifact) => store.plaintext_globals(artifact),
            Self::Signed(artifact) => store.globals_plaintext(artifact),
        }
    }

    /// The handle behind an unsigned artifact, for the one operation only that shape supports:
    /// rewriting its plaintext manifest in place.
    fn development(&self) -> Result<&S::Artifact> {
        match self {
            Self::Development(artifact) => Ok(artifact),
            Self::Signed(_) => bail!(
                "a signed artifact's manifest exists only inside an authenticated ciphertext, so its record cannot be rewritten in place"
            ),
        }
    }
}

pub fn now_unix_ms() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_millis())
}

/// SHA-256 over the archive table of contents. The payload digest binds the
/// bytes; this binds the content set, so `verify --level archive` can prove the
/// archive still lists what the manifest recorded rather than merely being
/// unread-but-intact.
pub fn toc_digest(lines: &[String]) -> Result<String> {
    if lines.is_empty() {
        bail!("archive table of contents is empty");
    }
    Ok(format!(
        "{:x}",
        sha2::Sha256::digest(lines.join("\n").as_bytes())
    ))
}

pub struct BackupService<E, S> {
    engine: E,
    store: S,
}

/// What a completed write published.
///
/// The two shapes report different records because they are known in different ways: a
/// development artifact's manifest is the plaintext file beside the payload, while a v1 write
/// returns both the discovery record a reader can check with no keys and the manifest the
/// signature authenticates.
#[derive(Debug)]
pub enum Created {
    Development(Box<DevelopmentManifest>),
    Signed {
        header: Box<PublicHeader>,
        manifest: Box<ArtifactManifest>,
    },
}

impl Created {
    pub fn id(&self) -> Uuid {
        match self {
            Self::Development(manifest) => manifest.id,
            Self::Signed { header, .. } => header.backup_id,
        }
    }
}

/// What `backup list` found.
#[derive(Debug)]
pub enum Inventory {
    Development(Vec<DevelopmentManifest>),
    Public(StoreListing),
}

/// What `backup inspect` read.
#[derive(Debug)]
pub enum Record {
    Development(Box<DevelopmentManifest>),
    Signed(Box<ArtifactManifest>),
}

impl Record {
    pub fn id(&self) -> Uuid {
        match self {
            Self::Development(manifest) => manifest.id,
            Self::Signed(manifest) => manifest.backup_id,
        }
    }
}

/// The profile snapshot a signed store records for a dump that named no profile.
///
/// A v1 manifest has no absent fields, and a whole-database dump did make a selection: every
/// object in the database. Recording that as a profile keeps the field honest instead of
/// leaving a hole where a scope should be. `large_objects` is what the native default did —
/// `pg_dump` with no blob flag includes them — and the reserved name says which case this is.
fn whole_database_profile(source: &Source) -> Profile {
    Profile {
        name: WHOLE_DATABASE_PROFILE.to_string(),
        database: source.database.clone(),
        mode: SelectionMode::default(),
        schemas: Vec::new(),
        exclude_schemas: Vec::new(),
        tables: Vec::new(),
        exclude_tables: Vec::new(),
        exclude_extensions: Vec::new(),
        large_objects: true,
    }
}

impl<E: DatabaseAdapter, S: ArtifactStore> BackupService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    /// Resolve a profile against the live catalog and refuse a selection that
    /// pg_dump could not restore on its own. `create` uses this before writing
    /// anything, so a dry run reports exactly what a backup would contain.
    pub fn resolve(
        &self,
        config: &Config,
        profile_name: Option<&str>,
    ) -> Result<(EngineInfo, ResolvedSelection)> {
        config.validate()?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        let profile = match profile_name {
            Some(name) => Some(config.profile(name)?),
            None => None,
        };
        let resolved = match profile {
            Some(profile) => self
                .engine
                .resolve_selection(&config.source, profile, timeout)?,
            None => ResolvedSelection {
                whole_database: true,
                ..Default::default()
            },
        };
        if !resolved.dangling.is_empty() {
            let named = resolved
                .dangling
                .iter()
                .map(|reference| {
                    format!(
                        "{} depends on {} ({})",
                        reference.dependent, reference.referenced, reference.kind
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            let who = match profile {
                Some(profile) => format!("profile {}", profile.name),
                None => "this selection".to_string(),
            };
            bail!(
                "{who} is not self-contained: {named}. pg_dump does not write objects from outside \
                 the selection, so this archive could not restore into an empty database on its \
                 own; widen the selection or restore into a database that already holds those objects"
            );
        }
        Ok((info, resolved))
    }

    pub fn create(&self, config: &Config, profile_name: Option<&str>) -> Result<Created> {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let (info, resolved) = self.resolve(config, profile_name)?;
        let profile = match profile_name {
            Some(name) => Some(config.profile(name)?),
            None => None,
        };
        let none_extensions: Vec<String> = Vec::new();
        let exclude_extensions = match profile {
            Some(profile) => &profile.exclude_extensions,
            None => &none_extensions,
        };
        let options = DumpOptions {
            major: info.source_major,
            mode: profile.map(|profile| profile.mode).unwrap_or_default(),
            selection: &resolved,
            large_objects: profile.map(|profile| profile.large_objects),
            exclude_extensions,
        };
        let id = Uuid::new_v4();
        // Claimed before anything is staged, so a second dump of the same scope meets a refusal
        // while the first is still writing rather than after it has produced a stage nobody knew
        // about. The whole-database name is what a run that named no profile actually selected.
        let fingerprint = source_fingerprint(&config.source, info.source_major);
        let job = self.store.begin_job(&JobRequest {
            source_fingerprint: fingerprint.clone(),
            profile_name: profile
                .as_ref()
                .map(|profile| profile.name.clone())
                .unwrap_or_else(|| WHOLE_DATABASE_PROFILE.to_string()),
            backup_id: id,
        })?;
        // Recorded before the dump runs, because a signed manifest states when the dump
        // started as well as when it finished, and the pair is inside the signature.
        let started_unix_ms = now_unix_ms()?;
        let stage = self.store.begin(
            id,
            &WriteOptions {
                with_globals: config.export_globals,
            },
        )?;
        let staged = {
            let mut payload_sink = self.store.payload_sink(&stage)?;
            self.engine
                .dump_stream(&config.source, &options, timeout, &mut |stream| {
                    io::copy(stream, &mut payload_sink)?;
                    Ok(())
                })
                .context("PostgreSQL dump failed; staged artifact was not published")?;
            payload_sink
                .finish()
                .context("payload stream was never finished; staged artifact was not published")?
        };
        // The published file is the ciphertext, so its size cannot prove the dump
        // produced anything: an empty archive still encrypts to an age header.
        if staged.plaintext_bytes == 0 {
            bail!("pg_dump produced an empty archive");
        }
        let inspected = self.store.plaintext_staged_payload(&stage)?;
        let toc = self
            .engine
            .inspect_archive(&config.source, inspected.path(), timeout)
            .context("PostgreSQL archive inspection failed; artifact was not published")?;
        let toc_sha256 = toc_digest(&toc)?;
        let (size_bytes, sha256) = self.store.measure(&stage)?;
        let mut globals_sha256 = None;
        let mut globals_size_bytes = None;
        if config.export_globals {
            let mut globals_sink = self.store.globals_sink(&stage)?;
            self.engine
                .dump_globals_stream(&config.source, timeout, &mut |stream| {
                    io::copy(stream, &mut globals_sink)?;
                    Ok(())
                })
                .context("PostgreSQL globals export failed; staged artifact was not published")?;
            let globals_staged = globals_sink
                .finish()
                .context("globals stream was never finished; staged artifact was not published")?;
            if globals_staged.plaintext_bytes == 0 {
                bail!("pg_dumpall produced an empty globals file");
            }
            let (gsize, gsha) = self.store.measure_globals(&stage)?;
            globals_size_bytes = Some(gsize);
            globals_sha256 = Some(gsha);
        }
        // Whether the artifact is encrypted is a fact the store reported through its
        // sink, not a flag the service carries: the format tag follows that report.
        let encrypted = staged.recipient_suite.is_some();
        let created_unix_ms = now_unix_ms()?;
        // Every stream this operation sealed is finished, and what remains is publication. Said
        // here rather than at each store, because the store's own sink cannot tell a payload that
        // is done from one whose globals are still running.
        job.staged()?;
        // A signed store has one shape to write, and it is not this one: the record a v1
        // artifact publishes is inside `manifest.age`, sealed and signed, and what the writer
        // gets back is the discovery header the rename left behind.
        if self.store.is_signed() {
            let facts = self.store.signed_key_facts()?;
            let recipient_suite = staged.recipient_suite.context(
                "a signed store seals its payload, but this one reported a plaintext archive",
            )?;
            let snapshot = match profile {
                Some(profile) => profile.clone(),
                None => whole_database_profile(&config.source),
            };
            let manifest = ArtifactManifest {
                format_version: ARTIFACT_FORMAT_VERSION,
                backup_id: id,
                engine: ENGINE_POSTGRESQL.to_string(),
                source_server_major: info.source_major,
                source_server_version: info.source_version.clone(),
                dump_client_version: info.dump_client_version.clone(),
                application_version: env!("CARGO_PKG_VERSION").to_string(),
                recipient_id: facts.recipient_id,
                signer_id: facts.signer_id,
                recipient_suite: recipient_suite.to_string(),
                signature_suite: facts.signature_suite.to_string(),
                started_at_utc: format_utc(started_unix_ms.try_into()?)?,
                completed_at_utc: format_utc(created_unix_ms.try_into()?)?,
                source_fingerprint: fingerprint.clone(),
                profile_snapshot: snapshot.clone(),
                requested_selection: RequestedSelection::from_profile(&snapshot),
                resolved_selection: resolved,
                archive_format: ARCHIVE_FORMAT.to_string(),
                compression: ARCHIVE_COMPRESSION.to_string(),
                subscription_policy: SUBSCRIPTION_POLICY_DROPPED.to_string(),
                globals_policy: if config.export_globals {
                    GLOBALS_POLICY_EXPORTED.to_string()
                } else {
                    GLOBALS_POLICY_SKIPPED.to_string()
                },
                globals_sha256,
                globals_ciphertext_bytes: globals_size_bytes,
                payload_ciphertext_sha256: sha256,
                payload_ciphertext_bytes: size_bytes,
                archive_plaintext_bytes: staged.plaintext_bytes,
                // The table of contents was listed from the staged archive before anything was
                // sealed, which is the only moment a signed manifest can learn it: writing a
                // later check into these bytes would change what the signature covers.
                archive_toc_sha256: Some(toc_sha256),
                verification_level: VERIFICATION_NONE.to_string(),
                compatibility_notes: Vec::new(),
            };
            let header = self.store.publish_signed(stage, &manifest)?;
            job.complete()?;
            return Ok(Created::Signed {
                header: Box::new(header),
                manifest: Box::new(manifest),
            });
        }
        let manifest = DevelopmentManifest {
            format: if encrypted {
                AGE_FORMAT.to_string()
            } else {
                DEV_FORMAT.to_string()
            },
            id,
            synthetic_only: true,
            database: config.source.database.clone(),
            source_major: info.source_major,
            source_version: info.source_version,
            dump_client_version: info.dump_client_version,
            application_version: env!("CARGO_PKG_VERSION").to_string(),
            archive_format: ARCHIVE_FORMAT.to_string(),
            compression: ARCHIVE_COMPRESSION.to_string(),
            created_unix_ms,
            size_bytes,
            sha256,
            status: BACKUP_STATUS.to_string(),
            security_globals: config.export_globals,
            globals_sha256,
            globals_size_bytes,
            verification_level: None,
            verified_unix_ms: None,
            scope: profile.map(|profile| ArtifactScope::from_profile(profile, &resolved)),
            toc_sha256: Some(toc_sha256),
            recipient_suite: staged.recipient_suite.map(str::to_string),
            payload_plaintext_bytes: encrypted.then_some(staged.plaintext_bytes),
        };
        manifest.validate_shape()?;
        self.store.publish(stage, &manifest)?;
        job.complete()?;
        Ok(Created::Development(Box::new(manifest)))
    }

    /// Lists the store the way it can be trusted: a signed store is discovered from
    /// `public.json` with no keys and nothing decrypted, and an unsigned one from the
    /// plaintext manifests beside its payloads.
    ///
    /// The signed listing reports less than a development one does on purpose — `public.json`
    /// holds no database name and no timestamp — because what it reports is a record a reader
    /// with no keys can believe.
    pub fn list(&self) -> Result<Inventory> {
        if self.store.is_signed() {
            return Ok(Inventory::Public(self.store.list_signed()?));
        }
        Ok(Inventory::Development(self.store.list()?))
    }

    /// Reads one artifact's record. A signed artifact's metadata is inside `manifest.age`, so
    /// this needs the store's decryption identity — the price of not leaving a plaintext
    /// manifest beside the ciphertext.
    pub fn inspect(&self, id: Uuid) -> Result<Record> {
        if self.store.is_signed() {
            return Ok(Record::Signed(Box::new(
                self.store.open_signed(id)?.manifest().clone(),
            )));
        }
        Ok(Record::Development(Box::new(self.store.inspect(id)?)))
    }
}

/// Who attested that an artifact came from the key holder, established by an origin
/// signature that verified.
///
/// Only a v1 artifact can supply this: a development artifact carries no signature at all, so
/// there is an integrity claim to check but no origin to name.
#[derive(Clone, Debug)]
pub struct OriginFacts {
    pub signer_id: String,
    pub recipient_id: String,
    pub signature_suite: String,
}

impl OriginFacts {
    fn from_header(header: &PublicHeader) -> Self {
        Self {
            signer_id: header.signer_id.clone(),
            recipient_id: header.recipient_id.clone(),
            signature_suite: header.signature_suite.clone(),
        }
    }

    fn from_manifest(manifest: &ArtifactManifest) -> Self {
        Self {
            signer_id: manifest.signer_id.clone(),
            recipient_id: manifest.recipient_id.clone(),
            signature_suite: manifest.signature_suite.clone(),
        }
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub artifact_id: Uuid,
    pub level: String,
    pub payload_size_bytes: u64,
    pub payload_sha256: String,
    pub globals_size_bytes: Option<u64>,
    pub globals_sha256: Option<String>,
    pub origin: Option<OriginFacts>,
}

pub struct VerifyService<E, S> {
    engine: E,
    store: S,
}

impl<E: DatabaseAdapter, S: ArtifactStore> VerifyService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    pub fn verify(&self, config: &Config, id: Uuid, level: &str) -> Result<VerifyReport> {
        if !matches!(level, VERIFY_SIGNATURE | VERIFY_CHECKSUM | VERIFY_ARCHIVE) {
            bail!("verification level must be signature, checksum or archive");
        }
        if self.store.is_signed() {
            return self.verify_v1(config, id, level);
        }
        if level == VERIFY_SIGNATURE {
            bail!(
                "this store's artifacts carry no origin signature, so signature level has nothing to verify; \
                 use --level checksum or --level archive, or configure [signing] before writing artifacts"
            );
        }
        let timeout = Duration::from_secs(config.timeout_seconds);
        // Opening the artifact already recomputes payload and globals digests
        // and rejects marker/manifest/shape mismatches: that is checksum level.
        let artifact = self.store.open(id)?;
        let manifest = artifact.manifest();
        if level == VERIFY_ARCHIVE {
            // The tool boundary reads plaintext, so an encrypted artifact is
            // decrypted into private storage that this scope ends the view of.
            let payload = self.store.plaintext_payload(&artifact)?;
            let toc = self
                .engine
                .inspect_archive(&config.source, payload.path(), timeout)
                .context("archive table of contents failed to parse")?;
            let digest = toc_digest(&toc)?;
            if let Some(recorded) = &manifest.toc_sha256
                && recorded != &digest
            {
                bail!(
                    "archive table of contents does not match the manifest; the payload was replaced or re-dumped"
                );
            }
        }
        Ok(VerifyReport {
            artifact_id: id,
            level: level.to_string(),
            payload_size_bytes: manifest.size_bytes,
            payload_sha256: manifest.sha256.clone(),
            globals_size_bytes: manifest.globals_size_bytes,
            globals_sha256: manifest.globals_sha256.clone(),
            origin: None,
        })
    }

    /// Verification for a signed store, which verifies the origin signature at every level
    /// rather than only at the top one.
    ///
    /// Signature level is the reader's first three steps and stops there: `public.json`, both
    /// ciphertext digests recomputed from the files on disk, and the hybrid signature over
    /// them. That is the level a disaster-recovery host runs when it holds a verifying key and
    /// no decryption identity, so nothing here may require a secret.
    fn verify_v1(&self, config: &Config, id: Uuid, level: &str) -> Result<VerifyReport> {
        if level == VERIFY_SIGNATURE {
            let header = self.store.verify_signed(id)?;
            return Ok(VerifyReport {
                artifact_id: id,
                level: level.to_string(),
                payload_size_bytes: header.payload_ciphertext_bytes,
                payload_sha256: header.payload_sha256.clone(),
                globals_size_bytes: None,
                globals_sha256: None,
                origin: Some(OriginFacts::from_header(&header)),
            });
        }
        // Opening does the signature check again from the top and only then decrypts the
        // manifest, so the digests below are read from an authenticated record.
        let artifact = self.store.open_signed(id)?;
        let manifest = artifact.manifest();
        if level == VERIFY_ARCHIVE {
            let payload = self.store.payload_plaintext(&artifact)?;
            let toc = self
                .engine
                .inspect_archive(
                    &config.source,
                    payload.path(),
                    Duration::from_secs(config.timeout_seconds),
                )
                .context("archive table of contents failed to parse")?;
            let digest = toc_digest(&toc)?;
            // A v1 manifest records its table of contents at write time, because it is signed
            // and a later check cannot be written into it.
            match &manifest.archive_toc_sha256 {
                Some(recorded) if recorded != &digest => bail!(
                    "archive table of contents does not match the signed manifest; the payload was replaced or re-dumped"
                ),
                None => bail!(
                    "the signed manifest records no archive table of contents, so archive level cannot be proven"
                ),
                Some(_) => {}
            }
        }
        Ok(VerifyReport {
            artifact_id: id,
            level: level.to_string(),
            payload_size_bytes: manifest.payload_ciphertext_bytes,
            payload_sha256: manifest.payload_ciphertext_sha256.clone(),
            globals_size_bytes: manifest.globals_ciphertext_bytes,
            globals_sha256: manifest.globals_sha256.clone(),
            origin: Some(OriginFacts::from_manifest(manifest)),
        })
    }
}

pub struct RestoreService<E, S> {
    engine: E,
    store: S,
}

#[derive(Debug)]
pub struct RestoreOutcome {
    pub plan: RestorePlan,
    /// The artifact's verification level after this run.
    pub verification_level: String,
    /// Whether that level is now written into the artifact itself.
    ///
    /// A v1 manifest is signed, so a restore on a disaster-recovery host cannot record
    /// anything into it — that host holds no signing key, and re-signing someone else's
    /// artifact would attribute it to this one. The run still proves the restore worked;
    /// only the artifact cannot carry the fact.
    pub recorded_in_artifact: bool,
}

impl<E: DatabaseAdapter, S: ArtifactStore> RestoreService<E, S> {
    pub fn new(engine: E, store: S) -> Self {
        Self { engine, store }
    }

    /// Refuses an artifact whose signed manifest was written for a different source than the
    /// configured one.
    ///
    /// A development manifest predates the field, so there is nothing to compare and the
    /// check passes: the database-name match below is the only binding that shape supports.
    fn check_source(config: &Config, facts: &ArtifactFacts, server_major: u32) -> Result<()> {
        let Some(recorded) = &facts.source_fingerprint else {
            return Ok(());
        };
        let configured = source_fingerprint(&config.source, server_major);
        if recorded != &configured {
            bail!(
                "this artifact was dumped from a different source than the configured one: the signed manifest \
                 records fingerprint {recorded} while {configured} describes the current configuration. \
                 Refusing to plan a restore whose archive does not belong to this server and database"
            );
        }
        Ok(())
    }

    pub fn plan(
        &self,
        config: &Config,
        artifact_id: Uuid,
        target: &str,
        security: RestoreSecurityPolicy,
        sections: RestoreSections,
    ) -> Result<RestorePlan> {
        config.validate()?;
        sections.validate()?;
        // Fail on the contradiction between sections and security before any
        // environment probe, so the refusal names the real reason.
        sections.check_security(&security)?;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let info = self.engine.preflight(&config.source, timeout)?;
        // A signed store authenticates before it decrypts, so a bad signature is refused
        // here — before a target database exists to be filled with a forgery.
        let artifact = Opened::open(&self.store, artifact_id)?;
        let facts = artifact.facts();
        if security.roles && !facts.has_globals {
            bail!("restore policy requires roles but the backup contains no globals security file");
        }
        if facts.source_major != info.source_major {
            bail!("client major does not match the backup source major; same-major restore only");
        }
        Self::check_source(config, &facts, info.source_major)?;
        if target == facts.database {
            bail!("restore target must differ from the backup source database");
        }
        if self
            .engine
            .database_exists(&config.source, target, timeout)?
        {
            bail!("target database already exists; restore only creates a new database");
        }
        if security.roles {
            let globals = artifact.globals(&self.store)?;
            let conflicts = self
                .engine
                .role_conflicts(&config.source, globals.path(), timeout)?;
            if !conflicts.is_empty() {
                bail!(
                    "DR role restore refused: these roles already exist in the cluster: {}; use the portable policy or remove them first",
                    conflicts.join(", ")
                );
            }
        }
        let created = now_unix_ms()?;
        let plan = RestorePlan {
            format: backup_domain::PLAN_FORMAT.to_string(),
            id: Uuid::new_v4(),
            artifact_id,
            artifact_database: facts.database.clone(),
            source_major: facts.source_major,
            client_version: info.dump_client_version,
            target_database: target.to_string(),
            security,
            sections,
            artifact_scope: facts.profile.clone(),
            created_unix_ms: created,
            expires_unix_ms: created + PLAN_TTL.as_millis(),
        };
        plan.validate(now_unix_ms()?)?;
        self.store.save_plan(&plan)?;
        Ok(plan)
    }

    pub fn run(
        &self,
        config: &Config,
        plan_id: Uuid,
        confirm_target: &str,
    ) -> Result<RestoreOutcome> {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let plan = self
            .store
            .load_plan(plan_id)?
            .context("restore plan not found")?;
        plan.validate(now_unix_ms()?)?;
        if plan.target_database != confirm_target {
            bail!("confirmation target does not match the planned database");
        }
        if plan.artifact_database != config.source.database {
            bail!("plan source database does not match the configuration");
        }
        let info = self.engine.preflight(&config.source, timeout)?;
        if info.source_major != plan.source_major {
            bail!("client or server major changed since the plan was created");
        }
        let artifact = Opened::open(&self.store, plan.artifact_id)?;
        let facts = artifact.facts();
        if facts.database != plan.artifact_database {
            bail!("artifact database identity does not match the plan");
        }
        // Re-bound here as well: a plan is a claim about a file that another process may
        // have swapped out while it sat in the store.
        Self::check_source(config, &facts, info.source_major)?;
        if self
            .engine
            .database_exists(&config.source, &plan.target_database, timeout)?
        {
            bail!("target database appeared after planning; refusing to touch it");
        }
        // Complete decryption and ciphertext binding before any cluster mutation.
        let payload = artifact.payload(&self.store)?;
        // Step 1 of the DR order: security metadata validated (digest binding
        // happened when the artifact was opened); re-check role conflicts at execution time.
        if plan.security.roles {
            let globals = artifact.globals(&self.store)?;
            let conflicts = self
                .engine
                .role_conflicts(&config.source, globals.path(), timeout)?;
            if !conflicts.is_empty() {
                bail!(
                    "DR role restore refused: these roles already exist in the cluster: {}",
                    conflicts.join(", ")
                );
            }
            // Step 2: roles, attributes, and memberships before any object
            // can be owned by or granted to them.
            self.engine
                .apply_globals(&config.source, globals.path(), timeout)
                .context("globals restore failed; cluster roles may be partially applied")?;
        }
        // Step 3: fresh target database; existence re-checked here.
        if self
            .engine
            .database_exists(&config.source, &plan.target_database, timeout)?
        {
            bail!("target database appeared after planning; refusing to touch it");
        }
        self.engine
            .create_database(&config.source, &plan.target_database, timeout)
            .context("target database creation failed")?;
        // A table-selected archive restores its relations but never creates
        // their namespaces; prepare them so the restore targets an otherwise
        // empty database, matching the schema-selection behavior.
        if !facts.required_schemas.is_empty() {
            self.engine
                .create_schemas(
                    &config.source,
                    &plan.target_database,
                    &facts.required_schemas,
                    timeout,
                )
                .context("target schema preparation failed")?;
        }
        // Steps 4-6: schema/data, then ownership and privileges from the
        // archive's own ALTER OWNER/GRANT entries (skipped per policy). The view is
        // held for the length of the restore and its plaintext is removed after.
        let restored = self.engine.restore_to_database(
            &config.source,
            &plan.target_database,
            payload.path(),
            plan.security,
            plan.sections,
            timeout,
        );
        if let Err(error) = restored {
            bail!(
                "database restore failed: {error:#}; target {} may be partially modified and was left in place for operator inspection",
                plan.target_database
            );
        }
        let recorded = facts
            .verification_level
            .clone()
            .unwrap_or_else(|| VERIFICATION_NONE.to_string());
        if self.store.is_signed() {
            // Replaying the archive into a live database is exactly what restore-tested means,
            // but the fact cannot be added to a signed manifest: that would need the signing
            // key, which a disaster-recovery host does not hold, and re-signing an artifact
            // this host produced nothing about would attribute it to one that did.
            return Ok(RestoreOutcome {
                plan,
                verification_level: recorded,
                recorded_in_artifact: false,
            });
        }
        if !plan.sections.is_full() {
            // A section-limited restore proves nothing about the rest of the
            // archive, so the artifact keeps its recorded verification level.
            return Ok(RestoreOutcome {
                plan,
                verification_level: recorded,
                recorded_in_artifact: false,
            });
        }
        // Record restore-tested verification on the artifact (additive field
        // update; payload and digests are unchanged).
        let unsigned = artifact.development()?;
        let mut updated = unsigned.manifest().clone();
        updated.verification_level = Some(VERIFY_RESTORE_TESTED.to_string());
        updated.verified_unix_ms = Some(now_unix_ms()?);
        updated.validate_shape()?;
        self.store
            .rewrite_manifest(unsigned, &updated)
            .context("restore succeeded but verification marking failed")?;
        Ok(RestoreOutcome {
            plan,
            verification_level: VERIFY_RESTORE_TESTED.to_string(),
            recorded_in_artifact: true,
        })
    }
}
