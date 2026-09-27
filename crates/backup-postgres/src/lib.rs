use anyhow::{Context, Result, bail};
use backup_application::{DatabaseAdapter, EngineInfo};
use backup_domain::{
    DanglingReference, DumpOptions, MIN_MAJOR_EXCLUDE_EXTENSION, Profile, ResolvedSelection,
    RestoreSections, RestoreSecurityPolicy, SelectionMode, Source,
};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CAPTURE: usize = 64 * 1024;
const MAX_GLOBALS_BYTES: u64 = 8 * 1024 * 1024;
/// A table-based profile is expanded into an explicit `--table` list, so the
/// argv vector and the recorded scope stay bounded.
const MAX_RESOLVED_TABLES: usize = 512;

pub struct PostgresAdapter;

impl DatabaseAdapter for PostgresAdapter {
    fn preflight(&self, source: &Source, timeout: Duration) -> Result<EngineInfo> {
        if let Some(path) = &source.password_file {
            let meta = fs::symlink_metadata(path).context("inspect password file")?;
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.permissions().mode() & 0o077 != 0
            {
                bail!(
                    "password_file must be a regular non-symlink file with mode 0600 or stricter"
                );
            }
        }
        let dump = tool(source, "pg_dump")?;
        let restore = tool(source, "pg_restore")?;
        let psql = tool(source, "psql")?;
        let dumpall = tool(source, "pg_dumpall")?;
        let createdb = tool(source, "createdb")?;
        let dump_version = tool_version(&dump, timeout)?;
        let restore_version = tool_version(&restore, timeout)?;
        let psql_version = tool_version(&psql, timeout)?;
        let dumpall_version = tool_version(&dumpall, timeout)?;
        let createdb_version = tool_version(&createdb, timeout)?;
        let majors = [
            dump_version.0,
            restore_version.0,
            psql_version.0,
            dumpall_version.0,
            createdb_version.0,
        ];
        if majors.windows(2).any(|pair| pair[0] != pair[1]) {
            bail!("PostgreSQL client tools are from different major versions");
        }
        let mut command = base_command(&psql, source);
        command.args([
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command=SHOW server_version_num",
        ]);
        let result = run(command, timeout, None).context("query PostgreSQL server version")?;
        let server_num: u32 = String::from_utf8(result.stdout)?
            .trim()
            .parse()
            .context("parse PostgreSQL server version")?;
        let major = server_num / 10_000;
        if !matches!(major, 16..=18) {
            bail!("backupctl supports PostgreSQL server majors 16 through 18");
        }
        if major != dump_version.0 {
            bail!("pg_dump major does not match source server major");
        }
        Ok(EngineInfo {
            source_major: major,
            source_version: server_num.to_string(),
            dump_client_version: dump_version.1,
        })
    }

    fn dump_to(
        &self,
        source: &Source,
        output: &Path,
        options: &DumpOptions,
        timeout: Duration,
    ) -> Result<()> {
        let dump = tool(source, "pg_dump")?;
        let mut command = base_command(&dump, source);
        for argument in dump_arguments(options)? {
            command.arg(argument);
        }
        command.arg(format!("--file={}", output.display()));
        let result = run(command, timeout, None).context("run pg_dump")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_dump emitted a warning; artifact was not published");
        }
        Ok(())
    }

    fn resolve_selection(
        &self,
        source: &Source,
        profile: &Profile,
        timeout: Duration,
    ) -> Result<ResolvedSelection> {
        self.check_large_objects(source, profile, timeout)?;
        if profile.is_whole_database() {
            return Ok(ResolvedSelection {
                whole_database: true,
                exclude_schemas: profile.exclude_schemas.clone(),
                exclude_tables: profile.exclude_tables.clone(),
                ..Default::default()
            });
        }
        let mut selection = ResolvedSelection {
            exclude_schemas: profile.exclude_schemas.clone(),
            exclude_tables: profile.exclude_tables.clone(),
            ..Default::default()
        };
        if profile.tables.is_empty() {
            let found = self.query_column(
                source,
                &format!(
                    "SELECT n.nspname FROM pg_catalog.pg_namespace n \
                     WHERE n.nspname IN ({}) ORDER BY 1",
                    literal_list(&profile.schemas)
                ),
                timeout,
                "probe selected schemas",
            )?;
            let missing = missing_names(&profile.schemas, &found);
            if !missing.is_empty() {
                bail!(
                    "profile {} selects schemas that match nothing: {}",
                    profile.name,
                    missing.join(", ")
                );
            }
            selection.schemas = found;
        } else {
            let found = self.query_column(
                source,
                &format!(
                    "SELECT n.nspname || '.' || c.relname \
                     FROM pg_catalog.pg_class c \
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                     JOIN (VALUES {}) r(name, tbl) \
                       ON r.name = n.nspname AND r.tbl = c.relname \
                     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 's') ORDER BY 1",
                    value_pairs(&profile.tables)
                ),
                timeout,
                "probe selected tables",
            )?;
            let missing = missing_names(&profile.tables, &found);
            if !missing.is_empty() {
                bail!(
                    "profile {} selects tables that match nothing: {}",
                    profile.name,
                    missing.join(", ")
                );
            }
            // Expand partition and inheritance families here instead of asking
            // pg_dump to do it, so the recorded scope and the requested scope
            // are literally the same list of names.
            let expanded = self.query_column(
                source,
                &format!(
                    "WITH RECURSIVE roots AS (SELECT c.oid FROM pg_catalog.pg_class c \
                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                        JOIN (VALUES {}) r(name, tbl) \
                          ON r.name = n.nspname AND r.tbl = c.relname), \
                     family AS (SELECT oid FROM roots \
                        UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i \
                        JOIN family f ON f.oid = i.inhparent) \
                     SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c \
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                     JOIN family f ON f.oid = c.oid ORDER BY 1",
                    value_pairs(&profile.tables)
                ),
                timeout,
                "expand partition and inheritance families",
            )?;
            if expanded.len() > MAX_RESOLVED_TABLES {
                bail!(
                    "profile {} resolves to more than {MAX_RESOLVED_TABLES} relations; select schemas instead",
                    profile.name
                );
            }
            selection.tables = expanded;
        }
        let included = included_relations_cte(&selection);
        selection.dangling = self.find_dangling(source, &included, timeout)?;
        selection.extension_members = self.query_column(
            source,
            &format!(
                "{included} \
                 SELECT DISTINCT x.extname FROM pg_catalog.pg_depend d \
                 JOIN pg_catalog.pg_extension x ON x.oid = d.refobjid \
                 WHERE d.classid = 'pg_class'::regclass \
                   AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'x' \
                   AND d.objid IN (SELECT oid FROM included) ORDER BY 1"
            ),
            timeout,
            "probe extension membership",
        )?;
        Ok(selection)
    }

    fn dump_globals(&self, source: &Source, output: &Path, timeout: Duration) -> Result<()> {
        let dumpall = tool(source, "pg_dumpall")?;
        let mut command = cluster_command(&dumpall, source);
        // --no-role-passwords keeps password verifiers out of the artifact;
        // plaintext artifacts are development-only until M4 encryption.
        // --roles-only avoids tablespaces and database attributes, which
        // belong to later cluster-object milestones.
        command.args(["--roles-only", "--no-role-passwords", "--no-sync"]);
        command.arg(format!("--file={}", output.display()));
        let result = run(command, timeout, None).context("run pg_dumpall globals export")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_dumpall emitted a warning; artifact was not published");
        }
        Ok(())
    }

    fn inspect_archive(
        &self,
        source: &Source,
        archive: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        let restore = tool(source, "pg_restore")?;
        let mut command = isolated_command(&restore, source);
        command.arg("--list").arg(archive);
        let result = run(command, timeout, None).context("inspect pg_dump archive")?;
        let text = String::from_utf8(result.stdout).context("decode archive table of contents")?;
        let lines: Vec<String> = text
            .lines()
            .map(|line| line.trim_end_matches('\r').to_string())
            .filter(|line| !line.is_empty())
            .collect();
        if lines.is_empty() {
            bail!("pg_restore returned an empty table of contents");
        }
        Ok(lines)
    }

    fn database_exists(&self, source: &Source, database: &str, timeout: Duration) -> Result<bool> {
        let psql = tool(source, "psql")?;
        let mut command = base_command(&psql, source);
        let statement = format!(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = {}",
            sql_literal(database)
        );
        command.args(["--no-psqlrc", "--tuples-only", "--no-align"]);
        command.arg(format!("--command={statement}"));
        let result = run(command, timeout, None).context("query target database existence")?;
        let text = String::from_utf8(result.stdout)?;
        Ok(!text.trim().is_empty())
    }

    fn role_conflicts(
        &self,
        source: &Source,
        globals: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        let statements = parse_role_statements(globals)?;
        let names = exported_role_names(&statements);
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let existing = self.existing_roles(source, &names, timeout)?;
        // A cluster that already contains every exported role (e.g. the
        // original one) is a real conflict. A baseline cluster that merely
        // shares maintenance roles is handled statement-by-statement when
        // applying.
        if names.iter().all(|name| existing.iter().any(|e| e == name)) {
            Ok(names)
        } else {
            Ok(Vec::new())
        }
    }

    fn apply_globals(&self, source: &Source, globals: &Path, timeout: Duration) -> Result<()> {
        let statements = parse_role_statements(globals)?;
        let text = fs::read_to_string(globals).context("read staged globals file")?;
        if text.len() as u64 > MAX_GLOBALS_BYTES {
            bail!("globals file exceeds size limit");
        }
        if has_password_clause(text.as_bytes()) {
            bail!(
                "globals file contains a PASSWORD clause; refusing to apply an unexported verifier"
            );
        }
        let names = exported_role_names(&statements);
        if names.is_empty() {
            bail!(
                "globals export contains no role statements; refusing to treat it as security metadata"
            );
        }
        let existing = self.existing_roles(source, &names, timeout)?;
        let (script, applied) = build_globals_script(&statements, &existing);
        if applied > 0 {
            let psql = tool(source, "psql")?;
            let mut command = base_command(&psql, source);
            command.args([
                "--no-psqlrc",
                "--quiet",
                "--single-transaction",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "-",
            ]);
            let result =
                run(command, timeout, Some(script.into_bytes())).context("apply globals script")?;
            if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
                bail!("globals apply emitted a warning; the transaction result is unknown");
            }
        }
        // A script that reaches the server but changes nothing must never read
        // as success: the roles the manifest promised are the post-condition.
        let after = self.existing_roles(source, &names, timeout)?;
        if let Some(missing) = names.iter().find(|name| !after.iter().any(|e| e == *name)) {
            bail!(
                "role {missing} is absent after the globals apply; security metadata was not reconstructed"
            );
        }
        Ok(())
    }

    fn create_database(&self, source: &Source, database: &str, timeout: Duration) -> Result<()> {
        if !database.starts_with(backup_domain::FIXTURE_PREFIX) {
            bail!("only synthetic fixture databases may be created");
        }
        let createdb = tool(source, "createdb")?;
        let mut command = cluster_command(&createdb, source);
        command.arg("--template=template0");
        command.arg(database);
        run(command, timeout, None).context("create target database")?;
        Ok(())
    }

    fn create_schemas(
        &self,
        source: &Source,
        database: &str,
        schemas: &[String],
        timeout: Duration,
    ) -> Result<()> {
        if !database.starts_with(backup_domain::FIXTURE_PREFIX) {
            bail!("only synthetic fixture databases may receive schemas");
        }
        let psql = tool(source, "psql")?;
        for schema in schemas {
            // Names arrive from a manifest scope; refuse anything that is not
            // an exact lower-case non-system identifier before issuing DDL.
            if !backup_domain::is_safe_created_schema_name(schema) {
                bail!("refusing to create a schema with an unexpected name");
            }
            let mut command = isolated_command(&psql, source);
            command
                .arg("--no-password")
                .arg(format!("--host={}", source.host))
                .arg(format!("--port={}", source.port))
                .arg(format!("--username={}", source.user))
                .arg(format!("--dbname={database}"))
                .args(["--no-psqlrc", "--quiet"])
                .arg(format!("--command=CREATE SCHEMA IF NOT EXISTS {schema}"));
            run(command, timeout, None)
                .with_context(|| format!("create schema {schema} in target database"))?;
        }
        Ok(())
    }

    fn restore_to_database(
        &self,
        source: &Source,
        database: &str,
        archive: &Path,
        security: RestoreSecurityPolicy,
        sections: RestoreSections,
        timeout: Duration,
    ) -> Result<()> {
        let restore = tool(source, "pg_restore")?;
        let mut command = isolated_command(&restore, source);
        command
            .arg("--no-password")
            .arg(format!("--host={}", source.host))
            .arg(format!("--port={}", source.port))
            .arg(format!("--username={}", source.user))
            .arg(format!("--dbname={database}"));
        command.args(["--exit-on-error"]);
        if !sections.is_full() {
            command.args(sections.argv());
        }
        if !security.ownership {
            command.arg("--no-owner");
        }
        if !security.privileges {
            command.arg("--no-privileges");
        }
        command.arg(archive);
        let result = run(command, timeout, None).context("run pg_restore")?;
        if result.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
            bail!("pg_restore emitted output on stderr; restore result is unverified");
        }
        Ok(())
    }
}

impl PostgresAdapter {
    /// Run one read-only catalog query and return its single-column result.
    /// Names reach PostgreSQL only through `sql_literal`, never as raw text.
    fn query_column(
        &self,
        source: &Source,
        sql: &str,
        timeout: Duration,
        context: &str,
    ) -> Result<Vec<String>> {
        let psql = tool(source, "psql")?;
        let mut command = base_command(&psql, source);
        command.args(["--no-psqlrc", "--tuples-only", "--no-align"]);
        command.arg(format!("--command={sql}"));
        let result = run(command, timeout, None).with_context(|| context.to_string())?;
        let text = String::from_utf8(result.stdout).context("decode catalog query")?;
        Ok(text
            .lines()
            .map(str::to_owned)
            .filter(|line| !line.is_empty())
            .collect())
    }

    /// Large objects are database-wide and have no schema or owner, so a
    /// profile can only take all of them or none of them.
    fn check_large_objects(
        &self,
        source: &Source,
        profile: &Profile,
        timeout: Duration,
    ) -> Result<()> {
        let rows = self.query_column(
            source,
            "SELECT count(*) FROM pg_catalog.pg_largeobject_metadata",
            timeout,
            "probe large objects",
        )?;
        let count: i64 = rows
            .first()
            .context("large object probe returned no row")?
            .parse()
            .context("parse large object count")?;
        if count == 0 {
            return Ok(());
        }
        if !profile.large_objects {
            bail!(
                "profile {} excludes large objects, but this database holds {count} of them: the archive would silently omit data that exists",
                profile.name
            );
        }
        if !profile.schemas.is_empty() || !profile.tables.is_empty() {
            bail!(
                "profile {} selects part of a database that holds {count} large objects, but pg_dump's --large-objects writes every large object in the database, not only those belonging to the selection; back up the whole database instead",
                profile.name
            );
        }
        Ok(())
    }

    /// Find references from objects inside the selection to objects outside it.
    /// `pg_dump` does not dump the referenced object, so such a selection cannot
    /// restore into an empty database on its own.
    fn find_dangling(
        &self,
        source: &Source,
        included: &str,
        timeout: Duration,
    ) -> Result<Vec<DanglingReference>> {
        let sql = format!(
            r#"{included},
            dangling AS (
                SELECT n.nspname || '.' || c.relname AS dependent,
                       rn.nspname || '.' || r.relname AS referenced,
                       'foreign key target' AS kind
                FROM pg_catalog.pg_constraint con
                JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_class r ON r.oid = con.confrelid
                JOIN pg_catalog.pg_namespace rn ON rn.oid = r.relnamespace
                WHERE con.contype = 'f'
                  AND con.conrelid IN (SELECT oid FROM included)
                  AND con.confrelid NOT IN (SELECT oid FROM included)

                UNION ALL

                SELECT cn.nspname || '.' || cc.relname,
                       pn.nspname || '.' || pc.relname,
                       'parent relation'
                FROM pg_catalog.pg_inherits i
                JOIN pg_catalog.pg_class cc ON cc.oid = i.inhrelid
                JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace
                JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent
                JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
                WHERE cc.oid IN (SELECT oid FROM included)
                  AND pc.oid NOT IN (SELECT oid FROM included)

                UNION ALL

                SELECT dn.nspname || '.' || dc.relname,
                       sn.nspname || '.' || sc.relname,
                       'sequence default'
                FROM pg_catalog.pg_attrdef ad
                JOIN pg_catalog.pg_depend d
                  ON d.classid = 'pg_attrdef'::regclass
                 AND d.objid = ad.oid
                 AND d.refclassid = 'pg_class'::regclass
                 AND d.deptype = 'n'
                JOIN pg_catalog.pg_class sc ON sc.oid = d.refobjid AND sc.relkind = 'S'
                JOIN pg_catalog.pg_namespace sn ON sn.oid = sc.relnamespace
                JOIN pg_catalog.pg_class dc ON dc.oid = ad.adrelid
                JOIN pg_catalog.pg_namespace dn ON dn.oid = dc.relnamespace
                WHERE ad.adrelid IN (SELECT oid FROM included)
                  AND sc.oid NOT IN (SELECT oid FROM included)

                UNION ALL

                SELECT tn.nspname || '.' || tc.relname,
                       un.nspname || '.' || et.typname,
                       'column type'
                FROM pg_catalog.pg_attribute a
                JOIN pg_catalog.pg_class tc ON tc.oid = a.attrelid
                JOIN pg_catalog.pg_namespace tn ON tn.oid = tc.relnamespace
                JOIN pg_catalog.pg_type at ON at.oid = a.atttypid
                JOIN pg_catalog.pg_type et
                  ON et.oid = (CASE WHEN at.typcategory = 'A' THEN at.typelem ELSE at.oid END)
                JOIN pg_catalog.pg_namespace un ON un.oid = et.typnamespace
                WHERE tc.oid IN (SELECT oid FROM included)
                  AND a.attnum > 0 AND NOT a.attisdropped
                  AND et.typtype IN ('e', 'd', 'c', 'p')
                  AND un.nspname NOT IN ('pg_catalog', 'information_schema')
                  AND et.typnamespace NOT IN (SELECT oid FROM included_namespace)

                UNION ALL

                SELECT vn.nspname || '.' || vc.relname,
                       bn.nspname || '.' || bc.relname,
                       'view base relation'
                FROM pg_catalog.pg_rewrite rw
                JOIN pg_catalog.pg_depend d
                  ON d.classid = 'pg_rewrite'::regclass
                 AND d.objid = rw.oid
                 AND d.refclassid = 'pg_class'::regclass
                 AND d.deptype = 'n'
                JOIN pg_catalog.pg_class vc ON vc.oid = rw.ev_class
                 AND vc.relkind IN ('v', 'm')
                JOIN pg_catalog.pg_namespace vn ON vn.oid = vc.relnamespace
                JOIN pg_catalog.pg_class bc ON bc.oid = d.refobjid
                JOIN pg_catalog.pg_namespace bn ON bn.oid = bc.relnamespace
                WHERE vc.oid IN (SELECT oid FROM included)
                  AND bc.oid NOT IN (SELECT oid FROM included)
                  AND bc.oid <> vc.oid

                UNION ALL

                SELECT fn_dependent, fn_referenced, 'function' FROM (
                    SELECT tn.nspname || '.' || tc.relname AS fn_dependent,
                           pn.nspname || '.' || p.proname AS fn_referenced
                    FROM pg_catalog.pg_trigger tg
                    JOIN pg_catalog.pg_class tc ON tc.oid = tg.tgrelid
                    JOIN pg_catalog.pg_namespace tn ON tn.oid = tc.relnamespace
                    JOIN pg_catalog.pg_proc p ON p.oid = tg.tgfoid
                    JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
                    WHERE NOT tg.tgisinternal
                      AND tc.oid IN (SELECT oid FROM included)
                      AND pn.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND p.pronamespace NOT IN (SELECT oid FROM included_namespace)

                    UNION ALL

                    SELECT an.nspname || '.' || ac.relname,
                           pn.nspname || '.' || p.proname
                    FROM pg_catalog.pg_depend d
                    JOIN pg_catalog.pg_attrdef ad ON ad.oid = d.objid
                    JOIN pg_catalog.pg_class ac ON ac.oid = ad.adrelid
                    JOIN pg_catalog.pg_namespace an ON an.oid = ac.relnamespace
                    JOIN pg_catalog.pg_proc p ON p.oid = d.refobjid
                    JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
                    WHERE d.classid = 'pg_attrdef'::regclass
                      AND d.refclassid = 'pg_proc'::regclass
                      AND ad.adrelid IN (SELECT oid FROM included)
                      AND pn.nspname NOT IN ('pg_catalog', 'information_schema')
                      AND p.pronamespace NOT IN (SELECT oid FROM included_namespace)
                ) calls
            )
            SELECT DISTINCT dependent || chr(9) || referenced || chr(9) || kind
            FROM dangling ORDER BY 1"#
        );
        let rows = self.query_column(source, &sql, timeout, "probe out-of-scope dependencies")?;
        let mut references = Vec::new();
        for row in rows {
            let mut fields = row.split('\t');
            let (dependent, referenced, kind) = (
                fields.next().unwrap_or_default().to_string(),
                fields.next().unwrap_or_default().to_string(),
                fields.next().unwrap_or_default().to_string(),
            );
            if dependent.is_empty() || referenced.is_empty() || kind.is_empty() {
                bail!("dependency probe returned an incomplete row; selection was not verified");
            }
            references.push(DanglingReference {
                dependent,
                referenced,
                kind,
            });
        }
        Ok(references)
    }

    fn existing_roles(
        &self,
        source: &Source,
        names: &[String],
        timeout: Duration,
    ) -> Result<Vec<String>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let psql = tool(source, "psql")?;
        let mut command = base_command(&psql, source);
        let list = names
            .iter()
            .map(|name| sql_literal(name))
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname IN ({list}) ORDER BY rolname"
        );
        command.args(["--no-psqlrc", "--tuples-only", "--no-align"]);
        command.arg(format!("--command={statement}"));
        let result = run(command, timeout, None).context("probe existing roles")?;
        let text = String::from_utf8(result.stdout)?;
        Ok(text
            .lines()
            .map(str::to_owned)
            .filter(|l| !l.is_empty())
            .collect())
    }
}

fn literal_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Turn validated `schema.table` names into SQL row values for catalog joins.
fn value_pairs(tables: &[String]) -> String {
    tables
        .iter()
        .map(|table| {
            let (schema, name) = table.split_once('.').unwrap_or((table.as_str(), ""));
            format!("({}, {})", sql_literal(schema), sql_literal(name))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn missing_names(requested: &[String], found: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|name| !found.iter().any(|present| present == *name))
        .cloned()
        .collect()
}

/// The relation set a selection resolves to, as a reusable CTE prefix.
fn included_relations_cte(selection: &ResolvedSelection) -> String {
    let mut predicate = if !selection.tables.is_empty() {
        format!(
            "(n.nspname, c.relname) IN (VALUES {})",
            value_pairs(&selection.tables)
        )
    } else {
        format!("n.nspname IN ({})", literal_list(&selection.schemas))
    };
    if !selection.exclude_schemas.is_empty() {
        predicate.push_str(&format!(
            " AND n.nspname NOT IN ({})",
            literal_list(&selection.exclude_schemas)
        ));
    }
    if !selection.exclude_tables.is_empty() {
        predicate.push_str(&format!(
            " AND (n.nspname || '.' || c.relname) NOT IN ({})",
            literal_list(&selection.exclude_tables)
        ));
    }
    // Standalone objects (types, functions) belong to a schema, not to a
    // table. pg_dump writes them for --schema selections and never for
    // --table selections, so a table-based scope covers no namespace at all.
    let namespaces = if selection.tables.is_empty() {
        let mut scope = format!(
            "SELECT ns.oid FROM pg_catalog.pg_namespace ns WHERE ns.nspname IN ({})",
            literal_list(&selection.schemas)
        );
        if !selection.exclude_schemas.is_empty() {
            scope.push_str(&format!(
                " AND ns.nspname NOT IN ({})",
                literal_list(&selection.exclude_schemas)
            ));
        }
        scope
    } else {
        "SELECT ns.oid FROM pg_catalog.pg_namespace ns WHERE false".to_string()
    };
    format!(
        "WITH included AS (SELECT c.oid FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND {predicate}), \
         included_namespace AS ({namespaces})"
    )
}

/// Build the pg_dump argument vector for a resolved selection. Pure so the
/// exact flag set per PostgreSQL major and selection mode is unit-testable
/// without a server.
fn dump_arguments(options: &DumpOptions) -> Result<Vec<String>> {
    let mut arguments = vec![
        "--format=custom".to_string(),
        "--compress=6".to_string(),
        "--no-subscriptions".to_string(),
        "--lock-wait-timeout=5s".to_string(),
    ];
    match options.mode {
        SelectionMode::SchemaAndData => {}
        SelectionMode::SchemaOnly => arguments.push("--schema-only".to_string()),
        SelectionMode::DataOnly => arguments.push("--data-only".to_string()),
    }
    let selection = options.selection;
    for schema in &selection.exclude_schemas {
        arguments.push(format!("--exclude-schema={schema}"));
    }
    for table in &selection.exclude_tables {
        arguments.push(format!("--exclude-table={table}"));
    }
    if !options.exclude_extensions.is_empty() {
        if options.major < MIN_MAJOR_EXCLUDE_EXTENSION {
            bail!(
                "excluding extensions needs pg_dump from PostgreSQL {MIN_MAJOR_EXCLUDE_EXTENSION} or newer, but this source is major {}",
                options.major
            );
        }
        for extension in options.exclude_extensions {
            arguments.push(format!("--exclude-extension={extension}"));
        }
    }
    if selection.whole_database {
        // None keeps the native default, which is what profile-less M1/M2
        // dumps produced.
        if let Some(large_objects) = options.large_objects {
            arguments.push(if large_objects {
                "--large-objects".to_string()
            } else {
                "--no-large-objects".to_string()
            });
        }
        return Ok(arguments);
    }
    for schema in &selection.schemas {
        arguments.push(format!("--schema={schema}"));
    }
    for table in &selection.tables {
        arguments.push(format!("--table={table}"));
    }
    arguments.push("--strict-names".to_string());
    // A filtered dump omits large objects unless asked; the resolver refuses
    // selections that would leave stored large objects unaccounted for.
    if options.large_objects.unwrap_or(false) {
        arguments.push("--large-objects".to_string());
    }
    Ok(arguments)
}

fn cluster_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg("--no-password")
        .arg(format!("--host={}", source.host))
        .arg(format!("--port={}", source.port))
        .arg(format!("--username={}", source.user));
    command
}

fn sql_literal(value: &str) -> String {
    if value.contains('\0') {
        // Caller-provided names are validated elsewhere; a NUL can never be
        // represented in a client encoding, so fail closed.
        panic!("database or role name contains a NUL byte");
    }
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatementKind {
    /// CREATE/ALTER ROLE for the named role.
    Role(String),
    /// GRANT <role> TO <grantee>: membership keyed on the grantee.
    Membership(String),
    /// Anything else in the globals script; never replayed.
    Other,
}

fn sql_role_name(token: &str) -> String {
    let token = token.trim_end_matches(';').trim();
    if token.starts_with('"') {
        // Identifier quoting doubles embedded quotes.
        return token.trim_matches('"').replace("\"\"", "\"");
    }
    token.to_string()
}

fn classify_statement(statement: &str) -> StatementKind {
    let mut parts = statement.split_whitespace();
    let first = loop {
        match parts.next() {
            Some(word) if word.starts_with("--") => continue,
            other => break other,
        }
    };
    match first {
        Some("CREATE") => match parts.next() {
            Some(kind)
                if kind.eq_ignore_ascii_case("ROLE") || kind.eq_ignore_ascii_case("USER") =>
            {
                match parts.next() {
                    Some(name) => StatementKind::Role(sql_role_name(name)),
                    None => StatementKind::Other,
                }
            }
            _ => StatementKind::Other,
        },
        Some("ALTER") => match parts.next() {
            Some(kind) if kind.eq_ignore_ascii_case("ROLE") => match parts.next() {
                Some(name) => StatementKind::Role(sql_role_name(name)),
                None => StatementKind::Other,
            },
            _ => StatementKind::Other,
        },
        Some("GRANT") => {
            // GRANT <member-role> [,...] TO <grantee> [,...]
            let grantee = parts
                .position(|token| token.eq_ignore_ascii_case("TO"))
                .and_then(|_| parts.next());
            match grantee {
                Some(name) => StatementKind::Membership(sql_role_name(name)),
                None => StatementKind::Other,
            }
        }
        _ => StatementKind::Other,
    }
}

/// Split a semicolon-delimited SQL script into statements, dropping trailing
/// empty fragments. String literals in role statements contain no semicolons
/// in our exports, so a naive split is safe here.
fn split_statements(text: &str) -> Vec<String> {
    text.split(';')
        .map(|chunk| {
            chunk
                .lines()
                .filter(|line| !line.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string()
        })
        .filter(|statement| !statement.is_empty())
        .collect()
}

fn parse_role_statements(path: &Path) -> Result<Vec<(StatementKind, String)>> {
    let meta = fs::metadata(path).context("inspect globals file")?;
    if meta.len() > MAX_GLOBALS_BYTES {
        bail!("globals file exceeds size limit");
    }
    let bytes = fs::read(path).context("read globals file")?;
    let text = String::from_utf8(bytes).context("globals file is not valid UTF-8")?;
    Ok(split_statements(&text)
        .into_iter()
        .map(|statement| {
            let kind = classify_statement(&statement);
            (kind, statement)
        })
        .collect())
}

/// Build the script replayed against the cluster. Role statements for a role
/// that already exists are dropped so an existing role is never rewritten,
/// memberships are always replayed (re-granting is a no-op), and every other
/// statement, including psql meta-commands, is excluded.
fn build_globals_script(
    statements: &[(StatementKind, String)],
    existing: &[String],
) -> (String, usize) {
    let mut script = String::from("-- filtered role security statements\n");
    let mut applied = 0usize;
    for (kind, statement) in statements {
        let skip = match kind {
            StatementKind::Role(name) => existing.iter().any(|e| e == name),
            StatementKind::Membership(_) => false,
            StatementKind::Other => true,
        };
        if skip {
            continue;
        }
        script.push_str(statement);
        script.push_str(";\n");
        applied += 1;
    }
    (script, applied)
}

fn exported_role_names(statements: &[(StatementKind, String)]) -> Vec<String> {
    let mut names: Vec<String> = statements
        .iter()
        .filter_map(|(kind, _)| match kind {
            StatementKind::Role(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn tool(source: &Source, name: &str) -> Result<PathBuf> {
    let path = source.client_bin_dir.join(name);
    if !path.is_absolute() || !fs::metadata(&path).is_ok_and(|m| m.is_file()) {
        bail!("missing PostgreSQL client tool: {name}");
    }
    Ok(path)
}

fn tool_version(path: &Path, timeout: Duration) -> Result<(u32, String)> {
    let mut command = Command::new(path);
    command.arg("--version").env_clear().env("LC_ALL", "C");
    let result = run(command, timeout, None)?;
    let version = String::from_utf8(result.stdout)?.trim().to_owned();
    let major = version
        .split_whitespace()
        .find_map(|part| part.split('.').next()?.parse::<u32>().ok())
        .context("parse PostgreSQL client version")?;
    Ok((major, version))
}

fn base_command(path: &Path, source: &Source) -> Command {
    let mut command = isolated_command(path, source);
    command
        .arg("--no-password")
        .arg(format!("--host={}", source.host))
        .arg(format!("--port={}", source.port))
        .arg(format!("--username={}", source.user))
        .arg(format!("--dbname={}", source.database));
    command
}

fn isolated_command(path: &Path, source: &Source) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PGCONNECT_TIMEOUT", "10")
        .env("PGSSLMODE", "disable");
    if let Some(password_file) = &source.password_file {
        command.env("PGPASSFILE", password_file);
    } else {
        command.env("PGPASSFILE", "/dev/null");
    }
    command
}

struct ProcessResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(
    mut command: Command,
    timeout: Duration,
    stdin_data: Option<Vec<u8>>,
) -> Result<ProcessResult> {
    let mut child = match stdin_data {
        Some(script) => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn PostgreSQL client tool")?;
            let mut stdin = child.stdin.take().context("capture stdin")?;
            thread::spawn(move || {
                let _ = stdin.write_all(&script);
                let _ = stdin.flush();
            });
            child
        }
        None => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command.spawn().context("spawn PostgreSQL client tool")?
        }
    };
    let stdout = child.stdout.take().context("capture stdout")?;
    let stderr = child.stderr.take().context("capture stderr")?;
    let out_reader = thread::spawn(move || read_bounded(stdout));
    let err_reader = thread::spawn(move || read_bounded(stderr));
    let started = Instant::now();
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            bail!("PostgreSQL client tool timed out");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
    let stderr = err_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    if !status.success() {
        bail!(
            "PostgreSQL client tool failed with status {status}; output withheld to protect data"
        );
    }
    Ok(ProcessResult { stdout, stderr })
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let remaining = MAX_CAPTURE.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..n.min(remaining)]);
    }
    Ok(captured)
}

/// Defense in depth: our export path uses --no-role-passwords, so a PASSWORD
/// clause means the file was forged or exported wrongly. Substring scan is
/// deliberately over-approximate; false positives only refuse a restore.
fn has_password_clause(script: &[u8]) -> bool {
    let upper = script
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect::<Vec<_>>();
    upper.windows(b"PASSWORD".len()).any(|w| w == b"PASSWORD")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn password_clause_detection_is_fail_closed() {
        assert!(has_password_clause(
            b"CREATE ROLE x PASSWORD 'SCRAM-SHA-256$1';"
        ));
        assert!(has_password_clause(b"ALTER ROLE x password NULL;"));
        assert!(has_password_clause(b"CREATE ROLE x   PASSWORD   NULL ;"));
        assert!(!has_password_clause(b"CREATE ROLE x NOINHERIT LOGIN;"));
        assert!(!has_password_clause(
            b"-- generated by pg_dumpall\nCREATE ROLE x;"
        ));
    }

    #[test]
    fn sql_literals_are_escaped_and_names_never_interpolated_raw() {
        assert_eq!(sql_literal("simple"), "'simple'");
        assert_eq!(sql_literal("it's"), "'it''s'");
        assert_eq!(
            sql_literal("a'); DROP TABLE t;--"),
            "'a''); DROP TABLE t;--'"
        );
    }

    #[test]
    fn role_statements_are_classified_from_pg_dumpall_shape() {
        let dir = std::env::temp_dir().join(format!("backupctl-pg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("globals.sql");
        std::fs::write(
            &path,
            "--\n-- Roles\n--\n\
             \\restrict abc123\n\
             SET default_transaction_read_only = off;\n\
             CREATE ROLE backupctl_fixture_alice;\n\
             ALTER ROLE backupctl_fixture_alice WITH NOSUPERUSER LOGIN;\n\
             CREATE ROLE postgres;\n\
             ALTER ROLE postgres WITH SUPERUSER;\n\
             CREATE USER bob WITH LOGIN;\n\
             GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;\n\
             \\unrestrict abc123\n",
        )
        .unwrap();
        let statements = parse_role_statements(&path).unwrap();
        assert_eq!(
            exported_role_names(&statements),
            ["backupctl_fixture_alice", "bob", "postgres"]
        );
        assert_eq!(
            statements
                .iter()
                .filter_map(|(kind, _)| match kind {
                    StatementKind::Membership(grantee) => Some(grantee.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec!["backupctl_fixture_alice".to_string()]
        );
        // SET and meta-command lines must never be replayed.
        assert!(
            statements
                .iter()
                .all(|(kind, statement)| kind == &StatementKind::Other
                    || (statement.starts_with("CREATE")
                        || statement.starts_with("ALTER")
                        || statement.starts_with("GRANT")))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn globals_script_replays_memberships_but_never_touches_existing_roles() {
        let dir = std::env::temp_dir().join(format!("backupctl-pg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("globals.sql");
        std::fs::write(
            &path,
            "\\restrict abc123\n\
             SET default_transaction_read_only = off;\n\
             CREATE ROLE backupctl_fixture_alice;\n\
             ALTER ROLE backupctl_fixture_alice WITH LOGIN;\n\
             CREATE ROLE postgres;\n\
             ALTER ROLE postgres WITH SUPERUSER;\n\
             GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;\n\
             \\unrestrict abc123\n",
        )
        .unwrap();
        let statements = parse_role_statements(&path).unwrap();
        let (script, applied) = build_globals_script(&statements, &["postgres".to_string()]);
        assert_eq!(applied, 3);
        assert!(script.contains("CREATE ROLE backupctl_fixture_alice;"));
        assert!(script.contains("ALTER ROLE backupctl_fixture_alice WITH LOGIN;"));
        // Membership is rebuilt even though the grantee is being created here.
        assert!(script.contains("GRANT backupctl_fixture_reporting TO backupctl_fixture_alice;"));
        // Predefined roles and psql meta-commands stay untouched.
        assert!(!script.contains("postgres;"));
        assert!(!script.contains("restrict"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quoted_role_names_are_decoded() {
        assert_eq!(sql_role_name("\"Mixed Case\""), "Mixed Case");
        assert_eq!(sql_role_name("plain"), "plain");
        assert_eq!(sql_role_name("trailing;"), "trailing");
    }

    fn whole_database() -> ResolvedSelection {
        ResolvedSelection {
            whole_database: true,
            ..Default::default()
        }
    }

    fn dump_options<'a>(
        selection: &'a ResolvedSelection,
        major: u32,
        mode: SelectionMode,
        large_objects: Option<bool>,
        exclude_extensions: &'a [String],
    ) -> DumpOptions<'a> {
        DumpOptions {
            major,
            mode,
            selection,
            large_objects,
            exclude_extensions,
        }
    }

    #[test]
    fn a_profile_less_dump_keeps_the_m2_argument_vector() {
        let selection = whole_database();
        let arguments = dump_arguments(&dump_options(
            &selection,
            16,
            SelectionMode::default(),
            None,
            &[],
        ))
        .unwrap();
        assert_eq!(
            arguments,
            vec![
                "--format=custom",
                "--compress=6",
                "--no-subscriptions",
                "--lock-wait-timeout=5s",
            ]
        );
    }

    #[test]
    fn schema_selection_dumps_named_schemas_and_strict_names() {
        let selection = ResolvedSelection {
            schemas: vec!["app".to_string(), "aux".to_string()],
            exclude_schemas: vec!["aux".to_string()],
            ..Default::default()
        };
        let arguments = dump_arguments(&dump_options(
            &selection,
            18,
            SelectionMode::SchemaOnly,
            Some(false),
            &[],
        ))
        .unwrap();
        assert!(arguments.contains(&"--schema-only".to_string()));
        assert!(arguments.contains(&"--schema=app".to_string()));
        assert!(arguments.contains(&"--schema=aux".to_string()));
        assert!(arguments.contains(&"--exclude-schema=aux".to_string()));
        // A filtered dump omits large objects natively; only an explicit
        // request adds them, and the resolver refuses that combination.
        assert!(!arguments.contains(&"--no-large-objects".to_string()));
        assert!(!arguments.contains(&"--large-objects".to_string()));
        assert!(arguments.contains(&"--strict-names".to_string()));
    }

    #[test]
    fn table_selection_and_data_only_are_passed_through_expanded() {
        let selection = ResolvedSelection {
            tables: vec![
                "app.partitioned_events".to_string(),
                "app.partitioned_events_2025".to_string(),
            ],
            exclude_tables: vec!["app.audit_events".to_string()],
            ..Default::default()
        };
        let arguments = dump_arguments(&dump_options(
            &selection,
            17,
            SelectionMode::DataOnly,
            None,
            &[],
        ))
        .unwrap();
        assert!(arguments.contains(&"--data-only".to_string()));
        assert!(arguments.contains(&"--table=app.partitioned_events".to_string()));
        assert!(
            arguments.contains(&"--table=app.partitioned_events_2025".to_string()),
            "family members must be dumped explicitly: {arguments:?}"
        );
        assert!(arguments.contains(&"--exclude-table=app.audit_events".to_string()));
        assert!(!arguments.contains(&"--large-objects".to_string()));
    }

    #[test]
    fn excluding_extensions_requires_pg_dump_17_or_newer() {
        let selection = whole_database();
        let extensions = vec!["hstore".to_string()];
        assert!(
            dump_arguments(&dump_options(
                &selection,
                16,
                SelectionMode::default(),
                None,
                &extensions
            ))
            .is_err()
        );
        let arguments = dump_arguments(&dump_options(
            &selection,
            17,
            SelectionMode::default(),
            None,
            &extensions,
        ))
        .unwrap();
        assert!(arguments.contains(&"--exclude-extension=hstore".to_string()));
    }

    #[test]
    fn catalog_lookups_only_ever_see_escaped_literals() {
        assert_eq!(
            literal_list(&["a".to_string(), "b'o".to_string()]),
            "'a', 'b''o'"
        );
        assert_eq!(
            value_pairs(&["app.accounts".to_string()]),
            "('app', 'accounts')"
        );
        // A name without a dot cannot silently become a schema-wide match.
        assert_eq!(value_pairs(&["accounts".to_string()]), "('accounts', '')");
        assert_eq!(
            missing_names(
                &["app.a".to_string(), "app.b".to_string()],
                &["app.a".to_string()]
            ),
            vec!["app.b".to_string()]
        );
    }

    #[test]
    fn the_included_scope_cte_names_relations_and_dumpable_namespaces() {
        let by_schema = included_relations_cte(&ResolvedSelection {
            schemas: vec!["app".to_string()],
            ..Default::default()
        });
        assert!(by_schema.contains("n.nspname IN ('app')"));
        assert!(by_schema.contains("ns.nspname IN ('app')"));

        // pg_dump writes no standalone types or functions for --table, so a
        // table-based scope must cover no namespace at all.
        let by_table = included_relations_cte(&ResolvedSelection {
            tables: vec!["app.accounts".to_string()],
            ..Default::default()
        });
        assert!(by_table.contains("(n.nspname, c.relname) IN (VALUES ('app', 'accounts'))"));
        assert!(by_table.contains("pg_namespace ns WHERE false"));
        assert!(by_table.contains("relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"));
    }
}
