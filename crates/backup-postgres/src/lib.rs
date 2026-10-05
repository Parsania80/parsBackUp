//! The PostgreSQL boundary: every interaction with a live cluster, expressed as
//! read-only catalog probes plus the client tools' own argv.
//!
//! Module map:
//! - `tools`: where the client binaries come from, how they are run, and the
//!   argument values they are given.
//! - `dump`: the `pg_dump` argument vector for a resolved selection.
//! - `catalog`: the catalog queries the resolver builds, and their escaping.
//! - `globals`: parsing and re-building a roles-only globals script.
//!
//! Engine output is never included in an error, so a failure cannot leak
//! credentials or row data.

mod catalog;
mod dump;
mod globals;
mod tools;

use crate::catalog::{
    included_relations_cte, literal_list, missing_names, sql_literal, value_pairs,
};
use crate::dump::dump_arguments;
use crate::globals::{
    build_globals_script, exported_role_names, has_password_clause, parse_role_statements,
};
use crate::tools::{
    ARG_DBNAME, ARG_HOST, ARG_NO_PASSWORD, ARG_PORT, ARG_USERNAME, CREATEDB, PG_DUMP, PG_DUMPALL,
    PG_RESTORE, PSQL, PSQL_QUERY_ARGS, base_command, cluster_command, isolated_command, run,
    run_streaming, tool, tool_version,
};
use anyhow::{Context, Result, bail};
use backup_application::{DatabaseAdapter, EngineInfo};
use backup_domain::{
    DanglingReference, DumpOptions, MAX_RESOLVED_TABLES, Profile, ResolvedSelection,
    RestoreSections, RestoreSecurityPolicy, SUPPORTED_MAJOR_RANGE, SUPPORTED_MAJORS, Source,
};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

/// A globals file is a role script, not a data dump; anything larger is not one
/// this tool knows how to reason about.
pub(crate) const MAX_GLOBALS_BYTES: u64 = 8 * 1024 * 1024;

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
        let dump = tool(source, PG_DUMP)?;
        let restore = tool(source, PG_RESTORE)?;
        let psql = tool(source, PSQL)?;
        let dumpall = tool(source, PG_DUMPALL)?;
        let createdb = tool(source, CREATEDB)?;
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
        command.args(PSQL_QUERY_ARGS);
        command.arg("--command=SHOW server_version_num");
        let result = run(command, timeout, None).context("query PostgreSQL server version")?;
        let server_num: u32 = String::from_utf8(result.stdout)?
            .trim()
            .parse()
            .context("parse PostgreSQL server version")?;
        let major = server_num / 10_000;
        if !SUPPORTED_MAJORS.contains(&major) {
            bail!("backupctl supports PostgreSQL server majors {SUPPORTED_MAJOR_RANGE}");
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

    fn dump_stream(
        &self,
        source: &Source,
        options: &DumpOptions,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let dump = tool(source, PG_DUMP)?;
        let mut command = base_command(&dump, source);
        for argument in dump_arguments(options)? {
            command.arg(argument);
        }
        // No `--file` argument: pg_dump writes the archive to its standard output, and
        // the caller's sink is the only thing that ever holds it.
        run_streaming(command, PG_DUMP, timeout, consume)
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

    fn dump_globals_stream(
        &self,
        source: &Source,
        timeout: Duration,
        consume: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let dumpall = tool(source, PG_DUMPALL)?;
        let mut command = cluster_command(&dumpall, source);
        // --no-role-passwords is what keeps password verifiers out of the artifact; it
        // is the reason in both modes, encrypted or not.
        // --roles-only avoids tablespaces and database attributes, which
        // belong to later cluster-object milestones.
        command.args(["--roles-only", "--no-role-passwords", "--no-sync"]);
        run_streaming(command, PG_DUMPALL, timeout, consume)
    }

    fn inspect_archive(
        &self,
        source: &Source,
        archive: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        let restore = tool(source, PG_RESTORE)?;
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
        let psql = tool(source, PSQL)?;
        let mut command = base_command(&psql, source);
        let statement = format!(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = {}",
            sql_literal(database)
        );
        command.args(PSQL_QUERY_ARGS);
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
            let psql = tool(source, PSQL)?;
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
        let createdb = tool(source, CREATEDB)?;
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
        let psql = tool(source, PSQL)?;
        for schema in schemas {
            // Names arrive from a manifest scope; refuse anything that is not
            // an exact lower-case non-system identifier before issuing DDL.
            if !backup_domain::is_safe_created_schema_name(schema) {
                bail!("refusing to create a schema with an unexpected name");
            }
            let mut command = isolated_command(&psql, source);
            command
                .arg(ARG_NO_PASSWORD)
                .arg(format!("{ARG_HOST}{}", source.host))
                .arg(format!("{ARG_PORT}{}", source.port))
                .arg(format!("{ARG_USERNAME}{}", source.user))
                .arg(format!("{ARG_DBNAME}{database}"))
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
        let restore = tool(source, PG_RESTORE)?;
        let mut command = isolated_command(&restore, source);
        command
            .arg(ARG_NO_PASSWORD)
            .arg(format!("{ARG_HOST}{}", source.host))
            .arg(format!("{ARG_PORT}{}", source.port))
            .arg(format!("{ARG_USERNAME}{}", source.user))
            .arg(format!("{ARG_DBNAME}{database}"));
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
        let psql = tool(source, PSQL)?;
        let mut command = base_command(&psql, source);
        command.args(PSQL_QUERY_ARGS);
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
        let psql = tool(source, PSQL)?;
        let mut command = base_command(&psql, source);
        let list = names
            .iter()
            .map(|name| sql_literal(name))
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "SELECT COALESCE(json_agg(rolname ORDER BY rolname), '[]'::json) FROM pg_catalog.pg_roles WHERE rolname IN ({list})"
        );
        command.args(PSQL_QUERY_ARGS);
        command.arg(format!("--command={statement}"));
        let result = run(command, timeout, None).context("probe existing roles")?;
        // JSON preserves whitespace/newlines inside quoted role names.
        serde_json::from_slice(&result.stdout).map_err(|_| {
            anyhow::anyhow!("cannot decode existing role names; output withheld to protect data")
        })
    }
}
