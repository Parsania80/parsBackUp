//! Internal consistency of the signed v2 catalog observation. This cannot prove
//! the historical catalog was truthful; the origin signature supplies that trust.

use crate::is_safe_created_schema_name;
use crate::profile::is_valid_table_name;
use crate::{MAX_RESOLVED_TABLES, MAX_TABLE_FAMILY_EDGES, ResolvedSelection};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableFamilyEdge {
    pub parent: String,
    pub child: String,
}

impl ResolvedSelection {
    /// Every added relation must be reachable from an honest literal request.
    /// A topological walk separately rejects cycles, including cycles reachable
    /// from a requested root (reachability alone would accept those).
    pub fn validate_table_family(&self, requested: &[String]) -> Result<()> {
        let family_edges = self.table_family_edges.as_deref().unwrap_or_default();
        ensure!(
            !self.whole_database && self.schemas.is_empty() && !requested.is_empty(),
            "table-family scope must be a filtered table selection"
        );
        ensure!(
            self.dangling.is_empty() && self.extension_members.is_empty(),
            "table-family scope has unsupported dependencies or extension members"
        );
        ensure!(
            self.tables.len() <= MAX_RESOLVED_TABLES
                && !family_edges.is_empty()
                && family_edges.len() <= MAX_TABLE_FAMILY_EDGES,
            "table-family scope exceeds its relation/edge bounds or has no edges"
        );
        let tables: BTreeSet<&str> = self.tables.iter().map(String::as_str).collect();
        let roots: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        ensure!(
            tables.len() == self.tables.len()
                && roots.len() == requested.len()
                && roots.is_subset(&tables)
                && tables.len() > roots.len(),
            "table-family scope must retain unique requested roots and add descendants"
        );
        for table in &tables {
            ensure!(
                is_valid_table_name(table)
                    && table
                        .split_once('.')
                        .is_some_and(|(schema, _)| is_safe_created_schema_name(schema)),
                "table-family scope contains an unsafe relation name"
            );
        }
        ensure!(
            !self
                .exclude_tables
                .iter()
                .any(|t| tables.contains(t.as_str()))
                && self.exclude_schemas.is_empty(),
            "table-family scope excludes a resolved relation"
        );
        let mut edges = BTreeSet::new();
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut indegree: BTreeMap<&str, usize> = tables.iter().map(|t| (*t, 0)).collect();
        for edge in family_edges {
            let (parent, child) = (edge.parent.as_str(), edge.child.as_str());
            ensure!(
                parent != child
                    && tables.contains(parent)
                    && tables.contains(child)
                    && edges.insert((parent, child)),
                "table-family graph has a self-link, duplicate or unknown endpoint"
            );
            children.entry(parent).or_default().push(child);
            *indegree.get_mut(child).expect("validated endpoint") += 1;
        }
        let mut pending: Vec<&str> = indegree
            .iter()
            .filter_map(|(t, n)| (*n == 0).then_some(*t))
            .collect();
        let mut visited = 0;
        while let Some(table) = pending.pop() {
            visited += 1;
            for child in children.get(table).into_iter().flatten() {
                let n = indegree.get_mut(child).expect("validated endpoint");
                *n -= 1;
                if *n == 0 {
                    pending.push(child);
                }
            }
        }
        ensure!(
            visited == tables.len(),
            "table-family graph contains a cycle"
        );
        let mut reached = roots.clone();
        let mut pending: Vec<&str> = roots.into_iter().collect();
        while let Some(table) = pending.pop() {
            for child in children.get(table).into_iter().flatten() {
                if reached.insert(child) {
                    pending.push(child);
                }
            }
        }
        ensure!(
            reached == tables,
            "table-family graph contains an unrequested unrelated relation"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactManifest, RequestedSelection, TABLE_FAMILY_FORMAT_VERSION, fixture};

    fn edge(parent: &str, child: &str) -> TableFamilyEdge {
        TableFamilyEdge {
            parent: parent.into(),
            child: child.into(),
        }
    }

    fn manifest() -> ArtifactManifest {
        let mut m = fixture::manifest_v1_fixture();
        m.format_version = TABLE_FAMILY_FORMAT_VERSION;
        m.profile_snapshot.schemas.clear();
        m.profile_snapshot.tables = vec!["app.root".into(), "app.other".into()];
        m.requested_selection = RequestedSelection::from_profile(&m.profile_snapshot);
        m.resolved_selection.schemas.clear();
        m.resolved_selection.extension_members.clear();
        m.resolved_selection.tables = vec![
            "app.root".into(),
            "app.other".into(),
            "aux.mid".into(),
            "aux.leaf".into(),
        ];
        m.resolved_selection.table_family_edges = Some(vec![
            edge("app.root", "aux.mid"),
            edge("app.other", "aux.mid"),
            edge("aux.mid", "aux.leaf"),
        ]);
        m
    }

    #[test]
    fn family_graph_preserves_multiple_inheritance_cross_schema_and_overlapping_roots() {
        let mut m = manifest();
        m.validate_writable().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let read: ArtifactManifest = serde_json::from_str(&json).unwrap();
        read.validate().unwrap();
        assert_eq!(read.resolved_selection, m.resolved_selection);
        m.profile_snapshot.tables.push("aux.mid".into());
        m.requested_selection = RequestedSelection::from_profile(&m.profile_snapshot);
        m.validate().unwrap();
        let header = crate::PublicHeader::seal(&m, &"a".repeat(64), 1024).unwrap();
        assert_eq!(header.format_version, 2);
        let mut wrong = header;
        wrong.format_version = 1;
        assert!(
            m.matches_header(&wrong)
                .unwrap_err()
                .to_string()
                .contains("format_version")
        );
    }

    #[test]
    fn v2_refuses_unaccounted_scope_cycles_duplicates_missing_roots_and_exclusions() {
        let cases: Vec<fn(&mut ArtifactManifest)> = vec![
            |m| m.resolved_selection.tables.push("aux.unrelated".into()),
            |m| m.resolved_selection.tables.retain(|t| t != "app.root"),
            |m| m.resolved_selection.tables.push("app.root".into()),
            |m| {
                m.resolved_selection
                    .table_family_edges
                    .as_mut()
                    .unwrap()
                    .push(edge("aux.leaf", "app.root"))
            },
            |m| {
                m.resolved_selection
                    .table_family_edges
                    .as_mut()
                    .unwrap()
                    .push(edge("app.root", "app.root"))
            },
            |m| {
                m.resolved_selection
                    .table_family_edges
                    .as_mut()
                    .unwrap()
                    .push(edge("app.root", "aux.mid"))
            },
            |m| {
                m.resolved_selection
                    .table_family_edges
                    .as_mut()
                    .unwrap()
                    .push(edge("app.root", "aux.unknown"))
            },
            |m| m.resolved_selection.table_family_edges = Some(vec![]),
            |m| m.resolved_selection.table_family_edges = None,
            |m| m.resolved_selection.tables.push("aux.bad*".into()),
            |m| m.resolved_selection.extension_members.push("hstore".into()),
            |m| m.resolved_selection.whole_database = true,
            |m| m.resolved_selection.schemas.push("app".into()),
            |m| m.profile_snapshot.tables.push("app.unrequested".into()),
            |m| m.profile_snapshot.exclude_extensions.push("hstore".into()),
            |m| {
                m.profile_snapshot.exclude_tables.push("aux.leaf".into());
                m.resolved_selection.exclude_tables.push("aux.leaf".into());
            },
            |m| m.resolved_selection.exclude_tables.push("aux.other".into()),
            |m| {
                m.resolved_selection.table_family_edges = Some(vec![
                    edge("app.root", "aux.mid");
                    MAX_TABLE_FAMILY_EDGES + 1
                ])
            },
            |m| {
                m.resolved_selection
                    .tables
                    .extend((0..MAX_RESOLVED_TABLES).map(|i| format!("aux.t{i}")))
            },
        ];
        for (index, change) in cases.into_iter().enumerate() {
            let mut m = manifest();
            change(&mut m);
            assert!(m.validate().is_err(), "invalid family case {index}");
        }
    }

    #[test]
    fn v1_omits_family_metadata_and_retains_literal_scope_refusal() {
        let old = fixture::manifest_v1_fixture();
        let json = serde_json::to_string(&old).unwrap();
        assert!(!json.contains("table_family_edges"));
        let mut m = manifest();
        m.format_version = 1;
        assert!(m.validate().is_err());
        m.resolved_selection.table_family_edges = None;
        assert!(
            m.validate()
                .unwrap_err()
                .to_string()
                .contains("without it being requested")
        );
        m.resolved_selection.table_family_edges = Some(vec![]);
        assert!(m.validate().is_err());
        let mut value = serde_json::to_value(&old).unwrap();
        value["resolved_selection"]["table_family_edges"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ArtifactManifest>(value).is_err());
    }

    #[test]
    fn family_metadata_is_closed_and_requires_real_expansion() {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["resolved_selection"]["table_family_edges"][0]["extra"] = true.into();
        assert!(serde_json::from_value::<ArtifactManifest>(value).is_err());
        let mut m = manifest();
        m.profile_snapshot.tables = m.resolved_selection.tables.clone();
        m.requested_selection = RequestedSelection::from_profile(&m.profile_snapshot);
        assert!(m.validate().is_err());
    }
}
