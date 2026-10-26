//! The data of the service: hosts, databases and tables, in memory.
//!
//! The service is the `datastore` example of protocol section 13. Its data is
//! a small fixed tree. A write changes the data in memory for the life of the
//! process. The tree is:
//!
//! | Host | Database | Tables |
//! | --- | --- | --- |
//! | `prod` | `test1` | `orders` (30 rows), `customers` (10 rows) |
//! | `prod` | `test2` | `orders` (2000 rows), `customers` (50 rows) |
//! | `prod` | `a/b` | `t` (3 rows) |
//! | `staging` | `test1` | `orders` (5 rows) |
//!
//! The id `a/b` has a slash, to test the percent-encoding of ids (4.1, 5.2, 5.7).

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use procurauth_core::path::NodePath;
use procurauth_pep::options::{Candidate, CandidatePage, OptionsSource};
use serde_json::{Value, json};

/// The rows of one table.
pub type Rows = Vec<Value>;

type Databases = BTreeMap<String, BTreeMap<String, Rows>>;

/// The nodes of the tree.
#[derive(Debug)]
pub struct Store {
    hosts: Mutex<BTreeMap<String, Databases>>,
}

fn rows(n: usize) -> Rows {
    (1..=n)
        .map(|i| json!({"id": i, "value": format!("row-{i}")}))
        .collect()
}

impl Store {
    /// The fixed data of the service.
    pub fn demo() -> Self {
        let mut prod = Databases::new();
        prod.insert(
            "test1".into(),
            BTreeMap::from([("orders".into(), rows(30)), ("customers".into(), rows(10))]),
        );
        prod.insert(
            "test2".into(),
            BTreeMap::from([
                ("orders".into(), rows(2000)),
                ("customers".into(), rows(50)),
            ]),
        );
        prod.insert("a/b".into(), BTreeMap::from([("t".into(), rows(3))]));
        let mut staging = Databases::new();
        staging.insert("test1".into(), BTreeMap::from([("orders".into(), rows(5))]));
        Self {
            hosts: Mutex::new(BTreeMap::from([
                ("prod".into(), prod),
                ("staging".into(), staging),
            ])),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Databases>> {
        self.hosts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The names of the hosts.
    pub fn hosts(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// The names of the tables of a database, or `None` when the database does not exist.
    pub fn tables(&self, host: &str, database: &str) -> Option<Vec<String>> {
        self.lock()
            .get(host)?
            .get(database)
            .map(|tables| tables.keys().cloned().collect())
    }

    /// True when the table exists.
    pub fn has_table(&self, host: &str, database: &str, table: &str) -> bool {
        self.lock()
            .get(host)
            .and_then(|d| d.get(database))
            .is_some_and(|t| t.contains_key(table))
    }

    /// The number of rows of a table, or `None` when it does not exist.
    pub fn row_count(&self, host: &str, database: &str, table: &str) -> Option<usize> {
        self.lock()
            .get(host)?
            .get(database)?
            .get(table)
            .map(Vec::len)
    }

    /// The first rows of a table, at most `limit`. The second value is the number of rows that the table has.
    pub fn read(
        &self,
        host: &str,
        database: &str,
        table: &str,
        limit: usize,
    ) -> Option<(Rows, usize)> {
        let hosts = self.lock();
        let all = hosts.get(host)?.get(database)?.get(table)?;
        Some((all.iter().take(limit).cloned().collect(), all.len()))
    }

    /// Add rows at the end of a table. The function makes the table when it does
    /// not exist and `create` is true. It returns the new number of rows. It
    /// returns `None` when the database does not exist. It also returns `None`
    /// when the table does not exist and `create` is false.
    pub fn append(
        &self,
        host: &str,
        database: &str,
        table: &str,
        new: Rows,
        create: bool,
    ) -> Option<usize> {
        let mut hosts = self.lock();
        let tables = hosts.get_mut(host)?.get_mut(database)?;
        if !create && !tables.contains_key(table) {
            return None;
        }
        let target = tables.entry(table.to_owned()).or_default();
        target.extend(new);
        Some(target.len())
    }
}

impl OptionsSource for Store {
    fn children(
        &self,
        parent: &NodePath,
        node_type: &str,
        q: Option<&str>,
        after: Option<&str>,
        max: usize,
    ) -> CandidatePage {
        let hosts = self.lock();
        let nodes = parent.nodes();
        let names: Vec<String> = match (nodes.len(), node_type) {
            (1, "host") => hosts.keys().cloned().collect(),
            (2, "database") => hosts
                .get(&nodes[1].id)
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default(),
            (3, "table") => hosts
                .get(&nodes[1].id)
                .and_then(|d| d.get(&nodes[2].id))
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let start = after.and_then(|a| a.parse::<usize>().ok()).unwrap_or(0);
        let matching: Vec<(usize, &String)> = names
            .iter()
            .enumerate()
            .skip(start)
            .filter(|(_, name)| q.is_none_or(|q| name.contains(q)))
            .collect();
        let candidates: Vec<Candidate> = matching
            .iter()
            .take(max)
            .map(|(index, name)| Candidate {
                id: (*name).clone(),
                label: (*name).clone(),
                has_children: node_type != "table",
                cursor: (index + 1).to_string(),
            })
            .collect();
        CandidatePage {
            more: matching.len() > candidates.len(),
            candidates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_pep::operation::node;

    #[test]
    fn the_tree_has_the_nodes_of_the_documentation() {
        let store = Store::demo();
        assert_eq!(store.hosts(), ["prod", "staging"]);
        assert_eq!(
            store.tables("prod", "test2").unwrap(),
            ["customers", "orders"]
        );
        assert_eq!(store.row_count("prod", "test2", "orders"), Some(2000));
        assert_eq!(store.row_count("prod", "a/b", "t"), Some(3));
        assert!(store.tables("prod", "nothing").is_none());
        assert!(!store.has_table("prod", "test1", "nothing"));
    }

    #[test]
    fn a_read_gives_the_first_rows_and_the_size_of_the_table() {
        let store = Store::demo();
        let (rows, total) = store.read("prod", "test2", "orders", 3).unwrap();
        assert_eq!((rows.len(), total), (3, 2000));
        assert_eq!(rows[0], json!({"id": 1, "value": "row-1"}));
        assert!(store.read("prod", "test2", "nothing", 3).is_none());
    }

    #[test]
    fn a_write_adds_rows_and_can_make_a_table() {
        let store = Store::demo();
        assert_eq!(
            store.append("prod", "test1", "customers", vec![json!({"id": 11})], false),
            Some(11)
        );
        assert_eq!(
            store.append("prod", "test1", "new", vec![json!({"id": 1})], false),
            None
        );
        assert_eq!(
            store.append("prod", "test1", "new", vec![json!({"id": 1})], true),
            Some(1)
        );
        assert_eq!(store.append("prod", "nothing", "t", vec![], true), None);
    }

    #[test]
    fn the_source_lists_the_children_with_a_cursor() {
        let store = Store::demo();
        let service = node("datastore", &[]).unwrap();
        let page = store.children(&service, "host", None, None, 1);
        assert_eq!(page.candidates[0].id, "prod");
        assert!(page.more);
        let page = store.children(&service, "host", None, Some(&page.candidates[0].cursor), 5);
        assert_eq!(page.candidates[0].id, "staging");
        assert!(!page.more);
        let prod = node("datastore", &[("host", "prod")]).unwrap();
        let page = store.children(&prod, "database", Some("test"), None, 10);
        let ids: Vec<_> = page.candidates.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["test1", "test2"]);
        assert!(page.candidates[0].has_children);
    }
}
