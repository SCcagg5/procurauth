//! The conformance data: the cases and the directory files.
//!
//! The program has a copy of the data in its binary. The option `--cases-dir`
//! reads the data from a directory instead. The directory has the same layout
//! as `conformance/`: `cases/U`, `cases/D`, `cases/E` and `directories`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use procurauth_core::json::parse_str;
use serde_json::Value;

use crate::model::{Case, DirectoryRef, Role};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

/// The cases and the directories.
pub(crate) struct Catalog {
    cases: Vec<Case>,
    directories: BTreeMap<String, Value>,
}

/// The number in an id, for the order of the cases.
fn number(id: &str) -> u32 {
    id.get(1..).and_then(|n| n.parse().ok()).unwrap_or(0)
}

impl Catalog {
    /// Load the data that the binary holds.
    ///
    /// # Errors
    /// Returns every problem of the data.
    pub(crate) fn embedded() -> Result<Self, Vec<String>> {
        let cases: Vec<(String, String)> = embedded::CASES
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
            .collect();
        let directories: Vec<(String, String)> = embedded::DIRECTORIES
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
            .collect();
        Self::build(&cases, &directories)
    }

    /// Load the data from a directory with the layout of `conformance/`.
    ///
    /// # Errors
    /// Returns every problem of the directory and of the data.
    pub(crate) fn from_dir(root: &Path) -> Result<Self, Vec<String>> {
        let mut cases = Vec::new();
        let mut directories = Vec::new();
        let mut errors = Vec::new();
        for series in ["U", "D", "E"] {
            let dir = root.join("cases").join(series);
            match list_json(&dir) {
                Ok(files) => {
                    for (name, text) in files {
                        cases.push((format!("{series}/{name}"), text));
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        match list_json(&root.join("directories")) {
            Ok(files) => directories = files,
            Err(e) => errors.push(e),
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Self::build(&cases, &directories)
    }

    fn build(
        cases: &[(String, String)],
        directories: &[(String, String)],
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let mut out = Vec::new();
        for (name, text) in cases {
            match Case::parse(text) {
                Ok(case) => {
                    let expected = format!("{}/{}.json", case.role.series(), case.id);
                    if &expected != name {
                        errors.push(format!(
                            "Case file `{name}`: expected the id and the role to name the file `{expected}`, found the id `{}` and the role `{}`.",
                            case.id,
                            case.role.name()
                        ));
                    } else {
                        out.push(case);
                    }
                }
                Err(why) => errors.push(format!("Case file `{name}`: {why}.")),
            }
        }
        let mut dirs = BTreeMap::new();
        for (name, text) in directories {
            match parse_str(text) {
                Ok(value) => {
                    dirs.insert(name.clone(), value);
                }
                Err(why) => errors.push(format!("Directory file `{name}`: {why}.")),
            }
        }
        out.sort_by_key(|c| (c.role.series(), number(&c.id)));
        for case in &out {
            if let Some(DirectoryRef::Name(name)) = &case.given.directory
                && !dirs.contains_key(name)
            {
                errors.push(format!(
                    "Case `{}`: the directory file `{name}` does not exist.",
                    case.id
                ));
            }
        }
        if errors.is_empty() {
            Ok(Self {
                cases: out,
                directories: dirs,
            })
        } else {
            Err(errors)
        }
    }

    /// The cases of a role, in the order of their numbers.
    pub(crate) fn cases_of(&self, role: Role) -> Vec<&Case> {
        self.cases.iter().filter(|c| c.role == role).collect()
    }

    /// The case with this id.
    pub(crate) fn case(&self, id: &str) -> Option<&Case> {
        self.cases.iter().find(|c| c.id == id)
    }

    /// A directory file, by name.
    pub(crate) fn directory(&self, name: &str) -> Option<&Value> {
        self.directories.get(name)
    }

    /// The directory of a case, with no clock and no counters of the case.
    ///
    /// # Errors
    /// Returns a message when the case has no directory.
    pub(crate) fn directory_of(&self, case: &Case) -> Result<Value, String> {
        match &case.given.directory {
            Some(DirectoryRef::Name(name)) => self
                .directory(name)
                .cloned()
                .ok_or_else(|| format!("the directory file `{name}` does not exist")),
            Some(DirectoryRef::Inline(value)) => Ok(value.clone()),
            None => Err("the case has no directory".to_owned()),
        }
    }

    /// The data of the test PDP for a case: the directory, with the clock and the counters of the case.
    ///
    /// # Errors
    /// Returns a message when the case has no directory.
    pub(crate) fn data_of(&self, case: &Case) -> Result<Value, String> {
        let mut data = match &case.given.directory {
            Some(DirectoryRef::Name(name)) => self
                .directory(name)
                .cloned()
                .ok_or_else(|| format!("the directory file `{name}` does not exist"))?,
            Some(DirectoryRef::Inline(value)) => value.clone(),
            None => return Err("the case has no directory".to_owned()),
        };
        if let Some(clock) = &case.given.clock {
            data["clock"] = serde_json::json!({"now": clock.now});
        }
        if !case.given.counters.is_empty() {
            let mut merged: Vec<Value> = data
                .get("counters")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for counter in &case.given.counters {
                merged.retain(|c| {
                    !(c["subject"] == counter["subject"]
                        && c["limit"] == counter["limit"]
                        && c["window"] == counter["window"])
                });
                merged.push(counter.clone());
            }
            data["counters"] = Value::Array(merged);
        }
        Ok(data)
    }
}

fn list_json(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("Cannot read the directory `{}`: {e}.", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("Cannot read the directory `{}`: {e}.", dir.display()))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = entry.file_name().to_string_lossy().into_owned();
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("Cannot read the file `{}`: {e}.", path.display()))?;
            files.push((name, text));
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_holds_the_191_cases() {
        let catalog = Catalog::embedded().unwrap();
        assert_eq!(catalog.cases_of(Role::Pep).len(), 99);
        assert_eq!(catalog.cases_of(Role::Pdp).len(), 74);
        assert_eq!(catalog.cases_of(Role::Edge).len(), 18);
        assert!(catalog.directory("datastore.json").is_some());
    }

    #[test]
    fn the_cases_have_the_order_of_their_numbers() {
        let catalog = Catalog::embedded().unwrap();
        let ids: Vec<&str> = catalog
            .cases_of(Role::Pep)
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids[0], "U01");
        assert_eq!(ids[8], "U09");
        assert_eq!(ids[9], "U10");
    }

    #[test]
    fn the_data_of_a_case_has_its_clock_and_its_counters() {
        let catalog = Catalog::embedded().unwrap();
        let case = catalog.case("D06").unwrap();
        let data = catalog.data_of(case).unwrap();
        assert!(data["clock"]["now"].is_u64());
        assert!(!data["counters"].as_array().unwrap().is_empty());
    }
}
