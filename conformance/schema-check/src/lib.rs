//! Loads the JSON Schemas of ProcurAuth and validates documents against them.
//!
//! The schemas are in the directory `schemas/` of the repository. They
//! refer to each other by `$id`, so this crate registers all of them before
//! it builds a validator. The crate reads files from the repository only. It
//! uses no network.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Resource;
use serde_json::{Value, json};

/// The start of the `$id` of each schema.
pub const BASE_URI: &str = "https://sccagg5.github.io/procurauth/schemas/";

/// The names of the schemas. The file of a schema is `schemas/<name>.schema.json`.
pub const SCHEMA_NAMES: [&str; 9] = [
    "action-document",
    "identity-token-claims",
    "key-format",
    "limit-values",
    "evaluation-context",
    "options-route-answer",
    "fake-pdp-data",
    "conformance-case",
    "access-token-config",
];

/// The root of the repository.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The `$id` of a schema.
pub fn schema_id(name: &str) -> String {
    format!("{BASE_URI}{name}.schema.json")
}

/// The schemas of the repository, loaded in memory.
pub struct Schemas {
    values: BTreeMap<String, Value>,
}

impl Schemas {
    /// Read the schema files from `schemas/`.
    ///
    /// # Errors
    /// Returns a message when a file is absent or is not JSON.
    pub fn load() -> Result<Self, String> {
        let dir = repository_root().join("schemas");
        let mut values = BTreeMap::new();
        for name in SCHEMA_NAMES {
            let path = dir.join(format!("{name}.schema.json"));
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let value: Value = serde_json::from_str(&text)
                .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
            values.insert(name.to_owned(), value);
        }
        Ok(Self { values })
    }

    /// The schema with this name.
    pub fn schema(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }

    /// The `examples` of a schema.
    pub fn examples(&self, name: &str) -> Vec<Value> {
        self.schema(name)
            .and_then(|s| s.get("examples"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn options(&self) -> Result<jsonschema::ValidationOptions, String> {
        let mut resources = Vec::new();
        for (name, value) in &self.values {
            let resource = Resource::from_contents(value.clone())
                .map_err(|e| format!("schema {name}: {e}"))?;
            resources.push((schema_id(name), resource));
        }
        Ok(jsonschema::options().with_resources(resources.into_iter()))
    }

    /// Build the validator of a schema. The call also checks the schema against its meta-schema.
    ///
    /// # Errors
    /// Returns a message when the schema is not valid.
    pub fn validator(&self, name: &str) -> Result<jsonschema::Validator, String> {
        let schema = self
            .schema(name)
            .ok_or_else(|| format!("no schema {name}"))?;
        self.options()?
            .build(schema)
            .map_err(|e| format!("schema {name} is not valid: {e}"))
    }

    /// Validate an instance against a schema. The answer is the list of errors, empty when the instance is valid.
    ///
    /// # Errors
    /// Returns a message when the schema cannot be built.
    pub fn validate(&self, name: &str, instance: &Value) -> Result<Vec<String>, String> {
        let validator = self.validator(name)?;
        Ok(validator
            .iter_errors(instance)
            .map(|e| format!("{}: {e}", e.instance_path))
            .collect())
    }

    /// Validate an instance against one definition of a schema: `$defs/<def>`.
    ///
    /// # Errors
    /// Returns a message when the schema cannot be built.
    pub fn validate_def(
        &self,
        name: &str,
        def: &str,
        instance: &Value,
    ) -> Result<Vec<String>, String> {
        let wrapper = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("{}#/$defs/{def}", schema_id(name)),
        });
        let validator = self
            .options()?
            .build(&wrapper)
            .map_err(|e| format!("{name}#{def}: {e}"))?;
        Ok(validator
            .iter_errors(instance)
            .map(|e| format!("{}: {e}", e.instance_path))
            .collect())
    }

    /// True when the instance is valid against the schema.
    ///
    /// # Errors
    /// Returns a message when the schema cannot be built.
    pub fn is_valid(&self, name: &str, instance: &Value) -> Result<bool, String> {
        Ok(self.validate(name, instance)?.is_empty())
    }
}
