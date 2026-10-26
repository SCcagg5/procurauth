//! Each schema is a valid JSON Schema, it has its documentation members, and each of its examples is valid.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use procurauth_schema_check::{SCHEMA_NAMES, Schemas, schema_id};

#[test]
fn every_schema_is_a_valid_schema_with_an_id() {
    let schemas = Schemas::load().unwrap();
    for name in SCHEMA_NAMES {
        let schema = schemas.schema(name).unwrap();
        assert_eq!(schema["$id"], schema_id(name), "{name}: $id");
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name}: $schema"
        );
        schemas.validator(name).unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn every_schema_has_a_title_a_description_and_examples() {
    let schemas = Schemas::load().unwrap();
    for name in SCHEMA_NAMES {
        let schema = schemas.schema(name).unwrap();
        for member in ["title", "description"] {
            let text = schema[member].as_str().unwrap_or_default();
            assert!(!text.is_empty(), "{name}: member {member} is missing");
        }
        assert!(
            !schemas.examples(name).is_empty(),
            "{name}: the schema has no examples"
        );
    }
}

#[test]
fn every_example_of_every_schema_is_valid() {
    let schemas = Schemas::load().unwrap();
    for name in SCHEMA_NAMES {
        for (index, example) in schemas.examples(name).iter().enumerate() {
            let errors = schemas.validate(name, example).unwrap();
            assert!(errors.is_empty(), "{name}: example {index}: {errors:?}");
        }
    }
}

#[test]
fn the_validator_rejects_a_document_that_is_not_valid() {
    let schemas = Schemas::load().unwrap();
    let bad = serde_json::json!({"server": 5});
    assert!(
        !schemas
            .validate("action-document", &bad)
            .unwrap()
            .is_empty()
    );
}
