//! The JSON Schemas and the Rust readers agree.
//!
//! Each row of a table gives a document and the verdict of the Rust reader
//! and of the schema. Most rows have the same verdict for both. The rows
//! where they differ show a rule that a schema cannot state, for example a
//! rule between two members. The text of a row names that rule.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use procurauth_core::action_document::analyze_value;
use procurauth_core::authzen::{Decision, RequestContext};
use procurauth_core::directory::Directory;
use procurauth_core::finding::{JsonPath, Report};
use procurauth_core::identity::Claims;
use procurauth_core::key_format::KeyFormat;
use procurauth_core::limits::read_limit_values;
use procurauth_core::options;
use procurauth_schema_check::Schemas;
use serde_json::{Value, json};

struct Row {
    label: &'static str,
    doc: Value,
    rust: bool,
    schema: bool,
}

/// The two verdicts are equal.
fn same(label: &'static str, doc: Value, verdict: bool) -> Row {
    Row {
        label,
        doc,
        rust: verdict,
        schema: verdict,
    }
}

/// The Rust reader refuses the document, and the schema accepts it.
fn rust_only(label: &'static str, doc: Value) -> Row {
    Row {
        label,
        doc,
        rust: false,
        schema: true,
    }
}

fn edit(base: &Value, change: impl FnOnce(&mut Value)) -> Value {
    let mut doc = base.clone();
    change(&mut doc);
    doc
}

fn remove(doc: &mut Value, key: &str) {
    doc.as_object_mut().unwrap().remove(key);
}

fn check(name: &str, def: Option<&str>, rows: &[Row], rust: impl Fn(&Value) -> bool) {
    let schemas = Schemas::load().unwrap();
    for row in rows {
        let schema_errors = match def {
            Some(def) => schemas.validate_def(name, def, &row.doc).unwrap(),
            None => schemas.validate(name, &row.doc).unwrap(),
        };
        assert_eq!(
            rust(&row.doc),
            row.rust,
            "{name}: the Rust reader does not give {} for the row {:?}: {}",
            row.rust,
            row.label,
            row.doc
        );
        assert_eq!(
            schema_errors.is_empty(),
            row.schema,
            "{name}: the schema does not give {} for the row {:?}: {schema_errors:?}",
            row.schema,
            row.label
        );
    }
}

fn examples_are_good(name: &str, rust: impl Fn(&Value) -> bool) {
    let schemas = Schemas::load().unwrap();
    for (index, example) in schemas.examples(name).iter().enumerate() {
        assert!(
            rust(example),
            "{name}: the Rust reader refuses example {index}"
        );
    }
}

// ---------------------------------------------------------------- action document

fn section_13() -> Value {
    json!({
        "server": "datastore",
        "resource_types": [
            {"name": "host", "parent": "service", "description": "One database server."},
            {"name": "database", "parent": "host", "description": "One database."},
            {"name": "table", "parent": "database", "description": "One table."}
        ],
        "actions": [
            {"name": "data.read", "resource_types": ["service", "host", "database", "table"],
             "description": "Read data.", "limits": ["requests", "max_rows", "max_duration"]},
            {"name": "data.write", "resource_types": ["service", "host", "database", "table"],
             "description": "Change data.", "limits": ["requests", "max_duration"]}
        ],
        "resources": [{"path": "host:prod", "label": "Production"}],
        "limits": [
            {"name": "requests", "label": "Requests", "description": "Requests that run.",
             "unit": "request", "kind": "budget"},
            {"name": "max_rows", "label": "Most rows", "description": "The most rows that one read gives.",
             "unit": "row", "kind": "ceiling", "min": 1, "max": 1_000_000},
            {"name": "max_duration", "label": "Longest run", "description": "The longest run of one use, in seconds.",
             "unit": "second", "kind": "ceiling", "min": 1, "max": 600}
        ]
    })
}

fn action_rows() -> Vec<Row> {
    let base = section_13();
    let e = |f: &dyn Fn(&mut Value)| edit(&base, |d| f(d));
    vec![
        same("section 13", base.clone(), true),
        same(
            "minimal",
            json!({"server": "s", "resource_types": [], "actions": []}),
            true,
        ),
        same(
            "unknown member at the top is a warning",
            e(&|d| d["extra"] = json!(1)),
            true,
        ),
        same(
            "unknown member in an action is a warning",
            e(&|d| d["actions"][0]["extra"] = json!(1)),
            true,
        ),
        same("missing server", e(&|d| remove(d, "server")), false),
        same(
            "missing resource_types",
            e(&|d| remove(d, "resource_types")),
            false,
        ),
        same("missing actions", e(&|d| remove(d, "actions")), false),
        same("empty server", e(&|d| d["server"] = json!("")), false),
        same("server is a number", e(&|d| d["server"] = json!(5)), false),
        same("not an object", json!([]), false),
        same(
            "unknown member in a limit declaration",
            e(&|d| d["limits"][0]["scope"] = json!("x")),
            false,
        ),
        same(
            "type name in upper case",
            e(&|d| d["resource_types"][0]["name"] = json!("Host")),
            false,
        ),
        same(
            "type named service",
            e(&|d| d["resource_types"][0]["name"] = json!("service")),
            false,
        ),
        same(
            "type without parent",
            e(&|d| {
                d["resource_types"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("parent");
            }),
            false,
        ),
        same(
            "action named access",
            e(&|d| d["actions"][0]["name"] = json!("access")),
            false,
        ),
        same(
            "action name in upper case",
            e(&|d| d["actions"][0]["name"] = json!("Data.read")),
            false,
        ),
        same(
            "action name with two dots",
            e(&|d| d["actions"][0]["name"] = json!("data..read")),
            false,
        ),
        same(
            "action type listed two times",
            e(&|d| d["actions"][0]["resource_types"] = json!(["host", "host"])),
            false,
        ),
        same(
            "action limit listed two times",
            e(&|d| d["actions"][0]["limits"] = json!(["requests", "requests"])),
            false,
        ),
        same(
            "resource path with a space",
            e(&|d| d["resources"][0]["path"] = json!("host:a b")),
            false,
        ),
        same(
            "resource path without a type",
            e(&|d| d["resources"][0]["path"] = json!("prod")),
            false,
        ),
        same(
            "resource path with a lower-case escape",
            e(&|d| d["resources"][0]["path"] = json!("host:a%2fb")),
            false,
        ),
        same(
            "resource without path",
            e(&|d| {
                d["resources"][0].as_object_mut().unwrap().remove("path");
            }),
            false,
        ),
        same(
            "resource path with an encoded slash",
            e(&|d| d["resources"][0]["path"] = json!("host:a%2Fb")),
            true,
        ),
        same(
            "limit kind quota",
            e(&|d| d["limits"][0]["kind"] = json!("quota")),
            false,
        ),
        same(
            "ceiling without max",
            e(&|d| {
                d["limits"][1].as_object_mut().unwrap().remove("max");
            }),
            false,
        ),
        same(
            "ceiling without min",
            e(&|d| {
                d["limits"][1].as_object_mut().unwrap().remove("min");
            }),
            false,
        ),
        same(
            "budget with min",
            e(&|d| d["limits"][0]["min"] = json!(1)),
            false,
        ),
        same(
            "budget with max",
            e(&|d| d["limits"][0]["max"] = json!(1)),
            false,
        ),
        same(
            "min is negative",
            e(&|d| d["limits"][1]["min"] = json!(-1)),
            false,
        ),
        same(
            "min is 1.5",
            e(&|d| d["limits"][1]["min"] = json!(1.5)),
            false,
        ),
        same(
            "min is a string",
            e(&|d| d["limits"][1]["min"] = json!("1")),
            false,
        ),
        same(
            "limit name of 33 characters",
            e(&|d| d["limits"][0]["name"] = json!("a".repeat(33))),
            false,
        ),
        same(
            "budget name starts with max_",
            e(&|d| {
                d["limits"][0]["name"] = json!("max_requests");
                d["actions"][0]["limits"] = json!(["max_requests"]);
                d["actions"][1]["limits"] = json!([]);
            }),
            false,
        ),
        rust_only(
            "min is 1.0: a schema accepts 1.0 as an integer, and the reader wants a whole-number form",
            e(&|d| d["limits"][1]["min"] = json!(1.0)),
        ),
        rust_only(
            "parent is not declared: a schema cannot check a reference",
            e(&|d| d["resource_types"][1]["parent"] = json!("ghost")),
        ),
        rust_only(
            "action lists a limit that no declaration has",
            e(&|d| d["actions"][0]["limits"] = json!(["ghost"])),
        ),
        rust_only(
            "action lists a type that no declaration has",
            e(&|d| d["actions"][0]["resource_types"] = json!(["ghost"])),
        ),
        rust_only(
            "two types have the same name",
            e(&|d| d["resource_types"][1]["name"] = json!("host")),
        ),
        rust_only(
            "min is above max",
            e(&|d| {
                d["limits"][1]["min"] = json!(10);
                d["limits"][1]["max"] = json!(5);
            }),
        ),
        rust_only("the depth of a type is 5", chain_of_five()),
        rust_only(
            "the server id is 129 two-byte characters: a schema counts characters",
            e(&|d| d["server"] = json!("\u{e9}".repeat(129))),
        ),
        rust_only(
            "the path holds an escaped control character",
            e(&|d| d["resources"][0]["path"] = json!("host:a%00b")),
        ),
        rust_only(
            "resource path with a type that is not declared",
            e(&|d| d["resources"][0]["path"] = json!("ghost:a")),
        ),
        rust_only(
            "resource lists an action that no declaration has",
            e(&|d| d["resources"][0]["actions"] = json!(["ghost"])),
        ),
    ]
}

fn chain_of_five() -> Value {
    let types: Vec<Value> = (1..=5)
        .map(|i| {
            let parent = if i == 1 {
                "service".to_owned()
            } else {
                format!("t{}", i - 1)
            };
            json!({"name": format!("t{i}"), "parent": parent, "description": "A type."})
        })
        .collect();
    json!({"server": "s", "resource_types": types, "actions": []})
}

#[test]
fn action_document_schema_and_reader_agree() {
    let rust = |v: &Value| analyze_value(v).document.is_some();
    check("action-document", None, &action_rows(), rust);
    examples_are_good("action-document", rust);
}

// ---------------------------------------------------------------- identity token claims

fn claims_rows() -> Vec<Row> {
    let base = json!({"iss": "https://edge.example", "sub": "key:9b1c04e2aa71f0c3", "aud": "datastore",
                      "iat": 1_792_569_600, "exp": 1_792_569_900, "owner": "alice"});
    let e = |f: &dyn Fn(&mut Value)| edit(&base, |d| f(d));
    let mut rows = vec![
        same("a token for a key", base.clone(), true),
        same(
            "an array of audiences",
            e(&|d| d["aud"] = json!(["a", "datastore"])),
            true,
        ),
        same(
            "an empty array of audiences",
            e(&|d| d["aud"] = json!([])),
            true,
        ),
        same(
            "an unknown claim is ignored",
            e(&|d| d["scope"] = json!("x")),
            true,
        ),
        same(
            "the claim act: the profile check refuses it, not the reader",
            e(&|d| d["act"] = json!({})),
            true,
        ),
        same("no owner", e(&|d| remove(d, "owner")), true),
        same("not an object", json!("x"), false),
        same("iss is empty", e(&|d| d["iss"] = json!("")), false),
        same("sub is empty", e(&|d| d["sub"] = json!("")), false),
        same("owner is empty", e(&|d| d["owner"] = json!("")), false),
        same("iat is a string", e(&|d| d["iat"] = json!("1")), false),
        same("exp is negative", e(&|d| d["exp"] = json!(-1)), false),
        same("exp is 1.5", e(&|d| d["exp"] = json!(1.5)), false),
        same("aud is a number", e(&|d| d["aud"] = json!(5)), false),
        same(
            "aud holds a number",
            e(&|d| d["aud"] = json!(["a", 5])),
            false,
        ),
        same("owner is a number", e(&|d| d["owner"] = json!(5)), false),
        rust_only("exp is 1.0", e(&|d| d["exp"] = json!(1_792_569_900.0))),
    ];
    for claim in ["iss", "sub", "aud", "iat", "exp"] {
        let label: &'static str = Box::leak(format!("missing {claim}").into_boxed_str());
        rows.push(same(label, e(&|d| remove(d, claim)), false));
    }
    rows
}

#[test]
fn identity_token_claims_schema_and_reader_agree() {
    let rust = |v: &Value| Claims::from_value(v).is_ok();
    check("identity-token-claims", None, &claims_rows(), rust);
    examples_are_good("identity-token-claims", rust);
}

#[test]
fn identity_token_header_definition_agrees_with_the_rules_of_9_2() {
    let schemas = Schemas::load().unwrap();
    let good = |v: Value| {
        schemas
            .validate_def("identity-token-claims", "header", &v)
            .unwrap()
            .is_empty()
    };
    assert!(good(json!({"alg": "Ed25519", "typ": "JWT"})));
    assert!(good(json!({"alg": "ES256", "typ": "JWT", "kid": "k1"})));
    for bad in [
        json!({"alg": "none", "typ": "JWT"}),
        json!({"alg": "EdDSA", "typ": "JWT"}),
        json!({"alg": "HS256", "typ": "JWT"}),
        json!({"alg": "Ed25519", "typ": "at+jwt"}),
        json!({"alg": "Ed25519"}),
        json!({"typ": "JWT"}),
        json!({"alg": "Ed25519", "typ": "JWT", "crit": ["x"]}),
        json!({"alg": "Ed25519", "typ": "JWT", "kid": ""}),
    ] {
        assert!(!good(bad.clone()), "{bad}");
    }
}

// ---------------------------------------------------------------- key format

fn key_format_rows() -> Vec<Row> {
    let base = json!({"prefix": "mcp_", "length": 53, "alphabet": "A-Za-z0-9",
                      "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6}});
    let e = |f: &dyn Fn(&mut Value)| edit(&base, |d| f(d));
    vec![
        same("the portal format", base.clone(), true),
        same("no checksum", e(&|d| remove(d, "checksum")), true),
        same(
            "covers prefix_and_random",
            e(&|d| d["checksum"]["covers"] = json!("prefix_and_random")),
            true,
        ),
        same("not an object", json!([]), false),
        same("unknown member", e(&|d| d["extra"] = json!(1)), false),
        same(
            "unknown member of the checksum",
            e(&|d| d["checksum"]["extra"] = json!(1)),
            false,
        ),
        same("missing prefix", e(&|d| remove(d, "prefix")), false),
        same("missing length", e(&|d| remove(d, "length")), false),
        same("missing alphabet", e(&|d| remove(d, "alphabet")), false),
        same("empty prefix", e(&|d| d["prefix"] = json!("")), false),
        same(
            "prefix with a space",
            e(&|d| d["prefix"] = json!("m c")),
            false,
        ),
        same(
            "prefix of 33 characters",
            e(&|d| d["prefix"] = json!("a".repeat(33))),
            false,
        ),
        same("length 0", e(&|d| d["length"] = json!(0)), false),
        same("length 1025", e(&|d| d["length"] = json!(1025)), false),
        same(
            "length is a string",
            e(&|d| d["length"] = json!("53")),
            false,
        ),
        same("empty alphabet", e(&|d| d["alphabet"] = json!("")), false),
        same(
            "alphabet with a space",
            e(&|d| d["alphabet"] = json!("a b")),
            false,
        ),
        same(
            "checksum without algorithm",
            e(&|d| {
                d["checksum"].as_object_mut().unwrap().remove("algorithm");
            }),
            false,
        ),
        same(
            "checksum algorithm md5",
            e(&|d| d["checksum"]["algorithm"] = json!("md5")),
            false,
        ),
        same(
            "checksum encoding base64",
            e(&|d| d["checksum"]["encoding"] = json!("base64")),
            false,
        ),
        same(
            "checksum of 0 characters",
            e(&|d| d["checksum"]["characters"] = json!(0)),
            false,
        ),
        same(
            "checksum of 65 characters",
            e(&|d| d["checksum"]["characters"] = json!(65)),
            false,
        ),
        same(
            "covers all",
            e(&|d| d["checksum"]["covers"] = json!("all")),
            false,
        ),
        rust_only("length is 53.0", e(&|d| d["length"] = json!(53.0))),
        rust_only("the range z-a", e(&|d| d["alphabet"] = json!("z-a"))),
        rust_only(
            "a character occurs two times in the alphabet",
            e(&|d| d["alphabet"] = json!("A-Za-z0-9a")),
        ),
        rust_only(
            "the alphabet lacks the digit 0 of base62",
            e(&|d| d["alphabet"] = json!("A-Za-z1-9")),
        ),
        rust_only(
            "5 characters are too few for a 32-bit value in base62",
            e(&|d| d["checksum"]["characters"] = json!(5)),
        ),
        rust_only(
            "no character is left for the random part",
            e(&|d| d["length"] = json!(10)),
        ),
    ]
}

#[test]
fn key_format_schema_and_reader_agree() {
    let rust = |v: &Value| KeyFormat::from_value(v).is_ok();
    check("key-format", None, &key_format_rows(), rust);
    examples_are_good("key-format", rust);
}

// ---------------------------------------------------------------- limit values

fn limit_values_rows() -> Vec<Row> {
    let day = json!([{"amount": 1, "window": "day"}]);
    vec![
        same("empty", json!({}), true),
        same("a ceiling", json!({"max_rows": 5000}), true),
        same("a ceiling of 0", json!({"max_rows": 0}), true),
        same("a budget with one item", json!({"requests": day}), true),
        same(
            "a budget with four windows",
            json!({"requests": [
            {"amount": 1, "window": "second"}, {"amount": 2, "window": "minute"},
            {"amount": 3, "window": "hour"}, {"amount": 4, "window": "day"}]}),
            true,
        ),
        same("not an object", json!([]), false),
        same("limit name in upper case", json!({"Bad": 1}), false),
        same("a negative ceiling", json!({"max_rows": -1}), false),
        same("a string value", json!({"max_rows": "5"}), false),
        same("a null value", json!({"max_rows": null}), false),
        same("a ceiling of 1.5", json!({"max_rows": 1.5}), false),
        same("a budget with no item", json!({"requests": []}), false),
        same(
            "a budget with five items",
            json!({"requests": [
            {"amount": 1, "window": "second"}, {"amount": 1, "window": "minute"}, {"amount": 1, "window": "hour"},
            {"amount": 1, "window": "day"}, {"amount": 1, "window": "day"}]}),
            false,
        ),
        same(
            "an amount of 0",
            json!({"requests": [{"amount": 0, "window": "day"}]}),
            false,
        ),
        same(
            "the window week",
            json!({"requests": [{"amount": 1, "window": "week"}]}),
            false,
        ),
        same(
            "an item without amount",
            json!({"requests": [{"window": "day"}]}),
            false,
        ),
        same(
            "an item without window",
            json!({"requests": [{"amount": 1}]}),
            false,
        ),
        same(
            "an item with an unknown member",
            json!({"requests": [{"amount": 1, "window": "day", "x": 1}]}),
            false,
        ),
        rust_only("a ceiling of 1.0", json!({"max_rows": 1.0})),
        rust_only(
            "an amount of 1.0",
            json!({"requests": [{"amount": 1.0, "window": "day"}]}),
        ),
        rust_only(
            "two items with the window minute",
            json!({"requests": [
            {"amount": 1, "window": "minute"}, {"amount": 2, "window": "minute"}]}),
        ),
    ]
}

#[test]
fn limit_values_schema_and_reader_agree() {
    let rust = |v: &Value| {
        let mut report = Report::new();
        read_limit_values(v, &JsonPath::root(), None, &mut report);
        !report.has_errors()
    };
    check("limit-values", None, &limit_values_rows(), rust);
    examples_are_good("limit-values", rust);
}

// ---------------------------------------------------------------- evaluation context

#[test]
fn request_context_schema_and_reader_agree() {
    let rows = vec![
        same("empty", json!({}), true),
        same("usage", json!({"usage": {"units": 1}}), true),
        same("match node", json!({"match": "node"}), true),
        same("match subtree", json!({"match": "subtree"}), true),
        same(
            "usage and match node",
            json!({"usage": {"units": 1}, "match": "node"}),
            true,
        ),
        same(
            "a later member of usage",
            json!({"usage": {"units": 1, "remaining": 5}}),
            true,
        ),
        same(
            "a member that this protocol does not know",
            json!({"other": true}),
            true,
        ),
        same("units 2", json!({"usage": {"units": 2}}), false),
        same("units 0", json!({"usage": {"units": 0}}), false),
        same("units -1", json!({"usage": {"units": -1}}), false),
        same("units is a string", json!({"usage": {"units": "1"}}), false),
        same("usage without units", json!({"usage": {}}), false),
        same("usage is a number", json!({"usage": 1}), false),
        same("match tree", json!({"match": "tree"}), false),
        same("match is a number", json!({"match": 1}), false),
        same(
            "usage with match subtree (6.11)",
            json!({"usage": {"units": 1}, "match": "subtree"}),
            false,
        ),
        rust_only("units 1.0", json!({"usage": {"units": 1.0}})),
    ];
    check("evaluation-context", Some("request_context"), &rows, |v| {
        RequestContext::from_context(v.as_object()).is_ok()
    });
}

#[test]
fn answer_context_schema_and_reader_agree() {
    let rows = vec![
        same("empty", json!({}), true),
        same(
            "limits",
            json!({"limits": {"max_rows": 100, "max_duration": 30}}),
            true,
        ),
        same("units 1", json!({"usage": {"units": 1}}), true),
        same("units 0", json!({"usage": {"units": 0}}), true),
        same("a reason", json!({"reason": "unknown_subject"}), true),
        same(
            "a reason that the protocol does not give",
            json!({"reason": "other"}),
            true,
        ),
        same(
            "budget_exceeded with retry_after",
            json!({"reason": "budget_exceeded", "retry_after": 12}),
            true,
        ),
        same(
            "a member that this protocol does not know",
            json!({"x": 1}),
            true,
        ),
        same("units 2", json!({"usage": {"units": 2}}), false),
        same("usage without units", json!({"usage": {}}), false),
        same(
            "a budget value in limits",
            json!({"limits": {"requests": [{"amount": 1, "window": "day"}]}}),
            false,
        ),
        same(
            "a negative ceiling",
            json!({"limits": {"max_rows": -1}}),
            false,
        ),
        same(
            "a limit name in upper case",
            json!({"limits": {"Max": 1}}),
            false,
        ),
        same("limits is an array", json!({"limits": []}), false),
        same(
            "retry_after 0",
            json!({"reason": "budget_exceeded", "retry_after": 0}),
            false,
        ),
        same(
            "retry_after is a string",
            json!({"reason": "budget_exceeded", "retry_after": "1"}),
            false,
        ),
        same(
            "retry_after 1.5",
            json!({"reason": "budget_exceeded", "retry_after": 1.5}),
            false,
        ),
        same(
            "budget_exceeded without retry_after",
            json!({"reason": "budget_exceeded"}),
            false,
        ),
        same("reason is a number", json!({"reason": 5}), false),
        rust_only("units 1.0", json!({"usage": {"units": 1.0}})),
    ];
    check("evaluation-context", Some("answer_context"), &rows, |v| {
        Decision::from_value(&json!({"decision": false, "context": v})).is_ok()
    });
}

#[test]
fn evaluation_context_root_schema_accepts_both_directions() {
    let rust = |v: &Value| {
        RequestContext::from_context(v.as_object()).is_ok()
            || Decision::from_value(&json!({"decision": false, "context": v})).is_ok()
    };
    examples_are_good("evaluation-context", rust);
}

// ---------------------------------------------------------------- options route answer

#[test]
fn options_route_answer_schema_and_reader_agree() {
    let item = json!({"id": "test1", "label": "test1", "has_children": true});
    let base = json!({"items": [item], "next": null});
    let e = |f: &dyn Fn(&mut Value)| edit(&base, |d| f(d));
    let rows = vec![
        same("one item", base.clone(), true),
        same("empty page", json!({"items": [], "next": "c"}), true),
        same(
            "an unknown member is a warning",
            e(&|d| d["total"] = json!(1)),
            true,
        ),
        same(
            "an unknown member of an item is a warning",
            e(&|d| d["items"][0]["x"] = json!(1)),
            true,
        ),
        same(
            "an id with a slash and a space",
            e(&|d| d["items"][0]["id"] = json!("a/b c")),
            true,
        ),
        same("not an object", json!([]), false),
        same("missing items", e(&|d| remove(d, "items")), false),
        same("missing next", e(&|d| remove(d, "next")), false),
        same("next is a number", e(&|d| d["next"] = json!(5)), false),
        same("items is an object", e(&|d| d["items"] = json!({})), false),
        same(
            "an item is a string",
            e(&|d| d["items"][0] = json!("x")),
            false,
        ),
        same(
            "an item without id",
            e(&|d| {
                d["items"][0].as_object_mut().unwrap().remove("id");
            }),
            false,
        ),
        same(
            "an item without label",
            e(&|d| {
                d["items"][0].as_object_mut().unwrap().remove("label");
            }),
            false,
        ),
        same(
            "an item without has_children",
            e(&|d| {
                d["items"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("has_children");
            }),
            false,
        ),
        same(
            "has_children is a string",
            e(&|d| d["items"][0]["has_children"] = json!("yes")),
            false,
        ),
        same(
            "an empty id",
            e(&|d| d["items"][0]["id"] = json!("")),
            false,
        ),
        same(
            "an id with a line end",
            e(&|d| d["items"][0]["id"] = json!("a\nb")),
            false,
        ),
        same(
            "an id of 257 characters",
            e(&|d| d["items"][0]["id"] = json!("a".repeat(257))),
            false,
        ),
    ];
    let rust = |v: &Value| options::analyze_value(v).0.is_some();
    check("options-route-answer", None, &rows, rust);
    examples_are_good("options-route-answer", rust);
}

// ---------------------------------------------------------------- data of the test PDP

fn directory_base() -> Value {
    let mut base = json!({
        "clock": {"now": 1_792_569_648},
        "services": [{"id": "datastore", "document": section_13()}],
        "subjects": [
            {"id": "alice", "grants": [
                {"action": "access", "resource": "service:datastore",
                 "limits": {"requests": [{"amount": 10, "window": "second"}]}},
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test1", "limits": {"max_rows": 1000}}]},
            {"id": "key:9b1c04e2aa71f0c3", "owner": "alice", "grants": [
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test1"}]}
        ],
        "counters": [{"subject": "alice", "limit": "requests", "window": "second", "used": 9}],
        "failures": [{"kind": "delay", "delay_ms": 250, "when": {"subject": "alice", "usage": true}, "times": 1}],
        "metadata": {"usage_max_seconds": 5}
    });
    base["services"][0]["credential_sha256"] = json!("ab".repeat(32));
    base
}

fn directory_rows() -> Vec<Row> {
    let base = directory_base();
    let e = |f: &dyn Fn(&mut Value)| edit(&base, |d| f(d));
    vec![
        same("a directory", base.clone(), true),
        same(
            "the smallest directory",
            json!({"services": [], "subjects": []}),
            true,
        ),
        same(
            "a service with no document",
            json!({"services": [{"id": "s"}], "subjects": []}),
            true,
        ),
        same(
            "the owner of a key can be absent from the file",
            e(&|d| d["subjects"][1]["owner"] = json!("nobody")),
            true,
        ),
        same(
            "a revoked key",
            e(&|d| d["subjects"][1]["state"] = json!("revoked")),
            true,
        ),
        same("not an object", json!([]), false),
        same(
            "unknown member at the top",
            e(&|d| d["extra"] = json!(1)),
            false,
        ),
        same("missing services", e(&|d| remove(d, "services")), false),
        same("missing subjects", e(&|d| remove(d, "subjects")), false),
        same("clock without now", e(&|d| d["clock"] = json!({})), false),
        same(
            "clock with a negative value",
            e(&|d| d["clock"]["now"] = json!(-1)),
            false,
        ),
        same(
            "metadata with 0",
            e(&|d| d["metadata"]["usage_max_seconds"] = json!(0)),
            false,
        ),
        same(
            "metadata with an unknown member",
            e(&|d| d["metadata"]["x"] = json!(1)),
            false,
        ),
        same(
            "service without id",
            e(&|d| {
                d["services"][0].as_object_mut().unwrap().remove("id");
            }),
            false,
        ),
        same(
            "credential digest in upper case",
            e(&|d| d["services"][0]["credential_sha256"] = json!("AB".repeat(32))),
            false,
        ),
        same(
            "credential digest too short",
            e(&|d| d["services"][0]["credential_sha256"] = json!("ab")),
            false,
        ),
        same(
            "a bad action document inside the data",
            e(&|d| d["services"][0]["document"]["limits"][0]["min"] = json!(1)),
            false,
        ),
        same(
            "a person with an owner",
            e(&|d| d["subjects"][0]["owner"] = json!("bob")),
            false,
        ),
        same(
            "a person with a state",
            e(&|d| d["subjects"][0]["state"] = json!("revoked")),
            false,
        ),
        same(
            "a key without an owner",
            e(&|d| {
                d["subjects"][1].as_object_mut().unwrap().remove("owner");
            }),
            false,
        ),
        same(
            "an owner that is a key",
            e(&|d| d["subjects"][1]["owner"] = json!("key:abc")),
            false,
        ),
        same(
            "a key with the state deleted",
            e(&|d| d["subjects"][1]["state"] = json!("deleted")),
            false,
        ),
        same(
            "an id with an unknown prefix",
            e(&|d| d["subjects"][1]["id"] = json!("svc:abc")),
            false,
        ),
        same(
            "a key with a local part of 65 characters",
            e(&|d| d["subjects"][1]["id"] = json!(format!("key:{}", "a".repeat(65)))),
            false,
        ),
        same(
            "a grant with an unknown member",
            e(&|d| d["subjects"][0]["grants"][0]["x"] = json!(1)),
            false,
        ),
        same(
            "a grant action in upper case",
            e(&|d| d["subjects"][0]["grants"][1]["action"] = json!("Data.read")),
            false,
        ),
        same(
            "a grant resource that is not a path of the service",
            e(&|d| d["subjects"][0]["grants"][1]["resource"] = json!("host:prod")),
            false,
        ),
        same(
            "a grant limit that is a string",
            e(&|d| d["subjects"][0]["grants"][1]["limits"]["max_rows"] = json!("5")),
            false,
        ),
        same(
            "a counter with the window week",
            e(&|d| d["counters"][0]["window"] = json!("week")),
            false,
        ),
        same(
            "a counter without used",
            e(&|d| {
                d["counters"][0].as_object_mut().unwrap().remove("used");
            }),
            false,
        ),
        same(
            "a delay without delay_ms",
            e(&|d| {
                d["failures"][0].as_object_mut().unwrap().remove("delay_ms");
            }),
            false,
        ),
        same(
            "error_503 with delay_ms",
            e(&|d| d["failures"][0]["kind"] = json!("error_503")),
            false,
        ),
        same(
            "a failure of an unknown kind",
            e(&|d| d["failures"][0]["kind"] = json!("boom")),
            false,
        ),
        same(
            "a failure that applies 0 times",
            e(&|d| d["failures"][0]["times"] = json!(0)),
            false,
        ),
        same(
            "a failure with an unknown endpoint",
            e(&|d| d["failures"][0]["when"]["endpoint"] = json!("tokens")),
            false,
        ),
        rust_only(
            "a grant on a service that the file does not have",
            e(&|d| d["subjects"][0]["grants"][1]["resource"] = json!("service:other/host:prod")),
        ),
        rust_only(
            "a grant of an action that the document does not declare",
            e(&|d| d["subjects"][0]["grants"][1]["action"] = json!("data.erase")),
        ),
        rust_only(
            "a grant of an action on a type that the action does not allow",
            e(&|d| {
                d["services"][0]["document"]["actions"][0]["resource_types"] = json!(["service"]);
            }),
        ),
        rust_only(
            "a counter for a subject that the file does not have",
            e(&|d| d["counters"][0]["subject"] = json!("ghost")),
        ),
        rust_only(
            "the id of the service differs from the member server",
            e(&|d| d["services"][0]["id"] = json!("other")),
        ),
        rust_only(
            "two subjects have the same id",
            e(&|d| {
                d["subjects"][1] = d["subjects"][0].clone();
            }),
        ),
        rust_only(
            "a grant on a node that does not follow the tree of types",
            e(&|d| {
                d["subjects"][0]["grants"][1]["resource"] =
                    json!("service:datastore/database:test1")
            }),
        ),
    ]
}

#[test]
fn fake_pdp_data_schema_and_reader_agree() {
    let rust = |v: &Value| Directory::from_value(v).is_ok();
    check("fake-pdp-data", None, &directory_rows(), rust);
    examples_are_good("fake-pdp-data", rust);
}
