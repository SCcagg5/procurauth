//! The table of keys, and the effective configuration.
//!
//! The table lists each option of the command line and each key of the
//! profile, with its type or range and its default. The README holds the same
//! table, and a test compares the two. The effective configuration shows the
//! value that applies for each key, and where the value comes from. A secret
//! never shows: a key that names a secret file shows the path of the file only.

use std::path::Path;

use procurauth_core::finding::show;
use serde_json::Value;

use crate::cli::{Cli, Format};
use crate::model::Role;
use crate::profile::{
    DEFAULT_CASE_SECONDS, DEFAULT_MAX_QUESTIONS, DEFAULT_REQUEST_SECONDS, DEFAULT_SETTLE_MS,
};

/// One row of the table of keys.
pub(crate) struct Key {
    /// The name. A name in angle brackets stands for any member name. `[]` stands for any array item.
    pub(crate) name: &'static str,
    /// Where the value comes from: `flag` or `profile`.
    pub(crate) source: &'static str,
    /// The type or the range.
    pub(crate) value: &'static str,
    /// The default, or a word that says that the key has none.
    pub(crate) default: &'static str,
    /// The meaning.
    pub(crate) meaning: &'static str,
}

const NONE: &str = "none";
const REQUIRED: &str = "none, mandatory";

macro_rules! key {
    ($name:expr, $source:expr, $value:expr, $default:expr, $meaning:expr) => {
        Key {
            name: $name,
            source: $source,
            value: $value,
            default: $default,
            meaning: $meaning,
        }
    };
}

/// The table of keys. The README holds the same table, and a test compares them.
pub(crate) const KEYS: &[Key] = &[
    key!(
        "--role",
        "flag",
        "`pep`, `pdp` or `edge`",
        REQUIRED,
        "The implementation under test."
    ),
    key!(
        "--profile",
        "flag",
        "path",
        REQUIRED,
        "The profile of the target."
    ),
    key!(
        "--url",
        "flag",
        "http URL with no path",
        "none, see the role",
        "The target. A PEP and an edge need it. A PDP needs it unless the profile starts fake-pdp."
    ),
    key!(
        "--cases",
        "flag",
        "ids with commas",
        "none, all the cases of the role",
        "Run only these cases."
    ),
    key!(
        "--series",
        "flag",
        "`U`, `D` or `E`",
        "none, the series of the role",
        "Run only this series. It must fit the role."
    ),
    key!(
        "--format",
        "flag",
        "`text` or `json`",
        "text",
        "The form of the result."
    ),
    key!(
        "--cases-dir",
        "flag",
        "path",
        "none, the copy in the program",
        "Read the cases from a directory with the layout of `conformance/`."
    ),
    key!(
        "--print-config",
        "flag",
        "no value",
        "off",
        "Check the profile and the files, print the values that apply, and exit with 0."
    ),
    key!(
        "timeouts.request_seconds",
        "profile",
        "whole number from 1 to 600",
        "10",
        "The time for one request to the target."
    ),
    key!(
        "timeouts.case_seconds",
        "profile",
        "whole number from 1 to 3600",
        "60",
        "The time for one case. A case that takes longer fails."
    ),
    key!(
        "timeouts.settle_ms",
        "profile",
        "whole number from 0 to 10000",
        "25",
        "The wait before the runner counts the questions of the PDP and the requests of the upstream."
    ),
    key!(
        "pep.service",
        "profile",
        "id of 1 to 256 bytes",
        REQUIRED,
        "The id of the service. It is the variable `service` and the claim `aud`."
    ),
    key!(
        "pep.token.header",
        "profile",
        "header name",
        REQUIRED,
        "The header of the identity token. It is the variable `token_header`."
    ),
    key!(
        "pep.token.iss",
        "profile",
        "text",
        REQUIRED,
        "The issuer that the service expects."
    ),
    key!(
        "pep.token.max_age_seconds",
        "profile",
        "whole number from 1 to 31536000",
        REQUIRED,
        "The longest life of a token that the service accepts."
    ),
    key!(
        "pep.token.skew_seconds",
        "profile",
        "whole number from 0 to 86400",
        REQUIRED,
        "The clock skew of the service."
    ),
    key!(
        "pep.token.keys[].alg",
        "profile",
        "`Ed25519` or `ES256`",
        REQUIRED,
        "The algorithm of the key. Each algorithm occurs one time."
    ),
    key!(
        "pep.token.keys[].kid",
        "profile",
        "text",
        NONE,
        "The header `kid` of the tokens that the key signs."
    ),
    key!(
        "pep.token.keys[].file",
        "profile",
        "path",
        REQUIRED,
        "A file with the private key, in PKCS#8 PEM form. The key is a secret."
    ),
    key!(
        "pep.pdp.listen",
        "profile",
        "ADDRESS:PORT",
        REQUIRED,
        "The address of the test PDP. The service calls it."
    ),
    key!(
        "pep.pdp.credential_file",
        "profile",
        "path",
        "none, no credential",
        "A file with the credential that the service sends to the PDP. The credential is a secret."
    ),
    key!(
        "pep.answer_cache",
        "profile",
        "boolean",
        "false",
        "True when the PEP keeps answers. A false value skips the cases that need a cache."
    ),
    key!(
        "pep.reset.method",
        "profile",
        "HTTP method",
        REQUIRED,
        "The method of the request that clears the state of the service before each case."
    ),
    key!(
        "pep.reset.path",
        "profile",
        "path",
        REQUIRED,
        "The path of that request."
    ),
    key!(
        "pep.reset.headers.<name>",
        "profile",
        "text",
        NONE,
        "A header of that request."
    ),
    key!(
        "pep.options_type",
        "profile",
        "text",
        "none, no options route",
        "The type of the nodes at the first level of the options route."
    ),
    key!(
        "pep.mcp.path",
        "profile",
        "path",
        REQUIRED,
        "The path of the MCP endpoint. It is the variable `mcp_path`."
    ),
    key!(
        "pep.mcp.session_budget",
        "profile",
        "boolean",
        "false",
        "True when the action `mcp.session` lists a budget."
    ),
    key!(
        "pep.operations.<operation>.method",
        "profile",
        "HTTP method",
        "see the operation",
        "The method of the operation."
    ),
    key!(
        "pep.operations.<operation>.path",
        "profile",
        "path template",
        "see the operation",
        "The path of the operation. It can hold variables."
    ),
    key!(
        "pep.operations.<operation>.headers.<name>",
        "profile",
        "text",
        NONE,
        "A header of the operation."
    ),
    key!(
        "pep.operations.<operation>.body",
        "profile",
        "JSON",
        NONE,
        "The body template, as JSON."
    ),
    key!(
        "pep.operations.<operation>.body_text",
        "profile",
        "text",
        NONE,
        "The body template, as text. Do not give it with `body`."
    ),
    key!(
        "pep.operations.<operation>.action",
        "profile",
        "text",
        "see the operation",
        "The variable `action`."
    ),
    key!(
        "pep.operations.<operation>.resource_type",
        "profile",
        "text",
        "see the operation",
        "The variable `resource_type`."
    ),
    key!(
        "pep.operations.<operation>.resource_id",
        "profile",
        "text",
        "see the operation",
        "The variable `resource_id`."
    ),
    key!(
        "pep.operations.<operation>.ancestors",
        "profile",
        "array of objects with `type` and `id`",
        "see the operation",
        "The variable `ancestors`."
    ),
    key!(
        "pep.operations.<operation>.tool",
        "profile",
        "text",
        "see the operation",
        "The variable `tool`."
    ),
    key!(
        "pep.operations.<operation>.ceiling",
        "profile",
        "text",
        "see the operation",
        "The variable `ceiling`."
    ),
    key!(
        "pep.operations.<operation>.ceiling_value",
        "profile",
        "whole number",
        "see the operation",
        "The variable `ceiling_value`."
    ),
    key!(
        "pep.operations.<operation>.arguments",
        "profile",
        "JSON",
        "none, an empty object",
        "The arguments of the tool of an MCP call."
    ),
    key!(
        "pep.operations.<operation>.capture.<name>",
        "profile",
        "JSON Pointer",
        NONE,
        "A name for a member of the JSON answer to the step before. The templates of the operation read it as a variable."
    ),
    key!(
        "pdp.spawn_fake_pdp",
        "profile",
        "boolean",
        "false",
        "True to start fake-pdp in the process, with the directory of each case. Do not give it with `--url`."
    ),
    key!(
        "pdp.credential_file",
        "profile",
        "path",
        "none, no credential",
        "A file with the credential that the PDP asks for. The credential is a secret."
    ),
    key!(
        "pdp.directory_check.mode",
        "profile",
        "`control_questions` or `none`",
        "control_questions",
        "How the runner proves that the PDP holds the directory of a case."
    ),
    key!(
        "pdp.directory_check.max_questions",
        "profile",
        "whole number from 1 to 10000",
        "100",
        "The most control questions for one directory."
    ),
    key!(
        "pdp.load.url",
        "profile",
        "http URL",
        REQUIRED,
        "The URL that loads the data of a case in the PDP under test."
    ),
    key!(
        "pdp.load.method",
        "profile",
        "`PUT` or `POST`",
        "PUT",
        "The method of the load request."
    ),
    key!(
        "pdp.reset_url",
        "profile",
        "http URL",
        "none, the counters cannot reset",
        "A URL that the runner posts to before each case, to put the counters back to their first values."
    ),
    key!(
        "pdp.clock_admin_url",
        "profile",
        "http URL",
        "none, the clock cannot move",
        "A URL that the runner posts to, with the body `{\"set\": T}`, to set the clock of the PDP."
    ),
    key!(
        "edge.service",
        "profile",
        "id of 1 to 256 bytes",
        REQUIRED,
        "The id of the service behind the edge. It is the variable `service`."
    ),
    key!(
        "edge.token_header",
        "profile",
        "header name",
        REQUIRED,
        "The header of the identity token. It is the variable `token_header`."
    ),
    key!(
        "edge.trust.iss",
        "profile",
        "text",
        REQUIRED,
        "The issuer that the edge writes in the tokens."
    ),
    key!(
        "edge.trust.max_age_seconds",
        "profile",
        "whole number from 1 to 31536000",
        REQUIRED,
        "The longest life of a token."
    ),
    key!(
        "edge.trust.skew_seconds",
        "profile",
        "whole number from 0 to 86400",
        REQUIRED,
        "The clock skew."
    ),
    key!(
        "edge.trust.jwks_file",
        "profile",
        "path",
        "none",
        "A JWK Set with the public keys of the edge. Give this key or `pem_keys`."
    ),
    key!(
        "edge.trust.pem_keys[].file",
        "profile",
        "path",
        REQUIRED,
        "A public key in PEM form."
    ),
    key!(
        "edge.trust.pem_keys[].kid",
        "profile",
        "text",
        NONE,
        "The `kid` of that key."
    ),
    key!(
        "edge.keys.valid.text_file",
        "profile",
        "path",
        REQUIRED,
        "A file with the text of a key that the edge accepts. The text is a secret."
    ),
    key!(
        "edge.keys.valid.subject",
        "profile",
        "text",
        REQUIRED,
        "The subject id of that key."
    ),
    key!(
        "edge.keys.valid.owner",
        "profile",
        "text",
        REQUIRED,
        "The owner of that key."
    ),
    key!(
        "edge.keys.no_access.text_file",
        "profile",
        "path",
        REQUIRED,
        "A file with the text of a key that the edge knows and whose subject has no `access`. The text is a secret."
    ),
    key!(
        "edge.keys.unknown.text_file",
        "profile",
        "path",
        REQUIRED,
        "A file with the text of a key that the edge does not know. The text is a secret."
    ),
    key!(
        "edge.upstream.listen",
        "profile",
        "ADDRESS:PORT",
        REQUIRED,
        "The address of the service behind the edge. The edge sends its requests there."
    ),
    key!(
        "edge.pdp.listen",
        "profile",
        "ADDRESS:PORT",
        REQUIRED,
        "The address of the PDP that the edge calls."
    ),
    key!(
        "edge.pdp.directory",
        "profile",
        "name of a directory file",
        "none, give this key or `directory_file`",
        "The data of the PDP, from the directory files of the cases."
    ),
    key!(
        "edge.pdp.directory_file",
        "profile",
        "path",
        "none, give this key or `directory`",
        "The data of the PDP, from a file."
    ),
    key!(
        "edge.pdp.credential_file",
        "profile",
        "path",
        "none, no credential",
        "A file with the credential that the edge sends to the PDP. The credential is a secret."
    ),
    key!(
        "edge.mcp_path",
        "profile",
        "path",
        "none, no MCP endpoint",
        "The path of the MCP endpoint. It is the variable `mcp_path`."
    ),
    key!(
        "edge.token_cache",
        "profile",
        "boolean",
        "false",
        "True when the edge keeps identity tokens."
    ),
];

/// The table of keys as a Markdown table. The README holds this text.
pub(crate) fn reference_table() -> String {
    let mut out = String::from(
        "| Key | Source | Value | Default | Meaning |\n| --- | --- | --- | --- | --- |\n",
    );
    for key in KEYS {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            key.name, key.source, key.value, key.default, key.meaning
        ));
    }
    out
}

/// One line of the effective configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfigLine {
    /// The key.
    pub(crate) key: String,
    /// The value that applies. A secret shows as `<hidden>`.
    pub(crate) value: String,
    /// Where the value comes from: `flag`, `default`, `profile` or `file:PATH`.
    pub(crate) source: String,
}

impl ConfigLine {
    fn new(key: impl Into<String>, value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            source: source.into(),
        }
    }

    /// The text of the line.
    pub(crate) fn text(&self) -> String {
        format!("{} = {} ({})", self.key, self.value, self.source)
    }
}

/// True when the key names a file that holds a secret.
fn is_secret_file(path: &str) -> bool {
    let last = path.rsplit('.').next().unwrap_or(path);
    matches!(last, "credential_file" | "text_file")
        || (path.starts_with("pep.token.keys[") && last == "file")
}

/// True when the key names a file or a directory file: the path is shown with its source.
fn is_file(path: &str) -> bool {
    let last = path.rsplit('.').next().unwrap_or(path);
    last.ends_with("_file") || last == "file"
}

fn leaves(value: &Value, path: &str, base: &Path, out: &mut Vec<ConfigLine>) {
    match value {
        Value::Object(map) => {
            // The body templates and the operations are shown as one value each.
            if path.ends_with(".body")
                || path.ends_with(".arguments")
                || path.ends_with(".ancestors")
            {
                out.push(ConfigLine::new(path, show(value), "profile"));
                return;
            }
            for (name, item) in map {
                let next = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                leaves(item, &next, base, out);
            }
        }
        Value::Array(items) => {
            if path.ends_with(".body")
                || path.ends_with(".arguments")
                || path.ends_with(".ancestors")
            {
                out.push(ConfigLine::new(path, show(value), "profile"));
                return;
            }
            for (index, item) in items.iter().enumerate() {
                leaves(item, &format!("{path}[{index}]"), base, out);
            }
        }
        other => {
            let generic = path.replace(|c: char| c.is_ascii_digit(), "");
            let _ = generic;
            if is_file(path) {
                let text = other.as_str().unwrap_or_default();
                let resolved = base.join(text).display().to_string();
                if is_secret_file(path) {
                    out.push(ConfigLine::new(
                        path,
                        "<hidden>",
                        format!("file:{resolved}"),
                    ));
                } else {
                    out.push(ConfigLine::new(path, resolved, "profile"));
                }
            } else {
                out.push(ConfigLine::new(path, show(other), "profile"));
            }
        }
    }
}

/// The effective configuration: the options, and each key of the profile with its source.
/// The keys with a default that the profile does not give show with the source `default`.
pub(crate) fn effective(cli: &Cli, role: Role, raw: &Value, base: &Path) -> Vec<ConfigLine> {
    let mut out = Vec::new();
    out.push(ConfigLine::new("--role", role.name(), "flag"));
    out.push(ConfigLine::new(
        "--profile",
        cli.profile.display().to_string(),
        "flag",
    ));
    out.push(match &cli.url {
        Some(url) => ConfigLine::new("--url", url.clone(), "flag"),
        None => ConfigLine::new("--url", "none", "default"),
    });
    out.push(if cli.cases.is_empty() {
        ConfigLine::new("--cases", "all", "default")
    } else {
        ConfigLine::new("--cases", cli.cases.join(","), "flag")
    });
    out.push(match cli.series {
        Some(_) => ConfigLine::new("--series", role.series().to_string(), "flag"),
        None => ConfigLine::new("--series", role.series().to_string(), "default"),
    });
    out.push(ConfigLine::new(
        "--format",
        match cli.format {
            Format::Text => "text",
            Format::Json => "json",
        },
        if cli.format == Format::Text {
            "default"
        } else {
            "flag"
        },
    ));
    out.push(match &cli.cases_dir {
        Some(dir) => ConfigLine::new("--cases-dir", dir.display().to_string(), "flag"),
        None => ConfigLine::new("--cases-dir", "built in", "default"),
    });
    out.push(ConfigLine::new(
        "--print-config",
        if cli.print_config { "on" } else { "off" },
        if cli.print_config { "flag" } else { "default" },
    ));
    let mut profile = Vec::new();
    if let Some(timeouts) = raw.get("timeouts") {
        leaves(timeouts, "timeouts", base, &mut profile);
    }
    if let Some(section) = raw.get(role.name()) {
        leaves(section, role.name(), base, &mut profile);
    }
    let has = |key: &str| profile.iter().any(|l| l.key == key);
    let mut defaults: Vec<ConfigLine> = Vec::new();
    for (key, value) in [
        (
            "timeouts.request_seconds",
            DEFAULT_REQUEST_SECONDS.to_string(),
        ),
        ("timeouts.case_seconds", DEFAULT_CASE_SECONDS.to_string()),
        ("timeouts.settle_ms", DEFAULT_SETTLE_MS.to_string()),
    ] {
        if !has(key) {
            defaults.push(ConfigLine::new(key, value, "default"));
        }
    }
    let section = raw.get(role.name());
    let section_has = |pointer: &str| section.and_then(|s| s.pointer(pointer)).is_some();
    match role {
        Role::Pep => {
            if !has("pep.answer_cache") {
                defaults.push(ConfigLine::new("pep.answer_cache", "false", "default"));
            }
            if section_has("/mcp") && !has("pep.mcp.session_budget") {
                defaults.push(ConfigLine::new(
                    "pep.mcp.session_budget",
                    "false",
                    "default",
                ));
            }
        }
        Role::Pdp => {
            if !has("pdp.spawn_fake_pdp") {
                defaults.push(ConfigLine::new("pdp.spawn_fake_pdp", "false", "default"));
            }
            if !has("pdp.directory_check.mode") {
                defaults.push(ConfigLine::new(
                    "pdp.directory_check.mode",
                    "control_questions",
                    "default",
                ));
            }
            if !has("pdp.directory_check.max_questions") {
                defaults.push(ConfigLine::new(
                    "pdp.directory_check.max_questions",
                    DEFAULT_MAX_QUESTIONS.to_string(),
                    "default",
                ));
            }
            if section_has("/load") && !has("pdp.load.method") {
                defaults.push(ConfigLine::new("pdp.load.method", "PUT", "default"));
            }
        }
        Role::Edge => {
            if !has("edge.token_cache") {
                defaults.push(ConfigLine::new("edge.token_cache", "false", "default"));
            }
        }
    }
    profile.extend(defaults);
    profile.sort_by(|a, b| a.key.cmp(&b.key));
    out.extend(profile);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_file_shows_its_path_and_never_its_content() {
        let raw = json!({"pdp": {"credential_file": "cred.txt", "spawn_fake_pdp": true}});
        let cli = <Cli as clap::Parser>::parse_from([
            "access-conformance",
            "--role",
            "pdp",
            "--profile",
            "p.json",
        ]);
        let lines = effective(&cli, Role::Pdp, &raw, Path::new("/base"));
        let line = lines
            .iter()
            .find(|l| l.key == "pdp.credential_file")
            .unwrap();
        assert_eq!(line.value, "<hidden>");
        assert_eq!(line.source, "file:/base/cred.txt");
    }

    #[test]
    fn the_defaults_show_with_the_source_default() {
        let raw = json!({"pdp": {"spawn_fake_pdp": true}});
        let cli = <Cli as clap::Parser>::parse_from([
            "access-conformance",
            "--role",
            "pdp",
            "--profile",
            "p.json",
        ]);
        let lines = effective(&cli, Role::Pdp, &raw, Path::new("/base"));
        let line = lines
            .iter()
            .find(|l| l.key == "timeouts.request_seconds")
            .unwrap();
        assert_eq!(line.text(), "timeouts.request_seconds = 10 (default)");
        let line = lines
            .iter()
            .find(|l| l.key == "pdp.spawn_fake_pdp")
            .unwrap();
        assert_eq!(line.source, "profile");
    }

    #[test]
    fn the_table_has_one_row_for_each_key_and_no_duplicate() {
        let mut names: Vec<&str> = KEYS.iter().map(|k| k.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
