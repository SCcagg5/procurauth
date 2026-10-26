//! The check of a token against the configuration of a service (protocol 9.2 to 9.4).
//!
//! The core runs 13 checks in a fixed order. This module reads the inputs,
//! runs the checks and writes the result as text or as JSON.

use procurauth_core::identity::{Check, Inspection, Outcome, inspect};
use serde_json::{Value, json};

use crate::cli::{CheckArgs, Format};
use crate::config::Config;
use crate::files::{read_text, strip_line_end};
use crate::make::render_json;
use crate::{EXIT_FINDING, EXIT_OK, Fault, Io, emit};

/// The signature part that stands for an empty signature. It is one zero byte.
const PLACEHOLDER_SIGNATURE: &str = "AA";

/// Run the checks of 9.4 on a token. The caller gives the time.
///
/// A token with an empty third part, as `alg: none` makes it, is not a
/// structure error here. The function gives the core a signature that no key
/// accepts. Thus the failure shows at the check `alg` or `signature`, which
/// is the paragraph that the token breaks (9.2).
pub fn check_token(token: &str, config: &Config, now: u64) -> Inspection {
    let unsigned = token
        .strip_suffix('.')
        .filter(|rest| rest.matches('.').count() == 1);
    match unsigned {
        Some(rest) => inspect(
            &format!("{rest}.{PLACEHOLDER_SIGNATURE}"),
            &config.keys,
            &config.policy,
            now,
        ),
        None => inspect(token, &config.keys, &config.policy, now),
    }
}

fn status_word(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "ok",
        Outcome::Fail => "fail",
        Outcome::NotRun => "skip",
    }
}

fn text_line(check: &Check) -> String {
    let name = check.name.as_str();
    let status = status_word(check.outcome);
    let line = match check.outcome {
        Outcome::Pass => format!("{name:<10} {status:<4} {}", check.detail),
        Outcome::Fail => format!(
            "{name:<10} {status:<4} {} (rule {})",
            check.detail,
            check.name.rule()
        ),
        Outcome::NotRun => format!("{name:<10} {status}"),
    };
    format!("{}\n", line.trim_end())
}

/// The result as text: one line for each check.
pub fn render_text(inspection: &Inspection) -> String {
    inspection.checks.iter().map(text_line).collect()
}

/// The result as JSON.
pub fn render_json_result(inspection: &Inspection, now: u64) -> String {
    let checks: Vec<Value> = inspection
        .checks
        .iter()
        .map(|check| {
            json!({
                "name": check.name.as_str(),
                "rule": check.name.rule(),
                "outcome": check.outcome,
                "detail": check.detail,
            })
        })
        .collect();
    let document = json!({
        "result": if inspection.passed() { "pass" } else { "fail" },
        "now": now,
        "checks": checks,
        "claims": inspection.claims.as_ref().map(procurauth_core::identity::Claims::to_value),
    });
    render_json(&document)
}

/// The configuration that applies, as text: one line for each value.
pub fn render_config_text(config: &Config) -> String {
    let mut text = String::new();
    let width = 16;
    for (name, value) in [
        ("token_header", config.token_header.clone()),
        ("iss", config.policy.issuer.clone()),
        ("service_id", config.policy.service_id.clone()),
        ("max_age_seconds", config.policy.max_age_seconds.to_string()),
        ("skew_seconds", config.policy.skew_seconds.to_string()),
    ] {
        text.push_str(&format!("{name:<width$}{value}  (file)\n"));
    }
    for key in &config.key_info {
        let kid = key.kid.as_deref().unwrap_or("none");
        text.push_str(&format!(
            "{:<width$}kid {kid}, alg {}  (file:{})\n",
            "key",
            key.algorithm.as_str(),
            key.source
        ));
    }
    text
}

fn read_config(args: &CheckArgs) -> Result<Config, Fault> {
    let text = read_text(&args.config, None)?;
    Config::parse(&text).map_err(|errors| {
        Fault::many(
            errors
                .iter()
                .map(|error| format!("Configuration `{}`: {error}", args.config.display()))
                .collect(),
        )
    })
}

/// Run the subcommand `check`.
///
/// # Errors
/// Returns a fault for a configuration or a token file that cannot be read,
/// and for a configuration that is not valid.
pub fn run_check(args: &CheckArgs, io: &mut Io<'_>) -> Result<u8, Fault> {
    let config = read_config(args)?;
    if args.print_config {
        let text = match args.format {
            Format::Text => render_config_text(&config),
            Format::Json => render_json(&config.effective()),
        };
        emit(io.stdout, &text)?;
        return Ok(EXIT_OK);
    }
    let Some(token_path) = &args.token else {
        return Err(Fault::new("The argument `TOKEN` is absent."));
    };
    let raw = read_text(token_path, Some(&mut *io.stdin))?;
    let token = strip_line_end(&raw);
    let now = match args.now {
        Some(now) => now,
        None => (io.clock)().map_err(Fault::new)?,
    };
    let inspection = check_token(token, &config, now);
    let text = match args.format {
        Format::Text => render_text(&inspection),
        Format::Json => render_json_result(&inspection, now),
    };
    emit(io.stdout, &text)?;
    Ok(if inspection.passed() {
        EXIT_OK
    } else {
        EXIT_FINDING
    })
}
