//! The setup of a run: read the files of the profile, start the test listeners,
//! and make the variables. Each problem stops the program before the first request.

use std::path::Path;
use std::time::Instant;

use fake_pdp::{Credential, Options as FakeOptions, Server as FakeServer};
use procurauth_core::json::parse_str;
use serde_json::{Value, json};

use crate::catalog::Catalog;
use crate::exec;
use crate::exec::{Capabilities, EdgeEnv, Endpoints, Env, PdpEnv, PepEnv, Runner};
use crate::http::{Authority, ClientRequest, HttpUrl, connect, send};
use crate::profile::{DirectorySource, EdgeProfile, PdpProfile, PepProfile, Profile};
use crate::testpdp::TestPdp;
use crate::tokens::{Signer, Verifier, read_file, read_secret};
use crate::upstream::Upstream;
use crate::vars::Vars;

/// The target of a run, from `--url`.
pub(crate) fn parse_target(text: &str) -> Result<Authority, String> {
    let url = HttpUrl::parse(text)
        .map_err(|why| format!("Option `--url`: expected an http URL, found \"{text}\": {why}."))?;
    if url.target != "/" {
        return Err(format!(
            "Option `--url`: expected an http URL with no path, found \"{text}\". The cases write their own paths."
        ));
    }
    Ok(url.authority)
}

fn join(errors: Vec<String>) -> Vec<String> {
    errors
}

/// Build the runner of a PEP run.
pub(crate) fn pep_runner<'a>(
    profile: &Profile,
    pep: &PepProfile,
    target: Authority,
    catalog: &'a Catalog,
    clock: &'a dyn Fn() -> u64,
) -> Result<Runner<'a>, Vec<String>> {
    let signer = Signer::load(&pep.token, &pep.service, "pep.token")?;
    let credential = match &pep.pdp.credential_file {
        Some(file) => Some(read_secret("pep.pdp.credential_file", file).map_err(|e| vec![e])?),
        None => None,
    };
    let pdp = TestPdp::start(pep.pdp.listen, credential).map_err(|e| vec![e])?;
    let mut global = Vars::new();
    global.set("service", json!(pep.service));
    global.set("token_header", json!(pep.token.header));
    if let Some(mcp) = &pep.mcp {
        global.set("mcp_path", json!(mcp.path));
    }
    if let Some(kind) = &pep.options_type {
        global.set("options_type", json!(kind));
    }
    Ok(Runner {
        catalog,
        timeouts: profile.timeouts.clone(),
        target: Some(target),
        now: clock,
        caps: Capabilities::for_pep(pep),
        global,
        notes: std::sync::Mutex::default(),
        env: Env::Pep(PepEnv {
            profile: pep.clone(),
            signer,
            pdp,
        }),
    })
}

fn directory_value(edge: &EdgeProfile, catalog: &Catalog) -> Result<Value, String> {
    match &edge.pdp.directory {
        DirectorySource::Named(name) => catalog.directory(name).cloned().ok_or_else(|| {
            format!("Key `edge.pdp.directory`: expected the name of a directory file of the cases, found \"{name}\".")
        }),
        DirectorySource::File(path) => {
            let text = read_file("edge.pdp.directory_file", path)?;
            parse_str(&text).map_err(|e| {
                format!(
                    "Key `edge.pdp.directory_file`: expected JSON in `{}`: {e}.",
                    path.display()
                )
            })
        }
    }
}

/// Build the runner of an edge run.
pub(crate) fn edge_runner<'a>(
    profile: &Profile,
    edge: &EdgeProfile,
    target: Authority,
    catalog: &'a Catalog,
    clock: &'a dyn Fn() -> u64,
) -> Result<Runner<'a>, Vec<String>> {
    let verifier = Verifier::load(&edge.trust, &edge.service)?;
    let mut errors = Vec::new();
    let mut secret = |key: &str, path: &Path| match read_secret(key, path) {
        Ok(text) => text,
        Err(e) => {
            errors.push(e);
            String::new()
        }
    };
    let valid = secret("edge.keys.valid.text_file", &edge.valid_key.text_file);
    let no_access = secret("edge.keys.no_access.text_file", &edge.no_access_key_file);
    let unknown = secret("edge.keys.unknown.text_file", &edge.unknown_key_file);
    let credential = match &edge.pdp.credential_file {
        Some(file) => match read_secret("edge.pdp.credential_file", file) {
            Ok(text) => Some(text),
            Err(e) => {
                errors.push(e);
                None
            }
        },
        None => None,
    };
    let directory = match directory_value(edge, catalog) {
        Ok(value) => Some(value),
        Err(e) => {
            errors.push(e);
            None
        }
    };
    if !errors.is_empty() {
        return Err(join(errors));
    }
    let mut options = FakeOptions::default();
    if let Some(text) = &credential {
        options.credential =
            Some(Credential::from_file_text(text, "the profile").map_err(|e| vec![e.to_string()])?);
    }
    let fake = FakeServer::from_value(&directory.unwrap_or(Value::Null), options)
        .map_err(|e| vec![format!("Key `edge.pdp`: the directory is not valid: {e}")])?
        .start(edge.pdp.listen)
        .map_err(|e| vec![format!("Key `edge.pdp.listen`: {e}")])?;
    let upstream = Upstream::start(edge.upstream_listen)
        .map_err(|e| vec![format!("Key `edge.upstream.listen`: {e}")])?;
    let mut global = Vars::new();
    global.set("service", json!(edge.service));
    global.set("token_header", json!(edge.token_header));
    if let Some(path) = &edge.mcp_path {
        global.set("mcp_path", json!(path));
    }
    global.set("valid_key_text", json!(valid));
    global.set("valid_key_subject", json!(edge.valid_key.subject));
    global.set("valid_key_owner", json!(edge.valid_key.owner));
    global.set("no_access_key_text", json!(no_access));
    global.set("unknown_key_text", json!(unknown));
    let caps = Capabilities::for_edge(edge, verifier.key_count());
    Ok(Runner {
        catalog,
        timeouts: profile.timeouts.clone(),
        target: Some(target),
        now: clock,
        caps,
        global,
        notes: std::sync::Mutex::default(),
        env: Env::Edge(EdgeEnv {
            profile: edge.clone(),
            verifier,
            upstream,
            pdp: fake,
        }),
    })
}

/// Build the runner of a PDP run.
pub(crate) fn pdp_runner<'a>(
    profile: &Profile,
    pdp: &PdpProfile,
    target: Option<Authority>,
    catalog: &'a Catalog,
    clock: &'a dyn Fn() -> u64,
) -> Result<Runner<'a>, Vec<String>> {
    let credential = match &pdp.credential_file {
        Some(file) => Some(read_secret("pdp.credential_file", file).map_err(|e| vec![e])?),
        None => None,
    };
    Ok(Runner {
        catalog,
        timeouts: profile.timeouts.clone(),
        target: target.clone(),
        now: clock,
        caps: Capabilities::for_pdp(),
        global: Vars::new(),
        notes: std::sync::Mutex::default(),
        env: Env::Pdp(PdpEnv {
            profile: pdp.clone(),
            credential,
            external: target.map(|a| Endpoints::on(&a)),
        }),
    })
}

/// Check that the target accepts a connection.
///
/// # Errors
/// Returns a message when the target is not reachable.
pub(crate) fn reach(runner: &Runner<'_>) -> Result<(), Vec<String>> {
    let Some(target) = &runner.target else {
        return Ok(());
    };
    let until = Instant::now() + runner.timeouts.request;
    connect(target, until).map(|_| ()).map_err(|why| {
        vec![format!(
            "The target {} is not reachable: {why}.",
            target.host_header()
        )]
    })
}

/// Read the metadata of the PDP under test, and change its endpoints when the metadata names them.
///
/// # Errors
/// Returns a message when the PDP is not reachable.
pub(crate) fn discover(runner: &mut Runner<'_>) -> Result<(), Vec<String>> {
    let timeout = runner.timeouts.request;
    let Env::Pdp(env) = &mut runner.env else {
        return Ok(());
    };
    let Some(endpoints) = env.external.as_mut() else {
        return Ok(());
    };
    let request = ClientRequest {
        method: "GET".to_owned(),
        target: endpoints.metadata.target.clone(),
        headers: Vec::new(),
        body: None,
    };
    let reply = send(
        &endpoints.metadata.authority,
        &request,
        Instant::now() + timeout,
    )
    .map_err(|why| {
        vec![format!(
            "The PDP {} is not reachable: {why}.",
            endpoints.metadata.authority.host_header()
        )]
    })?;
    if reply.status != 200 {
        return Ok(());
    }
    let Ok(body) = serde_json::from_slice::<Value>(&reply.body) else {
        return Ok(());
    };
    for (member, slot) in [
        ("access_evaluation_endpoint", &mut endpoints.evaluation),
        ("access_evaluations_endpoint", &mut endpoints.evaluations),
    ] {
        if let Some(text) = body.get(member).and_then(Value::as_str) {
            let url = HttpUrl::parse(text).map_err(|why| {
                vec![format!(
                    "The metadata of the PDP: member `{member}`: expected an http URL, found \"{text}\": {why}."
                )]
            })?;
            *slot = url;
        }
    }
    let _ = exec::METADATA_PATH;
    Ok(())
}

/// Stop the test listeners of a runner.
pub(crate) fn stop(runner: Runner<'_>) {
    match runner.env {
        Env::Pep(env) => env.pdp.shutdown(),
        Env::Edge(env) => {
            env.upstream.shutdown();
            env.pdp.shutdown();
        }
        Env::Pdp(_) => {}
    }
}

/// Check the files of the profile for the role, with no listener. `--print-config` uses it.
///
/// # Errors
/// Returns every problem with a file.
pub(crate) fn check_files(
    profile: &Profile,
    role: crate::model::Role,
    catalog: &Catalog,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    match role {
        crate::model::Role::Pep => {
            if let Some(pep) = &profile.pep {
                if let Err(e) = Signer::load(&pep.token, &pep.service, "pep.token") {
                    errors.extend(e);
                }
                if let Some(file) = &pep.pdp.credential_file
                    && let Err(e) = read_secret("pep.pdp.credential_file", file)
                {
                    errors.push(e);
                }
            }
        }
        crate::model::Role::Edge => {
            if let Some(edge) = &profile.edge {
                if let Err(e) = Verifier::load(&edge.trust, &edge.service) {
                    errors.extend(e);
                }
                for (key, path) in [
                    ("edge.keys.valid.text_file", &edge.valid_key.text_file),
                    ("edge.keys.no_access.text_file", &edge.no_access_key_file),
                    ("edge.keys.unknown.text_file", &edge.unknown_key_file),
                ] {
                    if let Err(e) = read_secret(key, path) {
                        errors.push(e);
                    }
                }
                if let Some(file) = &edge.pdp.credential_file
                    && let Err(e) = read_secret("edge.pdp.credential_file", file)
                {
                    errors.push(e);
                }
                if let Err(e) = directory_value(edge, catalog) {
                    errors.push(e);
                }
            }
        }
        crate::model::Role::Pdp => {
            if let Some(pdp) = &profile.pdp
                && let Some(file) = &pdp.credential_file
                && let Err(e) = read_secret("pdp.credential_file", file)
            {
                errors.push(e);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
