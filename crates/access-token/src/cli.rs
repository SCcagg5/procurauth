//! The command line of `access-token`, as clap types.
//!
//! The doc comments of the fields are the text of `--help`. The program reads
//! no environment variable. A flag that occurs two times is an error.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// The words that `--help` shows after the usage line.
const AFTER_HELP: &str = "\
Exit codes: 0 no finding, 1 at least one finding, 2 usage error or unreadable input.
The licence is Apache-2.0.";

/// Make and check the identity tokens of ProcurAuth (protocol section 9).
#[derive(Debug, Parser)]
#[command(
    name = "access-token",
    version = concat!(env!("CARGO_PKG_VERSION"), "\nApache-2.0"),
    after_help = AFTER_HELP,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// The work to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The two subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Make a signed identity token, good or bad, and write it to the standard output.
    Make(MakeArgs),
    /// Check a token against the configuration of a service, and write one line for each check.
    Check(CheckArgs),
}

/// The form of the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Lines of text.
    Text,
    /// One JSON document.
    Json,
}

/// The algorithm names for the header `alg` of a token that `make` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AlgName {
    /// Ed25519. A good token for an Ed25519 key.
    #[value(name = "Ed25519")]
    Ed25519,
    /// ES256. A good token for a P-256 key.
    #[value(name = "ES256")]
    Es256,
    /// A bad token: the name `EdDSA` is deprecated (protocol 9.2).
    #[value(name = "EdDSA")]
    EdDsa,
    /// A bad token: an algorithm with a shared secret.
    #[value(name = "HS256")]
    Hs256,
    /// A bad token: an algorithm that the protocol does not name.
    #[value(name = "RS256")]
    Rs256,
    /// A bad token with no signature (an unsecured JWS).
    #[value(name = "none")]
    None,
}

impl AlgName {
    /// The name in the header.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Hs256 => "HS256",
            Self::Rs256 => "RS256",
            Self::None => "none",
        }
    }
}

/// The arguments of `make`.
#[derive(Debug, Args)]
pub struct MakeArgs {
    /// The file with the private signing key: PKCS#8 PEM, for Ed25519 or P-256.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,

    /// The name in the header `alg`. The default is the algorithm of the key.
    /// A name that is not the algorithm of the key makes a bad token.
    #[arg(long, value_name = "ALG")]
    pub alg: Option<AlgName>,

    /// The value of the header `typ`. The default is `JWT`.
    /// Another value makes a bad token.
    #[arg(long = "typ", value_name = "TYPE")]
    pub typ: Option<String>,

    /// Put this id in the header `kid`.
    #[arg(long, value_name = "ID")]
    pub kid: Option<String>,

    /// Put the header `crit` with this name. This makes a bad token.
    #[arg(long, value_name = "NAME")]
    pub crit: Option<String>,

    /// Change the first byte of the signature. This makes a bad token.
    #[arg(long)]
    pub bad_signature: bool,

    /// Make the token also when the claims break the rules of protocol 9.3.
    /// Use it to make a token that lacks a claim.
    #[arg(long)]
    pub allow_bad_claims: bool,

    /// The form of the result.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// The file with the claims, as one JSON object. Use `-` for the standard input.
    #[arg(value_name = "CLAIMS")]
    pub claims: PathBuf,
}

/// The arguments of `check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The configuration of the service, as one JSON file.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,

    /// The form of the result.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// The time of the check, in seconds since the Unix epoch.
    /// For tests. Without it, the program reads the system clock.
    #[arg(long, value_name = "UNIX_SECONDS")]
    pub now: Option<u64>,

    /// Check the configuration, write the values that apply, and stop.
    #[arg(long, conflicts_with = "token")]
    pub print_config: bool,

    /// The file with the token. Use `-` for the standard input. It is needed, except with `--print-config`.
    #[arg(value_name = "TOKEN", required_unless_present = "print_config")]
    pub token: Option<PathBuf>,
}
