#!/usr/bin/env bash
# Check that the workspace builds with the oldest Rust version that it supports.
# The version is the `rust-version` of the root Cargo.toml.
# Use: scripts/msrv.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)"
image="rust:${version}-bookworm"
uid="$(id -u)"
gid="$(id -g)"

# The registry volume is the one of scripts/cargo.sh. The target directory is
# inside the container, so the normal build output stays as it is.
"$root/scripts/cargo.sh" --version >/dev/null
exec docker run --rm \
    --user "$uid:$gid" \
    --volume "$root:/work" \
    --volume "procurauth-cargo-registry:/cargo-home" \
    --workdir /work \
    --env CARGO_HOME=/cargo-home \
    --env CARGO_TARGET_DIR=/tmp/msrv-target \
    --env HOME=/cargo-home \
    "$image" cargo check --workspace --all-targets --locked
