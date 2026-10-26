#!/usr/bin/env bash
# Build the programs as static Linux files with the musl target, inside Docker.
# Use: scripts/static.sh            (build the seven programs)
#      scripts/static.sh --check    (build, then check that each file is static and runs)
# The files are in the target volume, in /cargo-target/x86_64-unknown-linux-musl/release.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/docker-env.sh"
ensure_image

static_image="procurauth-static:1"
if ! docker image inspect "$static_image" >/dev/null 2>&1; then
    docker build --quiet --tag "$static_image" --file "$root/scripts/Dockerfile.static" "$root/scripts" >/dev/null
fi

# Same volumes as scripts/cargo.sh. Run `scripts/cargo.sh --version` one time to create them.
programs=(keycheck access-token access-lint fake-pdp access-conformance reference-service reference-edge)
flags=()
for program in "${programs[@]}"; do flags+=(-p "$program"); done

check=""
if [ "${1:-}" = "--check" ]; then
    check='
cd /cargo-target/x86_64-unknown-linux-musl/release
for program in keycheck access-token access-lint fake-pdp access-conformance reference-service reference-edge; do
    if ! file "$program" | grep -q "static"; then echo "not static: $program" >&2; exit 1; fi
    if ldd "$program" 2>&1 | grep -q "=>"; then echo "dynamic: $program" >&2; exit 1; fi
    "./$program" --version
done'
fi

exec docker run --rm \
    --user "$uid:$gid" \
    --volume "$root:/work" \
    --volume "$registry_volume:/cargo-home" \
    --volume "$target_volume:/cargo-target" \
    --workdir /work \
    --env CARGO_HOME=/cargo-home \
    --env CARGO_TARGET_DIR=/cargo-target \
    --env HOME=/cargo-home \
    --env CARGO_TERM_COLOR=never \
    "$static_image" bash -c "cargo build --release --locked --target x86_64-unknown-linux-musl ${flags[*]} $check"
