#!/usr/bin/env bash
# Run cargo inside Docker. Nothing is installed on the host.
# Use: scripts/cargo.sh test --workspace
#      scripts/cargo.sh fmt --all -- --check
#      scripts/cargo.sh clippy --workspace --all-targets -- -D warnings
#
# The script runs as the host user. The cargo registry and the target
# directory live in named Docker volumes, so no root-owned file appears
# in the repository.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/docker-env.sh"
ensure_image

# Create each volume one time, and give it to the host user with a root container.
for volume in "$registry_volume" "$target_volume"; do
    if ! docker volume inspect "$volume" >/dev/null 2>&1; then
        docker volume create "$volume" >/dev/null
    fi
    owner="$(docker run --rm --user 0:0 --volume "$volume:/v" "$image" stat -c '%u:%g' /v)"
    if [ "$owner" != "$uid:$gid" ]; then
        docker run --rm --user 0:0 --volume "$volume:/v" "$image" chown -R "$uid:$gid" /v
    fi
done

tty_flag=()
if [ -t 0 ] && [ -t 1 ]; then
    tty_flag=(--tty)
fi

exec docker run --rm --interactive "${tty_flag[@]}" \
    --user "$uid:$gid" \
    --volume "$root:/work" \
    --volume "$registry_volume:/cargo-home" \
    --volume "$target_volume:/cargo-target" \
    --workdir /work \
    --env CARGO_HOME=/cargo-home \
    --env CARGO_TARGET_DIR=/cargo-target \
    --env HOME=/cargo-home \
    --env CARGO_TERM_COLOR=never \
    "$image" cargo "$@"
