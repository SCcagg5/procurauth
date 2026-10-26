#!/usr/bin/env bash
# Run the conformance runner against the reference implementations.
# Use: scripts/conformance.sh [pep|pdp|edge|all]
#
#   pep   The series U: access-conformance against reference-service.
#   pdp   The series D: access-conformance against fake-pdp, in the process and as a separate process.
#   edge  The series E: access-conformance against reference-edge.
#   all   The three runs. This is the default.
#
# The script builds the programs with scripts/cargo.sh. It then starts all the processes
# in ONE container, on the loopback address. The container has no network and it opens
# no port on the host. The container stops by itself after a time limit.
# The exit code is 0 when no case failed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode="${1:-all}"
case "$mode" in
    pep | pdp | edge | all) ;;
    *)
        echo "Use: scripts/conformance.sh [pep|pdp|edge|all]" >&2
        exit 2
        ;;
esac

source "$here/docker-env.sh"
ensure_image

echo "== build the programs"
"$here/cargo.sh" build --release --locked \
    -p access-conformance -p fake-pdp -p reference-service -p reference-edge

# The time limit of the whole run, in seconds. It is inside the container, so that
# the container stops even when the host script is killed.
limit=600
echo "== run the cases: $mode"
exec timeout $((limit + 60)) docker run --rm --init --network none \
    --user "$uid:$gid" \
    --volume "$root:/work:ro" \
    --volume "$target_volume:/cargo-target:ro" \
    --workdir /work \
    --env HOME=/tmp \
    "$image" timeout "$limit" bash scripts/conformance-run.sh "$mode"
