#!/usr/bin/env bash
# Run the checks of the repository in Docker: format, clippy and tests.
# Use: scripts/ci.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== cargo fmt"
"$here/cargo.sh" fmt --all -- --check
echo "== cargo clippy"
"$here/cargo.sh" clippy --workspace --all-targets -- -D warnings
echo "== cargo test"
"$here/cargo.sh" test --workspace
echo "== all checks passed"
