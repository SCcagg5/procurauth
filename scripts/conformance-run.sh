#!/usr/bin/env bash
# Run inside the container of scripts/conformance.sh. Do not run it on the host.
# The programs are in /cargo-target/release. The repository is in /work, read only.
# Use: scripts/conformance-run.sh pep|pdp|edge|all
set -euo pipefail

mode="${1:?mode}"
bin=/cargo-target/release
work="$(mktemp -d)"
pids=()
failed=0
declare -a summary=()

stop_all() {
    local pid
    for pid in "${pids[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
    pids=()
}
cleanup() {
    stop_all
    rm -rf "$work"
}
trap cleanup EXIT

# Start a background program. The log goes to a file.
start() {
    local name="$1"
    shift
    "$@" >"$work/$name.out" 2>"$work/$name.err" &
    pids+=("$!")
}

# Wait until a port on the loopback address accepts a connection.
wait_port() {
    local port="$1" i
    for i in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "The port $port did not open." >&2
    return 1
}

# Run the runner. Record the last line of the result.
run_runner() {
    local label="$1"
    shift
    local code=0
    echo "--- $label"
    "$bin/access-conformance" "$@" | tee "$work/runner.out" || code=$?
    local line
    line="$(tail -n 1 "$work/runner.out")"
    summary+=("$label: $line (exit $code)")
    if [ "$code" -ne 0 ]; then
        failed=1
    fi
    return "$code"
}

show_logs() {
    local name
    for name in "$@"; do
        echo "--- log of $name" >&2
        tail -n 40 "$work/$name.err" >&2 || true
    done
}

# The series U, with one configuration of the service.
# Arguments: the label, the configuration of the service, the profile of the runner.
run_pep_with() {
    local label="$1" config="$2" profile="$3"
    start service "$bin/reference-service" "$config"
    wait_port 8080 || { show_logs service; failed=1; return; }
    run_runner "$label" --role pep --profile "$profile" --url http://127.0.0.1:8080 \
        || show_logs service
    stop_all
}

run_pep() {
    local dir=crates/reference-service/examples
    export PROCURAUTH_PDP_CREDENTIAL
    PROCURAUTH_PDP_CREDENTIAL="$(tr -d '\n' <crates/access-conformance/examples/pdp-credential.txt)"
    run_pep_with "U, action mcp.session with no budget" \
        "$dir/conformance.json" "$dir/conformance-profile.json"
    run_pep_with "U, action mcp.session with a budget" \
        "$dir/conformance-session-budget.json" "$dir/conformance-profile-session-budget.json"
}

# The series D. First the runner starts fake-pdp in its own process. Then it
# calls fake-pdp as a separate process on the loopback address (the key --url).
run_pdp() {
    run_runner "D, fake-pdp in the process of the runner" --role pdp \
        --profile crates/access-conformance/examples/pdp-fake.json || true
    start pdp "$bin/fake-pdp" --listen 127.0.0.1:8181 --admin \
        --credential-file crates/access-conformance/examples/pdp-credential.txt \
        conformance/directories/datastore.json
    wait_port 8181 || { show_logs pdp; failed=1; return; }
    run_runner "D, fake-pdp as a separate process" --role pdp \
        --profile crates/fake-pdp/examples/conformance-profile.json \
        --url http://127.0.0.1:8181 || show_logs pdp
    stop_all
}

case "$mode" in
    pep) run_pep ;;
    pdp) run_pdp ;;
    edge) run_edge ;;
    all)
        run_pep
        run_pdp
        ;;
esac

echo "== summary"
printf '%s\n' "${summary[@]}"
exit "$failed"
