#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." &>/dev/null && pwd)"

# Default configurations
PRESET="release"
PACKET_COUNT=5000
BIND_PORT=10000
DEST_PORT=20000
USE_SQPOLL=""
SOCKET_PATH="/tmp/urtp_test_$$.sock"
URTP_PID=""

show_usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Run automated end-to-end UDP relay integration tests against urtp.

Options:
  -p, --preset <name>       Binary build preset: release (default), debug, or sanitize
  -n, --count <number>      Number of UDP packets to stream (default: 5000)
  --bind-port <port>        Relay incoming bind port (default: 10000)
  --dest-port <port>        Relay forwarding destination port (default: 20000)
  -l, --latch               Test Symmetric RTP and NAT latching
  -s, --sqpoll              Enable io_uring SQPOLL kernel polling thread
  -h, --help                Show this help message
EOF
}

LATCH_FLAG=""

# Parse CLI options
while [[ $# -gt 0 ]]; do
    case "${1,,}" in
        -p|--preset)
            PRESET="$2"
            shift 2
            ;;
        -n|--count)
            PACKET_COUNT="$2"
            shift 2
            ;;
        --bind-port)
            BIND_PORT="$2"
            shift 2
            ;;
        --dest-port)
            DEST_PORT="$2"
            shift 2
            ;;
        -l|--latch)
            LATCH_FLAG="--latch"
            shift
            ;;
        -s|--sqpoll)
            USE_SQPOLL="-s"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

URTP_BIN="$PROJECT_ROOT/build/$PRESET/urtp"

# Ensure binary is built
if [[ ! -x "$URTP_BIN" ]]; then
    echo "[*] Binary not found at $URTP_BIN. Building ($PRESET)..."
    "$PROJECT_ROOT/scripts/build.sh" "$PRESET"
fi

cleanup() {
    local exit_code=$?
    if [[ -n "$URTP_PID" ]] && kill -0 "$URTP_PID" 2>/dev/null; then
        kill -INT "$URTP_PID" 2>/dev/null || true
        wait "$URTP_PID" 2>/dev/null || true
    fi
    if [[ -e "$SOCKET_PATH" ]]; then
        trash "$SOCKET_PATH" 2>/dev/null || rm -f "$SOCKET_PATH"
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "=== urtp Relay Test: $PRESET ($PACKET_COUNT packets) ==="

# Launch daemon in background
"$URTP_BIN" -c "$SOCKET_PATH" $USE_SQPOLL &
URTP_PID=$!

# Wait for control socket readiness (max 2 seconds)
READY=false
for _ in {1..20}; do
    if [[ -S "$SOCKET_PATH" ]]; then
        READY=true
        break
    fi
    sleep 0.1
done

if [[ "$READY" != "true" ]]; then
    echo "Error: Control socket $SOCKET_PATH did not become ready in time" >&2
    exit 1
fi

# Execute automated load test
"$PROJECT_ROOT/scripts/client.py" \
    -s "$SOCKET_PATH" \
    --test \
    ${LATCH_FLAG:+"$LATCH_FLAG"} \
    -n "$PACKET_COUNT" \
    --bind-port "$BIND_PORT" \
    --dest-port "$DEST_PORT"

echo "=== Relay test passed successfully ==="
