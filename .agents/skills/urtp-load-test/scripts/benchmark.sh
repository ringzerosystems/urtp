#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." &>/dev/null && pwd)"

SOCKET="${1:-127.0.0.1:22222}"
SUITE="${2:-burst}"

cd "$REPO_ROOT"

case "$SUITE" in
    burst)
        echo "=== Running 10,000 Packet Zero-Copy UDP Relay Burst ==="
        python3 scripts/client.py -s "$SOCKET" --test -n 10000 --bind-port 30002 --dest-port 20000
        ;;
    sustained)
        echo "=== Running 30-Second Sustained Stream Benchmark (50 PPS) ==="
        python3 scripts/client.py -s "$SOCKET" --test -d 30.0 -r 50.0 --bind-port 30002 --dest-port 20000
        ;;
    latch)
        echo "=== Running Symmetric RTP / NAT Latching Benchmark ==="
        python3 scripts/client.py -s "$SOCKET" --test -n 3000 --latch --bind-port 30002
        ;;
    watchdog)
        echo "=== Running Watchdog Idle Session Reaper Test ==="
        python3 scripts/client.py -s "$SOCKET" --watchdog --idle-sessions 3 --bind-port 30010
        ;;
    all)
        echo "=== Executing Complete Relay Benchmark Suite ==="
        python3 scripts/client.py -s "$SOCKET" --test -n 10000 --bind-port 30002 --dest-port 20000
        sleep 1
        python3 scripts/client.py -s "$SOCKET" --test -n 3000 --latch --bind-port 30002
        ;;
    *)
        echo "Usage: $0 [control-socket: 127.0.0.1:22222] [burst|sustained|latch|watchdog|all]"
        exit 1
        ;;
esac
