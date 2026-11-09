#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." &>/dev/null && pwd)"

SOCKET="${1:-127.0.0.1:22222}"
PROFILE="${2:-all}"
WAV_PATH="${3:-assets/jediwarlock.wav}"

cd "$REPO_ROOT"

run_scenario() {
    local title="$1"
    shift
    echo ""
    echo "######################################################################"
    echo "# SCENARIO: $title"
    echo "######################################################################"
    python3 scripts/client.py -s "$SOCKET" --audio --wav "$WAV_PATH" "$@"
}

case "$PROFILE" in
    baseline)
        run_scenario "Baseline Transcode (No Loss)" --duration 8.0
        ;;
    jitter)
        run_scenario "Jitter Buffer Reorder Stress" --duration 10.0 --reorder-rate 0.15 --reorder-delay 35.0
        ;;
    loss|plc)
        run_scenario "Packet Loss Concealment (PLC)" --duration 10.0 --drop-rate 0.05 --drop-burst 2
        ;;
    idle|silence)
        run_scenario "Periodic Talkspurt Silence" --duration 12.0 --idle-interval 3.0 --idle-duration 2.0
        ;;
    all|stress)
        run_scenario "Comprehensive Jitter, Loss & Silence Stress Test" \
            --duration 15.0 \
            --drop-rate 0.04 \
            --drop-burst 2 \
            --reorder-rate 0.12 \
            --reorder-delay 35.0 \
            --idle-interval 3.0 \
            --idle-duration 1.5
        ;;
    *)
        echo "Usage: $0 [control-socket: 127.0.0.1:22222] [baseline|jitter|loss|idle|all] [wav-path]"
        exit 1
        ;;
esac
