#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/../../../.." &>/dev/null && pwd))"

# Default configurations
PRESET="release"
VIDEO_CODEC="vp8"
RESOLUTION="1920x1080"
DURATION=3
AUDIO_BIND_PORT=30000
VIDEO_BIND_PORT=30002
AUDIO_DEST_PORT=40000
VIDEO_DEST_PORT=40002
RECORD_FLAG=""
USE_SQPOLL=""
SOCKET_PATH="/tmp/urtp_video_test_$$.sock"
PCAP_DIR="/tmp/urtp_pcap_$$"
URTP_PID=""

show_usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Run automated end-to-end multi-stream audio + video relay integration tests against urtp.

Options:
  -p, --preset <name>         Binary build preset: release (default), debug, or sanitize
  -c, --codec <vp8|h264>      Video codec to test: vp8 (default) or h264
  -d, --duration <seconds>    Streaming duration in seconds (default: 3)
  --resolution <WxH>          Video resolution (default: 1920x1080)
  --audio-bind <port>         Relay audio listen port (default: 30000)
  --video-bind <port>         Relay video listen port (default: 30002)
  --audio-dest <port>         Relay audio destination port (default: 40000)
  --video-dest <port>         Relay video destination port (default: 40002)
  -r, --record                Enable urtp PCAP recording and verify captures
  -s, --sqpoll                Enable io_uring SQPOLL kernel polling thread
  -h, --help                  Show this help message
EOF
}

# Parse CLI options
while [[ $# -gt 0 ]]; do
    case "${1,,}" in
        -p|--preset)
            PRESET="$2"
            shift 2
            ;;
        -c|--codec)
            VIDEO_CODEC="${2,,}"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        --resolution)
            RESOLUTION="$2"
            shift 2
            ;;
        --audio-bind)
            AUDIO_BIND_PORT="$2"
            shift 2
            ;;
        --video-bind)
            VIDEO_BIND_PORT="$2"
            shift 2
            ;;
        --audio-dest)
            AUDIO_DEST_PORT="$2"
            shift 2
            ;;
        --video-dest)
            VIDEO_DEST_PORT="$2"
            shift 2
            ;;
        -r|--record)
            RECORD_FLAG="--record"
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
        for _ in {1..30}; do
            if ! kill -0 "$URTP_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        kill -KILL "$URTP_PID" 2>/dev/null || true
        wait "$URTP_PID" 2>/dev/null || true
    fi
    if [[ -e "$SOCKET_PATH" ]]; then
        trash "$SOCKET_PATH" 2>/dev/null || rm -f "$SOCKET_PATH"
    fi
    if [[ -d "$PCAP_DIR" ]]; then
        trash "$PCAP_DIR" 2>/dev/null || rm -rf "$PCAP_DIR"
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "=== urtp Multi-Stream Video Relay Test: $PRESET ($VIDEO_CODEC $RESOLUTION, ${DURATION}s) ==="

EXTRA_SERVER_ARGS=("-w" "1")
if [[ -n "$RECORD_FLAG" ]]; then
    mkdir -p "$PCAP_DIR"
    EXTRA_SERVER_ARGS+=("-r" "$PCAP_DIR" "-R")
fi

# Launch daemon in background
"$URTP_BIN" -c "$SOCKET_PATH" ${USE_SQPOLL:+"$USE_SQPOLL"} "${EXTRA_SERVER_ARGS[@]}" &
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

# Execute automated multi-stream video test
"$PROJECT_ROOT/scripts/client.py" \
    -s "$SOCKET_PATH" \
    --video-test \
    --video-codec "$VIDEO_CODEC" \
    --resolution "$RESOLUTION" \
    --duration "$DURATION" \
    --bind-port "$AUDIO_BIND_PORT" \
    --video-bind-port "$VIDEO_BIND_PORT" \
    --dest-port "$AUDIO_DEST_PORT" \
    --video-dest-port "$VIDEO_DEST_PORT"

# Validate PCAP capture if recording was enabled
if [[ -n "$RECORD_FLAG" ]]; then
    echo ""
    echo "=== Forensic PCAP Recording Analysis ==="
    PCAP_COUNT=$(find "$PCAP_DIR" -type f -name "*.pcap" | wc -l)
    if [[ "$PCAP_COUNT" -eq 0 ]]; then
        echo "Error: No PCAP recordings were generated in $PCAP_DIR" >&2
        exit 1
    fi

    for pcap_file in "$PCAP_DIR"/*.pcap; do
        pcap_size=$(stat -c%s "$pcap_file" 2>/dev/null || stat -f%z "$pcap_file" 2>/dev/null)
        echo "[+] Recorded PCAP: $(basename "$pcap_file") ($(( pcap_size / 1024 )) KB)"
        if [[ "$pcap_size" -lt 100 ]]; then
            echo "Error: PCAP file $pcap_file is unexpectedly small ($pcap_size bytes)" >&2
            exit 1
        fi
    done
    echo "[+] Forensic PCAP verification passed: recordings valid and non-empty."
fi

echo ""
echo "=== Multi-stream video relay test passed successfully ==="
