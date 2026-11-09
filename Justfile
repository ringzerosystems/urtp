# ==============================================================================
# urtp (uring-rtp) Justfile
# Ultra-low-latency, zero-copy Linux io_uring RTP media proxy
# ==============================================================================

set shell := ["bash", "-uc"]

# ------------------------------------------------------------------------------
# General & Help
# ------------------------------------------------------------------------------

# Show overview of available recipes
[group("general")]
help:
    @just --list

# ------------------------------------------------------------------------------
# Build Management
# ------------------------------------------------------------------------------

# Build urtp binary with CMake preset (debug, release, sanitize)
[group("build")]
build preset="debug":
    #!/usr/bin/env bash
    set -euo pipefail
    PRESET="{{ preset }}"
    echo "=== Building urtp (${PRESET}) ==="
    cmake --preset "${PRESET}"
    cmake --build --preset "${PRESET}" --parallel
    if [ -f "build/${PRESET}/compile_commands.json" ]; then
        ln -sf "${PRESET}/compile_commands.json" "build/compile_commands.json"
        ln -sf "build/${PRESET}/compile_commands.json" "compile_commands.json"
    fi

# Shorthand for: just build debug
[group("build")]
debug:
    @just build debug

# Shorthand for: just build release (optimized)
[group("build")]
release:
    @just build release

# Shorthand for: just build sanitize (AddressSanitizer + UndefinedBehaviorSanitizer)
[group("build")]
sanitize:
    @just build sanitize

# Clean build artifacts and compile_commands.json (uses trash if available)
[group("build")]
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Cleaning build artifacts..."
    if [ -d "build" ]; then
        if command -v trash &>/dev/null; then
            trash build
        else
            rm -rf build
        fi
    fi
    if [ -L "compile_commands.json" ] || [ -f "compile_commands.json" ]; then
        if command -v trash &>/dev/null; then
            trash compile_commands.json
        else
            rm -f compile_commands.json
        fi
    fi
    echo "Clean completed."

# Clean build artifacts and compile from scratch
[group("build")]
rebuild preset="debug": clean (build preset)

# ------------------------------------------------------------------------------
# Testing & Verification
# ------------------------------------------------------------------------------

# Run test suite via CTest (debug, release, sanitize)
[group("test")]
test preset="debug":
    #!/usr/bin/env bash
    set -euo pipefail
    PRESET="{{ preset }}"
    echo "=== Running Unity Tests via CTest (${PRESET}) ==="
    ctest --preset "test-${PRESET}"

# Shorthand for: just test debug
[group("test")]
test-debug:
    @just test debug

# Shorthand for: just test release
[group("test")]
test-release:
    @just test release

# Shorthand for: just test sanitize
[group("test")]
test-sanitize:
    @just test sanitize

# Build binary and run test suite
[group("test")]
build-test preset="debug": (build preset) (test preset)

# Run automated end-to-end UDP relay integration tests against urtp
[group("test")]
test-relay preset="release" count="5000" bind_port="10000" dest_port="20000" latch="" sqpoll="":
    #!/usr/bin/env bash
    set -euo pipefail
    PRESET="{{ preset }}"
    PACKET_COUNT="{{ count }}"
    BIND_PORT="{{ bind_port }}"
    DEST_PORT="{{ dest_port }}"
    LATCH="{{ latch }}"
    SQPOLL="{{ sqpoll }}"

    URTP_BIN="build/${PRESET}/urtp"
    if [[ ! -x "$URTP_BIN" ]]; then
        echo "[*] Binary not found at $URTP_BIN. Building (${PRESET})..."
        just build "${PRESET}"
    fi

    SOCKET_PATH="/tmp/urtp_test_$$.sock"
    URTP_PID=""

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

    echo "=== urtp Relay Test: ${PRESET} (${PACKET_COUNT} packets) ==="

    SERVER_ARGS=("-c" "$SOCKET_PATH")
    if [[ "$SQPOLL" == "true" || "$SQPOLL" == "-s" || "$SQPOLL" == "1" ]]; then
        SERVER_ARGS+=("-s")
    fi

    "$URTP_BIN" "${SERVER_ARGS[@]}" &
    URTP_PID=$!

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

    CLIENT_ARGS=("-s" "$SOCKET_PATH" "--test" "-n" "$PACKET_COUNT" "--bind-port" "$BIND_PORT" "--dest-port" "$DEST_PORT")
    if [[ "$LATCH" == "true" || "$LATCH" == "-l" || "$LATCH" == "--latch" || "$LATCH" == "1" ]]; then
        CLIENT_ARGS+=("--latch")
    fi

    python3 scripts/client.py "${CLIENT_ARGS[@]}"
    echo "=== Relay test passed successfully ==="

# Run automated multi-stream audio + video relay integration test (VP8/H.264)
[group("test")]
test-video preset="release" codec="vp8" duration="3" resolution="1920x1080" audio_bind="30000" video_bind="30002" audio_dest="40000" video_dest="40002" record="" sqpoll="":
    #!/usr/bin/env bash
    set -euo pipefail
    PRESET="{{ preset }}"
    VIDEO_CODEC="{{ codec }}"
    RESOLUTION="{{ resolution }}"
    DURATION="{{ duration }}"
    AUDIO_BIND_PORT="{{ audio_bind }}"
    VIDEO_BIND_PORT="{{ video_bind }}"
    AUDIO_DEST_PORT="{{ audio_dest }}"
    VIDEO_DEST_PORT="{{ video_dest }}"
    RECORD="{{ record }}"
    SQPOLL="{{ sqpoll }}"

    URTP_BIN="build/${PRESET}/urtp"
    if [[ ! -x "$URTP_BIN" ]]; then
        echo "[*] Binary not found at $URTP_BIN. Building (${PRESET})..."
        just build "${PRESET}"
    fi

    SOCKET_PATH="/tmp/urtp_video_test_$$.sock"
    PCAP_DIR="/tmp/urtp_pcap_$$"
    URTP_PID=""

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

    echo "=== urtp Multi-Stream Video Relay Test: ${PRESET} (${VIDEO_CODEC} ${RESOLUTION}, ${DURATION}s) ==="

    EXTRA_SERVER_ARGS=("-w" "1")
    if [[ "$RECORD" == "true" || "$RECORD" == "-r" || "$RECORD" == "--record" || "$RECORD" == "1" ]]; then
        mkdir -p "$PCAP_DIR"
        EXTRA_SERVER_ARGS+=("-r" "$PCAP_DIR" "-R")
    fi
    if [[ "$SQPOLL" == "true" || "$SQPOLL" == "-s" || "$SQPOLL" == "1" ]]; then
        EXTRA_SERVER_ARGS+=("-s")
    fi

    "$URTP_BIN" -c "$SOCKET_PATH" "${EXTRA_SERVER_ARGS[@]}" &
    URTP_PID=$!

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

    python3 scripts/client.py \
        -s "$SOCKET_PATH" \
        --video-test \
        --video-codec "$VIDEO_CODEC" \
        --resolution "$RESOLUTION" \
        --duration "$DURATION" \
        --bind-port "$AUDIO_BIND_PORT" \
        --video-bind-port "$VIDEO_BIND_PORT" \
        --dest-port "$AUDIO_DEST_PORT" \
        --video-dest-port "$VIDEO_DEST_PORT"

    if [[ "$RECORD" == "true" || "$RECORD" == "-r" || "$RECORD" == "--record" || "$RECORD" == "1" ]]; then
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

# Run audio streaming, jitter buffer, and packet loss concealment (PLC) tests
[group("test")]
test-audio profile="all" socket="127.0.0.1:22222" wav="assets/jediwarlock.wav":
    #!/usr/bin/env bash
    set -euo pipefail
    SOCKET="{{ socket }}"
    PROFILE="{{ profile }}"
    WAV_PATH="{{ wav }}"

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
            echo "Usage: just test-audio [baseline|jitter|loss|idle|all] [socket] [wav-path]" >&2
            exit 1
            ;;
    esac

# Run media forwarding throughput benchmarks (burst, sustained, latch, watchdog, all)
[group("test")]
benchmark suite="burst" socket="127.0.0.1:22222":
    #!/usr/bin/env bash
    set -euo pipefail
    SOCKET="{{ socket }}"
    SUITE="{{ suite }}"

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
            echo "Usage: just benchmark [burst|sustained|latch|watchdog|all] [socket]" >&2
            exit 1
            ;;
    esac

# ------------------------------------------------------------------------------
# Docker & Infrastructure
# ------------------------------------------------------------------------------

# Build urtp Docker container image
[group("docker")]
docker-build:
    docker compose build

# Start urtp Docker environment with specified profile (transcode, full, pcap, sqpoll, relay)
[group("docker")]
docker-up profile="transcode":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ profile }}" in
        transcode|transcode-jitter|.env.transcode) ENV_FILE=".env.transcode" ;;
        full|.env.full) ENV_FILE=".env.full" ;;
        pcap|.env.pcap) ENV_FILE=".env.pcap" ;;
        sqpoll|.env.sqpoll) ENV_FILE=".env.sqpoll" ;;
        relay|default|.env) ENV_FILE=".env" ;;
        *)
            if [[ -f "{{ profile }}" ]]; then
                ENV_FILE="{{ profile }}"
            else
                echo "[!] Unknown profile or env file: {{ profile }}" >&2
                echo "Available profiles: transcode, full, pcap, sqpoll, relay (or path to .env file)" >&2
                exit 1
            fi
            ;;
    esac
    mkdir -p ./pcap
    chmod 777 ./pcap 2>/dev/null || true
    echo "[*] Starting urtp Docker environment with profile $ENV_FILE..."
    docker compose --env-file "$ENV_FILE" up -d --build
    echo "[+] Stack started. Checking health..."
    sleep 1
    docker compose ps

# Stop and remove urtp Docker compose services
[group("docker")]
docker-down:
    @echo "[*] Stopping urtp Docker environment..."
    docker compose down -v
    @echo "[+] Stopped."

# Follow Docker container logs for a given service (default: urtp)
[group("docker")]
docker-logs service="urtp":
    docker compose logs -f {{ service }}

# Check container status, control plane, and Prometheus metrics
[group("docker")]
docker-status profile="transcode":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ profile }}" in
        transcode|transcode-jitter|.env.transcode) ENV_FILE=".env.transcode" ;;
        full|.env.full) ENV_FILE=".env.full" ;;
        pcap|.env.pcap) ENV_FILE=".env.pcap" ;;
        sqpoll|.env.sqpoll) ENV_FILE=".env.sqpoll" ;;
        relay|default|.env) ENV_FILE=".env" ;;
        *) ENV_FILE="{{ profile }}" ;;
    esac
    echo "=== urtp Docker Container Status ($ENV_FILE) ==="
    docker compose ps
    echo ""
    echo "=== Control Protocol (TCP 22222) ==="
    if python3 scripts/client.py -s 127.0.0.1:22222 -c "STATUS" 2>/dev/null; then
        echo "[+] urtp control plane is responsive."
    else
        echo "[!] urtp control plane is not responding on 127.0.0.1:22222."
    fi
    echo ""
    echo "=== HTTP Prometheus Metrics ==="
    if curl -s -f http://127.0.0.1:22222/metrics >/dev/null 2>&1; then
        echo "[+] Prometheus metrics endpoint is online at http://127.0.0.1:22222/metrics"
    else
        echo "[!] Metrics endpoint is not responding."
    fi

# Restart Docker environment with specified profile
[group("docker")]
docker-restart profile="transcode": docker-down (docker-up profile)

# Tear down containers and prune local volumes/images
[group("docker")]
docker-clean:
    docker compose down -v --rmi local --remove-orphans

# ------------------------------------------------------------------------------
# Performance & Profiling
# ------------------------------------------------------------------------------

# Profile urtp process with Linux perf (DWARF call graph at specified frequency)
[group("perf")]
profile target_pid="" freq="99":
    #!/usr/bin/env bash
    set -euo pipefail
    PROC_NAME="urtp"
    FREQ="{{ freq }}"
    TARGET_PID="{{ target_pid }}"

    if [[ -z "$TARGET_PID" ]]; then
        PIDS=$(pgrep -x "$PROC_NAME" || true)
        if [[ -z "$PIDS" ]]; then
            echo "Error: No running process found for '$PROC_NAME'." >&2
            exit 1
        fi
        PID_ARRAY=($PIDS)
        if [[ ${#PID_ARRAY[@]} -gt 1 ]]; then
            echo "Warning: Multiple processes found. Targeting the first one (${PID_ARRAY[0]})." >&2
        fi
        TARGET_PID="${PID_ARRAY[0]}"
    fi

    echo "Found $PROC_NAME at PID: $TARGET_PID"
    echo "Starting perf profiling at ${FREQ}Hz (Ctrl+C to stop)..."
    perf record -F "$FREQ" -p "$TARGET_PID" -g --call-graph dwarf
    echo "Profiling complete. Run 'just perf-report' to view results."

# Inspect CPU profiling report with perf report
[group("perf")]
perf-report:
    perf report

# ------------------------------------------------------------------------------
# Media Processing
# ------------------------------------------------------------------------------

# Extract PCMU audio from PCAP and convert to WAV via ffmpeg
[group("media")]
pcap-to-wav pcap="pcap/session_30002.pcap" wav="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ wav }}" ]]; then
        scripts/pcap-to-wav.sh "{{ pcap }}" "{{ wav }}"
    else
        scripts/pcap-to-wav.sh "{{ pcap }}"
    fi

# ------------------------------------------------------------------------------
# Code Quality & Formatting
# ------------------------------------------------------------------------------

# Format all C/header source files with clang-format
[group("code")]
format:
    find . -type d \( -name "vendored" -o -name "build" -o -name ".cache" \) -prune -o -type f \( -name "*.c" -o -name "*.h" \) -print | xargs --no-run-if-empty clang-format -i

# Check C/header formatting without applying changes
[group("code")]
format-check:
    find . -type d \( -name "vendored" -o -name "build" -o -name ".cache" \) -prune -o -type f \( -name "*.c" -o -name "*.h" \) -print | xargs --no-run-if-empty clang-format --dry-run --Werror

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

# Run python test client CLI with arguments
[group("util")]
client *args:
    python3 scripts/client.py {{ args }}

# Check toolchains, compilers, and required C libraries
[group("util")]
check-env:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "=== Toolchain & System Check ==="
    for cmd in clang clang-format cmake ctest ninja pkg-config python3 docker just; do
        if command -v "$cmd" >/dev/null 2>&1; then
            printf "  [+] %-14s %s\n" "$cmd:" "$(command -v "$cmd")"
        else
            printf "  [-] %-14s NOT FOUND\n" "$cmd:"
        fi
    done
    echo ""
    echo "=== Required Libraries (pkg-config) ==="
    for pkg in liburing libssl libcrypto libopus libavcodec libavutil libswresample; do
        if pkg-config --exists "$pkg" 2>/dev/null; then
            printf "  [+] %-14s %s\n" "$pkg:" "$(pkg-config --modversion "$pkg" 2>/dev/null || echo 'installed')"
        else
            printf "  [-] %-14s NOT FOUND\n" "$pkg:"
        fi
    done

# ------------------------------------------------------------------------------
# Aliases
# ------------------------------------------------------------------------------

alias b := build
alias t := test
alias c := clean
alias f := format
alias check := test
alias up := docker-up
alias down := docker-down
alias logs := docker-logs
alias status := docker-status
