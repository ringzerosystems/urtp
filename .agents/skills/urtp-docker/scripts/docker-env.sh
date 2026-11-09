#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." &>/dev/null && pwd)"

# Parse arguments flexibly: supports both `docker-env.sh [profile] [action]`
# and `docker-env.sh [action] [profile]`
ARG1="${1:-transcode}"
ARG2="${2:-}"

is_action() {
    case "$1" in
        up|start|down|stop|logs|status|check) return 0 ;;
        *) return 1 ;;
    esac
}

if is_action "$ARG1"; then
    ACTION="$ARG1"
    PROFILE="${ARG2:-transcode}"
else
    PROFILE="$ARG1"
    ACTION="${ARG2:-status}"
fi

# Resolve environment profile to corresponding .env file
case "$PROFILE" in
    transcode|transcode-jitter|.env.transcode)
        ENV_FILE=".env.transcode"
        ;;
    full|.env.full)
        ENV_FILE=".env.full"
        ;;
    pcap|.env.pcap)
        ENV_FILE=".env.pcap"
        ;;
    sqpoll|.env.sqpoll)
        ENV_FILE=".env.sqpoll"
        ;;
    relay|default|.env)
        ENV_FILE=".env"
        ;;
    *)
        if [[ -f "$REPO_ROOT/$PROFILE" ]]; then
            ENV_FILE="$PROFILE"
        else
            echo "[!] Unknown profile or env file: $PROFILE"
            echo "Available profiles: transcode, full, pcap, sqpoll, relay (or path to .env file)"
            exit 1
        fi
        ;;
esac

cd "$REPO_ROOT"

case "$ACTION" in
    up|start)
        mkdir -p ./pcap
        chmod 777 ./pcap 2>/dev/null || true
        echo "[*] Starting urtp Docker environment with profile $ENV_FILE..."
        docker compose --env-file "$ENV_FILE" up -d --build
        echo "[+] Stack started. Checking health..."
        sleep 1
        docker compose ps
        ;;
    down|stop)
        echo "[*] Stopping urtp Docker environment..."
        docker compose down -v
        echo "[+] Stopped."
        ;;
    logs)
        docker compose logs -f urtp
        ;;
    status|check)
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
        ;;
    *)
        echo "Usage: $0 [profile] [up|down|logs|status]"
        echo "   or: $0 [up|down|logs|status] [profile]"
        echo ""
        echo "Profiles: transcode (default), full, pcap, sqpoll, relay (or path to .env file)"
        echo "Example:  $0 transcode up"
        echo "          $0 up full"
        echo "          $0 down"
        exit 1
        ;;
esac
