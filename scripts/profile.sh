#!/usr/bin/env bash
set -euo pipefail

# Configuration
PROC_NAME="urtp"
FREQ=99

echo "Looking for process: $PROC_NAME"

# Fetch PID of urtp process
# -x ensures exact match to avoid matching substrings
# || true prevents script from exiting immediately due to set -e if pgrep fails
PIDS=$(pgrep -x "$PROC_NAME" || true)

if [[ -z "$PIDS" ]]; then
    echo "Error: No running process found for '$PROC_NAME'." >&2
    exit 1
fi

# Handle multiple instances
PID_ARRAY=($PIDS)
if [[ ${#PID_ARRAY[@]} -gt 1 ]]; then
    echo "Warning: Multiple processes found. Targeting the first one (${PID_ARRAY[0]})." >&2
fi

TARGET_PID="${PID_ARRAY[0]}"

echo "Found $PROC_NAME at PID: $TARGET_PID"
echo "Starting perf profiling (Ctrl+C to stop)..."

# Run perf record
# -F 99: Sample at 99Hz to avoid lockstep with standard kernel timers
# -g --call-graph dwarf: Capture call chains using DWARF debug info
# -p: Target specific PID
perf record -F "$FREQ" -p "$TARGET_PID" -g --call-graph dwarf

echo "Profiling complete. Run 'perf report' to view the results."
