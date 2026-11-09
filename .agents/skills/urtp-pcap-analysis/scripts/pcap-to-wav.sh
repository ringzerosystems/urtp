#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." &>/dev/null && pwd)"

PCAP_DIR="${REPO_ROOT}/pcap"
TARGET="${1:-latest}"

if [[ ! -d "$PCAP_DIR" ]]; then
    echo "[!] PCAP directory $PCAP_DIR does not exist."
    exit 1
fi

if [[ "$TARGET" == "latest" ]]; then
    PCAP_FILE=$(ls -t "${PCAP_DIR}"/*.pcap 2>/dev/null | head -n 1 || true)
    if [[ -z "$PCAP_FILE" ]]; then
        echo "[!] No .pcap files found in $PCAP_DIR"
        exit 1
    fi
else
    PCAP_FILE="$TARGET"
fi

if [[ ! -f "$PCAP_FILE" ]]; then
    echo "[!] PCAP file not found: $PCAP_FILE"
    exit 1
fi

WAV_FILE="${PCAP_FILE%.pcap}.wav"

echo "=== PCAP File: $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1)) ==="

# Extract RTP audio payload and convert to standard WAV
echo "[*] Extracting RTP audio from PCAP to WAV ($WAV_FILE)..."
python3 -c '
import sys, struct, subprocess

pcap_path = sys.argv[1]
wav_path = sys.argv[2]

payload_bytes = bytearray()
payload_types = set()

with open(pcap_path, "rb") as f:
    ghdr = f.read(24)
    if len(ghdr) < 24:
        sys.exit(1)
    endian = "<" if ghdr[:4] == b"\xd4\xc3\xb2\xa1" or ghdr[:4] == b"\xa1\xb2\xc3\xd4" else ">"
    
    while True:
        phdr = f.read(16)
        if len(phdr) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", phdr)
        pkt = f.read(incl_len)
        if len(pkt) >= 42 + 12:
            udp_payload = pkt[42:]
            rtp_hdr = struct.unpack("!BBHII", udp_payload[:12])
            pt = rtp_hdr[1] & 0x7F
            payload_types.add(pt)
            payload_bytes.extend(udp_payload[12:])

if not payload_bytes:
    print("[!] Error: No RTP audio payload found in PCAP", file=sys.stderr)
    sys.exit(1)

pt = list(payload_types)[0]
if pt == 0:
    fmt, ar, ac = "mulaw", "8000", "1"
elif pt == 8:
    fmt, ar, ac = "alaw", "8000", "1"
else:
    fmt, ar, ac = "s16le", "8000", "1"

proc = subprocess.Popen([
    "ffmpeg", "-y", "-f", fmt, "-ar", ar, "-ac", ac,
    "-i", "-", "-c:a", "pcm_s16le", wav_path,
    "-loglevel", "warning"
], stdin=subprocess.PIPE)
proc.communicate(input=payload_bytes)
if proc.returncode != 0:
    sys.exit(proc.returncode)
' "$PCAP_FILE" "$WAV_FILE"

if [[ -f "$WAV_FILE" ]]; then
    echo "[+] Extracted WAV successfully: $WAV_FILE ($(du -h "$WAV_FILE" | cut -f1))"
    ffmpeg -hide_banner -i "$WAV_FILE" 2>&1 | grep -E "Duration|Audio" || true
else
    echo "[!] Conversion failed."
    exit 1
fi

echo ""
echo "[+] To play the extracted audio: ffplay -nodisp -autoexit $WAV_FILE"
echo "[+] To open in Wireshark:        wireshark $PCAP_FILE &"
