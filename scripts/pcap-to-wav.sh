#!/usr/bin/env bash
set -euo pipefail

PCAP_FILE="${1:-pcap/session_30002.pcap}"
OUTPUT_WAV="${2:-${PCAP_FILE%.pcap}.wav}"

if [[ ! -f "${PCAP_FILE}" ]]; then
    echo "Error: PCAP file '${PCAP_FILE}' not found." >&2
    exit 1
fi

echo "[*] Extracting audio from '${PCAP_FILE}' -> '${OUTPUT_WAV}'..."

python3 - "${PCAP_FILE}" "${OUTPUT_WAV}" << 'PYEOF'
import sys
import struct
import subprocess

pcap_path = sys.argv[1]
output_wav = sys.argv[2]

packets = []

with open(pcap_path, "rb") as f:
    hdr = f.read(24)
    if len(hdr) < 24:
        sys.exit(f"Invalid PCAP file: header too short in {pcap_path}")
    magic = struct.unpack("<I", hdr[:4])[0]
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
        sys.exit(f"Unknown PCAP magic: {hex(magic)}")

    while True:
        p_hdr = f.read(16)
        if len(p_hdr) < 16:
            break
        _, _, incl_len, _ = struct.unpack("<IIII", p_hdr)
        data = f.read(incl_len)
        if len(data) < 54:
            continue

        proto = data[23]
        if proto != 17:
            continue

        udp_payload = data[42:]
        if len(udp_payload) < 12:
            continue

        v_p_x_cc = udp_payload[0]
        v = (v_p_x_cc >> 6) & 0x03
        if v != 2:
            continue

        pt = udp_payload[1] & 0x7f
        seq, ts = struct.unpack(">HI", udp_payload[2:8])
        rtp_payload = udp_payload[12:]
        if len(rtp_payload) == 0:
            continue

        # Filter to egress transcoded audio (PCMU pt=0)
        if pt == 0:
            packets.append((seq, ts, rtp_payload))

if not packets:
    sys.exit("No valid RTP PCMU audio packets found in PCAP file.")

packets.sort(key=lambda x: x[0])
print(f"[+] Extracted {len(packets)} RTP PCMU packets")

raw_audio = b"".join(p[2] for p in packets)

cmd = [
    "ffmpeg", "-y",
    "-f", "mulaw",
    "-ar", "8000",
    "-ac", "1",
    "-i", "pipe:0",
    output_wav
]

proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
_, stderr = proc.communicate(input=raw_audio)

if proc.returncode != 0:
    sys.exit(f"ffmpeg conversion failed: {stderr.decode('utf-8', errors='replace')}")

print(f"[+] Successfully generated: '{output_wav}'")
PYEOF

chmod 644 "${OUTPUT_WAV}" 2>/dev/null || true
