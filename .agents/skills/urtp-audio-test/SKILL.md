---
name: urtp-audio-test
description: >-
  Executes end-to-end audio streaming, transcoding, jitter buffer, packet loss concealment (PLC),
  and periodic talkspurt silence tests against urtp running in Docker or host.
  Use when validating audio fidelity, codec conversion, packet reordering, or loss handling.
---

# urtp Audio Transcode & Jitter Testing

Test audio transcoding fidelity, jitter buffer slot reordering, packet loss concealment (PLC), and periodic silence handling against `urtp` running in Docker.

## Prerequisites

1. Ensure the `urtp` container with transcoding & jitter buffer is running:
   ```bash
   docker compose --env-file .env.transcode up -d
   # or: ./.agents/skills/urtp-docker/scripts/docker-env.sh transcode up
   ```
2. Ensure `assets/jediwarlock.wav` (or your chosen audio file) exists.
3. System packages: `ffmpeg` (required) and `ffplay` (optional, for live listening).

## Test Command Reference (`scripts/client.py`)

Run tests via the Python client against the Docker control port (`127.0.0.1:22222`):

```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio [options]
```

### Key Parameters

- `--wav <path>`: Input WAV file (default: `assets/jediwarlock.wav`).
- `--src-codec <opus|pcmu|pcma>`: Ingress codec sent to urtp (default: `opus`).
- `--dst-codec <pcmu|pcma|opus>`: Egress codec expected from urtp (default: `pcmu`).
- `--backend <libopus|ffmpeg>`: Transcoder backend (default: `libopus`).
- `--jb <ms>`: Jitter buffer latency in ms (default: `40`).
- `--duration <sec>`: Streaming duration limit (default: `10.0`, `0` = entire file).
- `--drop-rate <0.0-1.0>`: Simulated packet loss rate (e.g. `0.05` for 5% loss).
- `--drop-burst <N>`: Consecutive packets dropped per loss event (default: `1`).
- `--reorder-rate <0.0-1.0>`: Out-of-order packet arrival probability (e.g. `0.15`).
- `--reorder-delay <ms>`: Delivery delay for reordered packets (default: `35.0`).
- `--idle-interval <sec>`: Active streaming duration before pausing (e.g. `3.0`).
- `--idle-duration <sec>`: Duration of silence gap before resuming (e.g. `2.0`).
- `--play`: Stream transcoded audio directly to speakers via `ffplay`.
- `--record-wav <file>`: Capture egress audio to a local WAV file.

## Test Profiles & Scenarios

### 1. Clean Transcode Verification (Opus $\to$ PCMU)
Verifies clean baseline audio conversion without network loss:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio --duration 10.0
```

### 2. Jitter Buffer Reordering Stress
Injects 15% out-of-order packet delivery delayed by 35ms. Verifies `urtp` circular slot buffer reorders packets seamlessly:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio \
    --duration 15.0 \
    --reorder-rate 0.15 \
    --reorder-delay 35.0
```

### 3. Packet Loss & Loss Concealment (PLC)
Injects 5% packet loss with 2-packet bursts. Verifies `urtp` detects sequence gaps and invokes Opus/G.711 PLC to synthesize concealment frames:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio \
    --duration 15.0 \
    --drop-rate 0.05 \
    --drop-burst 2
```

### 4. Periodic Talkspurt Silence / VAD Simulation
Streams for 3 seconds, goes completely silent for 2 seconds (simulating VAD / silence suppression), then resumes:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio \
    --duration 20.0 \
    --idle-interval 3.0 \
    --idle-duration 2.0
```

### 5. Live Audio Listening During Stress
Listen to the transcoded audio in real time while injecting jitter and drops:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --audio \
    --duration 15.0 \
    --drop-rate 0.03 \
    --reorder-rate 0.10 \
    --play
```

## Interpreting Engine Telemetry

At test conclusion, inspect the engine summary block:

```text
======================================================================
[*] urtp Transcode & Jitter Buffer Engine Telemetry:
======================================================================
  Summary:
    - Packets transcoded in  : 171
    - Packets transcoded out : 205
    - Decoder/Encoder errors : 0
    - Jitter buffer state    : active (target depth=2)
    - Out-of-order reordered : 7
    - Late packets dropped   : 4
    - Loss Concealments (PLC): 34
```

- **`reordered > 0`**: Verifies out-of-order arrivals were caught and restored in sequence.
- **`plc > 0`**: Verifies lost packet gaps triggered synthetic audio generation without decoder crashes.
- **`errors == 0`**: Verifies clean decoding and encoding without buffer overflows.

## Helper Utility

Run standard test profiles via the included runner script:
- [`scripts/run-test.sh`](./scripts/run-test.sh)
