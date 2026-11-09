---
name: urtp-video-relay
description: >-
  Executes automated end-to-end multi-stream audio and 1080p video relay tests, video RTCP PLI keyframe feedback,
  and forensic PCAP recording analysis using scripts/test-video-relay.sh and scripts/client.py.
  Use when testing VP8/H.264 video forwarding, stream isolation, packet throughput, or video PCAP recording.
---

# urtp Multi-Stream Video Relay & RTCP Feedback Testing

Execute automated end-to-end multi-stream audio (Opus) and 1080p video (VP8 / H.264) relay integration tests, verify jitter-buffer bypass stream isolation, validate RTCP Picture Loss Indication (PLI) feedback generation, and perform forensic PCAP capture analysis.

## Overview & Architecture

The multi-stream video subsystem in `urtp` mediates WebRTC bundled single-port streams and traditional dual-port SIP streams (Option B Gateway Mediation):
- **Zero-Allocation Routing**: Payload Type (PT) and SSRC demultiplexing without runtime heap allocations.
- **Stream Isolation**: High-throughput video packets strictly bypass the audio transcoder and jitter buffer circular slot queue.
- **Keyframe Feedback**: Synthetic RTCP PLI (RFC 4585) datagrams are triggered on endpoint latching to request immediate keyframes from video encoders.
- **High-Throughput IO**: Handled via 8,192-entry provided buffer rings, 4 MB socket buffers (`SO_RCVBUF`/`SO_SNDBUF`), and 1,024-packet libsrtp2 anti-replay windows.

---

## Canonical Test Runner (`test-video-relay.sh`)

[`test-video-relay.sh`](./scripts/test-video-relay.sh) is the canonical automated test harness. It compiles `urtp` (if needed), launches the daemon, orchestrates concurrent audio and video streaming via `ffmpeg`, verifies packet forwarding and throughput, and optionally analyzes captured PCAP recordings.

```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh [options]
```

### Options & Arguments

| Option | Argument | Description | Default |
| :--- | :--- | :--- | :--- |
| `-p`, `--preset` | `<name>` | Build preset: `release`, `debug`, or `sanitize` | `release` |
| `-c`, `--codec` | `<vp8\|h264>` | Video codec to stream | `vp8` |
| `-d`, `--duration` | `<sec>` | Streaming duration in seconds | `3` |
| `--resolution` | `<WxH>` | Video resolution | `1920x1080` |
| `--audio-bind` | `<port>` | urtp audio bind port | `30000` |
| `--video-bind` | `<port>` | urtp video bind port | `30002` |
| `--audio-dest` | `<port>` | Audio destination receiver port | `40000` |
| `--video-dest` | `<port>` | Video destination receiver port | `40002` |
| `-r`, `--record` | (none) | Enable urtp PCAP recording and verify captures | Disabled |
| `-s`, `--sqpoll` | (none) | Enable `io_uring` SQPOLL kernel thread | Disabled |
| `-h`, `--help` | (none) | Show usage information | — |

---

## Standard Test Profiles & Workflows

### 1. Baseline 1080p VP8 Multi-Stream Relay
Tests concurrent Opus audio (PT 111) and 1080p 30fps VP8 video (PT 96) relay with automated packet accounting:
```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh --preset release --codec vp8 --duration 3
```

### 2. High-Bitrate H.264 Video Relay
Tests H.264 (PT 97, `libx264` ultrafast zerolatency) video relay alongside audio:
```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh --preset release --codec h264 --duration 3
```

### 3. Kernel Polling (SQPOLL) Ultra-Low Latency Mode
Runs the multi-stream video pipeline with `io_uring` SQPOLL enabled, bypassing userspace syscall submission overhead:
```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh --preset release --codec vp8 --duration 3 -s
```

### 4. Memory Sanitizer Verification (ASan + UBSan)
Executes the full video relay pipeline compiled with AddressSanitizer and UndefinedBehaviorSanitizer to guarantee memory safety and zero bounds violations:
```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh --preset sanitize --codec vp8 --duration 2
```

### 5. Multi-Stream Video with Forensic PCAP Recording
Launches `urtp` with global PCAP recording (`-r <dir> -R`), relays media, and verifies that session PCAP recordings are created, non-empty, and valid:
```bash
./.agents/skills/urtp-video-relay/scripts/test-video-relay.sh --preset debug --codec vp8 --duration 3 --record
```

---

## Python Client Direct Invocation (`scripts/client.py`)

If `urtp` is already running (e.g. in Docker or started manually in another terminal):

```bash
# Connect to UNIX domain control socket:
python3 scripts/client.py -s /tmp/urtp.sock --video-test --video-codec vp8 --duration 3.0

# Connect to TCP or UDP NG control port:
python3 scripts/client.py -s 127.0.0.1:22222 --video-test --video-codec h264 --duration 5.0
```

---

## Forensic PCAP Analysis for Video Streams

When `--record` is used, `urtp` writes per-session PCAPs to the specified recording directory:
- `session_30000.pcap`: Ingress/egress Opus audio RTP packets.
- `session_30002.pcap`: Ingress/egress VP8 or H.264 video RTP packets.

### Inspecting Video Packets via `tshark`
```bash
# Count video RTP packets by payload type (e.g. PT 96 = VP8)
tshark -r /tmp/urtp_pcap_*/session_30002.pcap -Y "rtp.pt == 96" | wc -l

# Inspect RTP sequence numbers and frame marker bits
tshark -r /tmp/urtp_pcap_*/session_30002.pcap -T fields \
    -e frame.number -e rtp.seq -e rtp.timestamp -e rtp.marker -c 20
```

### Extracting or Playing Captured Video via `ffmpeg` / `ffplay`
```bash
# Generate SDP file for video RTP decoding
cat << 'EOF' > /tmp/video.sdp
v=0
o=- 0 0 IN IP4 127.0.0.1
s=Video-PCAP
c=IN IP4 127.0.0.1
t=0 0
m=video 30002 RTP/AVP 96
a=rtpmap:96 VP8/90000
EOF

# Play extracted video RTP frames
ffplay -protocol_whitelist file,udp,rtp -i /tmp/video.sdp
```

---

## Verification & Engine Telemetry

During and after video relay execution, check:
1. **Zero Drops / Full Frame Rate**: Verified by `client.py` packet counter matching `rate * duration`.
2. **Audio/Video Stream Isolation**: Inspect engine status (`STATUS`) to confirm video packets do not increment jitter buffer depth or transcode counters.
3. **Keyframe Synthesis**: Verify `RTCP PLI` packets emitted upon latching by checking `pcap` captures or running unit tests:
   ```bash
   ./scripts/build.sh test
   ```
