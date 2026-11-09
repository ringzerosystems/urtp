# urtp (uring-rtp)

[![RingZero Systems](https://img.shields.io/badge/Vendor-RingZero_Systems_LLC-00599C?style=for-the-badge&logo=c&logoColor=white)](https://ringzerosystems.com)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-red.svg?style=for-the-badge)](./LICENSE)
[![Commercial License](https://img.shields.io/badge/License-Commercial-blue.svg?style=for-the-badge)](./LICENSE-COMMERCIAL.md)
[![C23 GNU](https://img.shields.io/badge/C23-GNU_C23-00599C?style=for-the-badge&logo=c&logoColor=white)](https://en.cppreference.com/w/c/23)

**`urtp`** is a high-throughput, sub-millisecond latency RTP media proxy built for modern Linux.

Written in **GNU C23** (`-std=gnu23`), `urtp` eliminates traditional `epoll`, `recvmsg`, and `sendmsg` syscall bottlenecks by leveraging Linux 6.0+ **`io_uring`**. Utilizing asynchronous multishot receives, kernel-managed provided buffer rings, and submission queue polling (`SQPOLL`), `urtp` executes zero-syscall, zero-copy media forwarding entirely in user space.

---

## Table of Contents

- [urtp (uring-rtp)](#urtp-uring-rtp)
  - [Table of Contents](#table-of-contents)
  - [Architectural Highlights](#architectural-highlights)
  - [Key Features](#key-features)
    - [1. io\_uring Asynchronous Reactor](#1-io_uring-asynchronous-reactor)
    - [2. Zero-Allocation Hot Path \& C23 Primitives](#2-zero-allocation-hot-path--c23-primitives)
    - [3. Symmetric RTP \& NAT Latching](#3-symmetric-rtp--nat-latching)
    - [4. Kamailio \& OpenSIPS Control (`ng` Protocol)](#4-kamailio--opensips-control-ng-protocol)
    - [5. Interactive Control Plane (UNIX / TCP CLI)](#5-interactive-control-plane-unix--tcp-cli)
    - [6. RTCP Multiplexing (`rtcp-mux`, RFC 5761)](#6-rtcp-multiplexing-rtcp-mux-rfc-5761)
    - [7. Hardware-Accelerated SRTP \& SDES](#7-hardware-accelerated-srtp--sdes)
    - [8. WebRTC Interoperability (ICE \& DTLS-SRTP)](#8-webrtc-interoperability-ice--dtls-srtp)
    - [9. Asynchronous PCAP Call Recording](#9-asynchronous-pcap-call-recording)
    - [10. Real-Time Audio Transcoding](#10-real-time-audio-transcoding)
  - [Functional Domain Structure](#functional-domain-structure)
  - [Requirements \& Dependencies](#requirements--dependencies)
    - [Operating System \& Toolchain](#operating-system--toolchain)
    - [Required Libraries](#required-libraries)
  - [Building \& Testing](#building--testing)
    - [Build Presets](#build-presets)
    - [Running Test Suite](#running-test-suite)
  - [Command-Line Options](#command-line-options)
  - [Integration \& Examples](#integration--examples)
    - [Kamailio Integration](#kamailio-integration)
    - [Interactive Text CLI Control](#interactive-text-cli-control)
    - [Automated Relay Verification](#automated-relay-verification)
    - [Performance Profiling](#performance-profiling)
    - [Deployment Profiles (Docker Compose)](#deployment-profiles-docker-compose)
    - [Monitoring \& Telemetry (Prometheus \& Grafana)](#monitoring--telemetry-prometheus--grafana)
  - [Standards \& RFC Compliance](#standards--rfc-compliance)
  - [License \& Commercial Use](#license--commercial-use)

---

## Architectural Highlights

Traditional VoIP media proxies waste massive CPU cycles switching context between user space and kernel space on every UDP packet. Under high traffic (tens of thousands of concurrent audio/video channels), `epoll` wakeups and individual `recvmsg`/`sendmsg` syscalls saturate kernel execution time.

`urtp` inverts this architecture:

- **Multishot Receives:** Sockets are armed once via `io_uring_prep_recvmsg_multishot`. The kernel continuously consumes incoming packets and notifies user space via Completion Queue Entries (CQEs) without re-arming.
- **Kernel-Provided Buffer Rings:** User space registers contiguous memory arenas (`io_uring_buf_ring`). The kernel writes incoming UDP payloads directly into registered buffer IDs without allocation.
- **Zero-Syscall Relay (`SQPOLL`):** With `IORING_SETUP_SQPOLL`, an isolated kernel thread polls the submission queue. Packet relaying becomes pure shared-memory ring writes, achieving zero system calls during media routing.
- **Predictable Determinism:** Zero dynamic heap allocation (`malloc`/`free`) on the media forwarding path. All session descriptors, scratchpads, and packet buffers are statically pre-allocated and cache-line aligned (`alignas(64)`).

For detailed subsystem architecture diagrams, domain boundaries, and execution lifecycles, see the [Functional Domain Architecture in ARCHITECTURE.md](ARCHITECTURE.md#2-functional-domain-architecture--directory-layout).

---

## Key Features

### 1. io_uring Asynchronous Reactor

- **Multishot Networking:** Operates `io_uring_prep_recvmsg_multishot` on dual-stack UDP sockets, allowing the Linux kernel to drain network interfaces into userspace buffers automatically.

- **Provided Buffer Management:** Registers ring buffers (`io_uring_setup_buf_ring`) mapped into hardware page boundaries with zero per-packet allocation overhead.
- **SQPOLL Kernel Polling:** Configurable `--sqpoll` execution runs submission queue polling in the kernel, turning packet submission into atomic memory stores without syscall transitions.

### 2. Zero-Allocation Hot Path & C23 Primitives

- Strictly written to the **GNU C23** standard (`-std=gnu23`) using Clang 19+.

- Utilizes `nullptr`, `constexpr`, `alignas(64)`, `auto`, and `restrict` pointer semantics throughout hot paths.
- Zero dynamic memory allocations (`malloc`/`free`) after boot initialization. Memory pools (`memory_pool_t`), zero-copy spans (`span_t`), and non-owning string views (`sv_t`) govern packet routing.

### 3. Symmetric RTP & NAT Latching

- Solves private NAT traversal issues where SIP endpoints advertise non-routable addresses (RFC 1918).

- Inspects incoming UDP datagrams to dynamically latch onto the peer's actual public IP and port, transparently directing subsequent media return traffic to the latched endpoint.

### 4. Kamailio & OpenSIPS Control (`ng` Protocol)

- Direct drop-in replacement protocol for Sipwise `rtpengine` control modules over UDP (port `22222`).

- Zero-allocation Bencode parser and serializer handling commands:
  - `ping` (health check & cookie echo)
  - `offer` (caller SDP processing and media allocation)
  - `answer` (callee SDP processing and bridge completion)
  - `delete` (session teardown)
  - `query` & `list` (runtime session statistics)
  - `start recording` & `stop recording` (per-call packet capture)
- Full SDP parsing and rewriting: transforms IP addresses, media ports, and negotiates `a=rtcp-mux`, `a=crypto`, `a=fingerprint`, and ICE parameters.

### 5. Interactive Control Plane (UNIX / TCP CLI)

- Dedicated control interface for integration and CLI scripting supporting both UNIX domain sockets (`/tmp/urtp.sock`) and TCP ports.

- Commands supported:
  - `ALLOCATE PORT <bind_port> -> FORWARD TO <dest_ip>:<dest_port> [LATCH] [RTCP_MUX]`
  - `BRIDGE <port_a> <port_b>`
  - `LATCH <port> [ENABLE|DISABLE|RAW]`
  - `TRANSCODE <port> [backend=libopus|ffmpeg] [src=<codec>] [dst=<codec>]`
  - `RECORD <port|CALL id> [START|STOP]`
  - `STATUS`
  - `DELETE <port>`

### 6. RTCP Multiplexing (`rtcp-mux`, RFC 5761)

- Demultiplexes RTP (media) and RTCP (control/metrics) arriving on the exact same UDP port by inspecting the payload type byte.

- Routes RTCP packets to dedicated RTCP peer ports or preserves unified single-port multiplexing end-to-end.

### 7. Hardware-Accelerated SRTP & SDES

- Seamless cryptographic bridging between plain RTP and Secure RTP (RFC 3711) using `libsrtp2`.

- SDES key negotiation (RFC 4568) supporting crypto suites:
  - `AES_CM_128_HMAC_SHA1_80`
  - `AES_256_CM_HMAC_SHA1_80`
- In-line Base64 encoder/decoder for zero-allocation SDP key parsing and emission.

### 8. WebRTC Interoperability (ICE & DTLS-SRTP)

- **ICE / STUN Binding:** RFC 5389 message parser and responder handling STUN binding requests from WebRTC browsers directly on media sockets.

- **DTLS 1.2 Handshake:** OpenSSL memory BIO-driven DTLS state machine operating over UDP datagrams.
- **DTLS-SRTP Key Derivation:** Implements RFC 5764 to extract master encryption keys directly from the DTLS handshake and install them into the SRTP session engine.
- **Certificate Fingerprints:** Computes and injects SHA-256 certificate fingerprints (`a=fingerprint:sha-256`) into rewritten SDPs.

### 9. Asynchronous PCAP Call Recording

- Taps live media sessions to standard PCAP files (`.pcap`) for lawful interception, compliance, and quality debugging.

- Submits asynchronous file writes via `io_uring_prep_writev` on the **exact same reactor ring** as network traffic—ensuring disk I/O never blocks media routing.

### 10. Real-Time Audio Transcoding

- Modular audio transcoding pipeline supporting both `libopus` and FFmpeg (`libavcodec`, `libswresample`).

- In-flight bi-directional conversion between:
  - **Opus** (48 kHz wideband)
  - **G.711 µ-law / PCMU** (8 kHz narrowband)
  - **G.711 A-law / PCMA** (8 kHz narrowband)
- Pre-allocated static PCM scratchpads (`alignas(64)`) with automated RTP timestamp scaling and sequence re-stamping.

---

## Functional Domain Structure

The repository enforces a strict, unidirectional layered domain structure:

```text
src/
├── core/       # Foundational primitives: memory pool, spans, string views, hashing, cache macros
├── ring/       # io_uring reactor engine: provided buffer rings, CQE dispatch, user_data tagging
├── net/        # Network layer: UDP sockets, RTP/RTCP parsing, session table, STUN/ICE, PCAP capture
├── crypto/     # Cryptographic plane: Base64, SDES (RFC 4568), libsrtp2 sessions, OpenSSL DTLS engine
├── media/      # Media engine: Audio transcoding pipeline (libopus, FFmpeg, sample-rate converters)
├── control/    # Control plane: Bencode codec, ng protocol engine, SDP rewriter, UNIX/TCP text CLI
├── server.c    # Reactor loop, signal handling, CQE routing, and subsystem lifecycle
└── main.c      # CLI entry point and server startup
```

---

## Requirements & Dependencies

### Operating System & Toolchain

- **OS:** Modern Linux kernel **6.0+** (tested on Debian / Ubuntu).
- **Compiler:** **Clang 19+** supporting `-std=gnu23`.
- **Build System:** **CMake 3.28+**, `ninja-build` (or `make`), and **`just`** command runner.

### Required Libraries

Install the development dependencies via `apt`:

```bash
sudo apt update && sudo apt install -y \
    clang \
    cmake \
    ninja-build \
    just \
    pkg-config \
    liburing-dev \
    libssl-dev \
    libsrtp2-dev \
    libopus-dev \
    libavcodec-dev \
    libavutil-dev \
    libswresample-dev
```

---

## Building & Testing

`urtp` provides a comprehensive [`Justfile`](Justfile) (using the [`just`](https://github.com/casey/just) command runner) as well as canonical bash scripts in [`scripts/`](scripts/) for configuring CMake presets, building binaries, executing tests, and managing container environments.

Run `just` or `just help` to display all categorized recipes:

```bash
just
```

### Build Presets

```bash
# Debug Build (default with -Werror and strict warnings)
just build        # or: just debug

# Optimized Release Build
just release      # or: just build release

# Sanitizer Build (AddressSanitizer and UndefinedBehaviorSanitizer enabled)
just sanitize     # or: just build sanitize

# Clean build artifacts (purges build/ and compile_commands.json using trash)
just clean

# Clean and rebuild from scratch
just rebuild
```

### Running Test Suite

`urtp` includes 20 comprehensive unit test targets built on the Unity testing framework:

```bash
# Run test suite on Debug build
just test         # or: just check

# Build and immediately run tests
just build-test

# Run test suite under AddressSanitizer and UndefinedBehaviorSanitizer
just test-sanitize

# Run test suite on Optimized Release build
just test-release
```

Test coverage includes:

1. `test_string_view` — Zero-allocation string slicing and comparison
2. `test_span` — Non-owning byte slices and bounds validation
3. `test_hash` — Fast string and pointer hash functions
4. `test_memory` — Static memory pools and alignment guarantees
5. `test_ring` — `io_uring` initialization, buffer rings, and tagging
6. `test_net` — UDP socket creation, dual-stack binding, and session table
7. `test_control` — Text control protocol parsing (`ALLOCATE`, `BRIDGE`, `DELETE`)
8. `test_bencode` — Bencode dictionary and list serialization/parsing
9. `test_sdp` — SDP attribute parsing and IP/port rewriting
10. `test_ng` — Kamailio/OpenSIPS `ng` protocol commands (`offer`, `answer`, `delete`, `query`)
11. `test_base64` — RFC 4648 Base64 encode and decode validation
12. `test_sdes` — RFC 4568 SDES crypto attribute parsing and key generation
13. `test_srtp` — SRTP/SRTCP encryption and decryption with `libsrtp2`
14. `test_stun` — STUN Binding Request decode and response generation
15. `test_dtls` — DTLS 1.2 handshake and RFC 5764 DTLS-SRTP key derivation
16. `test_pcap` — Asynchronous PCAP packet logging via `io_uring_prep_writev`
17. `test_transcode` — Audio transcoding between Opus and G.711 (PCMU/PCMA)

---

## Command-Line Options

`urtp` configuration follows standard three-tier precedence:

> **Defaults** &lt; **Environment Variables (`URTP_*`)** &lt; **Command-Line Switches**

Command-line switches override environment variables, which in turn override compiled-in defaults.

```text
Usage: urtp [options]

Options:
  -c, --control-sock <path>      UNIX domain control socket path (default: /tmp/urtp.sock) [env: URTP_CONTROL_SOCK]
  -t, --control-tcp <port>       TCP control port (optional) [env: URTP_CONTROL_TCP]
  -n, --control-ng <port>        UDP NG control port for Kamailio/OpenSIPS (default: 22222) [env: URTP_CONTROL_NG]
  -m, --media-ip <ip>            Advertised media IP for SDP rewrite (default: 127.0.0.1) [env: URTP_MEDIA_IP]
  -r, --record-dir <path>        Volume/directory path for PCAP call captures [env: URTP_RECORD_DIR]
  -R, --record-all               Automatically record all media streams to PCAP [env: URTP_RECORD_ALL]
  -e, --entries <count>          io_uring submission queue entries (default: 1024) [env: URTP_ENTRIES]
  -b, --buffers <count>          Buffer ring entries (default: 4096) [env: URTP_BUFFERS]
  -s, --sqpoll                   Attempt io_uring SQPOLL kernel thread [env: URTP_SQPOLL]
  -T, --transcoder <backend>     Audio transcoding backend: libopus, ffmpeg, none (default: none) [env: URTP_TRANSCODER]
  -C, --transcode-codec <codec>  Default target codec: pcmu, pcma, opus, auto (default: auto) [env: URTP_TRANSCODE_CODEC]
  -j, --jitter-buffer <ms>       Jitter buffer target latency in ms (transcoding only, default: 0=disabled) [env: URTP_JITTER_BUFFER]
  -w, --shutdown-timeout <sec>   Timeout in seconds to wait for active sessions to drain (default: 30, 0=immediate) [env: URTP_SHUTDOWN_TIMEOUT]
  -I, --inactivity-timeout <sec> Inactivity timeout in seconds for active media (default: 60) [env: URTP_INACTIVITY_TIMEOUT]
  -S, --setup-timeout <sec>      Setup timeout in seconds for unconfirmed sessions (default: 30) [env: URTP_SETUP_TIMEOUT]
  -M, --metrics-interval <sec>   Periodic console telemetry summary interval (default: 0=disabled) [env: URTP_METRICS_INTERVAL]
  -v, --version                  Display version and build information
  -h, --help                     Display this help message
```

---

## Integration & Examples

### Kamailio Integration

`urtp` acts as a high-performance replacement for `rtpengine`. In your `kamailio.cfg`:

```cfg
loadmodule "rtpengine.so"

# Point to urtp's UDP NG control port
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:22222")

route[RELAY_MEDIA] {
    if (is_method("INVITE")) {
        if (has_body("application/sdp")) {
            # Intercept Offer: Rewrite SDP to point to urtp media IP
            rtpengine_offer("replace-origin replace-session-connection ICE=force RTP/SAVPF");
        }
    } else if (is_method("ACK")) {
        if (has_body("application/sdp")) {
            # Intercept Answer
            rtpengine_answer("replace-origin replace-session-connection");
        }
    } else if (is_method("BYE")) {
        # Teardown Media Session
        rtpengine_delete();
    }
}
```

### Interactive Text CLI Control

You can interact directly with `urtp` via its UNIX domain socket using `nc`, `socat`, or the included [`scripts/client.py`](scripts/client.py):

```bash
# Start urtp daemon
./build/release/urtp -c /tmp/urtp.sock -n 22222 -m 198.51.100.1 &

# Query server status
echo "STATUS" | nc -U /tmp/urtp.sock

# Allocate a relay port forwarding to a remote client
echo "ALLOCATE PORT 10000 -> FORWARD TO 203.0.113.5:20000 LATCH" | nc -U /tmp/urtp.sock

# Bridge two ports bidirectionally
echo "BRIDGE 10000 10002" | nc -U /tmp/urtp.sock

# Enable on-the-fly transcoding
echo "TRANSCODE 10000 backend=libopus dst=pcmu" | nc -U /tmp/urtp.sock

# Start call recording for a port
echo "RECORD 10000 START" | nc -U /tmp/urtp.sock

# Teardown port
echo "DELETE 10000" | nc -U /tmp/urtp.sock
```

### Automated Relay Verification

Execute high-load automated relay tests using `just test-relay` (or [`scripts/test-relay.sh`](scripts/test-relay.sh)):

```bash
# Run 10,000 UDP packet relay benchmark with symmetric RTP latching
just test-relay preset=release count=10000 latch=true

# Run relay test with io_uring SQPOLL kernel thread enabled
just test-relay preset=release count=50000 sqpoll=true
```

### Performance Profiling

Profile CPU cycles, hardware branch predictions, and kernel offloading using `just profile` (or [`scripts/profile.sh`](scripts/profile.sh)):

```bash
# Start profiling the running urtp daemon via Linux perf (DWARF call graph at 99Hz)
just profile

# Inspect profiling results
just perf-report
```

### Deployment Profiles (Docker Compose)

`urtp` provides purpose-built environment profiles sharing a single unified [`docker-compose.yml`](docker-compose.yml) manifest and container image. Manage them effortlessly via `just`:

| Environment Profile | Features Enabled | Description |
| :--- | :--- | :--- |
| [`.env`](.env) / [`.env.example`](.env.example) | **High-Throughput Relay (Default)** | Ultra-low-latency, zero-copy pure media relay (no disk I/O, no transcoding overhead). |
| [`.env.transcode`](.env.transcode) | **Transcoding + Jitter Buffer** | Real-time audio transcoding (Opus <-> G.711) with adaptive 40ms jitter buffer, PLC, and PCAP capture mount. |
| [`.env.pcap`](.env.pcap) | **PCAP Forensic Capture** | Pure media relay with continuous forensic packet recording to `./pcap` for call analysis & compliance. |
| [`.env.full`](.env.full) | **Full Feature Suite** | Complete stack: Transcoding, Jitter Buffer, continuous PCAP recording, Prometheus & Grafana. |
| [`.env.sqpoll`](.env.sqpoll) | **Kernel SQPOLL Mode** | Dedicated io_uring submission polling thread with tuned ring queues (4096 SQ/CQ, 8192 buffers). |

```bash
# 1. Standard Zero-Copy Media Relay (Default)
just docker-up relay          # or: docker compose up -d

# 2. Audio Transcoding with Adaptive Jitter Buffer (40ms) and PLC
just docker-up transcode      # or: docker compose --env-file .env.transcode up -d

# 3. Dedicated PCAP Call Recording Profile (Captures to ./pcap)
just docker-up pcap           # or: docker compose --env-file .env.pcap up -d

# 4. Full Observability & Transcoding & Forensics Stack
just docker-up full           # or: docker compose --env-file .env.full up -d

# 5. High-Throughput Kernel SQPOLL Mode (100k+ PPS)
just docker-up sqpoll         # or: docker compose --env-file .env.sqpoll up -d

# Check container and control plane health
just docker-status transcode  # or: just status

# Stop and tear down container environment
just docker-down              # or: just down
```

### Monitoring & Telemetry (Prometheus & Grafana)

`urtp` exposes real-time Prometheus metrics over its TCP control port (`GET /metrics` or CLI command `STATUS METRICS`). Every compose profile includes Prometheus and Grafana pre-wired:

```bash
# Scrape metrics directly via curl
curl http://localhost:22222/metrics

# Access Grafana dashboard (anonymous authentication enabled, no login required)
# Open in browser: http://localhost:3000
```

- **Grafana:** `http://localhost:3000` (Pre-configured with anonymous Admin access and the pre-loaded `urtp (uring-rtp) Media Proxy` dashboard including transcoding, jitter buffer, and io_uring health panels).
- **Prometheus:** `http://localhost:9090` (Scraping `urtp:22222/metrics` every 2 seconds).

---

## Standards & RFC Compliance

| RFC / Standard | Protocol / Feature | Implementation Details |
| :--- | :--- | :--- |
| **RFC 3550** | RTP: Transport Protocol for Real-Time Applications | Header parsing, sequence tracking, timestamp scaling |
| **RFC 3551** | RTP Profile for Audio and Video Conferences | Payload type mappings (PCMU, PCMA, Opus) |
| **RFC 3711** | SRTP: Secure Real-time Transport Protocol | Packet protection and unprotection via `libsrtp2` |
| **RFC 4568** | SDES: Security Descriptions for Media Streams | Key negotiation and inline Base64 attributes |
| **RFC 5389** | STUN: Session Traversal Utilities for NAT | Binding request parsing and response creation |
| **RFC 5761** | RTCP-MUX: Multiplexing RTP and RTCP | Single-port demultiplexing based on payload type |
| **RFC 5764** | DTLS-SRTP: Datagram TLS Extension for SRTP | Key extraction and cryptographic context installation |
| **RFC 8445** | ICE: Interactive Connectivity Establishment | SDP candidate parsing and WebRTC peer connectivity |

## License & Commercial Use

Copyright &copy; 2026 Mark Horila / RingZero Systems LLC.

`urtp` is dual-licensed:

1. **Open Source ([AGPL-3.0](./LICENSE)):** Free for open-source development, academic evaluation, and workflows that comply with the GNU Affero General Public License v3.0.
2. **Commercial License ([LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md)):** Organizations deploying, embedding, or modifying `urtp` in proprietary commercial environments or hosted internal developer platforms without AGPL-3.0 copyleft obligations may obtain a commercial license from **RingZero Systems LLC**.

For commercial licensing, enterprise pilots, or custom integration sprints, contact:

- **Web:** [https://ringzerosystems.com](https://ringzerosystems.com)
- **Direct:** `licensing@ringzerosystems.com`
