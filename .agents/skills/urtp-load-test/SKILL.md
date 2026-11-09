---
name: urtp-load-test
description: >-
  Executes high-throughput UDP media forwarding benchmarks, symmetric RTP NAT latching tests,
  and watchdog connection reaper tests against urtp running in Docker or host.
  Use when benchmarking throughput, testing packet pacing, or verifying connection lifecycles.
---

# urtp High-Throughput Media & Relay Load Testing

Execute zero-copy UDP forwarding benchmarks, symmetric RTP NAT latching tests, and watchdog connection reaper tests against `urtp` running in Docker.

## Prerequisites

Start the baseline or high-performance `urtp` Docker Compose profile:
```bash
docker compose up -d
# or for full transcoding/recording stack:
docker compose --env-file .env.full up -d
# or for high-throughput SQPOLL kernel polling:
docker compose --env-file .env.sqpoll up -d
```

Ensure control port `22222` and media ports `30000-30100` are mapped to host.

## Benchmark & Load Test Commands (`scripts/client.py`)

### 1. Burst Load Test (Packet Relay Speed)
Streams 10,000 UDP media packets through the proxy as fast as possible, measuring packet loss and PPS throughput:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --test -n 10000 --bind-port 30002 --dest-port 20000
```

### 2. Sustained Media Streaming Test (Real-Time Pacing)
Streams UDP media for 30 seconds paced at 50 packets per second (standard VoIP 20ms pacing):
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --test -d 30.0 -r 50.0 --bind-port 30002 --dest-port 20000
```

### 3. Symmetric RTP & NAT Latching Verification
Allocates an unconfirmed latching port, sends media from a dynamic client socket, and verifies that `urtp` latches onto the client's source IP and port for symmetric return traffic:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --test -n 2000 --latch --bind-port 30002
```

### 4. Watchdog Session Cleanup & Reaper Verification
Allocates 5 idle sessions, injects initial RTP packets to establish active media state, leaves them silent, and observes the background watchdog sweeper reap them after the inactivity timeout:
```bash
python3 scripts/client.py -s 127.0.0.1:22222 --watchdog --idle-sessions 5 --bind-port 30010
```

## Grafana & Prometheus Observability

While load tests are running, inspect real-time performance in Grafana and Prometheus:
- **Grafana Dashboard**: Open `http://localhost:3000` (Anonymous Admin access pre-configured).
  - Inspect **Throughput (Packets/sec & Mbits/sec)**.
  - Inspect **Kernel Memory & Buffer Ring Utilization**.
  - Inspect **Stream Inactivity & Watchdog Reaps**.
- **Raw Prometheus Metrics**:
  ```bash
  curl -s http://127.0.0.1:22222/metrics | grep -E "urtp_packets|urtp_active_sessions"
  ```

## Helper Utility

Run standard load test suites via the included runner script:
- [`scripts/benchmark.sh`](./scripts/benchmark.sh)
