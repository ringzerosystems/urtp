---
name: urtp-docker
description: >-
  Manages urtp Docker containers, builds images, and orchestrates multi-container
  test topologies (pure forwarding, transcoding + jitter buffer, and Prometheus/Grafana monitoring stack).
  Use when launching, testing, or diagnosing urtp services running in Docker.
---

# urtp Docker Environment Management

Orchestrate, build, and verify `urtp` containers and monitoring stacks for integration testing using a single canonical `docker-compose.yml` with purpose-built `.env` profiles.

## Environment Profiles (`.env.*`)

`urtp` configuration is driven via native `URTP_*` environment variables loaded through targeted `.env` profile files in the repository root:

| Profile File | Features Enabled | Use Case | Command |
|---|---|---|---|
| `.env.transcode` | Transcoding (Opus $\leftrightarrow$ G.711), 40ms Jitter Buffer, PCAP capture (`./pcap`), Prometheus, Grafana | **Recommended for audio, transcode, and jitter testing** | `docker compose --env-file .env.transcode up -d --build` |
| `.env.full` | All features enabled with auto-transcode and full observability | Full end-to-end regression testing | `docker compose --env-file .env.full up -d --build` |
| `.env.pcap` | Pure relay + automatic PCAP recording to `./pcap` | Forwarding-only PCAP inspection | `docker compose --env-file .env.pcap up -d --build` |
| `.env.sqpoll` | SQPOLL kernel polling + 4096 SQ/CQ & 8192 buffer ring tuning | 100k+ pps high-throughput benchmarks | `docker compose --env-file .env.sqpoll up -d --build` |
| `.env` | Plain zero-copy media forwarding + Prometheus/Grafana | Baseline forwarding and low-overhead testing | `docker compose up -d --build` |

## Required Privileges & Kernel Settings

`io_uring` requires specific container security and resource limits (pre-configured in `docker-compose.yml`):
- `security_opt: [seccomp:unconfined]`: Required for `io_uring_setup` and `io_uring_enter` syscalls.
- `cap_add: [SYS_NICE]`: Required if testing SQPOLL kernel polling thread (`URTP_SQPOLL=true`).
- `ulimits: memlock: -1`: Required for registered kernel buffer rings.

## Common Workflows

### 1. Build and Start Transcode & Jitter Testing Stack

```bash
# Ensure PCAP output directory exists
mkdir -p ./pcap

# Build and start urtp with transcoding profile + Prometheus + Grafana in background
docker compose --env-file .env.transcode up -d --build

# Alternatively, using the helper script:
./.agents/skills/urtp-docker/scripts/docker-env.sh transcode up
```

### 2. Verify Container Health and Readiness

```bash
# Check running containers
docker compose ps

# Inspect urtp startup logs
docker compose logs urtp

# Verify TCP control plane & HTTP metrics response
curl -s http://127.0.0.1:22222/metrics | head -n 15

# Verify control protocol responsiveness via client.py
python3 scripts/client.py -s 127.0.0.1:22222 -c "STATUS"
```

### 3. Live Log Streaming During Tests

```bash
# Stream urtp logs live
docker compose logs -f urtp
```

### 4. Stop and Clean Up Containers

```bash
# Stop containers and remove volumes
docker compose down -v

# Or using the helper script:
./.agents/skills/urtp-docker/scripts/docker-env.sh down
```

## Helper Utility

Use the included helper script for quick status checks and lifecycle commands:
- [`scripts/docker-env.sh`](./scripts/docker-env.sh)

```bash
# Usage examples:
./.agents/skills/urtp-docker/scripts/docker-env.sh transcode up
./.agents/skills/urtp-docker/scripts/docker-env.sh full up
./.agents/skills/urtp-docker/scripts/docker-env.sh status
./.agents/skills/urtp-docker/scripts/docker-env.sh down
```
