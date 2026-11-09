# ==============================================================================
# urtp (uring-rtp) Multi-Stage Dockerfile
# Stage 1: Build urtp with GNU C23 toolchain on GCC 14
# Stage 2: Ultra-minimal distroless runtime with cc-debian13:nonroot
# ==============================================================================

FROM gcc:14 AS builder

# Install build system and required library headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    pkg-config \
    liburing-dev \
    libssl-dev \
    libopus-dev \
    libavcodec-dev \
    libavutil-dev \
    libswresample-dev \
    git \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build-src

# Copy only build configuration and source tree
COPY CMakeLists.txt generate_version.cmake ./
COPY src/ ./src/

# Build release binary with GNU C23
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=gcc \
    -DURTP_ENABLE_WERROR=ON \
    -DURTP_BUILD_TESTS=OFF \
 && cmake --build build --parallel

# Prepare staging tree with binary and all dynamic library dependencies.
# Note: Debian 13 uses merged-usr (/lib -> usr/lib), so all copied libraries
# must be staged under /usr to prevent conflicts with root symlinks in distroless.
RUN mkdir -p /distroless-root/usr/local/bin /distroless-root/pcap \
 && chmod 777 /distroless-root/pcap \
 && cp build/urtp /distroless-root/usr/local/bin/urtp \
 && for lib in $(ldd build/urtp | grep -o '/[^ ]*' | sort -u); do \
      if [ -f "$lib" ]; then \
        real_file=$(realpath "$lib"); \
        canon_file=$(echo "$real_file" | sed -E 's|^/lib64|/usr/lib64|; s|^/lib/|/usr/lib/|'); \
        target_dir="/distroless-root$(dirname "$canon_file")"; \
        mkdir -p "$target_dir"; \
        cp -a "$real_file" "$target_dir/$(basename "$canon_file")" 2>/dev/null || true; \
        canon_lib=$(echo "$lib" | sed -E 's|^/lib64|/usr/lib64|; s|^/lib/|/usr/lib/|'); \
        if [ "$canon_lib" != "$canon_file" ]; then \
          sym_dir="/distroless-root$(dirname "$canon_lib")"; \
          mkdir -p "$sym_dir"; \
          cp -a "$lib" "$sym_dir/$(basename "$canon_lib")" 2>/dev/null || true; \
        fi; \
      fi; \
    done

# ==============================================================================
# Stage 2: Runtime image using distroless cc-debian13:nonroot
# ==============================================================================
FROM gcr.io/distroless/cc-debian13:nonroot

ENV LD_LIBRARY_PATH="/usr/local/lib64:/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib" \
    URTP_CONTROL_NG=22222 \
    URTP_CONTROL_TCP=22222 \
    URTP_MEDIA_IP=0.0.0.0

# Copy collected application binary and dynamic dependencies
COPY --from=builder /distroless-root /

# Media and Control Ports:
# - 22222/udp: Kamailio / OpenSIPS bencode ng control protocol
# - 22222/tcp: TCP control & Prometheus metrics endpoint (GET /metrics)
# - 30000-40000/udp: Symmetric RTP / RTCP media relay port range
EXPOSE 22222/udp
EXPOSE 22222/tcp
EXPOSE 30000-40000/udp

VOLUME ["/pcap"]

# Run urtp as entrypoint
ENTRYPOINT ["/usr/local/bin/urtp"]
CMD []
