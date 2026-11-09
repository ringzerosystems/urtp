#!/usr/bin/env python3
"""urtp test client: automated UDP relay testing and interactive control CLI."""

import argparse
import os
import socket
import subprocess
import sys
import threading
import time

def send_control(target: str, cmd: str) -> str:
    if (":" in target) or target.startswith("tcp://"):
        target_clean = target.removeprefix("tcp://")
        host, port_str = target_clean.split(":", 1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((host, int(port_str)))
            s.sendall(cmd.strip().encode("utf-8") + b"\n")
            return s.recv(4096).decode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect(target)
        s.sendall(cmd.strip().encode("utf-8") + b"\n")
        return s.recv(4096).decode("utf-8")

def detect_dest_ip(explicit_ip: str | None, sock_target: str) -> str:
    if explicit_ip:
        return explicit_ip
    if (":" in sock_target) or sock_target.startswith("tcp://"):
        import subprocess
        try:
            gw = subprocess.check_output(
                ["docker", "inspect", "urtp", "--format", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}"],
                stderr=subprocess.DEVNULL,
                timeout=1.0,
            ).decode("utf-8").strip()
            if gw:
                return gw
        except Exception:
            pass
    return "127.0.0.1"

def punch_conntrack(sock: socket.socket, target_port: int) -> None:
    """Send a small UDP packet to punch through Linux conntrack / UFW for Docker bridge networking."""
    import subprocess
    targets = [("127.0.0.1", target_port)]
    try:
        cip = subprocess.check_output(
            ["docker", "inspect", "urtp", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
            stderr=subprocess.DEVNULL,
            timeout=0.5,
        ).decode("utf-8").strip()
        if cip:
            targets.append((cip, target_port))
    except Exception:
        pass
    for ip, port in targets:
        try:
            sock.sendto(b"\x00", (ip, port))
        except Exception:
            pass

def run_relay_test(
    sock_path: str,
    bind_port: int,
    dest_port: int,
    count: int,
    latch: bool = False,
    duration: float = 0.0,
    pps: float = 50.0,
    dest_ip: str | None = None,
) -> None:
    target_ip = detect_dest_ip(dest_ip, sock_path)
    if latch:
        print(f"[*] Allocating latching relay port {bind_port} (ignoring fake SDP 192.168.1.99:9999) via {sock_path}...")
        resp = send_control(sock_path, f"ALLOCATE PORT {bind_port} -> FORWARD TO 192.168.1.99:9999 LATCH")
    else:
        print(f"[*] Allocating relay port {bind_port} -> {target_ip}:{dest_port} via {sock_path}...")
        resp = send_control(sock_path, f"ALLOCATE PORT {bind_port} -> FORWARD TO {target_ip}:{dest_port}")
    print(f"[<] {resp.strip()}")
    if not resp.startswith("OK"):
        sys.exit(1)

    import struct
    import threading

    received = 0
    done = threading.Event()

    if latch:
        # In Symmetric RTP, the same socket sends and receives media
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.settimeout(1.0)
        rx_sock = sock
        tx_sock = sock
    else:
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rx_sock.bind(("0.0.0.0", dest_port))
        rx_sock.settimeout(1.0)
        punch_conntrack(rx_sock, bind_port)
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def receiver():
        nonlocal received
        while not done.is_set():
            try:
                data, _ = rx_sock.recvfrom(2048)
                if data.startswith(b"RTP_PKT_") or (b"RTP_PKT_" in data):
                    received += 1
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    sent = 0
    start_time = time.perf_counter()

    if duration > 0:
        target_pps = max(pps, 1.0)
        interval = 1.0 / target_pps
        print(f"[*] Streaming UDP media to 127.0.0.1:{bind_port} for {duration:.1f}s at {target_pps:.0f} PPS...")
        next_send = time.perf_counter()
        end_time = start_time + duration
        last_log = start_time

        while time.perf_counter() < end_time:
            now = time.perf_counter()
            if latch:
                hdr = struct.pack("!BBHII", 0x80, 0, sent & 0xFFFF, (sent * 160) & 0xFFFFFFFF, 0xCAFE)
                payload = hdr + f"RTP_PKT_{sent:08d}".encode("utf-8")
            else:
                payload = f"RTP_PKT_{sent:08d}".encode("utf-8")
            tx_sock.sendto(payload, ("127.0.0.1", bind_port))
            sent += 1

            if now - last_log >= 2.0:
                cur_rate = received / (now - start_time) if (now - start_time) > 0 else 0
                print(f"  [>] Elapsed: {now - start_time:.1f}s | Sent: {sent} | Received: {received} ({cur_rate:.1f} PPS)")
                last_log = now

            next_send += interval
            sleep_sec = next_send - time.perf_counter()
            if sleep_sec > 0:
                time.sleep(sleep_sec)
    else:
        print(f"[*] Sending {count} UDP packets to 127.0.0.1:{bind_port}...")
        for i in range(count):
            if latch:
                hdr = struct.pack("!BBHII", 0x80, 0, i & 0xFFFF, (i * 160) & 0xFFFFFFFF, 0xCAFE)
                payload = hdr + f"RTP_PKT_{i:08d}".encode("utf-8")
            else:
                payload = f"RTP_PKT_{i:08d}".encode("utf-8")
            tx_sock.sendto(payload, ("127.0.0.1", bind_port))
            sent += 1

    # Give receiver time to drain
    time.sleep(0.2)
    done.set()
    t.join(timeout=1.0)

    elapsed = time.perf_counter() - start_time
    rate = received / elapsed if elapsed > 0 else 0
    print(f"[+] Relayed: {received}/{sent} packets in {elapsed:.2f} s ({rate:.1f} pkts/sec)")

    status = send_control(sock_path, "STATUS")
    print(f"[*] Engine status:\n{status.strip()}")

    # Cleanup
    del_resp = send_control(sock_path, f"DELETE {bind_port}")
    print(f"[*] Teardown: {del_resp.strip()}")

    rx_sock.close()
    if not latch:
        tx_sock.close()

def run_watchdog_test(
    sock_path: str,
    num_sessions: int = 3,
    start_port: int = 30010,
    send_rtp: bool = True,
    wait_reap: bool = True,
) -> None:
    import struct

    def parse_metrics() -> dict[str, int]:
        raw = send_control(sock_path, "STATUS METRICS")
        res: dict[str, int] = {}
        for line in raw.splitlines():
            parts = line.strip().split()
            if (len(parts) == 2) and parts[1].isdigit():
                res[parts[0]] = int(parts[1])
        return res

    initial = parse_metrics()
    initial_reaped = initial.get("urtp_sessions_reaped_total", 0)

    print(f"[*] Creating {num_sessions} idle relay session(s) starting at port {start_port}...")
    allocated_ports: list[int] = []
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if send_rtp else None

    try:
        for i in range(num_sessions):
            port = start_port + (i * 2)
            resp = send_control(sock_path, f"ALLOCATE PORT {port} LATCH")
            if not resp.startswith("OK"):
                print(f"[!] Failed to allocate port {port}: {resp.strip()}")
                continue
            allocated_ports.append(port)

            if tx_sock:
                ssrc = 0x1000 + i
                hdr = struct.pack("!BBHII", 0x80, 0, 1, 160, ssrc)
                payload = hdr + f"WATCHDOG_BURST_{ssrc}".encode("utf-8")
                tx_sock.sendto(payload, ("127.0.0.1", port))
                print(f"  [+] Port {port}: allocated, primed with RTP SSRC 0x{ssrc:X} ({ssrc})")
            else:
                print(f"  [+] Port {port}: allocated (unconfirmed setup)")

        print(f"[*] {len(allocated_ports)} idle session(s) created and left silent.")
        print("[*] Grafana: view 'Stream Inactivity by SSRC' and 'Watchdog Idle Session Reaps' at http://localhost:3000")

        if not wait_reap:
            return

        expected_timeout = 60 if send_rtp else 30
        print(f"[*] Monitoring watchdog sweeper (expected timeout: ~{expected_timeout}s)...")

        start = time.perf_counter()
        while True:
            time.sleep(2.0)
            elapsed = time.perf_counter() - start
            metrics = parse_metrics()
            active = metrics.get("urtp_active_sessions", 0)
            reaped = metrics.get("urtp_sessions_reaped_total", 0)
            reaped_delta = reaped - initial_reaped

            print(f"  [>] Elapsed: {elapsed:.1f}s | Active sessions: {active} | Watchdog reaped: {reaped} (+{reaped_delta})")

            if (reaped_delta >= len(allocated_ports)) or ((elapsed >= expected_timeout) and (active == 0)):
                print(f"[+] Success: watchdog reaped all {len(allocated_ports)} idle session(s)!")
                break
            if elapsed > (expected_timeout + 30):
                print(f"[!] Timeout: watchdog did not reap sessions within {expected_timeout + 30}s")
                break
    finally:
        if tx_sock:
            tx_sock.close()

def run_audio_test(
    sock_path: str,
    wav_path: str = "assets/jediwarlock.wav",
    bind_port: int = 30002,
    dest_port: int = 40000,
    dest_ip: str | None = None,
    src_codec: str = "opus",
    dst_codec: str = "pcmu",
    backend: str = "libopus",
    jb_ms: int = 40,
    duration: float = 10.0,
    drop_rate: float = 0.0,
    drop_burst: int = 1,
    reorder_rate: float = 0.0,
    reorder_delay: float = 35.0,
    idle_interval: float = 0.0,
    idle_duration: float = 2.0,
    play: bool = False,
    record_wav: str | None = None,
    no_record: bool = False,
) -> None:
    import queue
    import random
    import shutil
    import signal
    import subprocess
    import tempfile
    import threading

    # 1. Validate dependencies & audio asset
    if not shutil.which("ffmpeg"):
        print("[!] Error: 'ffmpeg' binary is required for audio streaming but not found in PATH.", file=sys.stderr)
        sys.exit(1)
    if play and not shutil.which("ffplay"):
        print("[!] Error: 'ffplay' binary is required for --play but not found in PATH.", file=sys.stderr)
        sys.exit(1)

    resolved_wav = wav_path
    if not os.path.isabs(resolved_wav) and not os.path.exists(resolved_wav):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        candidate = os.path.join(repo_root, wav_path)
        if os.path.exists(candidate):
            resolved_wav = os.path.abspath(candidate)

    if not os.path.exists(resolved_wav):
        print(f"[!] Error: Input audio file not found at '{wav_path}' (checked '{resolved_wav}')", file=sys.stderr)
        sys.exit(1)

    target_ip = detect_dest_ip(dest_ip, sock_path)

    print("=" * 70)
    print(f"[*] urtp Audio Transcode & Jitter Test: {src_codec.upper()} -> {dst_codec.upper()}")
    print("=" * 70)
    print(f"  Input audio file   : {resolved_wav}")
    print(f"  Relay ports        : Ingress {bind_port} -> Egress {target_ip}:{dest_port}")
    print(f"  Transcode backend  : {backend} ({src_codec} -> {dst_codec})")
    print(f"  Jitter buffer      : {jb_ms} ms {'(enabled)' if jb_ms > 0 else '(disabled)'}")
    print(f"  Duration limit     : {duration:.1f}s" if duration > 0 else "  Duration limit     : Entire file")
    print(f"  Impairments        : drop_rate={drop_rate*100:.1f}% (burst={drop_burst}), reorder_rate={reorder_rate*100:.1f}% (delay={reorder_delay:.0f}ms)")
    if idle_interval > 0:
        print(f"  Talkspurt / Silence: {idle_interval:.1f}s active -> {idle_duration:.1f}s idle pause (periodic)")
    else:
        print("  Talkspurt / Silence: Continuous streaming (idle intervals disabled)")
    print("=" * 70)

    # 2. Control plane: Allocate relay port
    print(f"[*] Allocating relay port {bind_port} -> {target_ip}:{dest_port}...")
    alloc_resp = send_control(sock_path, f"ALLOCATE PORT {bind_port} -> FORWARD TO {target_ip}:{dest_port}")
    print(f"[<] {alloc_resp.strip()}")
    if not alloc_resp.startswith("OK"):
        print(f"[!] Allocation failed: {alloc_resp.strip()}", file=sys.stderr)
        sys.exit(1)

    # 3. Control plane: Configure Transcode & Jitter Buffer
    transcode_cmd = f"TRANSCODE {bind_port} dst={dst_codec} src={src_codec} backend={backend}"
    if jb_ms > 0:
        transcode_cmd += f" jitter={jb_ms}"
    print(f"[*] Configuring transcode on port {bind_port}...")
    tc_resp = send_control(sock_path, transcode_cmd)
    print(f"[<] {tc_resp.strip()}")
    if not tc_resp.startswith("OK"):
        print(f"[!] Transcode setup failed: {tc_resp.strip()}", file=sys.stderr)
        send_control(sock_path, f"DELETE {bind_port}")
        sys.exit(1)

    # 4. Control plane: Activate PCAP call tapping if available
    pcap_file = None
    if not no_record:
        rec_resp = send_control(sock_path, f"RECORD START PORT {bind_port}")
        if rec_resp.startswith("OK"):
            if "FILE " in rec_resp:
                pcap_file = rec_resp.strip().split("FILE ")[1].strip()
            print(f"[*] urtp PCAP recording active: {pcap_file if pcap_file else rec_resp.strip()}")
        else:
            rec_stat = send_control(sock_path, "RECORD STATUS")
            for line in rec_stat.splitlines():
                if f"ports={bind_port}" in line or f"ports={bind_port}," in line:
                    for tok in line.split():
                        if tok.startswith("file="):
                            pcap_file = tok.removeprefix("file=")
            if pcap_file:
                print(f"[*] urtp PCAP recording active: {pcap_file}")
            else:
                print(f"[*] Notice: PCAP recording disabled or directory unconfigured ({rec_resp.strip()})")

    # 5. Receiver setup (ffplay live playback, ffmpeg WAV recording, or background packet counter)
    sdp_file = None
    receiver_proc = None
    rx_sock = None
    rx_done = threading.Event()
    received_count = 0

    if play or record_wav:
        # Punch conntrack towards container to allow egress RTP traffic through host firewall
        tmp_punch = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp_punch.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tmp_punch.bind(("0.0.0.0", dest_port))
            punch_conntrack(tmp_punch, bind_port)
        finally:
            tmp_punch.close()

        sdp_lines = [
            "v=0",
            "o=- 0 0 IN IP4 127.0.0.1",
            "s=URTP-Audio-Test",
            "c=IN IP4 127.0.0.1",
            "t=0 0",
        ]
        dst_lower = dst_codec.lower()
        if dst_lower == "pcmu":
            sdp_lines.extend([f"m=audio {dest_port} RTP/AVP 0", "a=rtpmap:0 PCMU/8000"])
        elif dst_lower == "pcma":
            sdp_lines.extend([f"m=audio {dest_port} RTP/AVP 8", "a=rtpmap:8 PCMA/8000"])
        elif dst_lower == "opus":
            sdp_lines.extend([f"m=audio {dest_port} RTP/AVP 96", "a=rtpmap:96 opus/48000/2"])
        else:
            sdp_lines.append(f"m=audio {dest_port} RTP/AVP 0")

        sdp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".sdp", delete=False)
        sdp_file.write("\n".join(sdp_lines) + "\n")
        sdp_file.flush()
        sdp_file.close()

        if play:
            print(f"[*] Launching ffplay live audio playback listening on UDP {dest_port}...")
            receiver_proc = subprocess.Popen(
                ["ffplay", "-nodisp", "-autoexit", "-protocol_whitelist", "file,udp,rtp", "-i", sdp_file.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif record_wav:
            print(f"[*] Recording transcoded audio stream on UDP {dest_port} to '{record_wav}'...")
            receiver_proc = subprocess.Popen(
                ["ffmpeg", "-y", "-protocol_whitelist", "file,udp,rtp", "-i", sdp_file.name, "-c:a", "copy", record_wav],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    else:
        # Standalone UDP receiver to drain port and verify egress packet flow
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        rx_sock.bind(("0.0.0.0", dest_port))
        rx_sock.settimeout(0.5)
        punch_conntrack(rx_sock, bind_port)

        def receiver_worker():
            nonlocal received_count
            while not rx_done.is_set():
                try:
                    data, _ = rx_sock.recvfrom(2048)
                    if len(data) > 1:
                        received_count += 1
                except (socket.timeout, OSError):
                    continue

        t_rx = threading.Thread(target=receiver_worker, daemon=True)
        t_rx.start()

    # 6. Ephemeral feeder socket to intercept ffmpeg RTP stream
    feeder_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    feeder_sock.bind(("127.0.0.1", 0))
    feeder_port = feeder_sock.getsockname()[1]
    feeder_sock.settimeout(0.2)

    ff_cmd = [
        "ffmpeg", "-re", "-i", resolved_wav,
        "-vn",
    ]
    if duration > 0:
        ff_cmd.extend(["-t", str(duration)])

    src_lower = src_codec.lower()
    if src_lower == "opus":
        ff_cmd.extend(["-c:a", "libopus", "-b:a", "32k", "-payload_type", "96"])
    elif src_lower == "pcmu":
        ff_cmd.extend(["-c:a", "pcm_mulaw", "-ar", "8000", "-ac", "1", "-payload_type", "0"])
    elif src_lower == "pcma":
        ff_cmd.extend(["-c:a", "pcm_alaw", "-ar", "8000", "-ac", "1", "-payload_type", "8"])

    ff_cmd.extend(["-f", "rtp", f"rtp://127.0.0.1:{feeder_port}", "-loglevel", "error"])
    print(f"[*] Starting ffmpeg audio source ({src_codec} @ 20ms frames)...")
    ff_proc = subprocess.Popen(ff_cmd, stdout=subprocess.DEVNULL)

    # 7. Outbound priority queue for pacing & out-of-order reordering
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pq = queue.PriorityQueue()
    sender_done = threading.Event()

    def sender_worker():
        while not sender_done.is_set():
            try:
                deliver_time, pkt = pq.get(timeout=0.01)
            except queue.Empty:
                continue
            now = time.perf_counter()
            if deliver_time > now:
                time.sleep(deliver_time - now)
            try:
                tx_sock.sendto(pkt, ("127.0.0.1", bind_port))
            except OSError:
                pass
            pq.task_done()

    t_tx = threading.Thread(target=sender_worker, daemon=True)
    t_tx.start()

    # 8. Main transmission loop: pacing, jitter/reorder, packet drops, and periodic idle
    sent_count = 0
    dropped_count = 0
    reordered_count = 0
    drop_burst_remaining = 0
    idle_count = 0

    start_time = time.perf_counter()
    last_idle_time = start_time
    last_log_time = start_time
    is_paused = False

    try:
        while True:
            # Check if source ffmpeg process finished
            if ff_proc.poll() is not None:
                # Drain remaining packets from feeder socket
                while True:
                    try:
                        pkt_data, _ = feeder_sock.recvfrom(2048)
                        sent_count += 1
                        pq.put((time.perf_counter() + 0.0002, pkt_data))
                    except (socket.timeout, OSError):
                        break
                break

            # Handle periodic talkspurt silence / idle intervals
            if (idle_interval > 0.0) and not is_paused:
                active_elapsed = time.perf_counter() - last_idle_time
                if active_elapsed >= idle_interval:
                    idle_count += 1
                    print(f"  [~] Entering IDLE / SILENT period for {idle_duration:.1f}s (talkspurt #{idle_count} pause)...")
                    try:
                        os.kill(ff_proc.pid, signal.SIGSTOP)
                    except OSError:
                        pass
                    # Flush pending reordered packets to urtp
                    pq.join()
                    time.sleep(idle_duration)
                    try:
                        os.kill(ff_proc.pid, signal.SIGCONT)
                    except OSError:
                        pass
                    print(f"  [+] Resumed audio streaming from idle!")
                    last_idle_time = time.perf_counter()

            # Read packet from ffmpeg feeder
            try:
                pkt_data, _ = feeder_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            now = time.perf_counter()

            # Evaluate packet dropping (simulates packet loss to trigger PLC)
            if drop_burst_remaining > 0:
                drop_burst_remaining -= 1
                dropped_count += 1
                continue
            elif (drop_rate > 0.0) and (random.random() < drop_rate):
                dropped_count += 1
                if drop_burst > 1:
                    drop_burst_remaining = drop_burst - 1
                continue

            # Evaluate packet reordering (simulates network jitter)
            if (reorder_rate > 0.0) and (random.random() < reorder_rate):
                reordered_count += 1
                delay_sec = max(reorder_delay / 1000.0, 0.005)
                pq.put((now + delay_sec, pkt_data))
            else:
                pq.put((now + 0.0002, pkt_data))

            sent_count += 1

            if now - last_log_time >= 1.5:
                rate = sent_count / (now - start_time) if (now - start_time) > 0 else 0
                recv_str = f" | Recv: {received_count}" if rx_sock else ""
                print(f"  [>] Elapsed: {now - start_time:.1f}s | Sent: {sent_count} ({rate:.0f} PPS) | Dropped: {dropped_count} | Reordered: {reordered_count} | Idles: {idle_count}{recv_str}")
                last_log_time = now

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user, terminating stream...")
    finally:
        # Cleanup sender and feeder
        if ff_proc.poll() is None:
            try:
                os.kill(ff_proc.pid, signal.SIGCONT)
                ff_proc.terminate()
                ff_proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                ff_proc.kill()

        feeder_sock.close()
        pq.join()
        sender_done.set()
        t_tx.join(timeout=1.0)
        tx_sock.close()

        # Let receiver drain
        time.sleep(0.3)
        rx_done.set()
        if rx_sock:
            rx_sock.close()
        if receiver_proc and (receiver_proc.poll() is None):
            try:
                receiver_proc.terminate()
                receiver_proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                receiver_proc.kill()

    total_time = time.perf_counter() - start_time
    print(f"\n[+] Audio transmission finished: {sent_count} packets sent in {total_time:.1f}s ({dropped_count} dropped, {reordered_count} reordered, {idle_count} idle pauses)")

    # 9. Query & display urtp telemetry
    status = send_control(sock_path, f"TRANSCODE STATUS {bind_port}")
    print("\n" + "=" * 70)
    print("[*] urtp Transcode & Jitter Buffer Engine Telemetry:")
    print("=" * 70)
    print(f"  {status.strip()}")

    # Parse and highlight key metrics
    metrics: dict[str, str] = {}
    for part in status.strip().split():
        if "=" in part:
            k, v = part.split("=", 1)
            metrics[k] = v

    if metrics:
        print("\n  Summary:")
        print(f"    - Packets transcoded in  : {metrics.get('in', '0')}")
        print(f"    - Packets transcoded out : {metrics.get('out', '0')}")
        print(f"    - Decoder/Encoder errors : {metrics.get('errors', '0')}")
        print(f"    - Jitter buffer state    : {metrics.get('jb', 'disabled')} (target depth={metrics.get('depth', '0')})")
        print(f"    - Out-of-order reordered : {metrics.get('reordered', '0')}")
        print(f"    - Late packets dropped   : {metrics.get('dropped_late', '0')}")
        print(f"    - Loss Concealments (PLC): {metrics.get('plc', '0')}")

    # 10. Wireshark PCAP playback instructions
    print("\n" + "=" * 70)
    print("[*] Wireshark PCAP Inspection & Playback:")
    print("=" * 70)
    local_pcap = pcap_file
    if local_pcap and not os.path.exists(local_pcap):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        if local_pcap.startswith("/pcap/"):
            cand = os.path.join(repo_root, "pcap", os.path.basename(local_pcap))
            if os.path.exists(cand):
                local_pcap = os.path.abspath(cand)

    if local_pcap and os.path.exists(local_pcap):
        file_size = os.path.getsize(local_pcap)
        print(f"  PCAP File: {local_pcap} ({file_size / 1024:.1f} KB)")
        print("\n  Playback in Wireshark:")
        print(f"    1. Open the PCAP file:")
        print(f"       wireshark {local_pcap} &")
        print("    2. In Wireshark menu, navigate to:")
        print("       Telephony -> RTP -> RTP Player")
        print("       (or Telephony -> RTP -> RTP Streams -> Stream Analysis)")
        print("    3. Click 'Play' to listen to the transcoded audio stream directly!")
        print("\n  Convert PCAP to WAV via ffmpeg:")
        print(f"    ffmpeg -i {local_pcap} /tmp/extracted_audio.wav")
    else:
        print("  Notice: Start urtp with '-r ./pcap -R' to capture PCAP files automatically.")

    # 11. Cleanup control plane
    del_resp = send_control(sock_path, f"DELETE {bind_port}")
    print(f"\n[*] Teardown session: {del_resp.strip()}")

    if sdp_file and os.path.exists(sdp_file.name):
        try:
            os.remove(sdp_file.name)
        except OSError:
            pass


def run_video_test(
    sock_path: str,
    audio_bind_port: int = 30000,
    video_bind_port: int = 30002,
    audio_dest_port: int = 40000,
    video_dest_port: int = 40002,
    video_codec: str = "vp8",
    resolution: str = "1920x1080",
    duration: float = 3.0,
    dest_ip: str | None = None,
    no_record: bool = False,
) -> None:
    target_ip = detect_dest_ip(dest_ip, sock_path)
    print("=" * 70)
    print(f"[*] urtp Multi-Stream Audio + Video ({video_codec.upper()} {resolution}) Test")
    print("=" * 70)

    # 1. Allocate relay sessions
    print(f"[*] Allocating Audio relay: port {audio_bind_port} -> {target_ip}:{audio_dest_port}")
    resp_a = send_control(sock_path, f"ALLOCATE PORT {audio_bind_port} -> FORWARD TO {target_ip}:{audio_dest_port}")
    if not resp_a.startswith("OK"):
        sys.exit(f"Failed to allocate audio relay: {resp_a}")

    print(f"[*] Allocating Video relay: port {video_bind_port} -> {target_ip}:{video_dest_port}")
    resp_v = send_control(sock_path, f"ALLOCATE PORT {video_bind_port} -> FORWARD TO {target_ip}:{video_dest_port}")
    if not resp_v.startswith("OK"):
        send_control(sock_path, f"DELETE {audio_bind_port}")
        sys.exit(f"Failed to allocate video relay: {resp_v}")

    # Optional recording
    if not no_record:
        send_control(sock_path, f"RECORD {audio_bind_port}")
        send_control(sock_path, f"RECORD {video_bind_port}")

    # 2. Setup UDP receivers
    audio_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    audio_rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    audio_rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    audio_rx.bind(("0.0.0.0", audio_dest_port))
    audio_rx.settimeout(0.5)

    video_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    video_rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    video_rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    video_rx.bind(("0.0.0.0", video_dest_port))
    video_rx.settimeout(0.5)

    punch_conntrack(audio_rx, audio_bind_port)
    punch_conntrack(video_rx, video_bind_port)

    import threading
    audio_recv_count = 0
    audio_recv_bytes = 0
    video_recv_count = 0
    video_recv_bytes = 0
    stop_event = threading.Event()

    def audio_worker():
        nonlocal audio_recv_count, audio_recv_bytes
        while not stop_event.is_set():
            try:
                data, _ = audio_rx.recvfrom(2048)
                if len(data) > 1:
                    audio_recv_count += 1
                    audio_recv_bytes += len(data)
            except (socket.timeout, OSError):
                continue

    def video_worker():
        nonlocal video_recv_count, video_recv_bytes
        while not stop_event.is_set():
            try:
                data, _ = video_rx.recvfrom(4096)
                if len(data) > 1:
                    video_recv_count += 1
                    video_recv_bytes += len(data)
            except (socket.timeout, OSError):
                continue

    t_a = threading.Thread(target=audio_worker, daemon=True)
    t_v = threading.Thread(target=video_worker, daemon=True)
    t_a.start()
    t_v.start()

    # 3. Launch ffmpeg streaming for both audio and video
    # Audio: 1 kHz test sine, 48kHz, Opus PT 111
    ff_audio_cmd = [
        "ffmpeg", "-re", "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=48000",
        "-c:a", "libopus", "-b:a", "32k", "-payload_type", "111",
        "-f", "rtp", f"rtp://127.0.0.1:{audio_bind_port}",
        "-t", str(duration),
    ]

    # Video: testsrc at specified resolution and 30fps
    if video_codec.lower() == "h264":
        ff_video_cmd = [
            "ffmpeg", "-re", "-f", "lavfi", "-i", f"testsrc=size={resolution}:rate=30",
            "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
            "-b:v", "2M", "-payload_type", "97",
            "-f", "rtp", f"rtp://127.0.0.1:{video_bind_port}",
            "-t", str(duration),
        ]
    else:  # vp8 default
        ff_video_cmd = [
            "ffmpeg", "-re", "-f", "lavfi", "-i", f"testsrc=size={resolution}:rate=30",
            "-c:v", "libvpx", "-b:v", "2M", "-payload_type", "96",
            "-f", "rtp", f"rtp://127.0.0.1:{video_bind_port}",
            "-t", str(duration),
        ]

    print(f"[*] Starting ffmpeg {resolution} {video_codec.upper()} video stream (duration: {duration:.1f}s)...")
    proc_video = subprocess.Popen(ff_video_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[*] Starting ffmpeg Opus audio stream (duration: {duration:.1f}s)...")
    proc_audio = subprocess.Popen(ff_audio_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    start_time = time.perf_counter()
    try:
        while (proc_video.poll() is None) or (proc_audio.poll() is None):
            time.sleep(0.5)
            elapsed = time.perf_counter() - start_time
            print(f"  [>] Elapsed: {elapsed:.1f}s | Audio RX: {audio_recv_count} pkts ({audio_recv_bytes/1024:.1f} KB) | Video RX: {video_recv_count} pkts ({video_recv_bytes/1024:.1f} KB)")
            if elapsed > duration + 5.0:
                break
    finally:
        for p in (proc_audio, proc_video):
            if p and (p.poll() is None):
                p.terminate()
                try:
                    p.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    p.kill()

    # Wait for in-flight packets to arrive
    time.sleep(0.3)
    stop_event.set()
    audio_rx.close()
    video_rx.close()
    t_a.join(timeout=1.0)
    t_v.join(timeout=1.0)

    # 4. Teardown
    send_control(sock_path, f"DELETE {audio_bind_port}")
    send_control(sock_path, f"DELETE {video_bind_port}")

    print("\n" + "=" * 70)
    print("[*] Multi-Stream Test Results:")
    print("=" * 70)
    print(f"  Audio Packets Received: {audio_recv_count} ({audio_recv_bytes / 1024:.1f} KB)")
    print(f"  Video Packets Received: {video_recv_count} ({video_recv_bytes / 1024:.1f} KB)")

    if audio_recv_count == 0:
        print("  [!] FAILURE: No audio packets received!")
        sys.exit(1)
    if video_recv_count == 0:
        print("  [!] FAILURE: No video packets received!")
        sys.exit(1)

    print(f"  [+] SUCCESS: Both audio and video streams relayed concurrently at high throughput!")


def main() -> None:
    parser = argparse.ArgumentParser(description="urtp test client")
    parser.add_argument(
        "-s",
        "--socket",
        default="127.0.0.1:22222" if not os.path.exists("/tmp/urtp.sock") else "/tmp/urtp.sock",
        help="Control socket path or host:port (default: /tmp/urtp.sock or 127.0.0.1:22222)",
    )
    parser.add_argument("-c", "--cmd", help="Send a single control command and print response")
    parser.add_argument("-t", "--test", action="store_true", help="Run automated UDP relay test")
    parser.add_argument("-w", "--watchdog", action="store_true", help="Run watchdog idle connection reap test")
    parser.add_argument("--idle-sessions", type=int, default=3, help="Number of idle sessions for watchdog test (default: 3)")
    parser.add_argument("--no-rtp", action="store_true", help="Do not send initial RTP packets (tests setup timeout 30s instead of 60s)")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for watchdog reaping (allocates and exits)")
    parser.add_argument("--latch", action="store_true", help="Enable Symmetric RTP and NAT latching test")
    parser.add_argument("--bind-port", type=int, default=30002, help="Relay listen port (default: 30002)")
    parser.add_argument("--dest-port", type=int, default=20000, help="Relay destination port (default: 20000)")
    parser.add_argument("--dest-ip", default=None, help="Forwarding destination IP (default: auto-detect)")
    parser.add_argument("-n", "--count", type=int, default=1000, help="Number of packets for burst test")
    parser.add_argument("-d", "--duration", type=float, default=0.0, help="Duration in seconds for sustained streaming test")
    parser.add_argument("-r", "--pps", type=float, default=50.0, help="Pacing in packets per second for duration test (default: 50)")

    # Audio Transcode & Jitter Buffer testing options
    parser.add_argument("-a", "--audio", "--audio-test", action="store_true", dest="audio_test", help="Run audio transcode & jitter test from a WAV file")
    parser.add_argument("--wav", default="assets/jediwarlock.wav", help="Input audio WAV file path (default: assets/jediwarlock.wav)")
    parser.add_argument("--src-codec", default="opus", choices=["opus", "pcmu", "pcma"], help="Source codec sent to urtp (default: opus)")
    parser.add_argument("--dst-codec", default="pcmu", choices=["pcmu", "pcma", "opus"], help="Target transcoded codec (default: pcmu)")
    parser.add_argument("--backend", default="libopus", choices=["libopus", "ffmpeg"], help="Transcoder backend (default: libopus)")
    parser.add_argument("--jb", "--jitter-buffer", type=int, default=40, dest="jb_ms", help="Jitter buffer latency in ms (default: 40, 0=disabled)")
    parser.add_argument("--drop-rate", type=float, default=0.0, help="Packet drop rate between 0.0 and 1.0 (default: 0.0)")
    parser.add_argument("--drop-burst", type=int, default=1, help="Consecutive packets to drop when a drop occurs (default: 1)")
    parser.add_argument("--reorder-rate", type=float, default=0.0, help="Packet reordering probability 0.0-1.0 (default: 0.0)")
    parser.add_argument("--reorder-delay", type=float, default=35.0, help="Delay in ms for reordered packets (default: 35.0)")
    parser.add_argument("--idle-interval", type=float, default=0.0, help="Active streaming duration in seconds before going idle (default: 0.0=disabled)")
    parser.add_argument("--idle-duration", type=float, default=2.0, help="Idle silence duration in seconds before resuming audio (default: 2.0)")
    parser.add_argument("--play", action="store_true", help="Play transcoded audio live using ffplay")
    parser.add_argument("--record-wav", type=str, default=None, help="Record transcoded output audio to a WAV file")
    parser.add_argument("--no-record", action="store_true", help="Do not start urtp PCAP recording")

    # Multi-Stream Audio + Video testing options
    parser.add_argument("-V", "--video", "--video-test", action="store_true", dest="video_test", help="Run multi-stream audio + video relay test")
    parser.add_argument("--video-codec", default="vp8", choices=["vp8", "h264"], help="Video codec (default: vp8)")
    parser.add_argument("--resolution", default="1920x1080", help="Video resolution (default: 1920x1080)")
    parser.add_argument("--video-bind-port", type=int, default=30002, help="Video relay listen port (default: 30002)")
    parser.add_argument("--video-dest-port", type=int, default=40002, help="Video relay destination port (default: 40002)")

    args = parser.parse_args()

    if args.cmd:
        print(send_control(args.socket, args.cmd).strip())
    elif args.video_test:
        run_video_test(
            sock_path=args.socket,
            audio_bind_port=args.bind_port if args.bind_port != 30002 else 30000,
            video_bind_port=args.video_bind_port,
            audio_dest_port=args.dest_port if args.dest_port != 20000 else 40000,
            video_dest_port=args.video_dest_port,
            video_codec=args.video_codec,
            resolution=args.resolution,
            duration=args.duration if args.duration > 0 else 3.0,
            dest_ip=args.dest_ip,
            no_record=args.no_record,
        )
    elif args.audio_test:
        run_audio_test(
            sock_path=args.socket,
            wav_path=args.wav,
            bind_port=args.bind_port,
            dest_port=args.dest_port if args.dest_port != 20000 else 40000,
            dest_ip=args.dest_ip,
            src_codec=args.src_codec,
            dst_codec=args.dst_codec,
            backend=args.backend,
            jb_ms=args.jb_ms,
            duration=args.duration,
            drop_rate=args.drop_rate,
            drop_burst=args.drop_burst,
            reorder_rate=args.reorder_rate,
            reorder_delay=args.reorder_delay,
            idle_interval=args.idle_interval,
            idle_duration=args.idle_duration,
            play=args.play,
            record_wav=args.record_wav,
            no_record=args.no_record,
        )
    elif args.test:
        run_relay_test(
            args.socket,
            args.bind_port,
            args.dest_port,
            args.count,
            args.latch,
            args.duration,
            args.pps,
            dest_ip=args.dest_ip,
        )
    elif args.watchdog:
        run_watchdog_test(
            args.socket,
            num_sessions=args.idle_sessions,
            start_port=args.bind_port,
            send_rtp=not args.no_rtp,
            wait_reap=not args.no_wait,
        )
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

