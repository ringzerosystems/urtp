#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "control/control.h"
#include "control/ng.h"
#include "core/metrics.h"
#include "core/watchdog.h"
#include "net/session.h"
#include "ring/timer.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_timer_engine_lifecycle(void) {
    timer_engine_t timer = {};
    TEST_ASSERT_TRUE(timer_engine_init(&timer, 1));
    TEST_ASSERT_TRUE(timer.initialized);
    TEST_ASSERT_TRUE(timer.timer_fd >= 0);
    TEST_ASSERT_EQUAL_UINT32(1, timer.interval_sec);

    ring_engine_t ring = {};
    TEST_ASSERT_TRUE(ring_engine_init(&ring, 32, 32, 2048, 1, false));

    TEST_ASSERT_TRUE(timer_engine_arm(&timer, &ring));
    TEST_ASSERT_TRUE(timer.armed);

    TEST_ASSERT_TRUE(timer_engine_rearm(&timer, &ring));
    TEST_ASSERT_TRUE(timer.armed);

    timer_engine_destroy(&timer);
    TEST_ASSERT_EQUAL_INT(-1, timer.timer_fd);

    ring_engine_destroy(&ring);
}

static void test_watchdog_systemd_protocol(void) {
    char const *const sock_path = "/tmp/test_urtp_watchdog.sock";
    (void)unlink(sock_path);

    int const sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(sfd >= 0);

    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };
    __builtin_memcpy(sun.sun_path, sock_path, __builtin_strlen(sock_path) + 1);
    TEST_ASSERT_EQUAL_INT(0, bind(sfd, (struct sockaddr const *)&sun, sizeof(struct sockaddr_un)));

    setenv("NOTIFY_SOCKET", sock_path, 1);
    setenv("WATCHDOG_USEC", "2000000", 1); // 2 seconds => 1 second interval

    systemd_watchdog_t wd = {};
    TEST_ASSERT_TRUE(watchdog_init(&wd));
    TEST_ASSERT_TRUE(wd.enabled);
    TEST_ASSERT_EQUAL_UINT64(1, wd.watchdog_interval_sec);

    watchdog_notify_ready(&wd);

    char    buf[256] = {};
    ssize_t n        = recv(sfd, buf, sizeof(buf) - 1, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';
    TEST_ASSERT_EQUAL_STRING("READY=1\n", buf);

    // Initial ping at tick now_sec = 1
    watchdog_ping(&wd, 1);
    n = recv(sfd, buf, sizeof(buf) - 1, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';
    TEST_ASSERT_EQUAL_STRING("WATCHDOG=1\n", buf);

    // Duplicate ping within interval should be suppressed
    watchdog_ping(&wd, 1);

    // Ping after interval elapsed at now_sec = 2
    watchdog_ping(&wd, 2);
    n = recv(sfd, buf, sizeof(buf) - 1, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';
    TEST_ASSERT_EQUAL_STRING("WATCHDOG=1\n", buf);

    watchdog_notify_stopping(&wd);
    n = recv(sfd, buf, sizeof(buf) - 1, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';
    TEST_ASSERT_EQUAL_STRING("STOPPING=1\n", buf);

    watchdog_destroy(&wd);
    TEST_ASSERT_EQUAL_INT(-1, wd.notify_fd);

    (void)close(sfd);
    (void)unlink(sock_path);
    unsetenv("NOTIFY_SOCKET");
    unsetenv("WATCHDOG_USEC");
}

static void test_session_inactivity_sweeper(void) {
    session_table_t  table   = {};
    server_metrics_t metrics = {};
    session_table_init(&table);
    metrics_init(&metrics);
    table.metrics              = &metrics;
    table.cached_monotonic_sec = 100;

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    // Session 1: Setup unconfirmed session (packets_relayed == 0)
    auto const s1 = session_create(&table, "127.0.0.1", 10000, "127.0.0.1", 20000);
    TEST_ASSERT_NOT_NULL(s1);
    TEST_ASSERT_EQUAL_UINT64(100, s1->created_sec);
    TEST_ASSERT_EQUAL_UINT64(100, s1->last_activity_sec);
    TEST_ASSERT_EQUAL_UINT64(0, s1->packets_relayed);

    // Sessions 2 & 3: Established bridged media sessions
    auto const s2 = session_create(&table, "127.0.0.1", 10002, "127.0.0.1", 20002);
    auto const s3 = session_create(&table, "127.0.0.1", 10004, "127.0.0.1", 20004);
    TEST_ASSERT_NOT_NULL(s2);
    TEST_ASSERT_NOT_NULL(s3);
    TEST_ASSERT_TRUE(session_bridge_pair(&table, 10002, 10004));

    s2->packets_relayed   = 50;
    s3->packets_relayed   = 48;
    s2->last_activity_sec = 100;
    s3->last_activity_sec = 100;

    // Associate an NG call with ports 10002 and 10004
    auto const call = ng_call_find_or_create(&call_table, SV_PSZ("call-sweep-1"), SV_PSZ("tag-1"));
    TEST_ASSERT_NOT_NULL(call);
    call->caller_port = 10002;
    call->callee_port = 10004;
    TEST_ASSERT_EQUAL_INT(1, call_table.active_count);
    TEST_ASSERT_EQUAL_INT(3, table.active_count);

    // At now_sec = 120 (setup: 30s, inactivity: 60s) -> nothing should expire (elapsed 20s)
    session_table_sweep_inactivity(&table, &call_table, nullptr, 120, 60, 30);
    TEST_ASSERT_EQUAL_INT(3, table.active_count);
    TEST_ASSERT_EQUAL_INT(1, call_table.active_count);
    TEST_ASSERT_EQUAL_UINT64(0, metrics.cumulative.sessions_reaped);

    // At now_sec = 135 (elapsed 35s >= 30s setup timeout) -> s1 should be reaped
    session_table_sweep_inactivity(&table, &call_table, nullptr, 135, 60, 30);
    TEST_ASSERT_EQUAL_INT(2, table.active_count);
    TEST_ASSERT_NULL(session_find_by_port(&table, 10000));
    TEST_ASSERT_NOT_NULL(session_find_by_port(&table, 10002));
    TEST_ASSERT_NOT_NULL(session_find_by_port(&table, 10004));
    TEST_ASSERT_EQUAL_INT(1, call_table.active_count);
    TEST_ASSERT_EQUAL_UINT64(1, metrics.cumulative.sessions_reaped);

    // At now_sec = 165 (elapsed 65s >= 60s inactivity timeout) -> s2 & s3 bridged pair and NG call
    // reaped
    session_table_sweep_inactivity(&table, &call_table, nullptr, 165, 60, 30);
    TEST_ASSERT_EQUAL_INT(0, table.active_count);
    TEST_ASSERT_NULL(session_find_by_port(&table, 10002));
    TEST_ASSERT_NULL(session_find_by_port(&table, 10004));
    TEST_ASSERT_EQUAL_INT(0, call_table.active_count);
    TEST_ASSERT_EQUAL_UINT64(3, metrics.cumulative.sessions_reaped);

    session_table_destroy(&table, nullptr);
    ng_call_table_destroy(&call_table, nullptr, nullptr);
}

static void test_metrics_rollup_and_prometheus(void) {
    server_metrics_t m = {};
    metrics_init(&m);

    m.cumulative.rx_packets              = 1000;
    m.cumulative.tx_packets              = 950;
    m.cumulative.rx_bytes                = 160000;
    m.cumulative.tx_bytes                = 152000;
    m.cumulative.rtp_packets             = 900;
    m.cumulative.rtcp_packets            = 100;
    m.cumulative.packets_dropped         = 5;
    m.cumulative.srtp_encrypted          = 500;
    m.cumulative.srtp_decrypted          = 500;
    m.cumulative.srtp_auth_failures      = 1;
    m.cumulative.transcode_decoded       = 200;
    m.cumulative.transcode_encoded       = 200;
    m.cumulative.buffer_ring_exhaustions = 2;
    m.cumulative.sessions_reaped         = 7;
    m.cumulative.video_rx_packets        = 500;
    m.cumulative.video_tx_packets        = 480;
    m.cumulative.video_rx_bytes          = 500000;
    m.cumulative.video_tx_bytes          = 480000;
    m.cumulative.rtcp_pli_packets        = 12;

    metrics_rollup(&m, 1);

    TEST_ASSERT_EQUAL_UINT64(1000, m.rate_per_sec.rx_packets);
    TEST_ASSERT_EQUAL_UINT64(950, m.rate_per_sec.tx_packets);
    TEST_ASSERT_EQUAL_UINT64(160000, m.rate_per_sec.rx_bytes);
    TEST_ASSERT_EQUAL_UINT64(152000, m.rate_per_sec.tx_bytes);
    TEST_ASSERT_EQUAL_UINT64(5, m.rate_per_sec.packets_dropped);
    TEST_ASSERT_EQUAL_UINT64(2, m.rate_per_sec.buffer_ring_exhaustions);
    TEST_ASSERT_EQUAL_UINT64(7, m.rate_per_sec.sessions_reaped);
    TEST_ASSERT_EQUAL_UINT64(500, m.rate_per_sec.video_rx_packets);
    TEST_ASSERT_EQUAL_UINT64(480, m.rate_per_sec.video_tx_packets);
    TEST_ASSERT_EQUAL_UINT64(500000, m.rate_per_sec.video_rx_bytes);
    TEST_ASSERT_EQUAL_UINT64(480000, m.rate_per_sec.video_tx_bytes);
    TEST_ASSERT_EQUAL_UINT64(12, m.rate_per_sec.rtcp_pli_packets);

    char   prom[8192] = {};
    size_t len        = metrics_format_prometheus(&m, 42, 10, prom, sizeof(prom));
    TEST_ASSERT_GREATER_THAN(0, len);

    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_rx_packets_total 1000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_tx_packets_total 950"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_rx_rate_bytes 160000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_active_sessions 42"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_buffer_ring_exhaustions_total 2"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_sessions_reaped_total 7"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_rx_packets_total 500"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_tx_packets_total 480"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_rx_bytes_total 500000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_tx_bytes_total 480000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_rtcp_pli_total 12"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_rx_rate_bytes 500000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_tx_rate_bytes 480000"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_rx_rate_packets 500"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_video_tx_rate_packets 480"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_active_video_sessions 10"));
}

/**
 * @brief Validates Prometheus text exposition formatting edge cases, null safety, and boundary
 * limits.
 */
static void test_metrics_format_prometheus_edge_cases(void) {
    server_metrics_t m = {};
    metrics_init(&m);

    char prom[8192] = {};

    // Null safety & zero capacity
    TEST_ASSERT_EQUAL_UINT64(0, metrics_format_prometheus(nullptr, 0, 0, prom, sizeof(prom)));
    TEST_ASSERT_EQUAL_UINT64(0, metrics_format_prometheus(&m, 0, 0, nullptr, sizeof(prom)));
    TEST_ASSERT_EQUAL_UINT64(0, metrics_format_prometheus(&m, 0, 0, prom, 0));

    // Insufficient buffer (truncation detection)
    char tiny[64] = {};
    TEST_ASSERT_EQUAL_UINT64(0, metrics_format_prometheus(&m, 0, 0, tiny, sizeof(tiny)));

    // Large 64-bit value formatting
    m.cumulative.rx_packets = 18446744073709551615ULL;
    m.cumulative.tx_packets = 999999999999ULL;
    m.rate_per_sec.rx_bytes = 0;
    size_t const len        = metrics_format_prometheus(&m, 12345678, 8765432, prom, sizeof(prom));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_rx_packets_total 18446744073709551615\n"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_tx_packets_total 999999999999\n"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_rx_rate_bytes 0\n"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_active_sessions 12345678\n"));
    TEST_ASSERT_NOT_NULL(strstr(prom, "urtp_active_video_sessions 8765432\n"));
    TEST_ASSERT_EQUAL_UINT8('\0', prom[len]);

    // Exact buffer size boundary checks
    char exact[8192] = {};
    TEST_ASSERT_EQUAL_UINT64(
        len,
        metrics_format_prometheus(&m, 12345678, 8765432, exact, (len + 1)));
    TEST_ASSERT_EQUAL_UINT64(0, metrics_format_prometheus(&m, 12345678, 8765432, exact, len));
}

static void test_control_status_metrics_command(void) {
    session_table_t  table   = {};
    server_metrics_t metrics = {};
    session_table_init(&table);
    metrics_init(&metrics);
    table.metrics = &metrics;

    metrics.cumulative.rx_packets = 4200;
    metrics.cumulative.tx_packets = 4100;
    metrics_rollup(&metrics, 1);

    char resp[CONTROL_BUFFER_SIZE] = {};
    TEST_ASSERT_TRUE(
        control_process_command("STATUS METRICS", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "urtp_rx_packets_total 4200"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "urtp_tx_packets_total 4100"));

    session_table_destroy(&table, nullptr);
}

static void test_ng_stats_command(void) {
    session_table_t  session_table = {};
    server_metrics_t metrics       = {};
    ng_call_table_t  call_table    = {};

    session_table_init(&session_table);
    metrics_init(&metrics);
    session_table.metrics = &metrics;
    ng_call_table_init(&call_table, "127.0.0.1");

    metrics.cumulative.rx_packets      = 1234;
    metrics.cumulative.tx_packets      = 1200;
    metrics.cumulative.sessions_reaped = 3;
    metrics_rollup(&metrics, 1);

    char const msg[]      = "cookie-xyz d7:command5:statse";
    char       resp[2048] = {};
    size_t     resp_len   = 0;

    TEST_ASSERT_TRUE(ng_process_message(
        msg,
        sizeof(msg) - 1,
        &session_table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_GREATER_THAN(0, resp_len);
    TEST_ASSERT_NOT_NULL(strstr(resp, "cookie-xyz"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "10:rx-packetsi1234e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "10:tx-packetsi1200e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "15:sessions-reapedi3e"));

    session_table_destroy(&session_table, nullptr);
    ng_call_table_destroy(&call_table, nullptr, nullptr);
}

static void test_ssrc_idle_time_and_prometheus(void) {
    session_table_t  table      = {};
    server_metrics_t metrics    = {};
    ng_call_table_t  call_table = {};

    session_table_init(&table);
    metrics_init(&metrics);
    table.metrics              = &metrics;
    table.cached_monotonic_sec = 105;
    ng_call_table_init(&call_table, "127.0.0.1");

    auto const s = session_create(&table, "127.0.0.1", 10010, "127.0.0.1", 20010);
    TEST_ASSERT_NOT_NULL(s);
    s->last_ssrc     = 0x12345678;
    s->last_ssrc_sec = 100; // 5s idle

    // Prometheus metric formatting check
    char resp[CONTROL_BUFFER_SIZE] = {};
    TEST_ASSERT_TRUE(
        control_process_command("STATUS METRICS", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(
        strstr(resp, "urtp_ssrc_idle_seconds{port=\"10010\",ssrc=\"305419896\"} 5"));

    // NG query check
    auto const call = ng_call_find_or_create(&call_table, SV_PSZ("call-ssrc-1"), SV_PSZ("tag-1"));
    TEST_ASSERT_NOT_NULL(call);
    call->caller_port = 10010;

    char const msg[]         = "cookie-abc d7:command5:query7:call-id11:call-ssrc-1e";
    char       ng_resp[2048] = {};
    size_t     ng_resp_len   = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        msg,
        sizeof(msg) - 1,
        &table,
        &call_table,
        nullptr,
        ng_resp,
        sizeof(ng_resp),
        &ng_resp_len));
    TEST_ASSERT_NOT_NULL(strstr(ng_resp, "11:caller-ssrci305419896e"));
    TEST_ASSERT_NOT_NULL(strstr(ng_resp, "20:caller-ssrc-idle-seci5e"));

    session_table_destroy(&table, nullptr);
    ng_call_table_destroy(&call_table, nullptr, nullptr);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_timer_engine_lifecycle);
    RUN_TEST(test_watchdog_systemd_protocol);
    RUN_TEST(test_session_inactivity_sweeper);
    RUN_TEST(test_metrics_rollup_and_prometheus);
    RUN_TEST(test_metrics_format_prometheus_edge_cases);
    RUN_TEST(test_control_status_metrics_command);
    RUN_TEST(test_ng_stats_command);
    RUN_TEST(test_ssrc_idle_time_and_prometheus);
    return UNITY_END();
}
