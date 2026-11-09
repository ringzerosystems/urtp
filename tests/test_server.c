#include "server.h"
#include "unity.h"
#include "urtp/version.h"

static void clean_urtp_env(void) {
    unsetenv("URTP_CONTROL_SOCK");
    unsetenv("URTP_CONTROL_SOCK_PATH");
    unsetenv("URTP_CONTROL_TCP");
    unsetenv("URTP_CONTROL_TCP_PORT");
    unsetenv("URTP_CONTROL_NG");
    unsetenv("URTP_CONTROL_NG_PORT");
    unsetenv("URTP_CONTROL_UDP_PORT");
    unsetenv("URTP_MEDIA_IP");
    unsetenv("URTP_RECORD_DIR");
    unsetenv("URTP_RECORD_ALL");
    unsetenv("URTP_ENTRIES");
    unsetenv("URTP_RING_ENTRIES");
    unsetenv("URTP_BUFFERS");
    unsetenv("URTP_BUF_ENTRIES");
    unsetenv("URTP_SQPOLL");
    unsetenv("URTP_TRANSCODER");
    unsetenv("URTP_TRANSCODE_BACKEND");
    unsetenv("URTP_TRANSCODE_CODEC");
    unsetenv("URTP_TRANSCODE");
    unsetenv("URTP_JITTER_BUFFER");
    unsetenv("URTP_JITTER");
    unsetenv("URTP_SHUTDOWN_TIMEOUT");
    unsetenv("URTP_INACTIVITY_TIMEOUT");
    unsetenv("URTP_SETUP_TIMEOUT");
    unsetenv("URTP_METRICS_INTERVAL");
}

void setUp(void) { clean_urtp_env(); }

void tearDown(void) { clean_urtp_env(); }

static void test_server_config_default(void) {
    server_config_t config = {};
    server_config_default(&config);

    TEST_ASSERT_EQUAL_STRING("/tmp/urtp.sock", config.control_sock_path);
    TEST_ASSERT_EQUAL_UINT16(0, config.control_tcp_port);
    TEST_ASSERT_EQUAL_UINT16(22222, config.control_udp_port);
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", config.media_ip);
    TEST_ASSERT_EQUAL_UINT32(30, config.shutdown_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(60, config.inactivity_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(30, config.setup_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(0, config.metrics_interval_sec);
    TEST_ASSERT_EQUAL_UINT32(RING_DEFAULT_ENTRIES, config.ring_entries);
    TEST_ASSERT_EQUAL_UINT32(RING_DEFAULT_BUF_ENTRIES, config.buf_entries);
}

static void test_server_config_parse_bg_tasks(void) {
    server_config_t config = {};

    char  a0[]   = "urtp";
    char  a1[]   = "-I";
    char  a2[]   = "45";
    char  a3[]   = "-S";
    char  a4[]   = "15";
    char  a5[]   = "-M";
    char  a6[]   = "5";
    char *argv[] = {a0, a1, a2, a3, a4, a5, a6, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 7, argv));
    TEST_ASSERT_EQUAL_UINT32(45, config.inactivity_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(15, config.setup_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(5, config.metrics_interval_sec);

    char  b0[]        = "urtp";
    char  b1[]        = "--inactivity-timeout";
    char  b2[]        = "90";
    char  b3[]        = "--setup-timeout";
    char  b4[]        = "20";
    char  b5[]        = "--metrics-interval";
    char  b6[]        = "10";
    char *argv_long[] = {b0, b1, b2, b3, b4, b5, b6, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 7, argv_long));
    TEST_ASSERT_EQUAL_UINT32(90, config.inactivity_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(20, config.setup_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(10, config.metrics_interval_sec);
}

static void test_server_config_parse_shutdown_timeout(void) {
    server_config_t config = {};

    char  a0[]         = "urtp";
    char  a1[]         = "-w";
    char  a2[]         = "15";
    char *argv_short[] = {a0, a1, a2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv_short));
    TEST_ASSERT_EQUAL_UINT32(15, config.shutdown_timeout_sec);

    char  b0[]        = "urtp";
    char  b1[]        = "--shutdown-timeout";
    char  b2[]        = "60";
    char *argv_long[] = {b0, b1, b2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv_long));
    TEST_ASSERT_EQUAL_UINT32(60, config.shutdown_timeout_sec);

    char  c0[]        = "urtp";
    char  c1[]        = "-w";
    char  c2[]        = "0";
    char *argv_zero[] = {c0, c1, c2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv_zero));
    TEST_ASSERT_EQUAL_UINT32(0, config.shutdown_timeout_sec);
}

static void test_server_config_parse_invalid(void) {
    server_config_t config = {};

    char  h0[]        = "urtp";
    char  h1[]        = "--help";
    char *argv_help[] = {h0, h1, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_EXIT_SUCCESS, server_config_parse(&config, 2, argv_help));

    char  b0[]       = "urtp";
    char  b1[]       = "--nonexistent";
    char *argv_bad[] = {b0, b1, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_parse(&config, 2, argv_bad));
}

static void test_server_config_parse_tcp(void) {
    server_config_t config = {};

    char  a0[]       = "urtp";
    char  a1[]       = "-t";
    char  a2[]       = "22222";
    char *argv_tcp[] = {a0, a1, a2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv_tcp));
    TEST_ASSERT_EQUAL_UINT16(22222, config.control_tcp_port);

    char  b0[]            = "urtp";
    char  b1[]            = "--control-tcp";
    char  b2[]            = "9100";
    char *argv_tcp_long[] = {b0, b1, b2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv_tcp_long));
    TEST_ASSERT_EQUAL_UINT16(9100, config.control_tcp_port);
}

static void test_server_config_parse_version(void) {
    server_config_t config = {};

    char  v0[]           = "urtp";
    char  v1[]           = "-v";
    char *argv_version[] = {v0, v1, nullptr};
    TEST_ASSERT_EQUAL_INT(
        SERVER_CONFIG_EXIT_SUCCESS,
        server_config_parse(&config, 2, argv_version));

    char  vlong0[]            = "urtp";
    char  vlong1[]            = "--version";
    char *argv_version_long[] = {vlong0, vlong1, nullptr};
    TEST_ASSERT_EQUAL_INT(
        SERVER_CONFIG_EXIT_SUCCESS,
        server_config_parse(&config, 2, argv_version_long));

    TEST_ASSERT_NOT_NULL(URTP_VERSION);
    TEST_ASSERT_TRUE(__builtin_strlen(URTP_VERSION) > 0);
    TEST_ASSERT_NOT_NULL(URTP_BUILD_DATE);
    TEST_ASSERT_TRUE(__builtin_strlen(URTP_BUILD_DATE) > 0);
    TEST_ASSERT_NOT_NULL(URTP_BUILD_TIME);
    TEST_ASSERT_TRUE(__builtin_strlen(URTP_BUILD_TIME) > 0);
}

static void test_server_config_env_all(void) {
    server_config_t config = {};

    setenv("URTP_CONTROL_SOCK", "/tmp/custom.sock", 1);
    setenv("URTP_CONTROL_TCP", "8080", 1);
    setenv("URTP_CONTROL_NG", "33333", 1);
    setenv("URTP_MEDIA_IP", "192.168.1.50", 1);
    setenv("URTP_RECORD_DIR", "/var/log/pcap", 1);
    setenv("URTP_RECORD_ALL", "true", 1);
    setenv("URTP_ENTRIES", "2048", 1);
    setenv("URTP_BUFFERS", "8192", 1);
    setenv("URTP_SQPOLL", "1", 1);
    setenv("URTP_TRANSCODER", "libopus", 1);
    setenv("URTP_TRANSCODE_CODEC", "pcmu", 1);
    setenv("URTP_JITTER_BUFFER", "40", 1);
    setenv("URTP_SHUTDOWN_TIMEOUT", "12", 1);
    setenv("URTP_INACTIVITY_TIMEOUT", "120", 1);
    setenv("URTP_SETUP_TIMEOUT", "45", 1);
    setenv("URTP_METRICS_INTERVAL", "15", 1);

    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));

    TEST_ASSERT_EQUAL_STRING("/tmp/custom.sock", config.control_sock_path);
    TEST_ASSERT_EQUAL_UINT16(8080, config.control_tcp_port);
    TEST_ASSERT_EQUAL_UINT16(33333, config.control_udp_port);
    TEST_ASSERT_EQUAL_STRING("192.168.1.50", config.media_ip);
    TEST_ASSERT_EQUAL_STRING("/var/log/pcap", config.record_dir);
    TEST_ASSERT_TRUE(config.record_all);
    TEST_ASSERT_EQUAL_UINT32(2048, config.ring_entries);
    TEST_ASSERT_EQUAL_UINT32(8192, config.buf_entries);
    TEST_ASSERT_TRUE(config.try_sqpoll);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, config.transcoder_backend);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, config.transcode_codec);
    TEST_ASSERT_EQUAL_UINT32(40, config.jitter_buffer_ms);
    TEST_ASSERT_EQUAL_UINT32(12, config.shutdown_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(120, config.inactivity_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(45, config.setup_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(15, config.metrics_interval_sec);
}

static void test_server_config_env_aliases(void) {
    server_config_t config = {};

    setenv("URTP_CONTROL_SOCK_PATH", "/tmp/alias.sock", 1);
    setenv("URTP_CONTROL_TCP_PORT", "9090", 1);
    setenv("URTP_CONTROL_UDP_PORT", "44444", 1);
    setenv("URTP_RING_ENTRIES", "1024", 1);
    setenv("URTP_BUF_ENTRIES", "2048", 1);
    setenv("URTP_TRANSCODE_BACKEND", "ffmpeg", 1);
    setenv("URTP_JITTER", "50", 1);

    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));

    TEST_ASSERT_EQUAL_STRING("/tmp/alias.sock", config.control_sock_path);
    TEST_ASSERT_EQUAL_UINT16(9090, config.control_tcp_port);
    TEST_ASSERT_EQUAL_UINT16(44444, config.control_udp_port);
    TEST_ASSERT_EQUAL_UINT32(1024, config.ring_entries);
    TEST_ASSERT_EQUAL_UINT32(2048, config.buf_entries);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, config.transcoder_backend);
    TEST_ASSERT_EQUAL_UINT32(50, config.jitter_buffer_ms);

    // Test URTP_CONTROL_NG_PORT alias
    clean_urtp_env();
    setenv("URTP_CONTROL_NG_PORT", "55555", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));
    TEST_ASSERT_EQUAL_UINT16(55555, config.control_udp_port);

    // Test URTP_TRANSCODE convenience option
    clean_urtp_env();
    setenv("URTP_TRANSCODE", "pcma", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMA, config.transcode_codec);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, config.transcoder_backend);
}

static void test_server_config_env_booleans(void) {
    server_config_t config = {};

    // Test truthy values
    char const *const truthy[] = {"1", "true", "TRUE", "yes", "YES", "on", "ON"};
    for (size_t i = 0; i < (sizeof(truthy) / sizeof(truthy[0])); ++i) {
        clean_urtp_env();
        setenv("URTP_RECORD_ALL", truthy[i], 1);
        setenv("URTP_SQPOLL", truthy[i], 1);
        server_config_default(&config);
        TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));
        TEST_ASSERT_TRUE(config.record_all);
        TEST_ASSERT_TRUE(config.try_sqpoll);
    }

    // Test falsy values
    char const *const falsy[] = {"0", "false", "FALSE", "no", "NO", "off", "OFF"};
    for (size_t i = 0; i < (sizeof(falsy) / sizeof(falsy[0])); ++i) {
        clean_urtp_env();
        setenv("URTP_RECORD_ALL", falsy[i], 1);
        setenv("URTP_SQPOLL", falsy[i], 1);
        server_config_default(&config);
        TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_env(&config));
        TEST_ASSERT_FALSE(config.record_all);
        TEST_ASSERT_FALSE(config.try_sqpoll);
    }
}

static void test_server_config_precedence(void) {
    server_config_t config = {};

    // 1. Set environment variables
    setenv("URTP_MEDIA_IP", "10.0.0.1", 1);
    setenv("URTP_SHUTDOWN_TIMEOUT", "50", 1);
    setenv("URTP_ENTRIES", "2048", 1);
    setenv("URTP_INACTIVITY_TIMEOUT", "99", 1); // Unchanged by CLI switches below
    setenv("URTP_RECORD_ALL", "false", 1);

    // 2. Pass CLI arguments that override some of the env vars
    char  a0[]   = "urtp";
    char  a1[]   = "-m";
    char  a2[]   = "192.168.1.1";
    char  a3[]   = "-w";
    char  a4[]   = "10";
    char  a5[]   = "-e";
    char  a6[]   = "512";
    char  a7[]   = "-R";
    char *argv[] = {a0, a1, a2, a3, a4, a5, a6, a7, nullptr};

    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 8, argv));

    // Assert that CLI arguments override environment variables
    TEST_ASSERT_EQUAL_STRING("192.168.1.1", config.media_ip);
    TEST_ASSERT_EQUAL_UINT32(10, config.shutdown_timeout_sec);
    TEST_ASSERT_EQUAL_UINT32(512, config.ring_entries);
    TEST_ASSERT_TRUE(config.record_all);

    // Assert that env var was applied for the switch NOT given on CLI
    TEST_ASSERT_EQUAL_UINT32(99, config.inactivity_timeout_sec);
}

static void test_server_config_env_invalid(void) {
    server_config_t config = {};

    // Bad port
    clean_urtp_env();
    setenv("URTP_CONTROL_TCP", "not_a_port", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));

    // Port out of bounds
    clean_urtp_env();
    setenv("URTP_CONTROL_TCP", "70000", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));

    // Negative count
    clean_urtp_env();
    setenv("URTP_ENTRIES", "-5", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));

    // Bad boolean
    clean_urtp_env();
    setenv("URTP_RECORD_ALL", "maybe", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));

    // Bad transcoder
    clean_urtp_env();
    setenv("URTP_TRANSCODER", "invalid_backend", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));

    // Bad codec
    clean_urtp_env();
    setenv("URTP_TRANSCODE_CODEC", "invalid_codec", 1);
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_env(&config));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_server_config_default);
    RUN_TEST(test_server_config_parse_bg_tasks);
    RUN_TEST(test_server_config_parse_shutdown_timeout);
    RUN_TEST(test_server_config_parse_tcp);
    RUN_TEST(test_server_config_parse_invalid);
    RUN_TEST(test_server_config_parse_version);
    RUN_TEST(test_server_config_env_all);
    RUN_TEST(test_server_config_env_aliases);
    RUN_TEST(test_server_config_env_booleans);
    RUN_TEST(test_server_config_precedence);
    RUN_TEST(test_server_config_env_invalid);
    return UNITY_END();
}
