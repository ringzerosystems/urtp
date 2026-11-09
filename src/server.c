#include "server.h"
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "core/log.h"
#include "core/macros.h"
#include "crypto/dtls.h"
#include "crypto/srtp_session.h"
#include "urtp/version.h"

static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_force_shutdown     = 0;

static void handle_signal(int const signum) {
    (void)signum;
    if (g_shutdown_requested) {
        g_force_shutdown = 1;
    } else {
        g_shutdown_requested = 1;
    }
}

static void print_usage(char const *const prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -c, --control-sock <path>      UNIX domain control socket path (default: "
           "/tmp/urtp.sock) [env: URTP_CONTROL_SOCK]\n");
    printf(
        "  -t, --control-tcp <port>       TCP control port (optional) [env: URTP_CONTROL_TCP]\n");
    printf("  -n, --control-ng <port>        UDP NG control port for Kamailio/OpenSIPS (default: "
           "22222) [env: URTP_CONTROL_NG]\n");
    printf("  -m, --media-ip <ip>            Advertised media IP for SDP rewrite (default: "
           "127.0.0.1) [env: URTP_MEDIA_IP]\n");
    printf("  -r, --record-dir <path>        Volume/directory path for PCAP call captures [env: "
           "URTP_RECORD_DIR]\n");
    printf("  -R, --record-all               Automatically record all media streams to PCAP [env: "
           "URTP_RECORD_ALL]\n");
    printf(
        "  -e, --entries <count>          io_uring submission queue entries (default: %u) [env: "
        "URTP_ENTRIES]\n",
        RING_DEFAULT_ENTRIES);
    printf(
        "  -b, --buffers <count>          Buffer ring entries (default: %u) [env: URTP_BUFFERS]\n",
        RING_DEFAULT_BUF_ENTRIES);
    printf("  -s, --sqpoll                   Attempt io_uring SQPOLL kernel thread [env: "
           "URTP_SQPOLL]\n");
    printf("  -T, --transcoder <backend>     Audio transcoding backend: libopus, ffmpeg, none "
           "(default: none) [env: URTP_TRANSCODER]\n");
    printf(
        "  -C, --transcode-codec <codec>  Default target codec: pcmu, pcma, opus, auto (default: "
        "auto) [env: URTP_TRANSCODE_CODEC]\n");
    printf("  -j, --jitter-buffer <ms>       Jitter buffer target latency in ms (transcoding only, "
           "default: 0=disabled) [env: URTP_JITTER_BUFFER]\n");
    printf(
        "  -w, --shutdown-timeout <sec>   Timeout in seconds to wait for active sessions to drain "
        "(default: 30, 0=immediate) [env: URTP_SHUTDOWN_TIMEOUT]\n");
    printf(
        "  -I, --inactivity-timeout <sec> Inactivity timeout in seconds for active media (default: "
        "60) [env: URTP_INACTIVITY_TIMEOUT]\n");
    printf("  -S, --setup-timeout <sec>      Setup timeout in seconds for unconfirmed sessions "
           "(default: 30) [env: URTP_SETUP_TIMEOUT]\n");
    printf("  -M, --metrics-interval <sec>   Periodic console telemetry summary interval (default: "
           "0=disabled) [env: URTP_METRICS_INTERVAL]\n");
    printf("  -v, --version                  Display version and build information\n");
    printf("  -h, --help                     Display this help message\n");
}

void server_config_default(server_config_t *restrict const config) {
    if (unlikely(config == nullptr)) {
        return;
    }
    *config = (server_config_t){
        .control_sock_path      = "/tmp/urtp.sock",
        .control_tcp_port       = 0,
        .control_udp_port       = 22222,
        .media_ip               = "127.0.0.1",
        .record_dir             = nullptr,
        .record_all             = false,
        .ring_entries           = RING_DEFAULT_ENTRIES,
        .buf_entries            = RING_DEFAULT_BUF_ENTRIES,
        .try_sqpoll             = false,
        .transcoder_backend     = TRANSCODER_BACKEND_NONE,
        .transcode_codec        = MEDIA_CODEC_NONE,
        .jitter_buffer_ms       = 0,
        .shutdown_timeout_sec   = 30,
        .inactivity_timeout_sec = 60,
        .setup_timeout_sec      = 30,
        .metrics_interval_sec   = 0,
    };
}

static char const *
get_env_alias2(char const *restrict const name1, char const *restrict const name2) {
    char const *const val1 = getenv(name1);
    if (val1 != nullptr) {
        return val1;
    }
    if (name2 != nullptr) {
        return getenv(name2);
    }
    return nullptr;
}

static char const *get_env_alias3(
    char const *restrict const name1,
    char const *restrict const name2,
    char const *restrict const name3) {
    char const *const val = get_env_alias2(name1, name2);
    if (val != nullptr) {
        return val;
    }
    if (name3 != nullptr) {
        return getenv(name3);
    }
    return nullptr;
}

static bool parse_bool_env(char const *restrict const str, bool *restrict const out) {
    if (unlikely((str == nullptr) || (out == nullptr))) {
        return false;
    }
    if ((strcasecmp(str, "1") == 0) || (strcasecmp(str, "true") == 0) ||
        (strcasecmp(str, "yes") == 0) || (strcasecmp(str, "on") == 0))
    {
        *out = true;
        return true;
    }
    if ((strcasecmp(str, "0") == 0) || (strcasecmp(str, "false") == 0) ||
        (strcasecmp(str, "no") == 0) || (strcasecmp(str, "off") == 0))
    {
        *out = false;
        return true;
    }
    return false;
}

static bool parse_uint32_env(char const *restrict const str, uint32_t *restrict const out) {
    if (unlikely((str == nullptr) || (*str == '\0') || (out == nullptr))) {
        return false;
    }
    if (*str == '-') {
        return false;
    }
    char *endptr   = nullptr;
    errno          = 0;
    auto const val = strtoul(str, &endptr, 10);
    if ((errno != 0) || (endptr == str) || (*endptr != '\0') || (val > UINT32_MAX)) {
        return false;
    }
    *out = (uint32_t)val;
    return true;
}

static bool parse_uint16_env(char const *restrict const str, uint16_t *restrict const out) {
    uint32_t val = 0;
    if (!parse_uint32_env(str, &val) || (val > UINT16_MAX)) {
        return false;
    }
    *out = (uint16_t)val;
    return true;
}

server_config_status_t server_config_env(server_config_t *restrict const config) {
    if (unlikely(config == nullptr)) {
        return SERVER_CONFIG_ERROR;
    }

    auto const sock_val = get_env_alias2("URTP_CONTROL_SOCK", "URTP_CONTROL_SOCK_PATH");
    if (sock_val != nullptr) {
        if ((sock_val[0] == '\0') || (strcmp(sock_val, "none") == 0)) {
            config->control_sock_path = nullptr;
        } else {
            config->control_sock_path = sock_val;
        }
    }

    auto const tcp_val = get_env_alias2("URTP_CONTROL_TCP", "URTP_CONTROL_TCP_PORT");
    if (tcp_val != nullptr) {
        uint16_t port = 0;
        if (!parse_uint16_env(tcp_val, &port)) {
            LOG_ERRO("Invalid URTP_CONTROL_TCP port value: %s", tcp_val);
            return SERVER_CONFIG_ERROR;
        }
        config->control_tcp_port = port;
    }

    auto const ng_val =
        get_env_alias3("URTP_CONTROL_NG", "URTP_CONTROL_NG_PORT", "URTP_CONTROL_UDP_PORT");
    if (ng_val != nullptr) {
        uint16_t port = 0;
        if (!parse_uint16_env(ng_val, &port)) {
            LOG_ERRO("Invalid URTP_CONTROL_NG port value: %s", ng_val);
            return SERVER_CONFIG_ERROR;
        }
        config->control_udp_port = port;
    }

    auto const media_ip = get_env_alias2("URTP_MEDIA_IP", nullptr);
    if ((media_ip != nullptr) && (media_ip[0] != '\0')) {
        config->media_ip = media_ip;
    }

    auto const record_dir = get_env_alias2("URTP_RECORD_DIR", nullptr);
    if (record_dir != nullptr) {
        if (record_dir[0] != '\0') {
            config->record_dir = record_dir;
        } else {
            config->record_dir = nullptr;
        }
    }

    auto const record_all_val = get_env_alias2("URTP_RECORD_ALL", nullptr);
    if (record_all_val != nullptr) {
        bool val = false;
        if (!parse_bool_env(record_all_val, &val)) {
            LOG_ERRO(
                "Invalid URTP_RECORD_ALL boolean value: %s (expected true/false, 1/0, yes/no, "
                "on/off)",
                record_all_val);
            return SERVER_CONFIG_ERROR;
        }
        config->record_all = val;
    }

    auto const entries_val = get_env_alias2("URTP_ENTRIES", "URTP_RING_ENTRIES");
    if (entries_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(entries_val, &val) || (val == 0)) {
            LOG_ERRO("Invalid URTP_ENTRIES value: %s (must be > 0)", entries_val);
            return SERVER_CONFIG_ERROR;
        }
        config->ring_entries = val;
    }

    auto const bufs_val = get_env_alias2("URTP_BUFFERS", "URTP_BUF_ENTRIES");
    if (bufs_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(bufs_val, &val) || (val == 0)) {
            LOG_ERRO("Invalid URTP_BUFFERS value: %s (must be > 0)", bufs_val);
            return SERVER_CONFIG_ERROR;
        }
        config->buf_entries = val;
    }

    auto const sqpoll_val = get_env_alias2("URTP_SQPOLL", nullptr);
    if (sqpoll_val != nullptr) {
        bool val = false;
        if (!parse_bool_env(sqpoll_val, &val)) {
            LOG_ERRO(
                "Invalid URTP_SQPOLL boolean value: %s (expected true/false, 1/0, yes/no, on/off)",
                sqpoll_val);
            return SERVER_CONFIG_ERROR;
        }
        config->try_sqpoll = val;
    }

    auto const transcoder_val = get_env_alias2("URTP_TRANSCODER", "URTP_TRANSCODE_BACKEND");
    if (transcoder_val != nullptr) {
        auto const backend = transcoder_backend_from_str(transcoder_val);
        if ((backend == TRANSCODER_BACKEND_NONE) && (strcasecmp(transcoder_val, "none") != 0)) {
            LOG_ERRO(
                "Invalid URTP_TRANSCODER value: %s (expected libopus, ffmpeg, none)",
                transcoder_val);
            return SERVER_CONFIG_ERROR;
        }
        config->transcoder_backend = backend;
    }

    auto const codec_val = get_env_alias2("URTP_TRANSCODE_CODEC", nullptr);
    if (codec_val != nullptr) {
        auto const codec = media_codec_from_str(codec_val);
        if ((codec == MEDIA_CODEC_NONE) && (strcasecmp(codec_val, "none") != 0)) {
            LOG_ERRO(
                "Invalid URTP_TRANSCODE_CODEC value: %s (expected pcmu, pcma, opus, auto)",
                codec_val);
            return SERVER_CONFIG_ERROR;
        }
        config->transcode_codec = codec;
    }

    auto const transcode_val = get_env_alias2("URTP_TRANSCODE", nullptr);
    if (transcode_val != nullptr) {
        auto const backend = transcoder_backend_from_str(transcode_val);
        if (backend != TRANSCODER_BACKEND_NONE) {
            config->transcoder_backend = backend;
        } else {
            auto const codec = media_codec_from_str(transcode_val);
            if (codec != MEDIA_CODEC_NONE) {
                config->transcode_codec = codec;
                if (config->transcoder_backend == TRANSCODER_BACKEND_NONE) {
                    config->transcoder_backend = TRANSCODER_BACKEND_OPUS;
                }
            } else if (strcasecmp(transcode_val, "none") == 0) {
                config->transcoder_backend = TRANSCODER_BACKEND_NONE;
            } else {
                LOG_ERRO("Invalid URTP_TRANSCODE value: %s", transcode_val);
                return SERVER_CONFIG_ERROR;
            }
        }
    }

    auto const jitter_val = get_env_alias2("URTP_JITTER_BUFFER", "URTP_JITTER");
    if (jitter_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(jitter_val, &val)) {
            LOG_ERRO("Invalid URTP_JITTER_BUFFER value: %s", jitter_val);
            return SERVER_CONFIG_ERROR;
        }
        config->jitter_buffer_ms = val;
    }

    auto const shutdown_val = get_env_alias2("URTP_SHUTDOWN_TIMEOUT", nullptr);
    if (shutdown_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(shutdown_val, &val)) {
            LOG_ERRO("Invalid URTP_SHUTDOWN_TIMEOUT value: %s", shutdown_val);
            return SERVER_CONFIG_ERROR;
        }
        config->shutdown_timeout_sec = val;
    }

    auto const inact_val = get_env_alias2("URTP_INACTIVITY_TIMEOUT", nullptr);
    if (inact_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(inact_val, &val)) {
            LOG_ERRO("Invalid URTP_INACTIVITY_TIMEOUT value: %s", inact_val);
            return SERVER_CONFIG_ERROR;
        }
        config->inactivity_timeout_sec = val;
    }

    auto const setup_val = get_env_alias2("URTP_SETUP_TIMEOUT", nullptr);
    if (setup_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(setup_val, &val)) {
            LOG_ERRO("Invalid URTP_SETUP_TIMEOUT value: %s", setup_val);
            return SERVER_CONFIG_ERROR;
        }
        config->setup_timeout_sec = val;
    }

    auto const metrics_val = get_env_alias2("URTP_METRICS_INTERVAL", nullptr);
    if (metrics_val != nullptr) {
        uint32_t val = 0;
        if (!parse_uint32_env(metrics_val, &val)) {
            LOG_ERRO("Invalid URTP_METRICS_INTERVAL value: %s", metrics_val);
            return SERVER_CONFIG_ERROR;
        }
        config->metrics_interval_sec = val;
    }

    return SERVER_CONFIG_OK;
}

server_config_status_t server_config_parse(
    server_config_t *restrict const config,
    int const          argc,
    char *const *const argv) {
    if (unlikely((config == nullptr) || (argv == nullptr))) {
        return SERVER_CONFIG_ERROR;
    }

    // Fast-path: Check for help/version flags early
    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0)) {
            print_usage(argv[0]);
            return SERVER_CONFIG_EXIT_SUCCESS;
        }
        if ((strcmp(argv[i], "-v") == 0) || (strcmp(argv[i], "--version") == 0)) {
            printf("urtp %s (built %s %s)\n", URTP_VERSION, URTP_BUILD_DATE, URTP_BUILD_TIME);
            return SERVER_CONFIG_EXIT_SUCCESS;
        }
    }

    // Tier 1: Initialize defaults
    server_config_default(config);

    // Tier 2: Overlay environment variables (URTP_*)
    auto const env_status = server_config_env(config);
    if (unlikely(env_status != SERVER_CONFIG_OK)) {
        return env_status;
    }

    // Tier 3: Overlay command-line arguments

    static struct option const long_options[] = {
        {"control-sock", required_argument, nullptr, 'c'},
        {"control-tcp", required_argument, nullptr, 't'},
        {"control-ng", required_argument, nullptr, 'n'},
        {"media-ip", required_argument, nullptr, 'm'},
        {"record-dir", required_argument, nullptr, 'r'},
        {"record-all", no_argument, nullptr, 'R'},
        {"entries", required_argument, nullptr, 'e'},
        {"buffers", required_argument, nullptr, 'b'},
        {"sqpoll", no_argument, nullptr, 's'},
        {"transcoder", required_argument, nullptr, 'T'},
        {"transcode-backend", required_argument, nullptr, 'T'},
        {"transcode-codec", required_argument, nullptr, 'C'},
        {"transcode", required_argument, nullptr, 1001},
        {"jitter-buffer", required_argument, nullptr, 'j'},
        {"jitter", required_argument, nullptr, 'j'},
        {"shutdown-timeout", required_argument, nullptr, 'w'},
        {"inactivity-timeout", required_argument, nullptr, 'I'},
        {"setup-timeout", required_argument, nullptr, 'S'},
        {"metrics-interval", required_argument, nullptr, 'M'},
        {"version", no_argument, nullptr, 'v'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}};

    optind  = 1;
    int opt = 0;
    while (
        (opt =
             getopt_long(argc, argv, "c:t:n:m:r:Re:b:shvT:C:w:I:S:M:j:", long_options, nullptr)) !=
        -1)
    {
        switch (opt) {

        case 'c':
            config->control_sock_path = optarg;
            break;
        case 't': {
            int const val = atoi(optarg);
            if ((val > 0) && (val <= 65535)) {
                config->control_tcp_port = (uint16_t)val;
            }
            break;
        }
        case 'n': {
            int const val = atoi(optarg);
            if ((val >= 0) && (val <= 65535)) {
                config->control_udp_port = (uint16_t)val;
            }
            break;
        }
        case 'm':
            config->media_ip = optarg;
            break;
        case 'r':
            config->record_dir = optarg;
            break;
        case 'R':
            config->record_all = true;
            break;
        case 'e': {
            int const val = atoi(optarg);
            if (val > 0) {
                config->ring_entries = (uint32_t)val;
            }
            break;
        }
        case 'b': {
            int const val = atoi(optarg);
            if (val > 0) {
                config->buf_entries = (uint32_t)val;
            }
            break;
        }
        case 's':
            config->try_sqpoll = true;
            break;
        case 'T': {
            auto const backend         = transcoder_backend_from_str(optarg);
            config->transcoder_backend = backend;
            break;
        }
        case 'C': {
            auto const codec        = media_codec_from_str(optarg);
            config->transcode_codec = codec;
            break;
        }
        case 1001: {
            auto const backend = transcoder_backend_from_str(optarg);
            if (backend != TRANSCODER_BACKEND_NONE) {
                config->transcoder_backend = backend;
            } else {
                auto const codec = media_codec_from_str(optarg);
                if (codec != MEDIA_CODEC_NONE) {
                    config->transcode_codec = codec;
                    if (config->transcoder_backend == TRANSCODER_BACKEND_NONE) {
                        config->transcoder_backend = TRANSCODER_BACKEND_OPUS;
                    }
                }
            }
            break;
        }
        case 'w': {
            int const val = atoi(optarg);
            if (val >= 0) {
                config->shutdown_timeout_sec = (uint32_t)val;
            }
            break;
        }
        case 'I': {
            int const val = atoi(optarg);
            if (val >= 0) {
                config->inactivity_timeout_sec = (uint32_t)val;
            }
            break;
        }
        case 'S': {
            int const val = atoi(optarg);
            if (val >= 0) {
                config->setup_timeout_sec = (uint32_t)val;
            }
            break;
        }
        case 'M': {
            int const val = atoi(optarg);
            if (val >= 0) {
                config->metrics_interval_sec = (uint32_t)val;
            }
            break;
        }
        case 'j': {
            int const val = atoi(optarg);
            if (val > 0) {
                config->jitter_buffer_ms = (uint32_t)val;
            } else {
                LOG_ERRO("Invalid jitter-buffer value: %s", optarg);
                return SERVER_CONFIG_ERROR;
            }
            break;
        }
        case 'v':
            printf("urtp %s (built %s %s)\n", URTP_VERSION, URTP_BUILD_DATE, URTP_BUILD_TIME);
            return SERVER_CONFIG_EXIT_SUCCESS;
        case 'h':

            print_usage(argv[0]);
            return SERVER_CONFIG_EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return SERVER_CONFIG_ERROR;
        }
    }

    if (config->jitter_buffer_ms > 0) {
        if (config->transcoder_backend == TRANSCODER_BACKEND_NONE) {
            LOG_ERRO("--jitter-buffer requires an active transcoder (--transcoder libopus|ffmpeg)");
            return SERVER_CONFIG_ERROR;
        }
        if ((config->jitter_buffer_ms < 20) || (config->jitter_buffer_ms > 100)) {
            LOG_ERRO(
                "--jitter-buffer value must be between 20 and 100 ms (got %u ms)",
                config->jitter_buffer_ms);
            return SERVER_CONFIG_ERROR;
        }
    }

    return SERVER_CONFIG_OK;
}

int server_run(server_config_t const *restrict const config) {
    if (unlikely(config == nullptr)) {
        return 1;
    }

    g_shutdown_requested = 0;
    g_force_shutdown     = 0;
    struct sigaction sa  = {};
    sa.sa_handler        = handle_signal;
    (void)sigaction(SIGINT, &sa, nullptr);
    (void)sigaction(SIGTERM, &sa, nullptr);

    LOG_INFO(
        "Starting urtp (uring-rtp) media proxy %s (built %s %s)...",
        URTP_VERSION,
        URTP_BUILD_DATE,
        URTP_BUILD_TIME);

    server_t server = {};
    server.config   = *config;

    if (!urtp_srtp_global_init()) {
        LOG_ERRO("Fatal: Failed to initialize libsrtp crypto engine");
        return 1;
    }

    if (!urtp_dtls_global_init()) {
        LOG_ERRO("Fatal: Failed to initialize OpenSSL DTLS engine");
        urtp_srtp_global_cleanup();
        return 1;
    }

    if (!urtp_transcode_global_init()) {
        LOG_ERRO("Fatal: Failed to initialize media transcoding engine");
        urtp_dtls_global_cleanup();
        urtp_srtp_global_cleanup();
        return 1;
    }

    if (!ring_engine_init(
            &(server.ring_engine),
            config->ring_entries,
            config->buf_entries,
            RING_DEFAULT_BUF_SIZE,
            RING_DEFAULT_BGID,
            config->try_sqpoll))
    {
        LOG_ERRO("Fatal: Failed to initialize io_uring reactor engine");
        urtp_transcode_global_cleanup();
        urtp_dtls_global_cleanup();
        urtp_srtp_global_cleanup();
        return 1;
    }

    session_table_init(&(server.session_table));
    session_table_set_default_transcoder(
        &(server.session_table),
        config->transcoder_backend,
        config->transcode_codec);
    if (config->jitter_buffer_ms > 0) {
        session_table_set_default_jitter(&(server.session_table), config->jitter_buffer_ms);
        LOG_INFO("Jitter buffer active: target=%u ms", config->jitter_buffer_ms);
    }

    metrics_init(&(server.metrics));
    server.session_table.metrics = &(server.metrics);

    struct timespec boot_now = {};
    (void)clock_gettime(CLOCK_MONOTONIC, &boot_now);
    server.session_table.cached_monotonic_sec = (uint64_t)boot_now.tv_sec;
    server.metrics.last_rollup_sec            = (uint64_t)boot_now.tv_sec;

    (void)watchdog_init(&(server.watchdog));

    if (!timer_engine_init(&(server.timer_engine), 1)) {
        LOG_WARN("Failed to initialize timer engine");
    } else {
        (void)timer_engine_arm(&(server.timer_engine), &(server.ring_engine));
    }

    if (config->transcoder_backend != TRANSCODER_BACKEND_NONE) {
        LOG_INFO(
            "Media transcoder active: backend=%s default_codec=%s",
            transcoder_backend_name(config->transcoder_backend),
            media_codec_name(config->transcode_codec));
    }

    if (config->record_dir != nullptr) {
        if (pcap_table_set_record_dir(&(server.session_table.pcap_table), config->record_dir)) {
            server.session_table.pcap_table.record_all = config->record_all;
            LOG_INFO(
                "PCAP recording volume configured at: %s (record_all=%s)",
                config->record_dir,
                config->record_all ? "true" : "false");
        } else {
            LOG_WARN("Failed to configure PCAP recording directory: %s", config->record_dir);
        }
    }

    bool control_started = false;
    control_server_set_media_ip(
        &(server.control_server),
        (config->media_ip != nullptr) ? config->media_ip : "127.0.0.1");

    if (config->control_sock_path != nullptr) {
        if (control_server_init_unix(
                &(server.control_server),
                config->control_sock_path,
                &(server.ring_engine)))
        {
            LOG_INFO("Control server listening on UNIX socket: %s", config->control_sock_path);
            control_started = true;
        } else {
            LOG_WARN("Failed to bind control UNIX socket at %s", config->control_sock_path);
        }
    }

    if (config->control_tcp_port > 0) {
        if (control_server_init_tcp(
                &(server.control_server),
                "0.0.0.0",
                config->control_tcp_port,
                &(server.ring_engine)))
        {
            LOG_INFO("Control server listening on TCP port: %u", config->control_tcp_port);
            control_started = true;
        } else {
            LOG_WARN("Failed to bind control TCP port %u", config->control_tcp_port);
        }
    }

    if (config->control_udp_port > 0) {
        if (control_server_init_udp(
                &(server.control_server),
                "0.0.0.0",
                config->control_udp_port,
                &(server.ring_engine)))
        {
            LOG_INFO("Control server listening on UDP port (NG): %u", config->control_udp_port);
            control_started = true;
        } else {
            LOG_WARN("Failed to bind control UDP port %u", config->control_udp_port);
        }
    }

    if (!control_started) {
        LOG_ERRO("Fatal: No control socket could be established");
        ring_engine_destroy(&(server.ring_engine));
        urtp_dtls_global_cleanup();
        urtp_srtp_global_cleanup();
        return 1;
    }

    LOG_INFO("urtp media engine ready. Entering reactor loop.");

    watchdog_notify_ready(&(server.watchdog));

    ring_engine_submit(&(server.ring_engine));

    constexpr unsigned int BATCH_CQE_COUNT       = 64;
    struct io_uring_cqe   *cqes[BATCH_CQE_COUNT] = {};

    typedef enum : uint8_t {
        SERVER_STATE_RUNNING  = 0,
        SERVER_STATE_DRAINING = 1,
    } server_run_state_t;

    server_run_state_t state              = SERVER_STATE_RUNNING;
    uint64_t           drain_deadline_sec = 0;

    while (!g_force_shutdown) {
        if (unlikely(g_shutdown_requested && (state == SERVER_STATE_RUNNING))) {
            if ((server.session_table.active_count == 0) || (config->shutdown_timeout_sec == 0)) {
                break;
            }
            state = SERVER_STATE_DRAINING;
            control_server_stop_listen(&(server.control_server), &(server.ring_engine));
            drain_deadline_sec =
                server.session_table.cached_monotonic_sec + (uint64_t)config->shutdown_timeout_sec;
            LOG_INFO(
                "Shutdown requested with %zu active session(s). Draining (timeout: %u s)...",
                server.session_table.active_count,
                config->shutdown_timeout_sec);
        }

        if (unlikely(state == SERVER_STATE_DRAINING)) {
            if (server.session_table.active_count == 0) {
                LOG_INFO("All sessions closed. Graceful shutdown complete.");
                break;
            }

            if (server.session_table.cached_monotonic_sec >= drain_deadline_sec) {
                LOG_WARN(
                    "Shutdown timeout reached with %zu active session(s). Forcing shutdown.",
                    server.session_table.active_count);
                break;
            }
        }

        int const wait_ret = ring_engine_submit_and_wait(&(server.ring_engine), 1);
        if (unlikely(wait_ret < 0)) {
            if (wait_ret == -EINTR) {
                continue;
            }
            LOG_ERRO("Error during io_uring_submit_and_wait: %s", strerror(-wait_ret));
            break;
        }

        struct timespec loop_cqe_start = {};
        (void)clock_gettime(CLOCK_MONOTONIC, &loop_cqe_start);

        auto const count =
            io_uring_peek_batch_cqe(&(server.ring_engine.ring), cqes, BATCH_CQE_COUNT);
        for (unsigned int i = 0; i < count; ++i) {
            struct io_uring_cqe const *const cqe = cqes[i];
            user_data_tag_t const            tag = {.raw = cqe->user_data};

            switch (tag.fields.op_type) {
            case OP_TYPE_UDP_RECV:
                session_handle_rx_cqe(
                    &(server.session_table),
                    &(server.ring_engine),
                    cqe,
                    tag.fields.index);
                break;
            case OP_TYPE_UDP_SEND:
                session_handle_tx_cqe(
                    &(server.session_table),
                    &(server.ring_engine),
                    cqe,
                    tag.fields.index,
                    tag.fields.bid,
                    tag.fields.flags);
                break;
            case OP_TYPE_CONTROL_ACCEPT:
                control_server_handle_accept_cqe(
                    &(server.control_server),
                    &(server.ring_engine),
                    cqe);
                break;
            case OP_TYPE_CONTROL_RECV:
                control_server_handle_rx_cqe(
                    &(server.control_server),
                    &(server.session_table),
                    &(server.ring_engine),
                    cqe,
                    tag.fields.index);
                break;
            case OP_TYPE_CONTROL_SEND:
                control_server_handle_tx_cqe(
                    &(server.control_server),
                    &(server.ring_engine),
                    cqe,
                    tag.fields.index);
                break;
            case OP_TYPE_CONTROL_UDP_RECV:
                control_server_handle_udp_rx_cqe(
                    &(server.control_server),
                    &(server.session_table),
                    &(server.ring_engine),
                    cqe);
                break;
            case OP_TYPE_CONTROL_UDP_SEND:
                control_server_handle_udp_tx_cqe(
                    &(server.control_server),
                    &(server.ring_engine),
                    cqe);
                break;
            case OP_TYPE_PCAP_WRITE:
                pcap_handle_write_cqe(
                    &(server.session_table.pcap_table),
                    &(server.ring_engine),
                    cqe,
                    tag.fields.index,
                    tag.fields.bid);
                break;
            case OP_TYPE_TIMER_TICK: {
                (void)timer_engine_rearm(&(server.timer_engine), &(server.ring_engine));
                struct timespec tick_now = {};
                (void)clock_gettime(CLOCK_MONOTONIC, &tick_now);
                uint64_t const now_sec                    = (uint64_t)tick_now.tv_sec;
                server.session_table.cached_monotonic_sec = now_sec;

                // 1. Watchdog Heartbeat
                watchdog_ping(&(server.watchdog), now_sec);

                // 2. Inactivity Sweeper
                session_table_sweep_inactivity(
                    &(server.session_table),
                    &(server.control_server.call_table),
                    &(server.ring_engine),
                    now_sec,
                    config->inactivity_timeout_sec,
                    config->setup_timeout_sec);

                // 3. Metrics Rollup
                metrics_rollup(&(server.metrics), now_sec);

                if ((config->metrics_interval_sec > 0) &&
                    ((now_sec % config->metrics_interval_sec) == 0))
                {
                    auto const     r    = &(server.metrics.rate_per_sec);
                    uint64_t const kbps = (r->tx_bytes * 8) / 1000;
                    LOG_INFO(
                        "[METRICS] sessions=%zu pps_in=%llu pps_out=%llu kbps=%llu "
                        "srtp_drops=%llu",
                        server.session_table.active_count,
                        (unsigned long long)r->rx_packets,
                        (unsigned long long)r->tx_packets,
                        (unsigned long long)kbps,
                        (unsigned long long)r->srtp_auth_failures);
                }
                break;
            }
            case OP_TYPE_NONE:
            default:
                break;
            }
        }

        if (count > 0) {
            io_uring_cq_advance(&(server.ring_engine.ring), count);
            struct timespec loop_cqe_end = {};
            (void)clock_gettime(CLOCK_MONOTONIC, &loop_cqe_end);
            uint64_t const iter_duration_ms =
                (uint64_t)((loop_cqe_end.tv_sec - loop_cqe_start.tv_sec) * 1000) +
                (uint64_t)((loop_cqe_end.tv_nsec - loop_cqe_start.tv_nsec) / 1000000);
            if (unlikely(iter_duration_ms > DEFAULT_STALL_THRESHOLD_MS)) {
                LOG_WARN(
                    "Reactor stall detected: loop iteration took %llu ms (handled %u "
                    "CQEs)",
                    (unsigned long long)iter_duration_ms,
                    count);
            }
        }

        if (unlikely(state == SERVER_STATE_DRAINING) && (server.session_table.active_count == 0)) {
            LOG_INFO("All sessions closed. Graceful shutdown complete.");
            break;
        }
    }

    LOG_INFO("Shutting down urtp...");
    watchdog_notify_stopping(&(server.watchdog));
    watchdog_destroy(&(server.watchdog));
    timer_engine_destroy(&(server.timer_engine));
    control_server_destroy(&(server.control_server), &(server.ring_engine));
    session_table_destroy(&(server.session_table), &(server.ring_engine));
    ring_engine_destroy(&(server.ring_engine));
    urtp_transcode_global_cleanup();
    urtp_dtls_global_cleanup();
    urtp_srtp_global_cleanup();

    LOG_INFO("urtp shutdown complete.");
    return 0;
}
