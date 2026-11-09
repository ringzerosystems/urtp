#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "control/control.h"
#include "core/metrics.h"
#include "core/watchdog.h"
#include "media/codec.h"
#include "media/transcode.h"
#include "net/session.h"
#include "ring/ring.h"
#include "ring/timer.h"

/**
 * @file server.h
 * @brief Top-level media proxy reactor server configuration and lifecycle orchestration.
 */

/**
 * @brief Command-line and runtime configuration parameters for the media proxy server.
 */
typedef struct {
    char const *control_sock_path; /**< Path to UNIX domain control socket (nullptr if disabled). */
    uint16_t    control_tcp_port;  /**< TCP port for control server (0 if disabled). */
    uint16_t    control_udp_port;  /**< UDP port for Kamailio NG control server (0 if disabled). */
    char const *media_ip;          /**< Advertised media IP embedded into rewritten SDPs. */
    char const *record_dir;        /**< Destination directory for forensic PCAP recordings. */
    bool        record_all;        /**< True to record all sessions automatically. */
    uint32_t    ring_entries;      /**< Submission queue depth for io_uring. */
    uint32_t    buf_entries;       /**< Number of buffers in io_uring provided buffer ring. */
    bool        try_sqpoll;        /**< Attempt kernel SQPOLL thread if permitted. */
    transcoder_backend_t
                  transcoder_backend;   /**< Configured transcoding backend (libopus or FFmpeg). */
    media_codec_t transcode_codec;      /**< Default transcoding target codec. */
    uint32_t      jitter_buffer_ms;     /**< Default playout delay for jitter buffering in ms. */
    uint32_t      shutdown_timeout_sec; /**< Graceful shutdown timeout in seconds. */
    uint32_t      inactivity_timeout_sec; /**< Session inactivity reap timeout in seconds. */
    uint32_t      setup_timeout_sec;      /**< Unconfirmed session setup reap timeout in seconds. */
    uint32_t      metrics_interval_sec;   /**< Interval in seconds for periodic metrics rollup. */
} server_config_t;

/**
 * @brief Top-level media proxy server instance state aggregating all subsystems.
 */
typedef struct {
    alignas(64) ring_engine_t ring_engine; /**< io_uring asynchronous reactor engine. */
    session_table_t    session_table;      /**< Active RTP/RTCP media session table. */
    control_server_t   control_server;     /**< Multi-transport control server. */
    timer_engine_t     timer_engine;       /**< Periodic monotonic timer engine. */
    server_metrics_t   metrics;            /**< Server telemetry metrics counters. */
    systemd_watchdog_t watchdog;           /**< Systemd watchdog notification client. */
    server_config_t    config;             /**< Active server configuration. */
} server_t;

/**
 * @brief Exit status codes for CLI configuration parsing.
 */
typedef enum : int {
    SERVER_CONFIG_OK           = 0, /**< Configuration parsed successfully; proceed to run. */
    SERVER_CONFIG_EXIT_SUCCESS = 1, /**< Command completed successfully (e.g. --help, --version). */
    SERVER_CONFIG_ERROR        = 2, /**< Error encountered parsing CLI options. */
} server_config_status_t;

/**
 * @brief Fills server configuration with default values.
 *
 * @param config Pointer to configuration struct.
 */
void server_config_default(server_config_t *restrict const config);

/**
 * @brief Parses environment variables prefixed with URTP_ into server configuration.
 *
 * Precedence: Defaults < Environment Variables (URTP_*) < Command-line Arguments.
 *
 * @param config Pointer to configuration struct.
 * @return SERVER_CONFIG_OK on success, or SERVER_CONFIG_ERROR if an env var is malformed.
 */
[[nodiscard]] server_config_status_t server_config_env(server_config_t *restrict const config);

/**
 * @brief Parses CLI arguments into server configuration.
 *
 * Defaults are initialized first, followed by environment variable overrides (URTP_*),
 * followed by command-line argument overrides.
 *
 * @param config Pointer to configuration struct.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return SERVER_CONFIG_OK on success, SERVER_CONFIG_EXIT_SUCCESS on help, or SERVER_CONFIG_ERROR.
 */
[[nodiscard]] server_config_status_t server_config_parse(
    server_config_t *restrict const config,
    int const          argc,
    char *const *const argv);

/**
 * @brief Initializes and runs the media proxy reactor server until shutdown.
 *
 * @param config Pointer to server configuration.
 * @return Exit status code (0 on normal termination).
 */
int server_run(server_config_t const *restrict const config);
