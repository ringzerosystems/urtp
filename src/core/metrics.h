#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @file metrics.h
 * @brief Server performance telemetry counters and Prometheus exposition.
 */

/**
 * @brief Raw event counters representing server operational telemetry.
 */
typedef struct {
    alignas(64) uint64_t rx_packets;  /**< Total UDP datagrams received. */
    uint64_t tx_packets;              /**< Total UDP datagrams transmitted. */
    uint64_t rx_bytes;                /**< Total bytes received over UDP. */
    uint64_t tx_bytes;                /**< Total bytes transmitted over UDP. */
    uint64_t rtp_packets;             /**< Classified RTP media packets processed. */
    uint64_t rtcp_packets;            /**< Classified RTCP control packets processed. */
    uint64_t packets_dropped;         /**< Packets dropped due to buffer or route errors. */
    uint64_t srtp_encrypted;          /**< Inbound/outbound packets encrypted via SRTP. */
    uint64_t srtp_decrypted;          /**< Inbound packets decrypted via SRTP. */
    uint64_t srtp_auth_failures;      /**< SRTP packets failing authentication checks. */
    uint64_t transcode_decoded;       /**< Audio frames decoded by transcoders. */
    uint64_t transcode_encoded;       /**< Audio frames encoded by transcoders. */
    uint64_t buffer_ring_exhaustions; /**< Out-of-buffer events on the provided buffer ring. */
    uint64_t sessions_reaped;         /**< Idle sessions reaped by watchdog/inactivity sweep. */
    uint64_t jb_packets_reordered;    /**< Out-of-order packets reordered by jitter buffer. */
    uint64_t jb_packets_dropped_late; /**< Late packets dropped past jitter playout deadline. */
    uint64_t jb_loss_concealments;    /**< Packet loss concealment (PLC) frames generated. */
    uint64_t video_rx_packets;        /**< Video RTP packets received. */
    uint64_t video_tx_packets;        /**< Video RTP packets transmitted. */
    uint64_t video_rx_bytes;          /**< Video bytes received. */
    uint64_t video_tx_bytes;          /**< Video bytes transmitted. */
    uint64_t rtcp_pli_packets;        /**< RTCP PLI keyframe request packets generated. */
} metrics_counters_t;

/**
 * @brief Server-wide metrics container with cumulative totals and 1-second rate rollups.
 */
typedef struct {
    alignas(64)
        metrics_counters_t cumulative;  /**< Cumulative total counters since server startup. */
    metrics_counters_t last_snapshot;   /**< Previous snapshot of counters for rate calculation. */
    metrics_counters_t rate_per_sec;    /**< Instantaneous per-second rate delta. */
    uint64_t           last_rollup_sec; /**< Timestamp in seconds of last rollup calculation. */
} server_metrics_t;

/**
 * @brief Zero-initializes server telemetry metrics structure.
 *
 * @param metrics Pointer to server metrics instance.
 */
void metrics_init(server_metrics_t *restrict const metrics);

/**
 * @brief Computes 1-second delta and instantaneous rates between cumulative and last snapshot.
 *
 * @param metrics Pointer to server metrics instance.
 * @param now_sec Current monotonic timestamp in seconds.
 */
void metrics_rollup(server_metrics_t *restrict const metrics, uint64_t const now_sec);

/**
 * @brief Formats metrics in Prometheus text exposition format.
 *
 * @param metrics Pointer to server metrics.
 * @param active_sessions Current number of active media relay sessions.
 * @param active_video_sessions Current number of active video relay sessions.
 * @param buf Output buffer for Prometheus formatted string.
 * @param max_len Capacity of output buffer.
 * @return Number of bytes written (excluding null terminator), or 0 on error.
 */
[[nodiscard]] size_t metrics_format_prometheus(
    server_metrics_t const *restrict const metrics,
    size_t const active_sessions,
    size_t const active_video_sessions,
    char *restrict const buf,
    size_t const max_len);

/**
 * @brief SSRC telemetry snapshot entry for Prometheus formatting.
 */
typedef struct {
    uint16_t port;
    uint32_t ssrc;
    uint64_t idle_sec;
} metric_ssrc_entry_t;

/**
 * @brief Formats SSRC idle duration metrics in Prometheus text exposition format.
 *
 * @param entries Array of SSRC metric entries.
 * @param count Number of entries.
 * @param buf Output buffer.
 * @param max_len Capacity of output buffer.
 * @return Number of bytes written (excluding null terminator), or 0 on error.
 */
[[nodiscard]] size_t metrics_format_ssrc(
    metric_ssrc_entry_t const *restrict const entries,
    size_t const count,
    char *restrict const buf,
    size_t const max_len);
