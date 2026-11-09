#include "core/metrics.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "core/macros.h"

void metrics_init(server_metrics_t *restrict const metrics) {
    if (unlikely(metrics == nullptr)) {
        return;
    }
    *metrics = (server_metrics_t){};
}

void metrics_rollup(server_metrics_t *restrict const metrics, uint64_t const now_sec) {
    if (unlikely(metrics == nullptr)) {
        return;
    }

    uint64_t const delta_sec =
        (now_sec > metrics->last_rollup_sec) ? (now_sec - metrics->last_rollup_sec) : 1;

    auto const c = &(metrics->cumulative);
    auto const s = &(metrics->last_snapshot);
    auto const r = &(metrics->rate_per_sec);

    r->rx_packets =
        (c->rx_packets >= s->rx_packets) ? ((c->rx_packets - s->rx_packets) / delta_sec) : 0;
    r->tx_packets =
        (c->tx_packets >= s->tx_packets) ? ((c->tx_packets - s->tx_packets) / delta_sec) : 0;
    r->rx_bytes = (c->rx_bytes >= s->rx_bytes) ? ((c->rx_bytes - s->rx_bytes) / delta_sec) : 0;
    r->tx_bytes = (c->tx_bytes >= s->tx_bytes) ? ((c->tx_bytes - s->tx_bytes) / delta_sec) : 0;
    r->rtp_packets =
        (c->rtp_packets >= s->rtp_packets) ? ((c->rtp_packets - s->rtp_packets) / delta_sec) : 0;
    r->rtcp_packets       = (c->rtcp_packets >= s->rtcp_packets)
                                ? ((c->rtcp_packets - s->rtcp_packets) / delta_sec)
                                : 0;
    r->packets_dropped    = (c->packets_dropped >= s->packets_dropped)
                                ? ((c->packets_dropped - s->packets_dropped) / delta_sec)
                                : 0;
    r->srtp_encrypted     = (c->srtp_encrypted >= s->srtp_encrypted)
                                ? ((c->srtp_encrypted - s->srtp_encrypted) / delta_sec)
                                : 0;
    r->srtp_decrypted     = (c->srtp_decrypted >= s->srtp_decrypted)
                                ? ((c->srtp_decrypted - s->srtp_decrypted) / delta_sec)
                                : 0;
    r->srtp_auth_failures = (c->srtp_auth_failures >= s->srtp_auth_failures)
                                ? ((c->srtp_auth_failures - s->srtp_auth_failures) / delta_sec)
                                : 0;
    r->transcode_decoded  = (c->transcode_decoded >= s->transcode_decoded)
                                ? ((c->transcode_decoded - s->transcode_decoded) / delta_sec)
                                : 0;
    r->transcode_encoded  = (c->transcode_encoded >= s->transcode_encoded)
                                ? ((c->transcode_encoded - s->transcode_encoded) / delta_sec)
                                : 0;
    r->buffer_ring_exhaustions =
        (c->buffer_ring_exhaustions >= s->buffer_ring_exhaustions)
            ? ((c->buffer_ring_exhaustions - s->buffer_ring_exhaustions) / delta_sec)
            : 0;
    r->sessions_reaped = (c->sessions_reaped >= s->sessions_reaped)
                             ? ((c->sessions_reaped - s->sessions_reaped) / delta_sec)
                             : 0;
    r->jb_packets_reordered =
        (c->jb_packets_reordered >= s->jb_packets_reordered)
            ? ((c->jb_packets_reordered - s->jb_packets_reordered) / delta_sec)
            : 0;
    r->jb_packets_dropped_late =
        (c->jb_packets_dropped_late >= s->jb_packets_dropped_late)
            ? ((c->jb_packets_dropped_late - s->jb_packets_dropped_late) / delta_sec)
            : 0;
    r->jb_loss_concealments =
        (c->jb_loss_concealments >= s->jb_loss_concealments)
            ? ((c->jb_loss_concealments - s->jb_loss_concealments) / delta_sec)
            : 0;
    r->video_rx_packets = (c->video_rx_packets >= s->video_rx_packets)
                              ? ((c->video_rx_packets - s->video_rx_packets) / delta_sec)
                              : 0;
    r->video_tx_packets = (c->video_tx_packets >= s->video_tx_packets)
                              ? ((c->video_tx_packets - s->video_tx_packets) / delta_sec)
                              : 0;
    r->video_rx_bytes   = (c->video_rx_bytes >= s->video_rx_bytes)
                              ? ((c->video_rx_bytes - s->video_rx_bytes) / delta_sec)
                              : 0;
    r->video_tx_bytes   = (c->video_tx_bytes >= s->video_tx_bytes)
                              ? ((c->video_tx_bytes - s->video_tx_bytes) / delta_sec)
                              : 0;
    r->rtcp_pli_packets = (c->rtcp_pli_packets >= s->rtcp_pli_packets)
                              ? ((c->rtcp_pli_packets - s->rtcp_pli_packets) / delta_sec)
                              : 0;

    metrics->last_snapshot   = *c;
    metrics->last_rollup_sec = now_sec;
}

/**
 * @brief Output buffer cursor for bounds-checked zero-allocation serialization.
 */
typedef struct {
    char       *ptr;      /**< Current write position. */
    char const *end;      /**< Maximum allowed write position (excluding null terminator). */
    bool        overflow; /**< Set to true if any write exceeded buffer capacity. */
} buffer_cursor_t;

/**
 * @brief Precomputed 2-digit lookup table for fast radix-10 integer serialization (00-99).
 */
static constexpr char DIGIT_PAIRS[] = "00010203040506070809"
                                      "10111213141516171819"
                                      "20212223242526272829"
                                      "30313233343536373839"
                                      "40414243444546474849"
                                      "50515253545556575859"
                                      "60616263646566676869"
                                      "70717273747576777879"
                                      "80818283848586878889"
                                      "90919293949596979899";

/**
 * @brief Serializes a Prometheus metric line with a 64-bit unsigned integer value.
 *
 * Employs a branchless 2-digit radix-10 lookup table into an L1-cached stack scratchpad,
 * performing a single upfront bounds check before writing the prefix and formatted digits.
 *
 * @param cursor Output buffer cursor tracking write position and capacity.
 * @param prefix Preformatted Prometheus HELP, TYPE, and metric name prefix string.
 * @param prefix_len Length of the prefix string in bytes.
 * @param val Metric counter or gauge 64-bit unsigned value.
 */
static inline void write_metric_u64(
    buffer_cursor_t *restrict const cursor,
    char const *restrict const prefix,
    size_t const prefix_len,
    uint64_t     val) {
    if (unlikely(cursor->overflow)) {
        return;
    }

    constexpr size_t SCRATCH_SIZE = 24;
    char             scratch[SCRATCH_SIZE];
    char *restrict p = (scratch + SCRATCH_SIZE);

    *(--p) = '\n';

    while (val >= 100) {
        auto const rem = (uint32_t)(val % 100);
        val            = (val / 100);
        p -= 2;
        __builtin_memcpy(p, &(DIGIT_PAIRS[rem * 2]), 2);
    }

    if (val < 10) {
        *(--p) = (char)('0' + val);
    } else {
        p -= 2;
        __builtin_memcpy(p, &(DIGIT_PAIRS[val * 2]), 2);
    }

    size_t const num_len   = (size_t)((scratch + SCRATCH_SIZE) - p);
    size_t const total_len = (prefix_len + num_len);

    if (unlikely((size_t)(cursor->end - cursor->ptr) < total_len)) {
        cursor->overflow = true;
        return;
    }

    __builtin_memcpy(cursor->ptr, prefix, prefix_len);
    cursor->ptr = (cursor->ptr + prefix_len);
    __builtin_memcpy(cursor->ptr, p, num_len);
    cursor->ptr = (cursor->ptr + num_len);
}

/**
 * @brief Generates compile-time concatenated Prometheus exposition metadata and metric name.
 *
 * @param name Metric identifier.
 * @param help Human-readable description.
 * @param type Metric exposition type (e.g., "counter" or "gauge").
 */
#define PROMETHEUS_METRIC_PREFIX(name, help, type)                                                 \
    "# HELP " name " " help "\n# TYPE " name " " type "\n" name " "

/**
 * @brief Emits a single Prometheus metric entry using compile-time prefix sizing.
 *
 * @param cursor Pointer to buffer_cursor_t instance.
 * @param name Metric identifier.
 * @param help Human-readable description.
 * @param type Metric exposition type ("counter" or "gauge").
 * @param val Unsigned 64-bit value to format.
 */
#define FORMAT_METRIC(cursor, name, help, type, val)                                               \
    write_metric_u64(                                                                              \
        (cursor),                                                                                  \
        PROMETHEUS_METRIC_PREFIX(name, help, type),                                                \
        (sizeof(PROMETHEUS_METRIC_PREFIX(name, help, type)) - 1),                                  \
        (uint64_t)(val))

/**
 * @brief Formats server telemetry in Prometheus text exposition format.
 *
 * @param metrics Pointer to server telemetry instance.
 * @param active_sessions Current active media session count.
 * @param active_video_sessions Current active video session count.
 * @param buf Output character buffer.
 * @param max_len Capacity of the output buffer.
 * @return Number of bytes written (excluding null terminator), or 0 on error/overflow.
 */
size_t metrics_format_prometheus(
    server_metrics_t const *restrict const metrics,
    size_t const active_sessions,
    size_t const active_video_sessions,
    char *restrict const buf,
    size_t const max_len) {
    if (unlikely((metrics == nullptr) || (buf == nullptr) || (max_len == 0))) {
        return 0;
    }

    buffer_cursor_t cursor = {};
    cursor.ptr             = buf;
    cursor.end             = (buf + (max_len - 1));

    auto const c = &(metrics->cumulative);
    auto const r = &(metrics->rate_per_sec);

    FORMAT_METRIC(
        &cursor,
        "urtp_rx_packets_total",
        "Total received packets",
        "counter",
        c->rx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_tx_packets_total",
        "Total transmitted packets",
        "counter",
        c->tx_packets);
    FORMAT_METRIC(&cursor, "urtp_rx_bytes_total", "Total received bytes", "counter", c->rx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_tx_bytes_total",
        "Total transmitted bytes",
        "counter",
        c->tx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_rtp_packets_total",
        "Total RTP media packets",
        "counter",
        c->rtp_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_rtcp_packets_total",
        "Total RTCP control packets",
        "counter",
        c->rtcp_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_packets_dropped_total",
        "Total dropped packets",
        "counter",
        c->packets_dropped);
    FORMAT_METRIC(
        &cursor,
        "urtp_srtp_encrypted_total",
        "Total SRTP encrypted packets",
        "counter",
        c->srtp_encrypted);
    FORMAT_METRIC(
        &cursor,
        "urtp_srtp_decrypted_total",
        "Total SRTP decrypted packets",
        "counter",
        c->srtp_decrypted);
    FORMAT_METRIC(
        &cursor,
        "urtp_srtp_auth_failures_total",
        "Total SRTP authentication failures",
        "counter",
        c->srtp_auth_failures);
    FORMAT_METRIC(
        &cursor,
        "urtp_transcode_decoded_total",
        "Total audio packets decoded",
        "counter",
        c->transcode_decoded);
    FORMAT_METRIC(
        &cursor,
        "urtp_transcode_encoded_total",
        "Total audio packets encoded",
        "counter",
        c->transcode_encoded);
    FORMAT_METRIC(
        &cursor,
        "urtp_buffer_ring_exhaustions_total",
        "Total buffer ring exhaustions",
        "counter",
        c->buffer_ring_exhaustions);
    FORMAT_METRIC(
        &cursor,
        "urtp_sessions_reaped_total",
        "Total idle sessions reaped by watchdog",
        "counter",
        c->sessions_reaped);
    FORMAT_METRIC(
        &cursor,
        "urtp_jb_packets_reordered_total",
        "Total packets reordered by jitter buffer",
        "counter",
        c->jb_packets_reordered);
    FORMAT_METRIC(
        &cursor,
        "urtp_jb_packets_dropped_late_total",
        "Total late packets dropped by jitter buffer",
        "counter",
        c->jb_packets_dropped_late);
    FORMAT_METRIC(
        &cursor,
        "urtp_jb_loss_concealments_total",
        "Total PLC loss concealments synthesized",
        "counter",
        c->jb_loss_concealments);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_rx_packets_total",
        "Total received video RTP packets",
        "counter",
        c->video_rx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_tx_packets_total",
        "Total transmitted video RTP packets",
        "counter",
        c->video_tx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_rx_bytes_total",
        "Total received video bytes",
        "counter",
        c->video_rx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_tx_bytes_total",
        "Total transmitted video bytes",
        "counter",
        c->video_tx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_rtcp_pli_total",
        "Total RTCP PLI keyframe request packets",
        "counter",
        c->rtcp_pli_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_rx_rate_bytes",
        "Instantaneous received bytes per second",
        "gauge",
        r->rx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_tx_rate_bytes",
        "Instantaneous transmitted bytes per second",
        "gauge",
        r->tx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_rx_rate_packets",
        "Instantaneous received packets per second",
        "gauge",
        r->rx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_tx_rate_packets",
        "Instantaneous transmitted packets per second",
        "gauge",
        r->tx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_rx_rate_bytes",
        "Instantaneous received video bytes per second",
        "gauge",
        r->video_rx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_tx_rate_bytes",
        "Instantaneous transmitted video bytes per second",
        "gauge",
        r->video_tx_bytes);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_rx_rate_packets",
        "Instantaneous received video packets per second",
        "gauge",
        r->video_rx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_video_tx_rate_packets",
        "Instantaneous transmitted video packets per second",
        "gauge",
        r->video_tx_packets);
    FORMAT_METRIC(
        &cursor,
        "urtp_active_sessions",
        "Active media sessions",
        "gauge",
        active_sessions);
    FORMAT_METRIC(
        &cursor,
        "urtp_active_video_sessions",
        "Active video relay sessions",
        "gauge",
        active_video_sessions);

    if (unlikely(cursor.overflow)) {
        return 0;
    }

    *(cursor.ptr) = '\0';
    return (size_t)(cursor.ptr - buf);
}

size_t metrics_format_ssrc(
    metric_ssrc_entry_t const *restrict const entries,
    size_t const count,
    char *restrict const buf,
    size_t const max_len) {
    if (unlikely((entries == nullptr) || (count == 0) || (buf == nullptr) || (max_len == 0))) {
        return 0;
    }

    buffer_cursor_t cursor = {};
    cursor.ptr             = buf;
    cursor.end             = (buf + (max_len - 1));

    constexpr char HEADER[] =
        "# HELP urtp_ssrc_idle_seconds Monotonic idle seconds by active SSRC\n"
        "# TYPE urtp_ssrc_idle_seconds gauge\n";
    constexpr size_t HEADER_LEN = sizeof(HEADER) - 1;

    if (unlikely((size_t)(cursor.end - cursor.ptr) < HEADER_LEN)) {
        return 0;
    }
    __builtin_memcpy(cursor.ptr, HEADER, HEADER_LEN);
    cursor.ptr += HEADER_LEN;

    for (size_t i = 0; i < count; ++i) {
        char      line_prefix[128] = {};
        int const plen             = snprintf(
            line_prefix,
            sizeof(line_prefix),
            "urtp_ssrc_idle_seconds{port=\"%u\",ssrc=\"%u\"} ",
            entries[i].port,
            entries[i].ssrc);
        if ((plen > 0) && ((size_t)plen < sizeof(line_prefix))) {
            write_metric_u64(&cursor, line_prefix, (size_t)plen, entries[i].idle_sec);
        }
    }

    if (unlikely(cursor.overflow)) {
        return 0;
    }

    *(cursor.ptr) = '\0';
    return (size_t)(cursor.ptr - buf);
}

#undef FORMAT_METRIC
#undef PROMETHEUS_METRIC_PREFIX
