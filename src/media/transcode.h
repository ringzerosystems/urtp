#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/macros.h"
#include "media/codec.h"

/**
 * @file transcode.h
 * @brief High-throughput zero-allocation audio transcoding pipeline (Opus and G.711 PCMU/PCMA).
 */

// Forward declarations for third-party codec handles
typedef struct OpusDecoder     OpusDecoder;
typedef struct OpusEncoder     OpusEncoder;
typedef struct AVCodecContext  AVCodecContext;
typedef struct SwrContext      SwrContext;
typedef struct AVFrame         AVFrame;
typedef struct AVPacket        AVPacket;
typedef struct jitter_buffer_s jitter_buffer_t;

/**
 * @brief State container for an active audio transcoding pipeline.
 */
typedef struct {
    alignas(64) transcoder_backend_t backend; /**< Active transcode backend (libopus or FFmpeg). */
    media_codec_t src_codec;                  /**< Inbound audio codec format. */
    media_codec_t dst_codec;                  /**< Target outbound audio codec format. */
    uint8_t       src_pt;                     /**< Inbound RTP payload type. */
    uint8_t       dst_pt;                     /**< Outbound RTP payload type. */
    uint32_t      src_rate;         /**< Inbound sampling rate in Hz (e.g. 8000 or 48000). */
    uint32_t      dst_rate;         /**< Outbound sampling rate in Hz (e.g. 8000 or 48000). */
    uint16_t      outbound_seq;     /**< Monotonically increasing outbound RTP sequence number. */
    uint32_t      outbound_ts;      /**< Scaled outbound RTP timestamp. */
    uint32_t      ssrc;             /**< Outbound RTP SSRC identifier. */
    bool          ssrc_initialized; /**< True if outbound SSRC has been generated. */
    bool          initialized;      /**< True if decoder/encoder contexts are ready. */
    bool          enabled;          /**< True if transcoding is active. */

    // libopus handles
    OpusDecoder *opus_dec; /**< Native libopus decoder handle. */
    OpusEncoder *opus_enc; /**< Native libopus encoder handle. */

    // FFmpeg handles
    AVCodecContext *ff_dec_ctx;   /**< FFmpeg decoder context. */
    AVCodecContext *ff_enc_ctx;   /**< FFmpeg encoder context. */
    SwrContext     *ff_swr_ctx;   /**< FFmpeg audio resampler context. */
    AVFrame        *ff_in_frame;  /**< FFmpeg decoded input audio frame. */
    AVFrame        *ff_out_frame; /**< FFmpeg encoded output audio frame. */
    AVPacket       *ff_in_pkt;    /**< FFmpeg input packet. */
    AVPacket       *ff_out_pkt;   /**< FFmpeg output packet. */

    // Pre-allocated static PCM and encoding scratchpads (Zero allocation in hot path)
    int16_t pcm_48k[MEDIA_SAMPLES_48K_20MS]; /**< 48 kHz linear PCM scratchpad (960 samples). */
    int16_t pcm_8k[MEDIA_SAMPLES_8K_20MS];   /**< 8 kHz linear PCM scratchpad (160 samples). */
    uint8_t scratch_buf[2048];               /**< Reusable buffer for encoded frame output. */

    // Optional Jitter Buffer attachment
    jitter_buffer_t *jitter_buf;     /**< Attached optional jitter buffer. */
    bool             jitter_enabled; /**< True if jitter buffering is active on this stream. */

    // Metrics
    uint64_t packets_in;  /**< Total audio packets received for transcoding. */
    uint64_t packets_out; /**< Total audio packets transcoded and transmitted. */
    uint64_t bytes_in;    /**< Total input payload bytes. */
    uint64_t bytes_out;   /**< Total output payload bytes. */
    uint64_t errors;      /**< Total decode/encode/transcode errors encountered. */
} transcoder_ctx_t;

/**
 * @brief Performs global one-time initialization for media transcoding engines.
 *
 * @return true on success, false on failure.
 */
[[nodiscard]] bool urtp_transcode_global_init(void);

/**
 * @brief Tears down any global state initialized by urtp_transcode_global_init.
 */
void urtp_transcode_global_cleanup(void);

/**
 * @brief Initializes a transcoder context for converting src_codec to dst_codec.
 *
 * @param ctx Pointer to transcoder context.
 * @param backend TRANSCODER_BACKEND_OPUS or TRANSCODER_BACKEND_FFMPEG.
 * @param src_codec Source codec (MEDIA_CODEC_OPUS, MEDIA_CODEC_PCMU, or MEDIA_CODEC_PCMA).
 * @param dst_codec Target codec (MEDIA_CODEC_OPUS, MEDIA_CODEC_PCMU, or MEDIA_CODEC_PCMA).
 * @return true on successful initialization, false on error.
 */
[[nodiscard]] bool transcoder_init(
    transcoder_ctx_t *restrict const ctx,
    transcoder_backend_t const backend,
    media_codec_t const        src_codec,
    media_codec_t const        dst_codec);

/**
 * @brief Tears down codec handles and frees context resources.
 *
 * @param ctx Pointer to transcoder context.
 */
void transcoder_destroy(transcoder_ctx_t *restrict const ctx);

/**
 * @brief Resets sequence numbers, timestamps, and codec decoder/encoder states.
 *
 * @param ctx Pointer to transcoder context.
 */
void transcoder_reset(transcoder_ctx_t *restrict const ctx);

/**
 * @brief Processes and transcodes an incoming RTP packet.
 *
 * Strips the RTP header, decodes audio using the configured backend (libopus or ffmpeg),
 * resamples between sample rates (e.g. 48kHz <-> 8kHz), encodes into the target codec,
 * attaches a freshly minted RFC 3550 RTP header with the destination payload type, sequence number,
 * and scaled timestamp, and writes the output packet to out_packet.
 *
 * @param ctx Pointer to active transcoder context.
 * @param in_packet Pointer to incoming raw RTP packet buffer.
 * @param in_len Length in bytes of incoming RTP packet.
 * @param out_packet Buffer to receive transcoded outgoing RTP packet.
 * @param out_cap Maximum capacity in bytes of out_packet buffer.
 * @param out_len Pointer to receive resulting byte count of out_packet.
 * @return true if successfully transcoded, false on parsing, decoding, or buffer error.
 */
[[nodiscard]] bool transcoder_process_rtp(
    transcoder_ctx_t *restrict const ctx,
    void const *restrict const in_packet,
    size_t const in_len,
    void *restrict const out_packet,
    size_t const out_cap,
    size_t *restrict const out_len);

/**
 * @brief Attaches or detaches an optional jitter buffer for this transcoder context.
 *
 * @param ctx Pointer to transcoder context.
 * @param jb Pointer to active jitter buffer struct, or nullptr to disable.
 */
void transcoder_set_jitter_buffer(
    transcoder_ctx_t *restrict const ctx,
    jitter_buffer_t *restrict const jb);

/**
 * @brief Generates a synthetic packet loss concealment (PLC) frame.
 *
 * Invokes native decoder PLC (e.g. opus_decode with NULL payload) or comfort noise,
 * builds a valid RFC 3550 RTP header, and advances sequence and timestamps.
 *
 * @param ctx Pointer to active transcoder context.
 * @param out_packet Buffer to receive resulting synthesized RTP packet.
 * @param out_cap Maximum capacity in bytes of out_packet buffer.
 * @param out_len Pointer to receive resulting byte count of out_packet.
 * @return true on success, false on error.
 */
[[nodiscard]] bool transcoder_process_plc(
    transcoder_ctx_t *restrict const ctx,
    void *restrict const out_packet,
    size_t const out_cap,
    size_t *restrict const out_len);
