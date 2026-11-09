#include "media/transcode.h"
#include <arpa/inet.h>
#include <string.h>
#include "core/macros.h"
#include "media/jitter.h"
#include "net/rtp.h"

#include <opus/opus.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wcast-qual"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

bool urtp_transcode_global_init(void) {
    // Modern libavcodec 61+ does not require avcodec_register_all()
    return true;
}

void urtp_transcode_global_cleanup(void) {
    // No global state to tear down
}

bool transcoder_init(
    transcoder_ctx_t *restrict const ctx,
    transcoder_backend_t const backend,
    media_codec_t const        src_codec,
    media_codec_t const        dst_codec) {
    if (unlikely(
            (ctx == nullptr) || (backend == TRANSCODER_BACKEND_NONE) ||
            (src_codec == MEDIA_CODEC_NONE) || (dst_codec == MEDIA_CODEC_NONE)))
    {
        return false;
    }

    *ctx = (transcoder_ctx_t){
        .backend   = backend,
        .src_codec = src_codec,
        .dst_codec = dst_codec,
        .src_pt    = media_codec_default_pt(src_codec),
        .dst_pt    = media_codec_default_pt(dst_codec),
        .src_rate  = media_codec_sample_rate(src_codec),
        .dst_rate  = media_codec_sample_rate(dst_codec),
    };

    if (backend == TRANSCODER_BACKEND_OPUS) {
        if (src_codec == MEDIA_CODEC_OPUS) {
            int err       = 0;
            ctx->opus_dec = opus_decoder_create(MEDIA_SAMPLE_RATE_48K, 1, &err);
            if (unlikely((ctx->opus_dec == nullptr) || (err != OPUS_OK))) {
                transcoder_destroy(ctx);
                return false;
            }
        }

        if (dst_codec == MEDIA_CODEC_OPUS) {
            int err = 0;
            ctx->opus_enc =
                opus_encoder_create(MEDIA_SAMPLE_RATE_48K, 1, OPUS_APPLICATION_VOIP, &err);
            if (unlikely((ctx->opus_enc == nullptr) || (err != OPUS_OK))) {
                transcoder_destroy(ctx);
                return false;
            }
            (void)opus_encoder_ctl(ctx->opus_enc, OPUS_SET_BITRATE(24000));
            (void)opus_encoder_ctl(ctx->opus_enc, OPUS_SET_COMPLEXITY(5));
            (void)opus_encoder_ctl(ctx->opus_enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        }

        ctx->initialized = true;
        ctx->enabled     = true;
        return true;
    }

    if (backend == TRANSCODER_BACKEND_FFMPEG) {
        ctx->ff_in_pkt   = av_packet_alloc();
        ctx->ff_out_pkt  = av_packet_alloc();
        ctx->ff_in_frame = av_frame_alloc();

        if (unlikely(
                (ctx->ff_in_pkt == nullptr) || (ctx->ff_out_pkt == nullptr) ||
                (ctx->ff_in_frame == nullptr)))
        {
            transcoder_destroy(ctx);
            return false;
        }

        if (src_codec == MEDIA_CODEC_OPUS) {
            AVCodec const *const dec = avcodec_find_decoder(AV_CODEC_ID_OPUS);
            if (unlikely(dec == nullptr)) {
                transcoder_destroy(ctx);
                return false;
            }
            ctx->ff_dec_ctx              = avcodec_alloc_context3(dec);
            ctx->ff_dec_ctx->sample_rate = MEDIA_SAMPLE_RATE_48K;
            av_channel_layout_default(&(ctx->ff_dec_ctx->ch_layout), 1);

            if (unlikely(avcodec_open2(ctx->ff_dec_ctx, dec, nullptr) < 0)) {
                transcoder_destroy(ctx);
                return false;
            }

            AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
            int const       sret = swr_alloc_set_opts2(
                &(ctx->ff_swr_ctx),
                &mono,
                AV_SAMPLE_FMT_S16,
                MEDIA_SAMPLE_RATE_8K,
                &mono,
                AV_SAMPLE_FMT_FLTP,
                MEDIA_SAMPLE_RATE_48K,
                0,
                nullptr);
            if (unlikely((sret < 0) || (swr_init(ctx->ff_swr_ctx) < 0))) {
                transcoder_destroy(ctx);
                return false;
            }
        }

        if (dst_codec == MEDIA_CODEC_OPUS) {
            AVCodec const *const enc = avcodec_find_encoder(AV_CODEC_ID_OPUS);
            if (unlikely(enc == nullptr)) {
                transcoder_destroy(ctx);
                return false;
            }
            ctx->ff_enc_ctx              = avcodec_alloc_context3(enc);
            ctx->ff_enc_ctx->sample_rate = MEDIA_SAMPLE_RATE_48K;
            av_channel_layout_default(&(ctx->ff_enc_ctx->ch_layout), 1);
            ctx->ff_enc_ctx->sample_fmt = AV_SAMPLE_FMT_FLT;
            ctx->ff_enc_ctx->bit_rate   = 24000;

            if (unlikely(avcodec_open2(ctx->ff_enc_ctx, enc, nullptr) < 0)) {
                transcoder_destroy(ctx);
                return false;
            }

            ctx->ff_in_frame->nb_samples = (int)MEDIA_SAMPLES_48K_20MS;
            ctx->ff_in_frame->format     = ctx->ff_enc_ctx->sample_fmt;
            (void)av_channel_layout_copy(
                &(ctx->ff_in_frame->ch_layout),
                &(ctx->ff_enc_ctx->ch_layout));
            ctx->ff_in_frame->sample_rate = MEDIA_SAMPLE_RATE_48K;
            if (unlikely(av_frame_get_buffer(ctx->ff_in_frame, 0) < 0)) {
                transcoder_destroy(ctx);
                return false;
            }
        }

        ctx->initialized = true;
        ctx->enabled     = true;
        return true;
    }

    return false;
}

void transcoder_destroy(transcoder_ctx_t *restrict const ctx) {
    if (unlikely(ctx == nullptr)) {
        return;
    }

    if (ctx->opus_dec != nullptr) {
        opus_decoder_destroy(ctx->opus_dec);
        ctx->opus_dec = nullptr;
    }

    if (ctx->opus_enc != nullptr) {
        opus_encoder_destroy(ctx->opus_enc);
        ctx->opus_enc = nullptr;
    }

    if (ctx->ff_in_frame != nullptr) {
        av_frame_free(&(ctx->ff_in_frame));
    }
    if (ctx->ff_out_frame != nullptr) {
        av_frame_free(&(ctx->ff_out_frame));
    }
    if (ctx->ff_in_pkt != nullptr) {
        av_packet_free(&(ctx->ff_in_pkt));
    }
    if (ctx->ff_out_pkt != nullptr) {
        av_packet_free(&(ctx->ff_out_pkt));
    }
    if (ctx->ff_swr_ctx != nullptr) {
        swr_free(&(ctx->ff_swr_ctx));
    }
    if (ctx->ff_dec_ctx != nullptr) {
        avcodec_free_context(&(ctx->ff_dec_ctx));
    }
    if (ctx->ff_enc_ctx != nullptr) {
        avcodec_free_context(&(ctx->ff_enc_ctx));
    }

    *ctx = (transcoder_ctx_t){};
}

void transcoder_reset(transcoder_ctx_t *restrict const ctx) {
    if (unlikely(ctx == nullptr)) {
        return;
    }

    ctx->outbound_seq     = 0;
    ctx->outbound_ts      = 0;
    ctx->ssrc             = 0;
    ctx->ssrc_initialized = false;

    if (ctx->opus_dec != nullptr) {
        (void)opus_decoder_ctl(ctx->opus_dec, OPUS_RESET_STATE);
    }
    if (ctx->opus_enc != nullptr) {
        (void)opus_encoder_ctl(ctx->opus_enc, OPUS_RESET_STATE);
    }
    if (ctx->ff_dec_ctx != nullptr) {
        avcodec_flush_buffers(ctx->ff_dec_ctx);
    }
    if (ctx->ff_enc_ctx != nullptr) {
        avcodec_flush_buffers(ctx->ff_enc_ctx);
    }
}

static inline void transcoder_finish_rtp_frame(
    transcoder_ctx_t *restrict const ctx,
    void *restrict const out_packet,
    size_t const  payload_len,
    uint8_t const marker_bit,
    size_t *restrict const out_len) {
    auto const out_hdr = (rtp_header_t *)out_packet;
    out_hdr->v_p_x_cc  = (RTP_VERSION_2 << 6);
    out_hdr->m_pt      = (uint8_t)((marker_bit & 0x80) | (ctx->dst_pt & 0x7F));
    out_hdr->seq       = htons(ctx->outbound_seq++);
    out_hdr->timestamp = htonl(ctx->outbound_ts);
    ctx->outbound_ts += (uint32_t)media_codec_frame_samples_20ms(ctx->dst_codec);
    out_hdr->ssrc = htonl(ctx->ssrc);

    *out_len = (sizeof(rtp_header_t) + payload_len);
    ctx->packets_out++;
    ctx->bytes_out += *out_len;
}

bool transcoder_process_rtp(
    transcoder_ctx_t *restrict const ctx,
    void const *restrict const in_packet,
    size_t const in_len,
    void *restrict const out_packet,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->enabled) || !(ctx->initialized) || (in_packet == nullptr) ||
            (out_packet == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    if (unlikely((in_len < RTP_HEADER_MIN_SIZE) || (out_cap < RTP_HEADER_MIN_SIZE))) {
        ctx->errors++;
        return false;
    }

    auto const in_hdr = (rtp_header_t const *)in_packet;
    if (unlikely(rtp_get_version(in_hdr) != RTP_VERSION_2)) {
        ctx->errors++;
        return false;
    }

    uint8_t const cc      = (uint8_t)(in_hdr->v_p_x_cc & 0x0F);
    size_t        hdr_len = (RTP_HEADER_MIN_SIZE + ((size_t)cc * 4));

    // RFC 3550 Extension header handling
    if ((in_hdr->v_p_x_cc & 0x10) != 0) {
        if (unlikely(in_len < (hdr_len + 4))) {
            ctx->errors++;
            return false;
        }
        uint16_t ext_words = 0;
        __builtin_memcpy(&ext_words, ((uint8_t const *)in_packet) + hdr_len + 2, sizeof(ext_words));
        ext_words = ntohs(ext_words);
        hdr_len += 4 + ((size_t)ext_words * 4);
    }

    if (unlikely(in_len < hdr_len)) {
        ctx->errors++;
        return false;
    }

    size_t padding_len = 0;
    if ((in_hdr->v_p_x_cc & 0x20) != 0) {
        padding_len = ((uint8_t const *)in_packet)[in_len - 1];
        if (unlikely((hdr_len + padding_len) > in_len)) {
            ctx->errors++;
            return false;
        }
    }

    uint8_t const *const in_payload     = ((uint8_t const *)in_packet) + hdr_len;
    size_t const         in_payload_len = (in_len - hdr_len - padding_len);
    if (unlikely(in_payload_len == 0)) {
        return false;
    }

    // Initialize outbound RTP sequence, timestamp, and SSRC on first packet
    if (unlikely(!(ctx->ssrc_initialized))) {
        ctx->ssrc            = ntohl(in_hdr->ssrc);
        ctx->outbound_seq    = ntohs(in_hdr->seq);
        uint32_t const in_ts = ntohl(in_hdr->timestamp);
        if (ctx->src_rate != ctx->dst_rate) {
            ctx->outbound_ts =
                (uint32_t)(((uint64_t)in_ts * (uint64_t)ctx->dst_rate) / (uint64_t)ctx->src_rate);
        } else {
            ctx->outbound_ts = in_ts;
        }
        ctx->ssrc_initialized = true;
    }

    uint8_t *const out_payload_ptr = ((uint8_t *)out_packet) + sizeof(rtp_header_t);
    size_t const   out_payload_cap =
        (out_cap > sizeof(rtp_header_t)) ? (out_cap - sizeof(rtp_header_t)) : 0;
    size_t out_payload_len = 0;

    /* ===================================================================== */
    /* Backend 1: libopus (Native)                                           */
    /* ===================================================================== */
    if (ctx->backend == TRANSCODER_BACKEND_OPUS) {
        // Case A: Opus -> G.711 (PCMU / PCMA)
        if ((ctx->src_codec == MEDIA_CODEC_OPUS) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            int const decoded_samples = opus_decode(
                ctx->opus_dec,
                in_payload,
                (opus_int32)in_payload_len,
                ctx->pcm_48k,
                (int)MEDIA_SAMPLES_48K_20MS,
                0);
            if (unlikely(decoded_samples <= 0)) {
                ctx->errors++;
                return false;
            }

            media_resample_48k_to_8k(
                ctx->pcm_48k,
                (size_t)decoded_samples,
                ctx->pcm_8k,
                MEDIA_SAMPLES_8K_20MS);

            if (unlikely(out_payload_cap < G711_PAYLOAD_SIZE_20MS)) {
                ctx->errors++;
                return false;
            }

            if (ctx->dst_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_ulaw(ctx->pcm_8k[i]);
                }
            } else {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_alaw(ctx->pcm_8k[i]);
                }
            }
            out_payload_len = G711_PAYLOAD_SIZE_20MS;
        }
        // Case B: G.711 (PCMU / PCMA) -> Opus
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            (ctx->dst_codec == MEDIA_CODEC_OPUS))
        {
            size_t const g711_samples =
                (in_payload_len < MEDIA_SAMPLES_8K_20MS) ? in_payload_len : MEDIA_SAMPLES_8K_20MS;

            if (ctx->src_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < g711_samples; ++i) {
                    ctx->pcm_8k[i] = media_ulaw_to_linear(in_payload[i]);
                }
            } else {
                for (size_t i = 0; i < g711_samples; ++i) {
                    ctx->pcm_8k[i] = media_alaw_to_linear(in_payload[i]);
                }
            }

            media_resample_8k_to_48k(
                ctx->pcm_8k,
                g711_samples,
                ctx->pcm_48k,
                MEDIA_SAMPLES_48K_20MS);

            int const enc_bytes = opus_encode(
                ctx->opus_enc,
                ctx->pcm_48k,
                (int)MEDIA_SAMPLES_48K_20MS,
                out_payload_ptr,
                (opus_int32)out_payload_cap);
            if (unlikely(enc_bytes <= 0)) {
                ctx->errors++;
                return false;
            }
            out_payload_len = (size_t)enc_bytes;
        }
        // Case C: G.711 <-> G.711 direct transcode
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            size_t const count =
                (in_payload_len < out_payload_cap) ? in_payload_len : out_payload_cap;
            if (ctx->src_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < count; ++i) {
                    int16_t const pcm  = media_ulaw_to_linear(in_payload[i]);
                    out_payload_ptr[i] = media_linear_to_alaw(pcm);
                }
            } else {
                for (size_t i = 0; i < count; ++i) {
                    int16_t const pcm  = media_alaw_to_linear(in_payload[i]);
                    out_payload_ptr[i] = media_linear_to_ulaw(pcm);
                }
            }
            out_payload_len = count;
        } else {
            ctx->errors++;
            return false;
        }
    }
    /* ===================================================================== */
    /* Backend 2: FFmpeg (libavcodec + libswresample)                         */
    /* ===================================================================== */
    else if (ctx->backend == TRANSCODER_BACKEND_FFMPEG)
    {
        // Case A: Opus -> G.711 (PCMU / PCMA)
        if ((ctx->src_codec == MEDIA_CODEC_OPUS) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            if (unlikely(in_payload_len > sizeof(ctx->scratch_buf))) {
                ctx->errors++;
                return false;
            }
            __builtin_memcpy(ctx->scratch_buf, in_payload, in_payload_len);
            ctx->ff_in_pkt->data = ctx->scratch_buf;
            ctx->ff_in_pkt->size = (int)in_payload_len;

            int ret = avcodec_send_packet(ctx->ff_dec_ctx, ctx->ff_in_pkt);
            if (unlikely(ret < 0)) {
                ctx->errors++;
                return false;
            }

            ret = avcodec_receive_frame(ctx->ff_dec_ctx, ctx->ff_in_frame);
            if (unlikely(ret < 0)) {
                ctx->errors++;
                return false;
            }

            // Convert and downsample using FFmpeg swresample
            uint8_t  *out_ch[1]   = {(uint8_t *)ctx->pcm_8k};
            int const out_samples = swr_convert(
                ctx->ff_swr_ctx,
                out_ch,
                (int)MEDIA_SAMPLES_8K_20MS,
                (uint8_t const *const *)ctx->ff_in_frame->data,
                ctx->ff_in_frame->nb_samples);

            if (unlikely(out_samples <= 0)) {
                // Fallback to internal resampler if swresample had insufficient samples
                float const *const flt_data = (float const *)(void *)ctx->ff_in_frame->data[0];
                size_t const       nb       = (size_t)ctx->ff_in_frame->nb_samples;
                for (size_t i = 0; i < nb && i < MEDIA_SAMPLES_48K_20MS; ++i) {
                    float const v   = flt_data[i];
                    ctx->pcm_48k[i] = (int16_t)(v * 32767.0f);
                }
                media_resample_48k_to_8k(ctx->pcm_48k, nb, ctx->pcm_8k, MEDIA_SAMPLES_8K_20MS);
            }

            if (unlikely(out_payload_cap < G711_PAYLOAD_SIZE_20MS)) {
                ctx->errors++;
                return false;
            }

            if (ctx->dst_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_ulaw(ctx->pcm_8k[i]);
                }
            } else {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_alaw(ctx->pcm_8k[i]);
                }
            }
            out_payload_len = G711_PAYLOAD_SIZE_20MS;
        }
        // Case B: G.711 (PCMU / PCMA) -> Opus
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            (ctx->dst_codec == MEDIA_CODEC_OPUS))
        {
            size_t const g711_samples =
                (in_payload_len < MEDIA_SAMPLES_8K_20MS) ? in_payload_len : MEDIA_SAMPLES_8K_20MS;

            if (ctx->src_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < g711_samples; ++i) {
                    ctx->pcm_8k[i] = media_ulaw_to_linear(in_payload[i]);
                }
            } else {
                for (size_t i = 0; i < g711_samples; ++i) {
                    ctx->pcm_8k[i] = media_alaw_to_linear(in_payload[i]);
                }
            }

            media_resample_8k_to_48k(
                ctx->pcm_8k,
                g711_samples,
                ctx->pcm_48k,
                MEDIA_SAMPLES_48K_20MS);

            // Populate FFmpeg frame for Opus encoder
            float *const f_data = (float *)(void *)ctx->ff_in_frame->data[0];
            for (size_t i = 0; i < MEDIA_SAMPLES_48K_20MS; ++i) {
                f_data[i] = (float)ctx->pcm_48k[i] / 32768.0f;
            }

            int ret = avcodec_send_frame(ctx->ff_enc_ctx, ctx->ff_in_frame);
            if (unlikely(ret < 0)) {
                ctx->errors++;
                return false;
            }

            av_packet_unref(ctx->ff_out_pkt);
            ret = avcodec_receive_packet(ctx->ff_enc_ctx, ctx->ff_out_pkt);
            if (unlikely((ret < 0) || (ctx->ff_out_pkt->size <= 0))) {
                ctx->errors++;
                return false;
            }

            if (unlikely((size_t)ctx->ff_out_pkt->size > out_payload_cap)) {
                ctx->errors++;
                return false;
            }

            __builtin_memcpy(out_payload_ptr, ctx->ff_out_pkt->data, (size_t)ctx->ff_out_pkt->size);
            out_payload_len = (size_t)ctx->ff_out_pkt->size;
        }
        // Case C: G.711 <-> G.711 direct transcode
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            size_t const count =
                (in_payload_len < out_payload_cap) ? in_payload_len : out_payload_cap;
            if (ctx->src_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < count; ++i) {
                    int16_t const pcm  = media_ulaw_to_linear(in_payload[i]);
                    out_payload_ptr[i] = media_linear_to_alaw(pcm);
                }
            } else {
                for (size_t i = 0; i < count; ++i) {
                    int16_t const pcm  = media_alaw_to_linear(in_payload[i]);
                    out_payload_ptr[i] = media_linear_to_ulaw(pcm);
                }
            }
            out_payload_len = count;
        } else {
            ctx->errors++;
            return false;
        }
    } else {
        ctx->errors++;
        return false;
    }

    transcoder_finish_rtp_frame(
        ctx,
        out_packet,
        out_payload_len,
        (uint8_t)(in_hdr->m_pt & 0x80),
        out_len);

    ctx->packets_in++;
    ctx->bytes_in += in_len;

    return true;
}

void transcoder_set_jitter_buffer(
    transcoder_ctx_t *restrict const ctx,
    jitter_buffer_t *restrict const jb) {
    if (unlikely(ctx == nullptr)) {
        return;
    }
    ctx->jitter_buf     = jb;
    ctx->jitter_enabled = (jb != nullptr);
}

bool transcoder_process_plc(
    transcoder_ctx_t *restrict const ctx,
    void *restrict const out_packet,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->enabled) || !(ctx->initialized) || (out_packet == nullptr) ||
            (out_len == nullptr) || (out_cap < (sizeof(rtp_header_t) + G711_PAYLOAD_SIZE_20MS))))
    {
        return false;
    }

    uint8_t *const out_payload_ptr = ((uint8_t *)out_packet) + sizeof(rtp_header_t);
    size_t const   out_payload_cap = out_cap - sizeof(rtp_header_t);
    size_t         out_payload_len = 0;

    if (ctx->backend == TRANSCODER_BACKEND_OPUS) {
        // Case A: Opus -> G.711 (PCMU / PCMA)
        if ((ctx->src_codec == MEDIA_CODEC_OPUS) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            // Native Opus Packet Loss Concealment (PLC): pass nullptr payload and 0 length
            int const decoded_samples = opus_decode(
                ctx->opus_dec,
                nullptr,
                0,
                ctx->pcm_48k,
                (int)MEDIA_SAMPLES_48K_20MS,
                0);
            if (unlikely(decoded_samples <= 0)) {
                ctx->errors++;
                return false;
            }

            media_resample_48k_to_8k(
                ctx->pcm_48k,
                (size_t)decoded_samples,
                ctx->pcm_8k,
                MEDIA_SAMPLES_8K_20MS);

            if (unlikely(out_payload_cap < G711_PAYLOAD_SIZE_20MS)) {
                ctx->errors++;
                return false;
            }

            if (ctx->dst_codec == MEDIA_CODEC_PCMU) {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_ulaw(ctx->pcm_8k[i]);
                }
            } else {
                for (size_t i = 0; i < MEDIA_SAMPLES_8K_20MS; ++i) {
                    out_payload_ptr[i] = media_linear_to_alaw(ctx->pcm_8k[i]);
                }
            }
            out_payload_len = G711_PAYLOAD_SIZE_20MS;
        }
        // Case B: G.711 -> Opus
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            (ctx->dst_codec == MEDIA_CODEC_OPUS))
        {
            // G.711 silence concealment: zero out 8k PCM and encode with Opus
            __builtin_memset(ctx->pcm_8k, 0, sizeof(ctx->pcm_8k));
            media_resample_8k_to_48k(
                ctx->pcm_8k,
                MEDIA_SAMPLES_8K_20MS,
                ctx->pcm_48k,
                MEDIA_SAMPLES_48K_20MS);

            int const enc_bytes = opus_encode(
                ctx->opus_enc,
                ctx->pcm_48k,
                (int)MEDIA_SAMPLES_48K_20MS,
                out_payload_ptr,
                (opus_int32)out_payload_cap);
            if (unlikely(enc_bytes <= 0)) {
                ctx->errors++;
                return false;
            }
            out_payload_len = (size_t)enc_bytes;
        }
        // Case C: G.711 -> G.711
        else if (
            ((ctx->src_codec == MEDIA_CODEC_PCMU) || (ctx->src_codec == MEDIA_CODEC_PCMA)) &&
            ((ctx->dst_codec == MEDIA_CODEC_PCMU) || (ctx->dst_codec == MEDIA_CODEC_PCMA)))
        {
            uint8_t const silence_byte = (ctx->dst_codec == MEDIA_CODEC_PCMU) ? 0xFF : 0xD5;
            __builtin_memset(out_payload_ptr, silence_byte, G711_PAYLOAD_SIZE_20MS);
            out_payload_len = G711_PAYLOAD_SIZE_20MS;
        } else {
            ctx->errors++;
            return false;
        }
    } else {
        // FFmpeg or fallback backend
        if (ctx->dst_codec == MEDIA_CODEC_OPUS) {
            __builtin_memset(out_payload_ptr, 0xF8, 3);
            out_payload_len = 3;
        } else {
            uint8_t const silence_byte = (ctx->dst_codec == MEDIA_CODEC_PCMU) ? 0xFF : 0xD5;
            __builtin_memset(out_payload_ptr, silence_byte, G711_PAYLOAD_SIZE_20MS);
            out_payload_len = G711_PAYLOAD_SIZE_20MS;
        }
    }

    transcoder_finish_rtp_frame(ctx, out_packet, out_payload_len, 0, out_len);
    return true;
}
