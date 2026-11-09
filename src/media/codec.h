#pragma once

#include <stddef.h>
#include <stdint.h>
#include <strings.h>
#include "core/macros.h"
#include "core/string_view.h"

/**
 * @file codec.h
 * @brief Zero-allocation audio codec definitions, G.711 ITU-T transforms, and audio resampling.
 */

/** @brief Standard static RTP payload type for G.711 mu-law (PCMU). */
constexpr uint8_t RTP_PT_PCMU = 0;
/** @brief Standard static RTP payload type for G.711 A-law (PCMA). */
constexpr uint8_t RTP_PT_PCMA = 8;
/** @brief Standard default dynamic RTP payload type for Opus audio (96). */
constexpr uint8_t RTP_PT_OPUS_DEFAULT = 96;
/** @brief Alternative standard dynamic RTP payload type for Opus audio (111). */
constexpr uint8_t RTP_PT_OPUS_ALT = 111;

/** @brief Standard sampling rate for narrowband telephony audio (8000 Hz). */
constexpr uint32_t MEDIA_SAMPLE_RATE_8K = 8000;
/** @brief Fullband sampling rate for Opus audio (48000 Hz). */
constexpr uint32_t MEDIA_SAMPLE_RATE_48K = 48000;

/** @brief Standard audio frame packetization duration in milliseconds (20ms). */
constexpr size_t MEDIA_FRAME_MS = 20;
/** @brief Number of mono PCM samples in a 20ms frame at 8 kHz (160 samples). */
constexpr size_t MEDIA_SAMPLES_8K_20MS = 160; // (8000 * 20) / 1000
/** @brief Number of mono PCM samples in a 20ms frame at 48 kHz (960 samples). */
constexpr size_t MEDIA_SAMPLES_48K_20MS = 960; // (48000 * 20) / 1000

/** @brief Standard payload byte size for a 20ms G.711 frame (160 bytes). */
constexpr size_t G711_PAYLOAD_SIZE_20MS = 160; // 1 byte per sample

/**
 * @brief Supported media audio codecs.
 */
typedef enum : uint8_t {
    MEDIA_CODEC_NONE = 0, /**< Unrecognized or unsupported codec. */
    MEDIA_CODEC_PCMU = 1, /**< ITU-T G.711 mu-law narrowband audio. */
    MEDIA_CODEC_PCMA = 2, /**< ITU-T G.711 A-law narrowband audio. */
    MEDIA_CODEC_OPUS = 3, /**< IETF RFC 6716 Opus audio codec. */
} media_codec_t;

/**
 * @brief Transcoding implementation engine backends.
 */
typedef enum : uint8_t {
    TRANSCODER_BACKEND_NONE   = 0, /**< Transcoding disabled (passthrough). */
    TRANSCODER_BACKEND_OPUS   = 1, /**< Native high-performance libopus backend. */
    TRANSCODER_BACKEND_FFMPEG = 2, /**< FFmpeg / libavcodec backend. */
} transcoder_backend_t;

/**
 * @brief Returns the human-readable string name of a media codec.
 *
 * @param codec Codec identifier.
 * @return Human-readable string representation ("PCMU", "PCMA", "opus", or "none").
 */
[[nodiscard]] static inline char const *media_codec_name(media_codec_t const codec) {
    switch (codec) {
    case MEDIA_CODEC_PCMU:
        return "PCMU";
    case MEDIA_CODEC_PCMA:
        return "PCMA";
    case MEDIA_CODEC_OPUS:
        return "opus";
    case MEDIA_CODEC_NONE:
    default:
        return "none";
    }
}

/**
 * @brief Parses a media codec from a string view or C string.
 *
 * @param str Case-insensitive codec name string.
 * @return Matching media_codec_t or MEDIA_CODEC_NONE.
 */
[[nodiscard]] static inline media_codec_t media_codec_from_str(char const *restrict const str) {
    if (unlikely(str == nullptr)) {
        return MEDIA_CODEC_NONE;
    }
    if ((strcasecmp(str, "PCMU") == 0) || (strcasecmp(str, "G711U") == 0) ||
        (strcasecmp(str, "ulaw") == 0))
    {
        return MEDIA_CODEC_PCMU;
    }
    if ((strcasecmp(str, "PCMA") == 0) || (strcasecmp(str, "G711A") == 0) ||
        (strcasecmp(str, "alaw") == 0))
    {
        return MEDIA_CODEC_PCMA;
    }
    if (strcasecmp(str, "opus") == 0) {
        return MEDIA_CODEC_OPUS;
    }
    return MEDIA_CODEC_NONE;
}

/**
 * @brief Returns the default RTP payload type for a given codec.
 *
 * @param codec Codec identifier.
 * @return Default RTP payload type byte.
 */
[[nodiscard]] static inline uint8_t media_codec_default_pt(media_codec_t const codec) {
    switch (codec) {
    case MEDIA_CODEC_PCMU:
        return RTP_PT_PCMU;
    case MEDIA_CODEC_PCMA:
        return RTP_PT_PCMA;
    case MEDIA_CODEC_OPUS:
        return RTP_PT_OPUS_DEFAULT;
    case MEDIA_CODEC_NONE:
    default:
        return 0;
    }
}

/**
 * @brief Infers the codec from an RTP payload type byte.
 *
 * @param pt RTP payload type byte.
 * @return Inferred media_codec_t or MEDIA_CODEC_NONE.
 */
[[nodiscard]] static inline media_codec_t media_codec_from_pt(uint8_t const pt) {
    if (pt == RTP_PT_PCMU) {
        return MEDIA_CODEC_PCMU;
    }
    if (pt == RTP_PT_PCMA) {
        return MEDIA_CODEC_PCMA;
    }
    if ((pt == RTP_PT_OPUS_DEFAULT) || (pt == RTP_PT_OPUS_ALT)) {
        return MEDIA_CODEC_OPUS;
    }
    // Dynamic payload type range fallback
    if ((pt >= 96) && (pt <= 127)) {
        return MEDIA_CODEC_OPUS;
    }
    return MEDIA_CODEC_NONE;
}

/**
 * @brief Returns the nominal sampling rate in Hz for a codec.
 *
 * @param codec Codec identifier.
 * @return Sample rate in Hz (e.g. 8000 or 48000).
 */
[[nodiscard]] static inline uint32_t media_codec_sample_rate(media_codec_t const codec) {
    switch (codec) {
    case MEDIA_CODEC_PCMU:
    case MEDIA_CODEC_PCMA:
        return MEDIA_SAMPLE_RATE_8K;
    case MEDIA_CODEC_OPUS:
        return MEDIA_SAMPLE_RATE_48K;
    case MEDIA_CODEC_NONE:
    default:
        return 0;
    }
}

/**
 * @brief Returns the number of samples in a standard 20ms frame for the codec.
 *
 * @param codec Codec identifier.
 * @return Number of samples per 20ms frame.
 */
[[nodiscard]] static inline size_t media_codec_frame_samples_20ms(media_codec_t const codec) {
    switch (codec) {
    case MEDIA_CODEC_PCMU:
    case MEDIA_CODEC_PCMA:
        return MEDIA_SAMPLES_8K_20MS;
    case MEDIA_CODEC_OPUS:
        return MEDIA_SAMPLES_48K_20MS;
    case MEDIA_CODEC_NONE:
    default:
        return 0;
    }
}

/**
 * @brief Returns the string name of a transcoder backend.
 *
 * @param backend Backend identifier.
 * @return Backend name string.
 */
[[nodiscard]] static inline char const *
transcoder_backend_name(transcoder_backend_t const backend) {
    switch (backend) {
    case TRANSCODER_BACKEND_OPUS:
        return "libopus";
    case TRANSCODER_BACKEND_FFMPEG:
        return "ffmpeg";
    case TRANSCODER_BACKEND_NONE:
    default:
        return "none";
    }
}

/**
 * @brief Parses a transcoder backend from string.
 *
 * @param str Backend name string.
 * @return Matching transcoder_backend_t.
 */
[[nodiscard]] static inline transcoder_backend_t
transcoder_backend_from_str(char const *restrict const str) {
    if (unlikely(str == nullptr)) {
        return TRANSCODER_BACKEND_NONE;
    }
    if ((strcasecmp(str, "libopus") == 0) || (strcasecmp(str, "opus") == 0)) {
        return TRANSCODER_BACKEND_OPUS;
    }
    if (strcasecmp(str, "ffmpeg") == 0) {
        return TRANSCODER_BACKEND_FFMPEG;
    }
    if ((strcasecmp(str, "none") == 0) || (strcasecmp(str, "off") == 0) ||
        (strcasecmp(str, "0") == 0))
    {
        return TRANSCODER_BACKEND_NONE;
    }
    return TRANSCODER_BACKEND_NONE;
}

/* ========================================================================= */
/* ITU-T G.711 Standard mu-Law and A-Law Conversions (Zero Allocations)      */
/* ========================================================================= */

/**
 * @brief Encodes a 16-bit signed linear PCM sample to 8-bit ITU-T G.711 mu-law.
 *
 * @param pcm_val 16-bit signed PCM sample.
 * @return 8-bit encoded mu-law sample.
 */
[[nodiscard]] static inline uint8_t media_linear_to_ulaw(int16_t const pcm_val) {
    int mask = 0;
    int seg  = 0;
    int pcm  = pcm_val;

    if (pcm < 0) {
        pcm  = -pcm;
        mask = 0x7F;
    } else {
        mask = 0xFF;
    }

    if (pcm > 32635) {
        pcm = 32635;
    }
    pcm = (pcm + 0x84);

    if (pcm >= 0x4000) {
        seg = 7;
    } else if (pcm >= 0x2000) {
        seg = 6;
    } else if (pcm >= 0x1000) {
        seg = 5;
    } else if (pcm >= 0x0800) {
        seg = 4;
    } else if (pcm >= 0x0400) {
        seg = 3;
    } else if (pcm >= 0x0200) {
        seg = 2;
    } else if (pcm >= 0x0100) {
        seg = 1;
    } else {
        seg = 0;
    }

    auto const uval = (uint8_t)((seg << 4) | ((pcm >> (seg + 3)) & 0x0F));
    return (uint8_t)(uval ^ mask);
}

/**
 * @brief Decodes an 8-bit ITU-T G.711 mu-law sample to 16-bit signed linear PCM.
 *
 * @param u_val 8-bit encoded mu-law sample.
 * @return 16-bit signed linear PCM sample.
 */
[[nodiscard]] static inline int16_t media_ulaw_to_linear(uint8_t const u_val) {
    auto const inverted = (uint8_t)(~u_val);
    int        t        = (((inverted & 0x0F) << 3) + 0x84);
    t <<= ((inverted & 0x70) >> 4);
    return (int16_t)((inverted & 0x80) ? (0x84 - t) : (t - 0x84));
}

/**
 * @brief Encodes a 16-bit signed linear PCM sample to 8-bit ITU-T G.711 A-law.
 *
 * @param pcm_val 16-bit signed PCM sample.
 * @return 8-bit encoded A-law sample.
 */
[[nodiscard]] static inline uint8_t media_linear_to_alaw(int16_t const pcm_val) {
    int mask = 0;
    int seg  = 0;
    int pcm  = pcm_val;

    if (pcm >= 0) {
        mask = 0xD5;
    } else {
        mask = 0x55;
        pcm  = (-pcm - 1);
    }

    if (pcm >= 0x4000) {
        seg = 7;
    } else if (pcm >= 0x2000) {
        seg = 6;
    } else if (pcm >= 0x1000) {
        seg = 5;
    } else if (pcm >= 0x0800) {
        seg = 4;
    } else if (pcm >= 0x0400) {
        seg = 3;
    } else if (pcm >= 0x0200) {
        seg = 2;
    } else if (pcm >= 0x0100) {
        seg = 1;
    } else {
        seg = 0;
    }

    uint8_t aval = 0;
    if (seg >= 8) {
        aval = 0x7F;
    } else if (seg < 1) {
        aval = (uint8_t)((pcm >> 4) & 0x0F);
    } else {
        aval = (uint8_t)((seg << 4) | ((pcm >> (seg + 3)) & 0x0F));
    }

    return (uint8_t)(aval ^ mask);
}

/**
 * @brief Decodes an 8-bit ITU-T G.711 A-law sample to 16-bit signed linear PCM.
 *
 * @param a_val 8-bit encoded A-law sample.
 * @return 16-bit signed linear PCM sample.
 */
[[nodiscard]] static inline int16_t media_alaw_to_linear(uint8_t const a_val) {
    auto const toggled = (uint8_t)(a_val ^ 0x55);
    int        t       = ((toggled & 0x0F) << 4);
    int const  seg     = ((toggled & 0x70) >> 4);

    switch (seg) {
    case 0:
        t += 8;
        break;
    case 1:
        t += 0x108;
        break;
    default:
        t += 0x108;
        t <<= (seg - 1);
        break;
    }

    return (int16_t)((toggled & 0x80) ? t : -t);
}

/* ========================================================================= */
/* Deterministic Zero-Allocation Audio Resampling (48 kHz <-> 8 kHz, 6:1)    */
/* ========================================================================= */

/**
 * @brief Downsamples 48 kHz mono PCM (960 samples) to 8 kHz mono PCM (160 samples).
 *
 * Uses anti-aliasing decimation averaging each 6 consecutive input samples.
 *
 * @param src Source 48 kHz PCM samples array.
 * @param src_samples Number of input samples.
 * @param dst Destination 8 kHz PCM buffer.
 * @param dst_cap Capacity in samples of destination buffer.
 */
static inline void media_resample_48k_to_8k(
    int16_t const *restrict const src,
    size_t const src_samples,
    int16_t *restrict const dst,
    size_t const dst_cap) {
    if (unlikely((src == nullptr) || (dst == nullptr))) {
        return;
    }
    size_t const out_count = (src_samples / 6);
    size_t const limit     = (out_count < dst_cap) ? out_count : dst_cap;

    for (size_t i = 0; i < limit; ++i) {
        int32_t      sum  = 0;
        size_t const base = (i * 6);
        for (size_t k = 0; k < 6; ++k) {
            sum += (int32_t)src[base + k];
        }
        dst[i] = (int16_t)(sum / 6);
    }
}

/**
 * @brief Upsamples 8 kHz mono PCM (160 samples) to 48 kHz mono PCM (960 samples).
 *
 * Uses linear interpolation across each consecutive sample pair.
 *
 * @param src Source 8 kHz PCM samples array.
 * @param src_samples Number of input samples.
 * @param dst Destination 48 kHz PCM buffer.
 * @param dst_cap Capacity in samples of destination buffer.
 */
static inline void media_resample_8k_to_48k(
    int16_t const *restrict const src,
    size_t const src_samples,
    int16_t *restrict const dst,
    size_t const dst_cap) {
    if (unlikely((src == nullptr) || (dst == nullptr) || (src_samples == 0))) {
        return;
    }
    size_t const max_in = (dst_cap / 6);
    size_t const in_len = (src_samples < max_in) ? src_samples : max_in;

    for (size_t i = 0; i < in_len; ++i) {
        int32_t const cur  = (int32_t)src[i];
        int32_t const next = ((i + 1) < src_samples) ? (int32_t)src[i + 1] : cur;
        int32_t const diff = (next - cur);
        size_t const  base = (i * 6);

        for (size_t k = 0; k < 6; ++k) {
            dst[base + k] = (int16_t)(cur + ((diff * (int32_t)k) / 6));
        }
    }
}
