#include <arpa/inet.h>
#include <string.h>
#include "control/control.h"
#include "core/macros.h"
#include "media/codec.h"
#include "media/transcode.h"
#include "net/rtp.h"
#include "net/session.h"
#include "ring/ring.h"
#include "server.h"
#include "unity.h"

#include <opus/opus.h>

void setUp(void) {}
void tearDown(void) {}

static void test_codec_helpers(void) {
    TEST_ASSERT_EQUAL_STRING("PCMU", media_codec_name(MEDIA_CODEC_PCMU));
    TEST_ASSERT_EQUAL_STRING("PCMA", media_codec_name(MEDIA_CODEC_PCMA));
    TEST_ASSERT_EQUAL_STRING("opus", media_codec_name(MEDIA_CODEC_OPUS));
    TEST_ASSERT_EQUAL_STRING("none", media_codec_name(MEDIA_CODEC_NONE));

    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, media_codec_from_str("PCMU"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, media_codec_from_str("ulaw"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMA, media_codec_from_str("PCMA"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMA, media_codec_from_str("alaw"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_OPUS, media_codec_from_str("opus"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_NONE, media_codec_from_str("unknown"));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_NONE, media_codec_from_str(nullptr));

    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMU, media_codec_default_pt(MEDIA_CODEC_PCMU));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMA, media_codec_default_pt(MEDIA_CODEC_PCMA));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, media_codec_default_pt(MEDIA_CODEC_OPUS));

    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, media_codec_from_pt(0));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMA, media_codec_from_pt(8));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_OPUS, media_codec_from_pt(96));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_OPUS, media_codec_from_pt(111));

    TEST_ASSERT_EQUAL_UINT32(8000, media_codec_sample_rate(MEDIA_CODEC_PCMU));
    TEST_ASSERT_EQUAL_UINT32(8000, media_codec_sample_rate(MEDIA_CODEC_PCMA));
    TEST_ASSERT_EQUAL_UINT32(48000, media_codec_sample_rate(MEDIA_CODEC_OPUS));

    TEST_ASSERT_EQUAL_size_t(160, media_codec_frame_samples_20ms(MEDIA_CODEC_PCMU));
    TEST_ASSERT_EQUAL_size_t(960, media_codec_frame_samples_20ms(MEDIA_CODEC_OPUS));

    TEST_ASSERT_EQUAL_STRING("libopus", transcoder_backend_name(TRANSCODER_BACKEND_OPUS));
    TEST_ASSERT_EQUAL_STRING("ffmpeg", transcoder_backend_name(TRANSCODER_BACKEND_FFMPEG));
    TEST_ASSERT_EQUAL_STRING("none", transcoder_backend_name(TRANSCODER_BACKEND_NONE));

    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, transcoder_backend_from_str("libopus"));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, transcoder_backend_from_str("opus"));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, transcoder_backend_from_str("ffmpeg"));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_NONE, transcoder_backend_from_str("none"));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_NONE, transcoder_backend_from_str("off"));
}

static void test_g711_conversion(void) {
    // Silence / 0
    uint8_t const u_zero = media_linear_to_ulaw(0);
    int16_t const pcm_u0 = media_ulaw_to_linear(u_zero);
    TEST_ASSERT_INT_WITHIN(10, 0, pcm_u0);

    uint8_t const a_zero = media_linear_to_alaw(0);
    int16_t const pcm_a0 = media_alaw_to_linear(a_zero);
    TEST_ASSERT_INT_WITHIN(10, 0, pcm_a0);

    // Range of test amplitudes: -30000 to +30000 in steps of 500
    for (int p = -30000; p <= 30000; p += 500) {
        int16_t const orig  = (int16_t)p;
        uint8_t const u     = media_linear_to_ulaw(orig);
        int16_t const dec_u = media_ulaw_to_linear(u);

        // G.711 is lossy 8-bit, error should be well within standard quantization noise
        int const diff_u = (orig > dec_u) ? (orig - dec_u) : (dec_u - orig);
        // Relative error bounded by ~5% for non-zero signals
        if (orig != 0) {
            int const allowed = ((orig < 0 ? -orig : orig) / 10) + 100;
            TEST_ASSERT_TRUE(diff_u <= allowed);
        }

        uint8_t const a      = media_linear_to_alaw(orig);
        int16_t const dec_a  = media_alaw_to_linear(a);
        int const     diff_a = (orig > dec_a) ? (orig - dec_a) : (dec_a - orig);
        if (orig != 0) {
            int const allowed = ((orig < 0 ? -orig : orig) / 10) + 100;
            TEST_ASSERT_TRUE(diff_a <= allowed);
        }
    }
}

static void test_audio_resampling(void) {
    int16_t in_48k[960]   = {};
    int16_t out_8k[160]   = {};
    int16_t back_48k[960] = {};

    // Constant DC signal of 5000
    for (size_t i = 0; i < 960; ++i) {
        in_48k[i] = 5000;
    }

    media_resample_48k_to_8k(in_48k, 960, out_8k, 160);
    for (size_t i = 0; i < 160; ++i) {
        TEST_ASSERT_EQUAL_INT16(5000, out_8k[i]);
    }

    media_resample_8k_to_48k(out_8k, 160, back_48k, 960);
    for (size_t i = 0; i < 960; ++i) {
        TEST_ASSERT_EQUAL_INT16(5000, back_48k[i]);
    }
}

static void test_libopus_transcoding_opus_to_pcmu(void) {
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_OPUS, MEDIA_CODEC_OPUS, MEDIA_CODEC_PCMU));
    TEST_ASSERT_TRUE(ctx.initialized);
    TEST_ASSERT_TRUE(ctx.enabled);
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMU, ctx.dst_pt);

    // Generate an input Opus RTP packet
    int          err = 0;
    OpusEncoder *enc = opus_encoder_create(MEDIA_SAMPLE_RATE_48K, 1, OPUS_APPLICATION_VOIP, &err);
    TEST_ASSERT_NOT_NULL(enc);

    int16_t pcm[960] = {};
    for (int i = 0; i < 960; ++i) {
        pcm[i] = (int16_t)(i * 20);
    }

    uint8_t rtp_in[1500] = {};
    auto    in_hdr       = (rtp_header_t *)rtp_in;
    in_hdr->v_p_x_cc     = (RTP_VERSION_2 << 6);
    in_hdr->m_pt         = 96;
    in_hdr->seq          = htons(100);
    in_hdr->timestamp    = htonl(48000);
    in_hdr->ssrc         = htonl(0x12345678);

    int const opus_bytes = opus_encode(
        enc,
        pcm,
        960,
        rtp_in + sizeof(rtp_header_t),
        (opus_int32)(sizeof(rtp_in) - sizeof(rtp_header_t)));
    TEST_ASSERT_GREATER_THAN(0, opus_bytes);
    size_t const in_len = sizeof(rtp_header_t) + (size_t)opus_bytes;

    opus_encoder_destroy(enc);

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(
        transcoder_process_rtp(&ctx, rtp_in, in_len, rtp_out, sizeof(rtp_out), &out_len));

    // Verify output RTP packet
    TEST_ASSERT_EQUAL_size_t(sizeof(rtp_header_t) + 160, out_len);
    auto const out_hdr = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(out_hdr));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMU, rtp_get_payload_type(out_hdr));
    TEST_ASSERT_EQUAL_UINT16(100, ntohs(out_hdr->seq));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, ntohl(out_hdr->ssrc));

    transcoder_destroy(&ctx);
    TEST_ASSERT_FALSE(ctx.enabled);
}

static void test_libopus_transcoding_pcmu_to_opus(void) {
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_OPUS, MEDIA_CODEC_PCMU, MEDIA_CODEC_OPUS));
    TEST_ASSERT_TRUE(ctx.initialized);
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, ctx.dst_pt);

    // Construct a G.711 PCMU RTP packet (160 bytes payload)
    uint8_t rtp_in[sizeof(rtp_header_t) + 160] = {};
    auto    in_hdr                             = (rtp_header_t *)rtp_in;
    in_hdr->v_p_x_cc                           = (RTP_VERSION_2 << 6);
    in_hdr->m_pt                               = RTP_PT_PCMU;
    in_hdr->seq                                = htons(42);
    in_hdr->timestamp                          = htonl(8000);
    in_hdr->ssrc                               = htonl(0xAABBCCDD);

    for (size_t i = 0; i < 160; ++i) {
        rtp_in[sizeof(rtp_header_t) + i] = media_linear_to_ulaw((int16_t)(i * 100));
    }

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(
        transcoder_process_rtp(&ctx, rtp_in, sizeof(rtp_in), rtp_out, sizeof(rtp_out), &out_len));

    TEST_ASSERT_GREATER_THAN(sizeof(rtp_header_t), out_len);
    auto const out_hdr = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(out_hdr));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, rtp_get_payload_type(out_hdr));
    TEST_ASSERT_EQUAL_UINT16(42, ntohs(out_hdr->seq));
    TEST_ASSERT_EQUAL_HEX32(0xAABBCCDD, ntohl(out_hdr->ssrc));

    // Verify the produced Opus payload decodes cleanly with libopus
    int          err = 0;
    OpusDecoder *dec = opus_decoder_create(MEDIA_SAMPLE_RATE_48K, 1, &err);
    TEST_ASSERT_NOT_NULL(dec);

    int16_t   decoded[960] = {};
    int const decoded_cnt  = opus_decode(
        dec,
        rtp_out + sizeof(rtp_header_t),
        (opus_int32)(out_len - sizeof(rtp_header_t)),
        decoded,
        960,
        0);
    TEST_ASSERT_EQUAL_INT(960, decoded_cnt);

    opus_decoder_destroy(dec);
    transcoder_destroy(&ctx);
}

static void test_libopus_transcoding_pcma_roundtrip(void) {
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_OPUS, MEDIA_CODEC_PCMA, MEDIA_CODEC_OPUS));

    uint8_t rtp_in[sizeof(rtp_header_t) + 160] = {};
    auto    in_hdr                             = (rtp_header_t *)rtp_in;
    in_hdr->v_p_x_cc                           = (RTP_VERSION_2 << 6);
    in_hdr->m_pt                               = RTP_PT_PCMA;
    in_hdr->seq                                = htons(77);
    in_hdr->timestamp                          = htonl(16000);
    in_hdr->ssrc                               = htonl(0x55667788);

    for (size_t i = 0; i < 160; ++i) {
        rtp_in[sizeof(rtp_header_t) + i] = media_linear_to_alaw((int16_t)(i * 150));
    }

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(
        transcoder_process_rtp(&ctx, rtp_in, sizeof(rtp_in), rtp_out, sizeof(rtp_out), &out_len));

    auto const out_hdr = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, rtp_get_payload_type(out_hdr));
    TEST_ASSERT_EQUAL_UINT16(77, ntohs(out_hdr->seq));

    transcoder_destroy(&ctx);
}

static void test_ffmpeg_transcoding_opus_to_pcmu(void) {
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_FFMPEG, MEDIA_CODEC_OPUS, MEDIA_CODEC_PCMU));
    TEST_ASSERT_TRUE(ctx.initialized);
    TEST_ASSERT_TRUE(ctx.enabled);

    // Encode a valid Opus frame using libopus to send to FFmpeg decoder
    int          err = 0;
    OpusEncoder *enc = opus_encoder_create(MEDIA_SAMPLE_RATE_48K, 1, OPUS_APPLICATION_VOIP, &err);
    TEST_ASSERT_NOT_NULL(enc);

    int16_t pcm[960] = {};
    for (int i = 0; i < 960; ++i) {
        pcm[i] = (int16_t)(i * 15);
    }

    uint8_t rtp_in[1500] = {};
    auto    in_hdr       = (rtp_header_t *)rtp_in;
    in_hdr->v_p_x_cc     = (RTP_VERSION_2 << 6);
    in_hdr->m_pt         = 96;
    in_hdr->seq          = htons(200);
    in_hdr->timestamp    = htonl(96000);
    in_hdr->ssrc         = htonl(0xFEEDFACE);

    int const opus_bytes = opus_encode(
        enc,
        pcm,
        960,
        rtp_in + sizeof(rtp_header_t),
        (opus_int32)(sizeof(rtp_in) - sizeof(rtp_header_t)));
    TEST_ASSERT_GREATER_THAN(0, opus_bytes);
    size_t const in_len = sizeof(rtp_header_t) + (size_t)opus_bytes;
    opus_encoder_destroy(enc);

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(
        transcoder_process_rtp(&ctx, rtp_in, in_len, rtp_out, sizeof(rtp_out), &out_len));

    TEST_ASSERT_EQUAL_size_t(sizeof(rtp_header_t) + 160, out_len);
    auto const out_hdr = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(out_hdr));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMU, rtp_get_payload_type(out_hdr));
    TEST_ASSERT_EQUAL_UINT16(200, ntohs(out_hdr->seq));
    TEST_ASSERT_EQUAL_HEX32(0xFEEDFACE, ntohl(out_hdr->ssrc));

    transcoder_destroy(&ctx);
}

static void test_ffmpeg_transcoding_pcmu_to_opus(void) {
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_FFMPEG, MEDIA_CODEC_PCMU, MEDIA_CODEC_OPUS));
    TEST_ASSERT_TRUE(ctx.initialized);

    uint8_t rtp_in[sizeof(rtp_header_t) + 160] = {};
    auto    in_hdr                             = (rtp_header_t *)rtp_in;
    in_hdr->v_p_x_cc                           = (RTP_VERSION_2 << 6);
    in_hdr->m_pt                               = RTP_PT_PCMU;
    in_hdr->seq                                = htons(300);
    in_hdr->timestamp                          = htonl(24000);
    in_hdr->ssrc                               = htonl(0xDEADBEEF);

    for (size_t i = 0; i < 160; ++i) {
        rtp_in[sizeof(rtp_header_t) + i] = media_linear_to_ulaw((int16_t)(i * 80));
    }

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(
        transcoder_process_rtp(&ctx, rtp_in, sizeof(rtp_in), rtp_out, sizeof(rtp_out), &out_len));

    TEST_ASSERT_GREATER_THAN(sizeof(rtp_header_t), out_len);
    auto const out_hdr = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(out_hdr));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, rtp_get_payload_type(out_hdr));
    TEST_ASSERT_EQUAL_UINT16(300, ntohs(out_hdr->seq));
    TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, ntohl(out_hdr->ssrc));

    transcoder_destroy(&ctx);
}

static void test_server_config_cli_parsing(void) {
    server_config_t config = {};

    // Default configuration
    server_config_default(&config);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_NONE, config.transcoder_backend);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_NONE, config.transcode_codec);

    // Pass -T libopus
    char  a0[]    = "urtp";
    char  a1[]    = "-T";
    char  a2[]    = "libopus";
    char *argv1[] = {a0, a1, a2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv1));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, config.transcoder_backend);

    // Pass -T ffmpeg
    char  b0[]    = "urtp";
    char  b1[]    = "-T";
    char  b2[]    = "ffmpeg";
    char *argv2[] = {b0, b1, b2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv2));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, config.transcoder_backend);

    // Pass --transcoder libopus
    char  c0[]    = "urtp";
    char  c1[]    = "--transcoder";
    char  c2[]    = "libopus";
    char  c3[]    = "-C";
    char  c4[]    = "pcmu";
    char *argv3[] = {c0, c1, c2, c3, c4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 5, argv3));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, config.transcoder_backend);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, config.transcode_codec);

    // Pass --transcoder ffmpeg
    char  d0[]    = "urtp";
    char  d1[]    = "--transcoder";
    char  d2[]    = "ffmpeg";
    char  d3[]    = "--transcode-codec";
    char  d4[]    = "opus";
    char *argv4[] = {d0, d1, d2, d3, d4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 5, argv4));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, config.transcoder_backend);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_OPUS, config.transcode_codec);

    // Pass --transcode ffmpeg
    char  e0[]    = "urtp";
    char  e1[]    = "--transcode";
    char  e2[]    = "ffmpeg";
    char *argv5[] = {e0, e1, e2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv5));
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, config.transcoder_backend);

    // Pass --transcode pcma
    char  f0[]    = "urtp";
    char  f1[]    = "--transcode";
    char  f2[]    = "pcma";
    char *argv6[] = {f0, f1, f2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 3, argv6));
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMA, config.transcode_codec);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, config.transcoder_backend);

    // Jitter buffer without transcoder must fail validation
    char  j0[]    = "urtp";
    char  j1[]    = "-j";
    char  j2[]    = "40";
    char *argv7[] = {j0, j1, j2, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_parse(&config, 3, argv7));

    // Jitter buffer out of range (<20) with transcoder must fail validation
    char  jl0[]   = "urtp";
    char  jl1[]   = "-T";
    char  jl2[]   = "libopus";
    char  jl3[]   = "-j";
    char  jl4[]   = "10";
    char *argv8[] = {jl0, jl1, jl2, jl3, jl4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_parse(&config, 5, argv8));

    // Jitter buffer out of range (>100) with transcoder must fail validation
    char jh0[]    = "urtp";
    jh0[0]        = 'u';
    char  jh1[]   = "--transcoder";
    char  jh2[]   = "libopus";
    char  jh3[]   = "--jitter-buffer";
    char  jh4[]   = "150";
    char *argv9[] = {jh0, jh1, jh2, jh3, jh4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_ERROR, server_config_parse(&config, 5, argv9));

    // Valid jitter buffer with transcoder
    char  jv0[]    = "urtp";
    char  jv1[]    = "-T";
    char  jv2[]    = "libopus";
    char  jv3[]    = "-j";
    char  jv4[]    = "40";
    char *argv10[] = {jv0, jv1, jv2, jv3, jv4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 5, argv10));
    TEST_ASSERT_EQUAL_UINT32(40, config.jitter_buffer_ms);

    // Valid --jitter-buffer with --transcoder
    char  jw0[]    = "urtp";
    char  jw1[]    = "--transcoder";
    char  jw2[]    = "ffmpeg";
    char  jw3[]    = "--jitter-buffer";
    char  jw4[]    = "60";
    char *argv11[] = {jw0, jw1, jw2, jw3, jw4, nullptr};
    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, 5, argv11));
    TEST_ASSERT_EQUAL_UINT32(60, config.jitter_buffer_ms);
}

static void test_control_transcode_command(void) {
    session_table_t table = {};
    session_table_init(&table);

    char resp[512] = {};

    // Allocate session on port 40000
    TEST_ASSERT_TRUE(control_process_command(
        "ALLOCATE PORT 40000 -> FORWARD TO 127.0.0.1:40001\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));

    // TRANSCODE 40000 PCMU libopus
    TEST_ASSERT_TRUE(control_process_command(
        "TRANSCODE 40000 PCMU libopus\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK TRANSCODE PORT 40000 backend=libopus src=opus dst=PCMU\n", resp);

    auto const session = session_find_by_port(&table, 40000);
    TEST_ASSERT_NOT_NULL(session);
    TEST_ASSERT_TRUE(session->transcode_enabled);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_OPUS, session->transcode_ctx.backend);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_OPUS, session->transcode_ctx.src_codec);
    TEST_ASSERT_EQUAL_INT(MEDIA_CODEC_PCMU, session->transcode_ctx.dst_codec);

    // TRANSCODE STATUS 40000 without jitter buffer
    TEST_ASSERT_TRUE(
        control_process_command("TRANSCODE STATUS 40000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK TRANSCODE PORT 40000 backend=libopus src=opus dst=PCMU"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "jb=disabled"));

    // TRANSCODE 40000 PCMU libopus jitter=40 enables jitter buffer
    TEST_ASSERT_TRUE(control_process_command(
        "TRANSCODE 40000 PCMU libopus jitter=40\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING(
        "OK TRANSCODE PORT 40000 backend=libopus src=opus dst=PCMU jb=40 ms\n",
        resp);
    TEST_ASSERT_TRUE(session->jitter_enabled);
    TEST_ASSERT_NOT_NULL(session->jitter_buf);
    TEST_ASSERT_EQUAL_UINT32(40, session->jitter_buf->target_delay_ms);

    // TRANSCODE STATUS 40000 with jitter buffer
    TEST_ASSERT_TRUE(
        control_process_command("TRANSCODE STATUS 40000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "jb=active depth=2"));

    // TRANSCODE 40000 OFF releases jitter buffer
    TEST_ASSERT_TRUE(
        control_process_command("TRANSCODE 40000 OFF\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK TRANSCODE DISABLED PORT 40000\n", resp);
    TEST_ASSERT_FALSE(session->transcode_enabled);
    TEST_ASSERT_FALSE(session->jitter_enabled);
    TEST_ASSERT_NULL(session->jitter_buf);

    // TRANSCODE 40000 OPUS ffmpeg
    TEST_ASSERT_TRUE(control_process_command(
        "TRANSCODE 40000 OPUS ffmpeg\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK TRANSCODE PORT 40000 backend=ffmpeg src=PCMU dst=opus\n", resp);
    TEST_ASSERT_TRUE(session->transcode_enabled);
    TEST_ASSERT_EQUAL_INT(TRANSCODER_BACKEND_FFMPEG, session->transcode_ctx.backend);

    session_table_destroy(&table, nullptr);
}

static void test_transcoder_plc_synthesis(void) {
    // 1. Opus to PCMU PLC synthesis
    transcoder_ctx_t ctx = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx, TRANSCODER_BACKEND_OPUS, MEDIA_CODEC_OPUS, MEDIA_CODEC_PCMU));
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40);
    transcoder_set_jitter_buffer(&ctx, &jb);
    ctx.outbound_seq = 101;
    ctx.outbound_ts  = 8000;

    uint8_t rtp_out[1500] = {};
    size_t  out_len       = 0;
    TEST_ASSERT_TRUE(transcoder_process_plc(&ctx, rtp_out, sizeof(rtp_out), &out_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(rtp_header_t) + 160, out_len);

    auto const hdr1 = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(hdr1));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_PCMU, rtp_get_payload_type(hdr1));
    TEST_ASSERT_EQUAL_UINT16(101, ntohs(hdr1->seq));
    TEST_ASSERT_EQUAL_UINT32(8000, ntohl(hdr1->timestamp));

    transcoder_destroy(&ctx);

    // 2. PCMU to Opus PLC synthesis (comfort noise/silence encoded to Opus)
    transcoder_ctx_t ctx2 = {};
    TEST_ASSERT_TRUE(
        transcoder_init(&ctx2, TRANSCODER_BACKEND_OPUS, MEDIA_CODEC_PCMU, MEDIA_CODEC_OPUS));
    transcoder_set_jitter_buffer(&ctx2, &jb);
    ctx2.outbound_seq = 202;
    ctx2.outbound_ts  = 16000;

    out_len = 0;
    TEST_ASSERT_TRUE(transcoder_process_plc(&ctx2, rtp_out, sizeof(rtp_out), &out_len));
    TEST_ASSERT_GREATER_THAN(sizeof(rtp_header_t), out_len);

    auto const hdr2 = (rtp_header_t const *)rtp_out;
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtp_get_version(hdr2));
    TEST_ASSERT_EQUAL_UINT8(RTP_PT_OPUS_DEFAULT, rtp_get_payload_type(hdr2));
    TEST_ASSERT_EQUAL_UINT16(202, ntohs(hdr2->seq));
    TEST_ASSERT_EQUAL_UINT32(16000, ntohl(hdr2->timestamp));

    transcoder_destroy(&ctx2);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_codec_helpers);
    RUN_TEST(test_g711_conversion);
    RUN_TEST(test_audio_resampling);
    RUN_TEST(test_libopus_transcoding_opus_to_pcmu);
    RUN_TEST(test_libopus_transcoding_pcmu_to_opus);
    RUN_TEST(test_libopus_transcoding_pcma_roundtrip);
    RUN_TEST(test_ffmpeg_transcoding_opus_to_pcmu);
    RUN_TEST(test_ffmpeg_transcoding_pcmu_to_opus);
    RUN_TEST(test_server_config_cli_parsing);
    RUN_TEST(test_control_transcode_command);
    RUN_TEST(test_transcoder_plc_synthesis);
    return UNITY_END();
}
