#include <string.h>
#include "control/sdp.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_sdp_parsing(void) {
    char const sample_sdp[] = "v=0\r\n"
                              "o=alice 2890844526 2890844526 IN IP4 192.168.1.10\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.10\r\n"
                              "t=0 0\r\n"
                              "m=audio 10000 RTP/AVP 0 8 101\r\n"
                              "a=rtpmap:0 PCMU/8000\r\n"
                              "a=rtcp:10001\r\n";

    sdp_info_t info = {};
    TEST_ASSERT_TRUE(sdp_parse(SV_PSZ(sample_sdp), &info));
    TEST_ASSERT_TRUE(info.has_connection);
    TEST_ASSERT_TRUE(info.has_media);
    TEST_ASSERT_TRUE(info.has_rtcp);
    TEST_ASSERT_EQUAL_STRING("192.168.1.10", info.connection_ip);
    TEST_ASSERT_EQUAL_UINT16(10000, info.media_port);
    TEST_ASSERT_EQUAL_UINT16(10001, info.rtcp_port);
    TEST_ASSERT_EQUAL_STRING("audio", info.media_type);
    TEST_ASSERT_EQUAL_STRING("RTP/AVP", info.transport_proto);
}

static void test_sdp_rewriting(void) {
    char const sample_sdp[] = "v=0\r\n"
                              "o=alice 123 456 IN IP4 10.0.0.5\r\n"
                              "s=-\r\n"
                              "c=IN IP4 10.0.0.5\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/AVP 0 8\r\n"
                              "a=rtpmap:0 PCMU/8000\r\n"
                              "a=rtcp:20001\r\n";

    char   rewritten[1024] = {};
    size_t out_len         = 0;
    TEST_ASSERT_TRUE(sdp_rewrite(
        SV_PSZ(sample_sdp),
        "127.0.0.1",
        35000,
        rewritten,
        sizeof(rewritten),
        &out_len));
    TEST_ASSERT_TRUE(out_len > 0);

    // Verify rewritten connection IP and media port
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "c=IN IP4 127.0.0.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 35000 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:35001 IN IP4 127.0.0.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "o=alice 123 456 IN IP4 127.0.0.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtpmap:0 PCMU/8000\r\n"));
}

static void test_sdp_rtcp_mux(void) {
    char const sample_mux_sdp[] = "v=0\r\n"
                                  "o=bob 123 456 IN IP4 10.0.0.8\r\n"
                                  "s=-\r\n"
                                  "c=IN IP4 10.0.0.8\r\n"
                                  "t=0 0\r\n"
                                  "m=audio 10000 RTP/AVP 96\r\n"
                                  "a=rtpmap:96 opus/48000/2\r\n"
                                  "a=rtcp:10001\r\n"
                                  "a=rtcp-mux\r\n";

    sdp_info_t info = {};
    TEST_ASSERT_TRUE(sdp_parse(SV_PSZ(sample_mux_sdp), &info));
    TEST_ASSERT_TRUE(info.has_rtcp_mux);
    TEST_ASSERT_TRUE(info.has_rtcp);
    TEST_ASSERT_EQUAL_UINT16(10000, info.media_port);

    // 1. Rewrite with auto-detection of rtcp-mux in input
    char   rewritten[1024] = {};
    size_t out_len         = 0;
    TEST_ASSERT_TRUE(sdp_rewrite(
        SV_PSZ(sample_mux_sdp),
        "192.0.2.1",
        40000,
        rewritten,
        sizeof(rewritten),
        &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 40000 RTP/AVP 96\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:40000 IN IP4 192.0.2.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp-mux\r\n"));

    // 2. Explicitly force rtcp-mux on non-mux SDP input
    char const non_mux_sdp[] = "v=0\r\n"
                               "o=charlie 1 1 IN IP4 10.0.0.9\r\n"
                               "s=-\r\n"
                               "c=IN IP4 10.0.0.9\r\n"
                               "t=0 0\r\n"
                               "m=audio 20000 RTP/AVP 0\r\n"
                               "a=rtcp:20001\r\n";
    TEST_ASSERT_TRUE(sdp_rewrite_ex(
        SV_PSZ(non_mux_sdp),
        "192.0.2.1",
        42000,
        true,
        rewritten,
        sizeof(rewritten),
        &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:42000 IN IP4 192.0.2.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp-mux\r\n"));

    // 3. Explicitly disable rtcp-mux (strip) on mux SDP input
    TEST_ASSERT_TRUE(sdp_rewrite_ex(
        SV_PSZ(sample_mux_sdp),
        "192.0.2.1",
        44000,
        false,
        rewritten,
        sizeof(rewritten),
        &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:44001 IN IP4 192.0.2.1\r\n"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=rtcp-mux"));
}

static void test_sdp_crypto_parsing(void) {
    char const sample_srtp_sdp[] = "v=0\r\n"
                                   "o=alice 100 100 IN IP4 192.168.1.50\r\n"
                                   "s=-\r\n"
                                   "c=IN IP4 192.168.1.50\r\n"
                                   "t=0 0\r\n"
                                   "m=audio 16000 RTP/SAVP 0 8\r\n"
                                   "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                                   "inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n";

    sdp_info_t info = {};
    TEST_ASSERT_TRUE(sdp_parse(SV_PSZ(sample_srtp_sdp), &info));
    TEST_ASSERT_TRUE(info.is_savp);
    TEST_ASSERT_TRUE(info.has_crypto);
    TEST_ASSERT_EQUAL_size_t(1, info.crypto_count);
    TEST_ASSERT_EQUAL_UINT32(1, info.crypto_attrs[0].tag);
    TEST_ASSERT_EQUAL_INT(SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80, info.crypto_attrs[0].suite);
    TEST_ASSERT_EQUAL_size_t(30, info.crypto_attrs[0].master_key_len);
    TEST_ASSERT_EQUAL_STRING(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
        info.crypto_attrs[0].b64_key);
}

static void test_sdp_crypto_rewriting(void) {
    char const plain_sdp[] = "v=0\r\n"
                             "o=alice 100 100 IN IP4 192.168.1.50\r\n"
                             "s=-\r\n"
                             "c=IN IP4 192.168.1.50\r\n"
                             "t=0 0\r\n"
                             "m=audio 16000 RTP/AVP 0 8\r\n";

    // 1. Plain RTP -> SRTP (add crypto, set transport to RTP/SAVP)
    char               rewritten[1024] = {};
    size_t             out_len         = 0;
    sdp_rewrite_opts_t opts_add        = {
               .new_ip          = "10.0.0.1",
               .new_port        = 30000,
               .enable_rtcp_mux = false,
               .add_crypto      = true,
               .crypto_tag      = 1,
               .crypto_suite    = SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
               .crypto_b64_key  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
               .set_transport   = true,
               .transport_proto = "RTP/SAVP",
    };

    TEST_ASSERT_TRUE(
        sdp_rewrite_opts(SV_PSZ(plain_sdp), &opts_add, rewritten, sizeof(rewritten), &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 30000 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(
        rewritten,
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n"));

    // 2. SRTP -> Plain RTP (strip crypto, set transport to RTP/AVP)
    char const srtp_sdp[] = "v=0\r\n"
                            "o=bob 200 200 IN IP4 192.168.1.60\r\n"
                            "s=-\r\n"
                            "c=IN IP4 192.168.1.60\r\n"
                            "t=0 0\r\n"
                            "m=audio 18000 RTP/SAVP 0 8\r\n"
                            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                            "inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n";

    sdp_rewrite_opts_t opts_strip = {
        .new_ip          = "10.0.0.1",
        .new_port        = 30002,
        .enable_rtcp_mux = false,
        .strip_crypto    = true,
        .set_transport   = true,
        .transport_proto = "RTP/AVP",
    };

    rewritten[0] = '\0';
    TEST_ASSERT_TRUE(
        sdp_rewrite_opts(SV_PSZ(srtp_sdp), &opts_strip, rewritten, sizeof(rewritten), &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 30002 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=crypto:"));

    // 3. SRTP re-encryption (replace existing crypto key with proxy's key)
    sdp_rewrite_opts_t opts_replace = {
        .new_ip          = "10.0.0.1",
        .new_port        = 30004,
        .enable_rtcp_mux = false,
        .add_crypto      = true,
        .crypto_tag      = 1,
        .crypto_suite    = SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        .crypto_b64_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .set_transport   = true,
        .transport_proto = "RTP/SAVP",
    };

    rewritten[0] = '\0';
    TEST_ASSERT_TRUE(
        sdp_rewrite_opts(SV_PSZ(srtp_sdp), &opts_replace, rewritten, sizeof(rewritten), &out_len));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 30004 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(
        rewritten,
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"));
    TEST_ASSERT_NULL(strstr(rewritten, "W3UZetnkEPlastic"));
}

static void test_sdp_webrtc_parsing(void) {
    char const webrtc_sdp[] = "v=0\r\n"
                              "o=- 123456 2 IN IP4 192.0.2.1\r\n"
                              "s=-\r\n"
                              "t=0 0\r\n"
                              "c=IN IP4 192.0.2.1\r\n"
                              "m=audio 9 UDP/TLS/RTP/SAVPF 111 9\r\n"
                              "a=rtcp:9 IN IP4 192.0.2.1\r\n"
                              "a=ice-ufrag:testufrag\r\n"
                              "a=ice-pwd:testpassword1234567890\r\n"
                              "a=fingerprint:sha-256 "
                              "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:"
                              "66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
                              "a=setup:actpass\r\n"
                              "a=mid:0\r\n"
                              "a=sendrecv\r\n"
                              "a=rtcp-mux\r\n"
                              "a=candidate:1 1 UDP 2130706431 192.0.2.1 54321 typ host\r\n";

    sdp_info_t info = {};
    TEST_ASSERT_TRUE(sdp_parse(SV_PSZ(webrtc_sdp), &info));
    TEST_ASSERT_TRUE(info.is_webrtc);
    TEST_ASSERT_TRUE(info.is_savp);
    TEST_ASSERT_TRUE(info.has_ice);
    TEST_ASSERT_EQUAL_STRING("testufrag", info.ice_ufrag);
    TEST_ASSERT_EQUAL_STRING("testpassword1234567890", info.ice_pwd);
    TEST_ASSERT_TRUE(info.has_dtls);
    TEST_ASSERT_EQUAL_STRING(
        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:"
        "EE:FF",
        info.dtls_fingerprint);
    TEST_ASSERT_EQUAL_STRING("actpass", info.dtls_setup);
    TEST_ASSERT_TRUE(info.has_rtcp_mux);
}

static void test_sdp_webrtc_rewriting(void) {
    char const sip_sdp[] = "v=0\r\n"
                           "o=alice 100 200 IN IP4 10.0.0.1\r\n"
                           "s=-\r\n"
                           "c=IN IP4 10.0.0.1\r\n"
                           "t=0 0\r\n"
                           "m=audio 16000 RTP/AVP 0 8\r\n";

    char   rewritten[2048] = {};
    size_t out_len         = 0;

    // 1. Synthesize WebRTC SDP from legacy SIP
    sdp_rewrite_opts_t opts_to_webrtc = {
        .new_ip           = "198.51.100.1",
        .new_port         = 25000,
        .enable_rtcp_mux  = true,
        .add_ice          = true,
        .ice_ufrag        = "localufrag12",
        .ice_pwd          = "localpassword3456",
        .add_dtls         = true,
        .dtls_fingerprint = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
                            "88:99:AA:BB:CC:DD:EE:FF:00",
        .dtls_setup       = "actpass",
        .set_transport    = true,
        .transport_proto  = "UDP/TLS/RTP/SAVPF",
    };

    TEST_ASSERT_TRUE(
        sdp_rewrite_opts(SV_PSZ(sip_sdp), &opts_to_webrtc, rewritten, sizeof(rewritten), &out_len));

    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 25000 UDP/TLS/RTP/SAVPF 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=ice-ufrag:localufrag12\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=ice-pwd:localpassword3456\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=fingerprint:sha-256 11:22:33:"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=setup:actpass\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=candidate:1 1 UDP "));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp-mux\r\n"));

    // 2. Strip WebRTC attributes to bridge to legacy SIP
    char const webrtc_sdp[] = "v=0\r\n"
                              "o=- 123 456 IN IP4 192.0.2.1\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.0.2.1\r\n"
                              "t=0 0\r\n"
                              "m=audio 9 UDP/TLS/RTP/SAVPF 0 8\r\n"
                              "a=ice-ufrag:abcd\r\n"
                              "a=ice-pwd:secret\r\n"
                              "a=fingerprint:sha-256 00:11:22:33\r\n"
                              "a=setup:active\r\n"
                              "a=candidate:1 1 UDP 2130706431 192.0.2.1 54321 typ host\r\n";

    sdp_rewrite_opts_t opts_to_sip = {
        .new_ip          = "198.51.100.1",
        .new_port        = 26000,
        .strip_ice       = true,
        .strip_dtls      = true,
        .set_transport   = true,
        .transport_proto = "RTP/AVP",
    };

    rewritten[0] = '\0';
    TEST_ASSERT_TRUE(
        sdp_rewrite_opts(SV_PSZ(webrtc_sdp), &opts_to_sip, rewritten, sizeof(rewritten), &out_len));

    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 26000 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=ice-ufrag"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=ice-pwd"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=fingerprint"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=setup"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=candidate"));
}

static void test_sdp_multi_parse_webrtc_bundle(void) {
    char const sample_webrtc_bundle[] =
        "v=0\r\n"
        "o=- 8123456789 2 IN IP4 192.0.2.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=msid-semantic: WMS\r\n"
        "c=IN IP4 192.0.2.1\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8\r\n"
        "a=mid:0\r\n"
        "a=rtcp:9 IN IP4 192.0.2.1\r\n"
        "a=rtcp-mux\r\n"
        "a=rtcp-fb:111 nack\r\n"
        "a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
        "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
        "a=ice-ufrag:audio_ufrag\r\n"
        "a=ice-pwd:audio_secret_password\r\n"
        "a=fingerprint:sha-256 "
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
        "88:99\r\n"
        "a=setup:actpass\r\n"
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n"
        "a=mid:1\r\n"
        "a=rtcp:9 IN IP4 192.0.2.1\r\n"
        "a=rtcp-mux\r\n"
        "a=rtcp-fb:96 goog-remb\r\n"
        "a=rtcp-fb:96 transport-cc\r\n"
        "a=rtcp-fb:96 ccm fir\r\n"
        "a=rtcp-fb:96 nack\r\n"
        "a=rtcp-fb:96 nack pli\r\n"
        "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
        "a=ice-ufrag:video_ufrag\r\n"
        "a=ice-pwd:video_secret_password\r\n"
        "a=fingerprint:sha-256 "
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
        "88:99\r\n"
        "a=setup:actpass\r\n";

    sdp_multi_info_t info = {};
    TEST_ASSERT_TRUE(sdp_parse_multi(SV_PSZ(sample_webrtc_bundle), &info));
    TEST_ASSERT_TRUE(info.has_connection);
    TEST_ASSERT_EQUAL_STRING("192.0.2.1", info.connection_ip);
    TEST_ASSERT_TRUE(info.has_bundle);
    TEST_ASSERT_EQUAL_size_t(2, info.bundle_mid_count);
    TEST_ASSERT_EQUAL_STRING("0", info.bundle_mids[0]);
    TEST_ASSERT_EQUAL_STRING("1", info.bundle_mids[1]);
    TEST_ASSERT_TRUE(info.is_webrtc);
    TEST_ASSERT_EQUAL_size_t(2, info.stream_count);

    // Audio stream
    auto const audio = &(info.streams[0]);
    TEST_ASSERT_EQUAL(SDP_MEDIA_AUDIO, audio->type);
    TEST_ASSERT_EQUAL_STRING("audio", audio->media_name);
    TEST_ASSERT_EQUAL_UINT16(9, audio->port);
    TEST_ASSERT_EQUAL_STRING("UDP/TLS/RTP/SAVPF", audio->transport);
    TEST_ASSERT_TRUE(audio->is_savp);
    TEST_ASSERT_TRUE(audio->has_mid);
    TEST_ASSERT_EQUAL_STRING("0", audio->mid);
    TEST_ASSERT_TRUE(audio->rtcp_mux);
    TEST_ASSERT_EQUAL_size_t(5, audio->payload_type_count);
    TEST_ASSERT_EQUAL_UINT8(111, audio->payload_types[0]);
    TEST_ASSERT_TRUE(audio->has_nack);
    TEST_ASSERT_EQUAL_size_t(2, audio->extension_count);
    TEST_ASSERT_EQUAL_UINT8(1, audio->extensions[0].id);

    // Video stream
    auto const video = &(info.streams[1]);
    TEST_ASSERT_EQUAL(SDP_MEDIA_VIDEO, video->type);
    TEST_ASSERT_EQUAL_STRING("video", video->media_name);
    TEST_ASSERT_EQUAL_UINT16(9, video->port);
    TEST_ASSERT_EQUAL_STRING("UDP/TLS/RTP/SAVPF", video->transport);
    TEST_ASSERT_TRUE(video->is_savp);
    TEST_ASSERT_TRUE(video->has_mid);
    TEST_ASSERT_EQUAL_STRING("1", video->mid);
    TEST_ASSERT_TRUE(video->rtcp_mux);
    TEST_ASSERT_EQUAL_size_t(2, video->payload_type_count);
    TEST_ASSERT_EQUAL_UINT8(96, video->payload_types[0]);
    TEST_ASSERT_EQUAL_UINT8(97, video->payload_types[1]);
    TEST_ASSERT_TRUE(video->has_nack);
    TEST_ASSERT_TRUE(video->has_pli);
    TEST_ASSERT_TRUE(video->has_fir);
    TEST_ASSERT_TRUE(video->has_remb);
    TEST_ASSERT_TRUE(video->has_twcc);
    TEST_ASSERT_EQUAL_size_t(1, video->extension_count);
    TEST_ASSERT_EQUAL_UINT8(3, video->extensions[0].id);
}

static void test_sdp_multi_rewrite_webrtc_to_sip(void) {
    char const sample_webrtc_bundle[] = "v=0\r\n"
                                        "o=- 8123456789 2 IN IP4 192.0.2.1\r\n"
                                        "s=-\r\n"
                                        "t=0 0\r\n"
                                        "a=group:BUNDLE 0 1\r\n"
                                        "c=IN IP4 192.0.2.1\r\n"
                                        "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\n"
                                        "a=mid:0\r\n"
                                        "a=rtcp:9 IN IP4 192.0.2.1\r\n"
                                        "a=rtcp-mux\r\n"
                                        "a=ice-ufrag:audio_ufrag\r\n"
                                        "a=ice-pwd:audio_secret_password\r\n"
                                        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n"
                                        "a=setup:actpass\r\n"
                                        "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n"
                                        "a=mid:1\r\n"
                                        "a=rtcp:9 IN IP4 192.0.2.1\r\n"
                                        "a=rtcp-mux\r\n"
                                        "a=simulcast:send 1;2;3\r\n"
                                        "a=rid:1 send\r\n"
                                        "a=rid:2 send\r\n"
                                        "a=ice-ufrag:video_ufrag\r\n"
                                        "a=ice-pwd:video_secret_password\r\n"
                                        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n"
                                        "a=setup:actpass\r\n";

    char   rewritten[4096] = {};
    size_t out_len         = 0;

    sdp_multi_rewrite_opts_t opts = {
        .new_ip                  = "192.168.1.50",
        .audio_port              = 30002,
        .video_port              = 30004,
        .bundle_into_single_port = false, // Option B: Unbundle to dual distinct SIP ports
        .strip_simulcast         = true,
        .strip_ice               = true,
        .strip_dtls              = true,
        .set_transport           = true,
        .transport_proto         = "RTP/AVP",
        .enable_rtcp_mux         = false,
    };

    TEST_ASSERT_TRUE(sdp_rewrite_multi(
        SV_PSZ(sample_webrtc_bundle),
        &opts,
        rewritten,
        sizeof(rewritten),
        &out_len));
    TEST_ASSERT_TRUE(out_len > 0);

    // Verify unbundled media ports
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "c=IN IP4 192.168.1.50\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 30002 RTP/AVP 111 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=video 30004 RTP/AVP 96 97\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:30003 IN IP4 192.168.1.50\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:30005 IN IP4 192.168.1.50\r\n"));

    // Verify BUNDLE and Simulcast stripped
    TEST_ASSERT_NULL(strstr(rewritten, "a=group:BUNDLE"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=simulcast"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=rid"));

    // Verify ICE/DTLS stripped
    TEST_ASSERT_NULL(strstr(rewritten, "a=ice-ufrag"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=ice-pwd"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=fingerprint"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=setup"));
    TEST_ASSERT_NULL(strstr(rewritten, "a=rtcp-mux"));
}

static void test_sdp_multi_rewrite_sip_to_webrtc(void) {
    char const sample_sip_dual[] = "v=0\r\n"
                                   "o=sip_endpoint 100 200 IN IP4 10.0.0.10\r\n"
                                   "s=-\r\n"
                                   "c=IN IP4 10.0.0.10\r\n"
                                   "t=0 0\r\n"
                                   "m=audio 10000 RTP/AVP 0 8\r\n"
                                   "a=mid:0\r\n"
                                   "a=rtpmap:0 PCMU/8000\r\n"
                                   "m=video 10002 RTP/AVP 96\r\n"
                                   "a=mid:1\r\n"
                                   "a=rtpmap:96 VP8/90000\r\n";

    char   rewritten[4096] = {};
    size_t out_len         = 0;

    sdp_multi_rewrite_opts_t opts = {
        .new_ip                  = "198.51.100.1",
        .audio_port              = 30000,
        .video_port              = 30000,
        .bundle_into_single_port = true, // Option B: Bundle into single WebRTC port
        .enable_rtcp_mux         = true,
        .add_ice                 = true,
        .ice_ufrag               = "webrtc_ufrag",
        .ice_pwd                 = "webrtc_secret_pwd",
        .add_dtls                = true,
        .dtls_fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:"
                            "77:88:99:AA:BB:CC:DD:EE:FF",
        .dtls_setup       = "actpass",
        .set_transport    = true,
        .transport_proto  = "UDP/TLS/RTP/SAVPF",
    };

    TEST_ASSERT_TRUE(
        sdp_rewrite_multi(SV_PSZ(sample_sip_dual), &opts, rewritten, sizeof(rewritten), &out_len));
    TEST_ASSERT_TRUE(out_len > 0);

    // Both audio and video must share port 30000
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "c=IN IP4 198.51.100.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=audio 30000 UDP/TLS/RTP/SAVPF 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "m=video 30000 UDP/TLS/RTP/SAVPF 96\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp:30000 IN IP4 198.51.100.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=rtcp-mux\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=ice-ufrag:webrtc_ufrag\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=ice-pwd:webrtc_secret_pwd\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=fingerprint:sha-256 00:11:22:33"));
    TEST_ASSERT_NOT_NULL(strstr(rewritten, "a=setup:actpass\r\n"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sdp_parsing);
    RUN_TEST(test_sdp_rewriting);
    RUN_TEST(test_sdp_rtcp_mux);
    RUN_TEST(test_sdp_crypto_parsing);
    RUN_TEST(test_sdp_crypto_rewriting);
    RUN_TEST(test_sdp_webrtc_parsing);
    RUN_TEST(test_sdp_webrtc_rewriting);
    RUN_TEST(test_sdp_multi_parse_webrtc_bundle);
    RUN_TEST(test_sdp_multi_rewrite_webrtc_to_sip);
    RUN_TEST(test_sdp_multi_rewrite_sip_to_webrtc);
    return UNITY_END();
}
