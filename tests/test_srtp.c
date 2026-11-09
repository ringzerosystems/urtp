#include <string.h>
#include "crypto/srtp_session.h"
#include "unity.h"

void setUp(void) { (void)urtp_srtp_global_init(); }

void tearDown(void) { urtp_srtp_global_cleanup(); }

static void test_srtp_rfc3711_appendix_b3_test_vector(void) {
    // RFC 3711 Appendix B.3 test vector
    // Master Key (16 octets):  e1f97a0d3e018be0d64fa32c06de4139
    // Master Salt (14 octets): 0ec675ad498afeebb6960b3aabe6
    uint8_t const key_salt[30] = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f,
                                  0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39, 0x0e, 0xc6, 0x75, 0xad,
                                  0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6};

    // Plaintext RTP packet (28 bytes: 12 header with ssrc 0xcafebabe + 16 payload 0xab)
    uint8_t const plain_rtp[28] = {0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe,
                                   0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                                   0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab};

    // Expected ciphertext from libsrtp reference validation (38 bytes: 12 header + 16 cipher + 10
    // tag)
    uint8_t const expected_srtp[38] = {// Header (unencrypted)
                                       0x80,
                                       0x0f,
                                       0x12,
                                       0x34,
                                       0xde,
                                       0xca,
                                       0xfb,
                                       0xad,
                                       0xca,
                                       0xfe,
                                       0xba,
                                       0xbe,
                                       // Encrypted payload
                                       0x4e,
                                       0x55,
                                       0xdc,
                                       0x4c,
                                       0xe7,
                                       0x99,
                                       0x78,
                                       0xd8,
                                       0x8c,
                                       0xa4,
                                       0xd2,
                                       0x15,
                                       0x94,
                                       0x9d,
                                       0x24,
                                       0x02,
                                       // HMAC-SHA1-80 authentication tag (10 octets)
                                       0xb7,
                                       0x8d,
                                       0x6a,
                                       0xcc,
                                       0x99,
                                       0xea,
                                       0x17,
                                       0x9b,
                                       0x8d,
                                       0xbb};

    // Initialize outbound SRTP context
    urtp_srtp_ctx_t out_ctx = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &out_ctx,
        SRTP_DIR_OUTBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        sizeof(key_salt)));

    uint8_t pkt_buf[128] = {};
    memcpy(pkt_buf, plain_rtp, sizeof(plain_rtp));

    size_t srtp_len = 0;
    TEST_ASSERT_TRUE(
        urtp_srtp_protect_rtp(&out_ctx, pkt_buf, sizeof(plain_rtp), sizeof(pkt_buf), &srtp_len));

    TEST_ASSERT_EQUAL_size_t(38, srtp_len);
    TEST_ASSERT_EQUAL_MEMORY(expected_srtp, pkt_buf, 38);

    // Initialize inbound SRTP context with same key
    urtp_srtp_ctx_t in_ctx = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &in_ctx,
        SRTP_DIR_INBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        sizeof(key_salt)));

    size_t plain_len = 0;
    TEST_ASSERT_TRUE(urtp_srtp_unprotect_rtp(&in_ctx, pkt_buf, srtp_len, &plain_len));

    TEST_ASSERT_EQUAL_size_t(sizeof(plain_rtp), plain_len);
    TEST_ASSERT_EQUAL_MEMORY(plain_rtp, pkt_buf, plain_len);

    urtp_srtp_ctx_destroy(&out_ctx);
    urtp_srtp_ctx_destroy(&in_ctx);
}

static void test_srtp_unprotect_tamper_detection(void) {
    uint8_t const key_salt[30] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                                  0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
                                  0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};

    uint8_t plain_rtp[28] = {0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x01, 0x02,
                             0x03, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
                             0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    urtp_srtp_ctx_t out_ctx = {};
    urtp_srtp_ctx_t in_ctx  = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &out_ctx,
        SRTP_DIR_OUTBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        30));
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &in_ctx,
        SRTP_DIR_INBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        30));

    uint8_t buf[64] = {};
    memcpy(buf, plain_rtp, sizeof(plain_rtp));

    size_t srtp_len = 0;
    TEST_ASSERT_TRUE(
        urtp_srtp_protect_rtp(&out_ctx, buf, sizeof(plain_rtp), sizeof(buf), &srtp_len));

    // Tamper with one bit in the payload
    buf[15] ^= 0x01;

    size_t out_len = 0;
    // Must fail unprotect due to HMAC authentication failure
    TEST_ASSERT_FALSE(urtp_srtp_unprotect_rtp(&in_ctx, buf, srtp_len, &out_len));

    urtp_srtp_ctx_destroy(&out_ctx);
    urtp_srtp_ctx_destroy(&in_ctx);
}

static void test_srtcp_protect_and_unprotect(void) {
    uint8_t const key_salt[30] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
                                  0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
                                  0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd};

    // 28-byte RTCP Receiver Report
    uint8_t const plain_rtcp[28] = {
        0x81, 0xc9, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, // Header (pt=201 RR)
        0xde, 0xca, 0xfb, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    urtp_srtp_ctx_t out_ctx = {};
    urtp_srtp_ctx_t in_ctx  = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &out_ctx,
        SRTP_DIR_OUTBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        30));
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &in_ctx,
        SRTP_DIR_INBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_salt,
        30));

    uint8_t buf[128] = {};
    memcpy(buf, plain_rtcp, sizeof(plain_rtcp));

    size_t srtcp_len = 0;
    TEST_ASSERT_TRUE(
        urtp_srtp_protect_rtcp(&out_ctx, buf, sizeof(plain_rtcp), sizeof(buf), &srtcp_len));
    // 28 bytes + 4 bytes SRTCP index + 10 bytes tag = 42 bytes
    TEST_ASSERT_EQUAL_size_t(42, srtcp_len);

    size_t dec_len = 0;
    TEST_ASSERT_TRUE(urtp_srtp_unprotect_rtcp(&in_ctx, buf, srtcp_len, &dec_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(plain_rtcp), dec_len);
    TEST_ASSERT_EQUAL_MEMORY(plain_rtcp, buf, dec_len);

    urtp_srtp_ctx_destroy(&out_ctx);
    urtp_srtp_ctx_destroy(&in_ctx);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_srtp_rfc3711_appendix_b3_test_vector);
    RUN_TEST(test_srtp_unprotect_tamper_detection);
    RUN_TEST(test_srtcp_protect_and_unprotect);
    return UNITY_END();
}
