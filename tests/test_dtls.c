#include <string.h>
#include "crypto/dtls.h"
#include "crypto/srtp_session.h"
#include "unity.h"

void setUp(void) {
    (void)urtp_srtp_global_init();
    (void)urtp_dtls_global_init();
}

void tearDown(void) {
    urtp_dtls_global_cleanup();
    urtp_srtp_global_cleanup();
}

static void test_dtls_init_and_fingerprint(void) {
    char const *const fp = urtp_dtls_get_fingerprint();
    TEST_ASSERT_NOT_NULL(fp);

    // SHA-256 fingerprint formatted as 32 hex pairs separated by colons (95 characters)
    size_t const len = strlen(fp);
    TEST_ASSERT_EQUAL_size_t(95, len);

    for (size_t i = 0; i < len; ++i) {
        if ((i % 3) == 2) {
            TEST_ASSERT_EQUAL_CHAR(':', fp[i]);
        } else {
            bool const is_hex =
                ((fp[i] >= '0') && (fp[i] <= '9')) || ((fp[i] >= 'A') && (fp[i] <= 'F'));
            TEST_ASSERT_TRUE(is_hex);
        }
    }
}

static void test_dtls_packet_classifier(void) {
    // DTLS records have leading byte in [20, 63] and length >= 13
    uint8_t dtls_rec[13] = {22, 0xfe, 0xfd}; // Handshake record, DTLS 1.2
    TEST_ASSERT_TRUE(urtp_dtls_is_packet(dtls_rec, sizeof(dtls_rec)));

    uint8_t rtp_pkt[13] = {0x80, 0x00}; // RTP (128)
    TEST_ASSERT_FALSE(urtp_dtls_is_packet(rtp_pkt, sizeof(rtp_pkt)));

    uint8_t stun_pkt[13] = {0x00, 0x01}; // STUN (0)
    TEST_ASSERT_FALSE(urtp_dtls_is_packet(stun_pkt, sizeof(stun_pkt)));

    TEST_ASSERT_FALSE(urtp_dtls_is_packet(nullptr, 13));
    TEST_ASSERT_FALSE(urtp_dtls_is_packet(dtls_rec, 12));
}

static void test_dtls_handshake_and_srtp_key_exchange(void) {
    urtp_dtls_session_t client = {};
    urtp_dtls_session_t server = {};

    TEST_ASSERT_TRUE(urtp_dtls_session_init(&client, DTLS_ROLE_CLIENT));
    TEST_ASSERT_TRUE(urtp_dtls_session_init(&server, DTLS_ROLE_SERVER));

    uint8_t          flight_buf[4096] = {};
    constexpr size_t MAX_ITERATIONS   = 20;
    size_t           iter             = 0;

    while (((client.state != DTLS_STATE_CONNECTED) || (server.state != DTLS_STATE_CONNECTED)) &&
           (iter < MAX_ITERATIONS))
    {
        ++iter;

        // Step client
        (void)urtp_dtls_step(&client);
        size_t const c_out = urtp_dtls_get_pending_output(&client, flight_buf, sizeof(flight_buf));
        if (c_out > 0) {
            TEST_ASSERT_TRUE(urtp_dtls_feed_packet(&server, flight_buf, c_out));
        }

        // Step server
        (void)urtp_dtls_step(&server);
        size_t const s_out = urtp_dtls_get_pending_output(&server, flight_buf, sizeof(flight_buf));
        if (s_out > 0) {
            TEST_ASSERT_TRUE(urtp_dtls_feed_packet(&client, flight_buf, s_out));
        }
    }

    TEST_ASSERT_EQUAL_INT(DTLS_STATE_CONNECTED, client.state);
    TEST_ASSERT_EQUAL_INT(DTLS_STATE_CONNECTED, server.state);

    // Export SRTP keys on client and server
    srtp_crypto_suite_t client_suite       = SRTP_CRYPTO_SUITE_NONE;
    uint8_t             client_in_key[64]  = {};
    size_t              client_in_len      = 0;
    uint8_t             client_out_key[64] = {};
    size_t              client_out_len     = 0;

    TEST_ASSERT_TRUE(urtp_dtls_export_srtp_keys(
        &client,
        &client_suite,
        client_in_key,
        sizeof(client_in_key),
        &client_in_len,
        client_out_key,
        sizeof(client_out_key),
        &client_out_len));

    srtp_crypto_suite_t server_suite       = SRTP_CRYPTO_SUITE_NONE;
    uint8_t             server_in_key[64]  = {};
    size_t              server_in_len      = 0;
    uint8_t             server_out_key[64] = {};
    size_t              server_out_len     = 0;

    TEST_ASSERT_TRUE(urtp_dtls_export_srtp_keys(
        &server,
        &server_suite,
        server_in_key,
        sizeof(server_in_key),
        &server_in_len,
        server_out_key,
        sizeof(server_out_key),
        &server_out_len));

    // Both should negotiate the same cipher suite
    TEST_ASSERT_EQUAL_INT(client_suite, server_suite);
    TEST_ASSERT_EQUAL_size_t(client_out_len, server_in_len);
    TEST_ASSERT_EQUAL_size_t(client_in_len, server_out_len);

    // Key symmetry: Client outbound == Server inbound; Client inbound == Server outbound
    TEST_ASSERT_EQUAL_MEMORY(client_out_key, server_in_key, client_out_len);
    TEST_ASSERT_EQUAL_MEMORY(client_in_key, server_out_key, client_in_len);

    // End-to-end SRTP test: Client encrypts an RTP packet, Server decrypts it
    urtp_srtp_ctx_t srtp_client_out = {};
    urtp_srtp_ctx_t srtp_server_in  = {};

    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &srtp_client_out,
        SRTP_DIR_OUTBOUND,
        client_suite,
        client_out_key,
        client_out_len));

    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &srtp_server_in,
        SRTP_DIR_INBOUND,
        server_suite,
        server_in_key,
        server_in_len));

    // Sample plaintext RTP packet (header: 12 bytes + payload: 16 bytes = 28 bytes)
    uint8_t plain_rtp[28]   = {0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x01, 0xe0, 0x12, 0x34,
                               0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44,
                               0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
    uint8_t packet_buf[128] = {};
    __builtin_memcpy(packet_buf, plain_rtp, sizeof(plain_rtp));

    size_t protected_len = 0;
    TEST_ASSERT_TRUE(urtp_srtp_protect_rtp(
        &srtp_client_out,
        packet_buf,
        sizeof(plain_rtp),
        sizeof(packet_buf),
        &protected_len));

    TEST_ASSERT_TRUE(protected_len > sizeof(plain_rtp));

    size_t unprotected_len = 0;
    TEST_ASSERT_TRUE(
        urtp_srtp_unprotect_rtp(&srtp_server_in, packet_buf, protected_len, &unprotected_len));

    TEST_ASSERT_EQUAL_size_t(sizeof(plain_rtp), unprotected_len);
    TEST_ASSERT_EQUAL_MEMORY(plain_rtp, packet_buf, sizeof(plain_rtp));

    urtp_srtp_ctx_destroy(&srtp_client_out);
    urtp_srtp_ctx_destroy(&srtp_server_in);
    urtp_dtls_session_destroy(&client);
    urtp_dtls_session_destroy(&server);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_dtls_init_and_fingerprint);
    RUN_TEST(test_dtls_packet_classifier);
    RUN_TEST(test_dtls_handshake_and_srtp_key_exchange);
    return UNITY_END();
}
