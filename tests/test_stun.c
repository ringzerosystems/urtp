#include <arpa/inet.h>
#include <string.h>
#include "net/stun.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_stun_crc32(void) {
    TEST_ASSERT_EQUAL_HEX32(0x00000000U, stun_crc32(nullptr, 0));
    TEST_ASSERT_EQUAL_HEX32(0x00000000U, stun_crc32("", 0));

    // Standard IEEE 802.3 CRC-32 test vector for "123456789"
    char const *const test_vec = "123456789";
    TEST_ASSERT_EQUAL_HEX32(0xCBF43926U, stun_crc32(test_vec, 9));
}

static void test_stun_is_binding_request_invalid(void) {
    // Null data or too short
    TEST_ASSERT_FALSE(stun_is_binding_request(nullptr, 0));
    TEST_ASSERT_FALSE(stun_is_binding_request(nullptr, 100));
    uint8_t short_buf[19] = {};
    TEST_ASSERT_FALSE(stun_is_binding_request(short_buf, sizeof(short_buf)));

    // Invalid magic cookie
    uint8_t bad_cookie[20] = {
        0x00, 0x01, 0x00, 0x00, // Binding Request, len 0
        0x12, 0x34, 0x56, 0x78, // Wrong cookie
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b // TxID
    };
    TEST_ASSERT_FALSE(stun_is_binding_request(bad_cookie, sizeof(bad_cookie)));

    // Non-binding-request message type (e.g. Binding Response 0x0101)
    uint8_t resp_msg[20] = {
        0x01, 0x01, 0x00, 0x00,                                                // Binding Response
        0x21, 0x12, 0xa4, 0x42,                                                // Magic cookie
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b // TxID
    };
    TEST_ASSERT_FALSE(stun_is_binding_request(resp_msg, sizeof(resp_msg)));
}

static void test_stun_binding_request_valid(void) {
    uint8_t valid_req[20] = {
        0x00, 0x01, 0x00, 0x00, // Binding Request, length 0
        0x21, 0x12, 0xa4, 0x42, // Magic cookie
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c // TxID
    };
    TEST_ASSERT_TRUE(stun_is_binding_request(valid_req, sizeof(valid_req)));

    stun_request_t parsed = {};
    TEST_ASSERT_TRUE(stun_parse_request(valid_req, sizeof(valid_req), &parsed));
    TEST_ASSERT_EQUAL_MEMORY(valid_req + 8, parsed.tx_id, STUN_TX_ID_LEN);
    TEST_ASSERT_FALSE(parsed.has_username);
    TEST_ASSERT_FALSE(parsed.has_priority);
    TEST_ASSERT_FALSE(parsed.has_use_candidate);
}

static void test_stun_binding_request_with_attributes(void) {
    // Construct STUN binding request with USERNAME, PRIORITY, and USE-CANDIDATE
    uint8_t packet[128] = {
        0x00,
        0x01,
        0x00,
        0x1c, // Binding Request, len 28 (0x1c)
        0x21,
        0x12,
        0xa4,
        0x42, // Magic cookie
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88, // TxID

        // Attr 1: USERNAME (0x0006), len 9 -> padded to 12
        0x00,
        0x06,
        0x00,
        0x09,
        'u',
        's',
        'e',
        'r',
        ':',
        'p',
        'a',
        's',
        's',
        0x00,
        0x00,
        0x00,

        // Attr 2: PRIORITY (0x0024), len 4
        0x00,
        0x24,
        0x00,
        0x04,
        0x7e,
        0x00,
        0x01,
        0xff,

        // Attr 3: USE-CANDIDATE (0x0025), len 0
        0x00,
        0x25,
        0x00,
        0x00};

    TEST_ASSERT_TRUE(stun_is_binding_request(packet, 20 + 28));

    stun_request_t parsed = {};
    TEST_ASSERT_TRUE(stun_parse_request(packet, 20 + 28, &parsed));
    TEST_ASSERT_TRUE(parsed.has_username);
    TEST_ASSERT_EQUAL_STRING("user:pass", parsed.username);
    TEST_ASSERT_TRUE(parsed.has_priority);
    TEST_ASSERT_EQUAL_HEX32(0x7e0001ff, parsed.priority);
    TEST_ASSERT_TRUE(parsed.has_use_candidate);
}

static void test_stun_build_binding_response_ipv4(void) {
    uint8_t const tx_id[STUN_TX_ID_LEN] =
        {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0};

    struct sockaddr_storage src = {};
    auto const              sin = (struct sockaddr_in *)&src;
    sin->sin_family             = AF_INET;
    sin->sin_port               = htons(54321);
    inet_pton(AF_INET, "192.0.2.1", &(sin->sin_addr));

    uint8_t           resp[256] = {};
    size_t            resp_len  = 0;
    char const *const ice_pwd   = "secret_ice_password";

    TEST_ASSERT_TRUE(stun_build_binding_response(
        tx_id,
        &src,
        sizeof(struct sockaddr_in),
        ice_pwd,
        resp,
        sizeof(resp),
        &resp_len));

    // Verify response structure:
    // Header (20) + XOR-MAPPED-ADDRESS (12) + MESSAGE-INTEGRITY (24) + FINGERPRINT (8) = 64 bytes
    TEST_ASSERT_EQUAL_size_t(64, resp_len);

    // Check message type (0x0101)
    uint16_t msg_type = 0;
    __builtin_memcpy(&msg_type, resp, 2);
    TEST_ASSERT_EQUAL_HEX16(0x0101, ntohs(msg_type));

    // Check message length (44 bytes = 64 - 20)
    uint16_t msg_len = 0;
    __builtin_memcpy(&msg_len, resp + 2, 2);
    TEST_ASSERT_EQUAL_UINT16(44, ntohs(msg_len));

    // Check magic cookie
    uint32_t cookie = 0;
    __builtin_memcpy(&cookie, resp + 4, 4);
    TEST_ASSERT_EQUAL_HEX32(STUN_MAGIC_COOKIE, ntohl(cookie));

    // Check transaction ID
    TEST_ASSERT_EQUAL_MEMORY(tx_id, resp + 8, STUN_TX_ID_LEN);

    // Verify XOR-MAPPED-ADDRESS attribute
    uint16_t attr_type = 0;
    __builtin_memcpy(&attr_type, resp + 20, 2);
    TEST_ASSERT_EQUAL_HEX16(STUN_ATTR_XOR_MAPPED_ADDRESS, ntohs(attr_type));

    uint16_t attr_len = 0;
    __builtin_memcpy(&attr_len, resp + 22, 2);
    TEST_ASSERT_EQUAL_UINT16(8, ntohs(attr_len));

    uint8_t const family = resp[25];
    TEST_ASSERT_EQUAL_HEX8(0x01, family); // IPv4

    uint16_t xor_port = 0;
    __builtin_memcpy(&xor_port, resp + 26, 2);
    uint16_t const actual_port = ntohs(xor_port) ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
    TEST_ASSERT_EQUAL_UINT16(54321, actual_port);

    uint32_t xor_ip = 0;
    __builtin_memcpy(&xor_ip, resp + 28, 4);
    uint32_t const actual_ip               = ntohl(xor_ip) ^ STUN_MAGIC_COOKIE;
    char           ip_str[INET_ADDRSTRLEN] = {};
    struct in_addr in_a                    = {.s_addr = htonl(actual_ip)};
    inet_ntop(AF_INET, &in_a, ip_str, sizeof(ip_str));
    TEST_ASSERT_EQUAL_STRING("192.0.2.1", ip_str);

    // Verify FINGERPRINT attribute at offset 56 (64 - 8)
    uint16_t fp_type = 0;
    __builtin_memcpy(&fp_type, resp + 56, 2);
    TEST_ASSERT_EQUAL_HEX16(STUN_ATTR_FINGERPRINT, ntohs(fp_type));

    uint16_t fp_len = 0;
    __builtin_memcpy(&fp_len, resp + 58, 2);
    TEST_ASSERT_EQUAL_UINT16(4, ntohs(fp_len));

    uint32_t fp_val = 0;
    __builtin_memcpy(&fp_val, resp + 60, 4);
    uint32_t const expected_crc = stun_crc32(resp, 56) ^ STUN_FINGERPRINT_XOR;
    TEST_ASSERT_EQUAL_HEX32(expected_crc, ntohl(fp_val));
}

static void test_stun_build_binding_response_ipv6(void) {
    uint8_t const tx_id[STUN_TX_ID_LEN] =
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    struct sockaddr_storage src  = {};
    auto const              sin6 = (struct sockaddr_in6 *)&src;
    sin6->sin6_family            = AF_INET6;
    sin6->sin6_port              = htons(65432);
    inet_pton(AF_INET6, "2001:db8::1", &(sin6->sin6_addr));

    uint8_t resp[256] = {};
    size_t  resp_len  = 0;

    TEST_ASSERT_TRUE(stun_build_binding_response(
        tx_id,
        &src,
        sizeof(struct sockaddr_in6),
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    // Without ice_pwd: Header (20) + XOR-MAPPED-ADDRESS (24) + FINGERPRINT (8) = 52 bytes
    TEST_ASSERT_EQUAL_size_t(52, resp_len);

    uint16_t attr_type = 0;
    __builtin_memcpy(&attr_type, resp + 20, 2);
    TEST_ASSERT_EQUAL_HEX16(STUN_ATTR_XOR_MAPPED_ADDRESS, ntohs(attr_type));

    uint8_t const family = resp[25];
    TEST_ASSERT_EQUAL_HEX8(0x02, family); // IPv6

    uint16_t xor_port = 0;
    __builtin_memcpy(&xor_port, resp + 26, 2);
    uint16_t const actual_port = ntohs(xor_port) ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
    TEST_ASSERT_EQUAL_UINT16(65432, actual_port);

    // Check IPv6 XOR unmasking
    uint8_t        expected_xor[16] = {};
    uint32_t const cookie_be        = htonl(STUN_MAGIC_COOKIE);
    __builtin_memcpy(expected_xor, &cookie_be, 4);
    __builtin_memcpy(expected_xor + 4, tx_id, STUN_TX_ID_LEN);

    uint8_t actual_ip[16] = {};
    for (size_t i = 0; i < 16; ++i) {
        actual_ip[i] = resp[28 + i] ^ expected_xor[i];
    }
    char ip_str[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, actual_ip, ip_str, sizeof(ip_str));
    TEST_ASSERT_EQUAL_STRING("2001:db8::1", ip_str);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_stun_crc32);
    RUN_TEST(test_stun_is_binding_request_invalid);
    RUN_TEST(test_stun_binding_request_valid);
    RUN_TEST(test_stun_binding_request_with_attributes);
    RUN_TEST(test_stun_build_binding_response_ipv4);
    RUN_TEST(test_stun_build_binding_response_ipv6);
    return UNITY_END();
}
