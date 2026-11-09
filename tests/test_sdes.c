#include <string.h>
#include "crypto/sdes.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_sdes_parse_rfc4568_attributes(void) {
    // Standard RFC 4568 attribute with 40-char base64 key (30 bytes: 16 key + 14 salt)
    char const line1[] =
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n";
    sdes_crypto_attr_t attr1 = {};
    TEST_ASSERT_TRUE(sdes_parse_crypto_attr(line1, strlen(line1), &attr1));
    TEST_ASSERT_EQUAL_UINT32(1, attr1.tag);
    TEST_ASSERT_EQUAL_INT(SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80, attr1.suite);
    TEST_ASSERT_EQUAL_STRING("AES_CM_128_HMAC_SHA1_80", attr1.suite_str);
    TEST_ASSERT_EQUAL_STRING("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", attr1.b64_key);
    TEST_ASSERT_EQUAL_size_t(30, attr1.master_key_len);

    // Attribute with lifetime and MKI parameters
    char const         line2[] = "a=crypto:2 AES_CM_128_HMAC_SHA1_32 "
                                 "inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn|2^20|1:32\r\n";
    sdes_crypto_attr_t attr2   = {};
    TEST_ASSERT_TRUE(sdes_parse_crypto_attr(line2, strlen(line2), &attr2));
    TEST_ASSERT_EQUAL_UINT32(2, attr2.tag);
    TEST_ASSERT_EQUAL_INT(SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32, attr2.suite);
    TEST_ASSERT_EQUAL_STRING("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", attr2.b64_key);
    TEST_ASSERT_EQUAL_size_t(30, attr2.master_key_len);
}

static void test_sdes_format_and_generate(void) {
    uint8_t key_bin[64]  = {};
    size_t  key_bin_len  = 0;
    char    key_b64[128] = {};
    size_t  key_b64_len  = 0;

    TEST_ASSERT_TRUE(sdes_generate_key(
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_bin,
        sizeof(key_bin),
        &key_bin_len,
        key_b64,
        sizeof(key_b64),
        &key_b64_len));

    TEST_ASSERT_EQUAL_size_t(30, key_bin_len);
    TEST_ASSERT_EQUAL_size_t(40, key_b64_len);

    char   attr_line[256] = {};
    size_t line_len       = 0;
    TEST_ASSERT_TRUE(sdes_format_crypto_attr(
        1,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        key_b64,
        attr_line,
        sizeof(attr_line),
        &line_len));

    sdes_crypto_attr_t parsed = {};
    TEST_ASSERT_TRUE(sdes_parse_crypto_attr(attr_line, line_len, &parsed));
    TEST_ASSERT_EQUAL_UINT32(1, parsed.tag);
    TEST_ASSERT_EQUAL_INT(SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80, parsed.suite);
    TEST_ASSERT_EQUAL_STRING(key_b64, parsed.b64_key);
    TEST_ASSERT_EQUAL_size_t(30, parsed.master_key_len);
    TEST_ASSERT_EQUAL_MEMORY(key_bin, parsed.master_key, 30);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sdes_parse_rfc4568_attributes);
    RUN_TEST(test_sdes_format_and_generate);
    return UNITY_END();
}
