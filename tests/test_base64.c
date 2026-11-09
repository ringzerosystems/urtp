#include <string.h>
#include "crypto/base64.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_base64_rfc4648_test_vectors(void) {
    struct {
        char const *plain;
        char const *expected_b64;
    } const cases[] = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char       b64_buf[64] = {};
        size_t     b64_len     = 0;
        bool const enc_ok      = base64_encode(
            (uint8_t const *)cases[i].plain,
            strlen(cases[i].plain),
            b64_buf,
            sizeof(b64_buf),
            &b64_len);
        TEST_ASSERT_TRUE(enc_ok);
        TEST_ASSERT_EQUAL_STRING(cases[i].expected_b64, b64_buf);
        TEST_ASSERT_EQUAL_size_t(strlen(cases[i].expected_b64), b64_len);

        uint8_t    dec_buf[64] = {};
        size_t     dec_len     = 0;
        bool const dec_ok = base64_decode(b64_buf, b64_len, dec_buf, sizeof(dec_buf), &dec_len);
        TEST_ASSERT_TRUE(dec_ok);
        TEST_ASSERT_EQUAL_size_t(strlen(cases[i].plain), dec_len);
        if (dec_len > 0) {
            TEST_ASSERT_EQUAL_MEMORY(cases[i].plain, dec_buf, dec_len);
        }
    }
}

static void test_base64_30_byte_srtp_key(void) {
    uint8_t const test_key_salt[30] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                       0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                       0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e};

    char   b64[64] = {};
    size_t b64_len = 0;
    TEST_ASSERT_TRUE(
        base64_encode(test_key_salt, sizeof(test_key_salt), b64, sizeof(b64), &b64_len));
    TEST_ASSERT_EQUAL_size_t(40, b64_len);

    uint8_t decoded[64] = {};
    size_t  dec_len     = 0;
    TEST_ASSERT_TRUE(base64_decode(b64, b64_len, decoded, sizeof(decoded), &dec_len));
    TEST_ASSERT_EQUAL_size_t(30, dec_len);
    TEST_ASSERT_EQUAL_MEMORY(test_key_salt, decoded, 30);
}

static void test_base64_decode_invalid(void) {
    uint8_t out[32] = {};
    size_t  out_len = 0;

    // Invalid character
    TEST_ASSERT_FALSE(base64_decode("Zg=!", 4, out, sizeof(out), &out_len));

    // Invalid length (not multiple of 4)
    TEST_ASSERT_FALSE(base64_decode("Zg", 2, out, sizeof(out), &out_len));

    // Buffer too small
    TEST_ASSERT_FALSE(base64_decode("Zm9v", 4, out, 2, &out_len));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_base64_rfc4648_test_vectors);
    RUN_TEST(test_base64_30_byte_srtp_key);
    RUN_TEST(test_base64_decode_invalid);
    return UNITY_END();
}
