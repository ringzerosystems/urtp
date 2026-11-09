#include "core/hash.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_hash_u32(void) {
    uint32_t const val1 = 12345;
    uint32_t const val2 = 12346;

    uint32_t const h1 = hash_u32(val1);
    uint32_t const h2 = hash_u32(val2);

    TEST_ASSERT_NOT_EQUAL_UINT32(h1, h2);
    TEST_ASSERT_EQUAL_UINT32(h1, hash_u32(val1));
}

static void test_hash_combine(void) {
    uint32_t const seed = 0x12345678;
    uint32_t const h1   = hash_combine(seed, 100);
    uint32_t const h2   = hash_combine(seed, 101);

    TEST_ASSERT_NOT_EQUAL_UINT32(h1, h2);
    TEST_ASSERT_NOT_EQUAL_UINT32(seed, h1);
}

static void test_hash_string(void) {
    auto const sv1 = SV_PSZ("stream_audio_0");
    auto const sv2 = SV_PSZ("stream_audio_0");
    auto const sv3 = SV_PSZ("stream_audio_1");
    auto const sv4 = SV_PSZ("STREAM_AUDIO_0");

    TEST_ASSERT_EQUAL_UINT32(hash_string(sv1), hash_string(sv2));
    TEST_ASSERT_NOT_EQUAL_UINT32(hash_string(sv1), hash_string(sv3));
    TEST_ASSERT_NOT_EQUAL_UINT32(hash_string(sv1), hash_string(sv4));
}

static void test_hash_stringi(void) {
    auto const sv1 = SV_PSZ("SIP/2.0/UDP");
    auto const sv2 = SV_PSZ("sip/2.0/udp");
    auto const sv3 = SV_PSZ("Sip/2.0/Udp");
    auto const sv4 = SV_PSZ("sip/2.0/tcp");

    TEST_ASSERT_EQUAL_UINT32(hash_stringi(sv1), hash_stringi(sv2));
    TEST_ASSERT_EQUAL_UINT32(hash_stringi(sv1), hash_stringi(sv3));
    TEST_ASSERT_NOT_EQUAL_UINT32(hash_stringi(sv1), hash_stringi(sv4));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_hash_u32);
    RUN_TEST(test_hash_combine);
    RUN_TEST(test_hash_string);
    RUN_TEST(test_hash_stringi);
    return UNITY_END();
}
