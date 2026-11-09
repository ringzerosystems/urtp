#include "core/string_view.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_sv_init_and_psz(void) {
    char const text[] = "hello urtp";
    auto const sv     = SV_PSZ(text);

    TEST_ASSERT_EQUAL_PTR(text, sv.data);
    TEST_ASSERT_EQUAL_size_t(10, sv.length);
    TEST_ASSERT_FALSE(SV_IS_EMPTY(sv));
}

static void test_sv_empty_and_clear(void) {
    auto sv = SV_EMPTY;
    TEST_ASSERT_NULL(sv.data);
    TEST_ASSERT_EQUAL_size_t(0, sv.length);
    TEST_ASSERT_TRUE(SV_IS_EMPTY(sv));

    char const text[] = "temp";
    SV_SET(sv, text, 4);
    TEST_ASSERT_FALSE(SV_IS_EMPTY(sv));

    SV_CLEAR(sv);
    TEST_ASSERT_NULL(sv.data);
    TEST_ASSERT_EQUAL_size_t(0, sv.length);
    TEST_ASSERT_TRUE(SV_IS_EMPTY(sv));
}

static void test_sv_equals(void) {
    auto const sv1 = SV_PSZ("rtp_multishot");
    auto const sv2 = SV_PSZ("rtp_multishot");
    auto const sv3 = SV_PSZ("rtp_multishot_different");
    auto const sv4 = SV_PSZ("rtp_monoshot");

    TEST_ASSERT_TRUE(sv_equals(sv1, sv2));
    TEST_ASSERT_FALSE(sv_equals(sv1, sv3));
    TEST_ASSERT_FALSE(sv_equals(sv1, sv4));
}

static void test_sv_cmp(void) {
    auto const a = SV_PSZ("abc");
    auto const b = SV_PSZ("abc");
    auto const c = SV_PSZ("abd");
    auto const d = SV_PSZ("abcd");

    TEST_ASSERT_EQUAL_INT(0, sv_cmp(a, b));
    TEST_ASSERT_TRUE(sv_cmp(a, c) < 0);
    TEST_ASSERT_TRUE(sv_cmp(c, a) > 0);
    TEST_ASSERT_TRUE(sv_cmp(a, d) < 0);
    TEST_ASSERT_TRUE(sv_cmp(d, a) > 0);
}

static void test_sv_case_conversion(void) {
    char lower_buf[] = "rtpengine-ng";
    sv_toupper(lower_buf, sizeof(lower_buf) - 1);
    TEST_ASSERT_EQUAL_STRING("RTPENGINE-NG", lower_buf);

    char upper_buf[] = "IO_URING_SQPOLL";
    sv_tolower(upper_buf, sizeof(upper_buf) - 1);
    TEST_ASSERT_EQUAL_STRING("io_uring_sqpoll", upper_buf);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sv_init_and_psz);
    RUN_TEST(test_sv_empty_and_clear);
    RUN_TEST(test_sv_equals);
    RUN_TEST(test_sv_cmp);
    RUN_TEST(test_sv_case_conversion);
    return UNITY_END();
}
