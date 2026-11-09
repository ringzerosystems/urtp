#include <string.h>
#include "control/bencode.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_bencode_parse_string(void) {
    sv_t          input = SV_PSZ("4:spam");
    bencode_val_t val   = {};
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_STR, val.type);
    TEST_ASSERT_EQUAL_size_t(4, val.str.length);
    TEST_ASSERT_EQUAL_STRING_LEN("spam", val.str.data, 4);
    TEST_ASSERT_EQUAL_size_t(0, input.length);

    // Zero-length string
    input = SV_PSZ("0:");
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_STR, val.type);
    TEST_ASSERT_EQUAL_size_t(0, val.str.length);

    // Invalid string: leading zero with non-zero length
    input = SV_PSZ("04:spam");
    TEST_ASSERT_FALSE(bencode_parse_element(&input, &val));

    // Invalid string: truncated
    input = SV_PSZ("10:short");
    TEST_ASSERT_FALSE(bencode_parse_element(&input, &val));
}

static void test_bencode_parse_int(void) {
    sv_t          input = SV_PSZ("i42e");
    bencode_val_t val   = {};
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_INT, val.type);
    TEST_ASSERT_EQUAL_INT64(42, val.integer);

    // Negative int
    input = SV_PSZ("i-12345e");
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_INT64(-12345, val.integer);

    // Zero
    input = SV_PSZ("i0e");
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_INT64(0, val.integer);

    // Invalid: "-0"
    input = SV_PSZ("i-0e");
    TEST_ASSERT_FALSE(bencode_parse_element(&input, &val));

    // Invalid: leading zero
    input = SV_PSZ("i03e");
    TEST_ASSERT_FALSE(bencode_parse_element(&input, &val));
}

static void test_bencode_parse_list(void) {
    sv_t          input = SV_PSZ("l4:spami42ee");
    bencode_val_t val   = {};
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_LIST, val.type);
    TEST_ASSERT_TRUE(bencode_list_contains_str(val.raw, SV_PSZ("spam")));
    TEST_ASSERT_FALSE(bencode_list_contains_str(val.raw, SV_PSZ("eggs")));

    // Empty list
    input = SV_PSZ("le");
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_LIST, val.type);
}

static void test_bencode_parse_dict(void) {
    sv_t          input = SV_PSZ("d7:command4:ping7:call-id6:call_13:numi99ee");
    bencode_val_t val   = {};
    TEST_ASSERT_TRUE(bencode_parse_element(&input, &val));
    TEST_ASSERT_EQUAL_UINT8(BENCODE_TYPE_DICT, val.type);

    sv_t cmd = SV_EMPTY;
    TEST_ASSERT_TRUE(bencode_dict_get_str(val.raw, SV_PSZ("command"), &cmd));
    TEST_ASSERT_TRUE(sv_equals(cmd, SV_PSZ("ping")));

    sv_t call_id = SV_EMPTY;
    TEST_ASSERT_TRUE(bencode_dict_get_str(val.raw, SV_PSZ("call-id"), &call_id));
    TEST_ASSERT_TRUE(sv_equals(call_id, SV_PSZ("call_1")));

    int64_t num = 0;
    TEST_ASSERT_TRUE(bencode_dict_get_int(val.raw, SV_PSZ("num"), &num));
    TEST_ASSERT_EQUAL_INT64(99, num);

    // Non-existent key
    TEST_ASSERT_FALSE(bencode_dict_get_str(val.raw, SV_PSZ("nonexistent"), &cmd));
}

static void test_bencode_serializer(void) {
    char          buf[256] = {};
    bencode_buf_t b        = {};
    bencode_buf_init(&b, buf, sizeof(buf));

    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "result", "ok"));
    TEST_ASSERT_TRUE(bencode_write_kv_int(&b, "port", 30000));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    TEST_ASSERT_EQUAL_STRING("d6:result2:ok4:porti30000ee", buf);

    // Test buffer overflow protection
    char small_buf[8] = {};
    bencode_buf_init(&b, small_buf, sizeof(small_buf));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_FALSE(bencode_write_kv_str(&b, "toolongkey", "value"));
    TEST_ASSERT_TRUE(b.overflow);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_bencode_parse_string);
    RUN_TEST(test_bencode_parse_int);
    RUN_TEST(test_bencode_parse_list);
    RUN_TEST(test_bencode_parse_dict);
    RUN_TEST(test_bencode_serializer);
    return UNITY_END();
}
