#include "core/memory.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_aligned_alloc_and_free(void) {
    size_t const     before   = memory_total_allocated();
    constexpr size_t alloc_sz = 1024;

    void *const ptr = mem_alloc_aligned(64, alloc_sz);
    TEST_ASSERT_NOT_NULL(ptr);
    TEST_ASSERT_EQUAL_UINT64(0, ((uintptr_t)ptr) % 64);
    TEST_ASSERT_EQUAL_size_t(before + alloc_sz, memory_total_allocated());

    mem_free_aligned(ptr, alloc_sz);
    TEST_ASSERT_EQUAL_size_t(before, memory_total_allocated());

    // Invalid parameters
    TEST_ASSERT_NULL(mem_alloc_aligned(0, 1024));
    TEST_ASSERT_NULL(mem_alloc_aligned(64, 0));
}

static void test_conversion_helpers(void) {
    TEST_ASSERT_EQUAL_size_t(1024 * 1024, mb_to_bytes(1));
    TEST_ASSERT_EQUAL_size_t(4 * 1024 * 1024, mb_to_bytes(4));
    TEST_ASSERT_FLOAT_WITHIN(0.001, 1.0, (float)bytes_to_mb(1024 * 1024));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_aligned_alloc_and_free);
    RUN_TEST(test_conversion_helpers);
    return UNITY_END();
}
