#include "ring/ring.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_ring_init_and_destroy(void) {
    ring_engine_t      engine      = {};
    constexpr uint32_t entries     = 64;
    constexpr uint32_t buf_entries = 64;
    constexpr uint32_t buf_size    = 2048;
    constexpr int      bgid        = 1;

    TEST_ASSERT_TRUE(ring_engine_init(&engine, entries, buf_entries, buf_size, bgid, false));
    TEST_ASSERT_TRUE(engine.initialized);
    TEST_ASSERT_EQUAL_UINT32(entries, engine.ring_entries);
    TEST_ASSERT_EQUAL_UINT32(buf_entries, engine.buf_ring_entries);
    TEST_ASSERT_EQUAL_UINT32(buf_size, engine.buf_size);
    TEST_ASSERT_EQUAL_INT(bgid, engine.buf_group_id);

    // Buffer lookup checks
    uint8_t *const b0 = ring_engine_get_buf(&engine, 0);
    TEST_ASSERT_NOT_NULL(b0);
    uint8_t *const b63 = ring_engine_get_buf(&engine, 63);
    TEST_ASSERT_NOT_NULL(b63);
    TEST_ASSERT_NULL(ring_engine_get_buf(&engine, 64));

    // Send context lookup checks
    ring_send_ctx_t *const s0 = ring_engine_get_send_ctx(&engine, 0);
    TEST_ASSERT_NOT_NULL(s0);
    TEST_ASSERT_NULL(ring_engine_get_send_ctx(&engine, 64));

    // SQE retrieval
    struct io_uring_sqe *const sqe = ring_engine_get_sqe(&engine);
    TEST_ASSERT_NOT_NULL(sqe);

    // Recycle buffer
    ring_engine_recycle_buf(&engine, 0);

    // Destroy
    ring_engine_destroy(&engine);
    TEST_ASSERT_FALSE(engine.initialized);
    TEST_ASSERT_NULL(engine.buffers);
}

static void test_ring_invalid_params(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_FALSE(ring_engine_init(nullptr, 64, 64, 2048, 1, false));
    TEST_ASSERT_FALSE(ring_engine_init(&engine, 0, 64, 2048, 1, false));
    TEST_ASSERT_FALSE(ring_engine_init(&engine, 64, 0, 2048, 1, false));
    TEST_ASSERT_FALSE(ring_engine_init(&engine, 64, 64, 0, 1, false));
}

static void test_ring_submit_and_wait_timeout(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    struct __kernel_timespec ts = {
        .tv_sec  = 0,
        .tv_nsec = 10000000, // 10ms
    };

    TEST_ASSERT_EQUAL_INT(-EINVAL, ring_engine_submit_and_wait_timeout(nullptr, 1, &ts));

    int const res = ring_engine_submit_and_wait_timeout(&engine, 1, &ts);
    TEST_ASSERT_EQUAL_INT(-ETIME, res);

    ring_engine_destroy(&engine);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ring_init_and_destroy);
    RUN_TEST(test_ring_invalid_params);
    RUN_TEST(test_ring_submit_and_wait_timeout);
    return UNITY_END();
}
