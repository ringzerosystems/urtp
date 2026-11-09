#include <arpa/inet.h>
#include <string.h>
#include "core/macros.h"
#include "media/jitter.h"
#include "net/rtp.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void make_test_rtp(
    uint8_t *restrict const buf,
    size_t const   payload_len,
    uint16_t const seq,
    uint32_t const ts,
    uint32_t const ssrc,
    uint8_t const  pt) {
    rtp_header_t hdr = {
        .v_p_x_cc  = 0x80, // V=2
        .m_pt      = (uint8_t)(pt & 0x7F),
        .seq       = htons(seq),
        .timestamp = htonl(ts),
        .ssrc      = htonl(ssrc),
    };
    __builtin_memcpy(buf, &hdr, sizeof(hdr));
    for (size_t i = 0; i < payload_len; ++i) {
        buf[sizeof(hdr) + i] = (uint8_t)((seq + i) & 0xFF);
    }
}

static void test_jitter_init_and_reset(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40);

    TEST_ASSERT_TRUE(jb.enabled);
    TEST_ASSERT_EQUAL_UINT32(40, jb.target_delay_ms);
    TEST_ASSERT_EQUAL_UINT16(2, jb.target_depth);
    TEST_ASSERT_EQUAL_UINT16(4, jb.max_depth);
    TEST_ASSERT_EQUAL_UINT16(0, jb.occupancy);
    TEST_ASSERT_FALSE(jb.seq_initialized);

    // Test clamped delays
    jitter_buffer_t jb_clamped = {};
    jitter_buffer_init(&jb_clamped, 5); // Below min
    TEST_ASSERT_EQUAL_UINT32(JITTER_DEFAULT_DELAY_MS, jb_clamped.target_delay_ms);

    jitter_buffer_init(&jb_clamped, 500); // Above max
    TEST_ASSERT_EQUAL_UINT32(JITTER_MAX_DELAY_MS, jb_clamped.target_delay_ms);

    // Reset test
    jb.packets_inserted = 10;
    jitter_buffer_reset(&jb);
    TEST_ASSERT_EQUAL_UINT64(0, jb.packets_inserted);
    TEST_ASSERT_TRUE(jb.enabled);
}

static void test_jitter_in_order_playout(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40); // target depth 2

    uint8_t pkt1[64] = {};
    uint8_t pkt2[64] = {};
    uint8_t pkt3[64] = {};
    make_test_rtp(pkt1, 20, 100, 1000, 0x1234, 0);
    make_test_rtp(pkt2, 20, 101, 1160, 0x1234, 0);
    make_test_rtp(pkt3, 20, 102, 1320, 0x1234, 0);

    // Insert packet 1: should buffer (depth < 2)
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 1000000ULL));
    TEST_ASSERT_EQUAL_UINT16(1, jb.occupancy);

    uint8_t  out[128] = {};
    size_t   out_len  = 0;
    uint16_t out_seq  = 0;
    uint32_t out_ts   = 0;

    // Pop while buffering should return EMPTY
    TEST_ASSERT_EQUAL_INT(
        JB_POP_EMPTY,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));

    // Insert packet 2: reaches target depth 2
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt2, sizeof(pkt2), 2000000ULL));
    TEST_ASSERT_EQUAL_UINT16(2, jb.occupancy);

    // Now pop packet 1
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(100, out_seq);
    TEST_ASSERT_EQUAL_UINT32(1000, out_ts);
    TEST_ASSERT_EQUAL_size_t(sizeof(pkt1), out_len);
    TEST_ASSERT_EQUAL_UINT16(1, jb.occupancy);

    // Pop packet 2
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(101, out_seq);
    TEST_ASSERT_EQUAL_UINT32(1160, out_ts);
    TEST_ASSERT_EQUAL_UINT16(0, jb.occupancy);

    // Empty pop
    TEST_ASSERT_EQUAL_INT(
        JB_POP_EMPTY,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));

    // Insert packet 3: since buffering was cleared, pops immediately
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt3, sizeof(pkt3), 3000000ULL));
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(102, out_seq);
}

static void test_jitter_out_of_order_reorder(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40); // target depth 2

    uint8_t pkt1[64] = {};
    uint8_t pkt2[64] = {};
    uint8_t pkt3[64] = {};
    make_test_rtp(pkt1, 20, 100, 1000, 0x1234, 0);
    make_test_rtp(pkt2, 20, 101, 1160, 0x1234, 0);
    make_test_rtp(pkt3, 20, 102, 1320, 0x1234, 0);

    // Send packet 1, then packet 3 (packet 2 skipped/delayed)
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 1000000ULL));
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt3, sizeof(pkt3), 2000000ULL));

    uint8_t  out[128] = {};
    size_t   out_len  = 0;
    uint16_t out_seq  = 0;
    uint32_t out_ts   = 0;

    // Pop packet 1
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(100, out_seq);

    // Try pop: packet 2 is missing, lag (102 - 101 = 1) is within max_depth (4) -> EMPTY
    TEST_ASSERT_EQUAL_INT(
        JB_POP_EMPTY,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));

    // Now out-of-order packet 2 arrives!
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt2, sizeof(pkt2), 3000000ULL));
    TEST_ASSERT_EQUAL_UINT64(1, jb.packets_reordered);

    // Pop packet 2
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(101, out_seq);

    // Pop packet 3 (restored in sequence!)
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(102, out_seq);
}

static void test_jitter_duplicate_and_late_drops(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40);

    uint8_t pkt1[64] = {};
    uint8_t pkt2[64] = {};
    make_test_rtp(pkt1, 20, 200, 1000, 0x1234, 0);
    make_test_rtp(pkt2, 20, 201, 1160, 0x1234, 0);

    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 1000000ULL));
    // Duplicate insertion of packet 1
    TEST_ASSERT_FALSE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 1000500ULL));
    TEST_ASSERT_EQUAL_UINT64(1, jb.packets_dropped_dup);

    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt2, sizeof(pkt2), 2000000ULL));

    uint8_t  out[128] = {};
    size_t   out_len  = 0;
    uint16_t out_seq  = 0;
    uint32_t out_ts   = 0;

    // Pop both packets
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(200, out_seq);
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(201, out_seq);

    // Now try to insert packet 200 again (late arrival)
    TEST_ASSERT_FALSE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 3000000ULL));
    TEST_ASSERT_EQUAL_UINT64(1, jb.packets_dropped_late);
}

static void test_jitter_plc_gap_trigger(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40); // max_depth is 4

    uint8_t pkt1[64] = {};
    uint8_t pkt6[64] = {};
    make_test_rtp(pkt1, 20, 500, 1000, 0x1234, 0);
    // Sequence 501, 502, 503, 504 are lost; 505 arrives!
    make_test_rtp(pkt6, 20, 505, 1800, 0x1234, 0);

    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt1, sizeof(pkt1), 1000000ULL));
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt6, sizeof(pkt6), 5000000ULL));

    uint8_t  out[128] = {};
    size_t   out_len  = 0;
    uint16_t out_seq  = 0;
    uint32_t out_ts   = 0;

    // Pop packet 500
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(500, out_seq);

    // Lag is 505 - 501 = 4 >= max_depth (4) -> triggers PLC for 501!
    TEST_ASSERT_EQUAL_INT(
        JB_POP_PLC,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(501, out_seq);
    TEST_ASSERT_EQUAL_UINT64(1, jb.loss_concealments);

    // Triggers PLC for 502
    TEST_ASSERT_EQUAL_INT(
        JB_POP_PLC,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(502, out_seq);
    TEST_ASSERT_EQUAL_UINT64(2, jb.loss_concealments);

    // Triggers PLC for 503
    TEST_ASSERT_EQUAL_INT(
        JB_POP_PLC,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(503, out_seq);

    // Triggers PLC for 504
    TEST_ASSERT_EQUAL_INT(
        JB_POP_PLC,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(504, out_seq);

    // Now 505 is reached and popped as normal packet!
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(505, out_seq);
}

static void test_jitter_seq_wraparound(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40);

    uint8_t pkt_wrap0[64] = {};
    uint8_t pkt_wrap1[64] = {};
    uint8_t pkt_wrap2[64] = {};
    make_test_rtp(pkt_wrap0, 20, 65535, 1000, 0x1234, 0);
    make_test_rtp(pkt_wrap1, 20, 0, 1160, 0x1234, 0);
    make_test_rtp(pkt_wrap2, 20, 1, 1320, 0x1234, 0);

    // Insert 65535, then 1 (skipping 0)
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt_wrap0, sizeof(pkt_wrap0), 1000000ULL));
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt_wrap2, sizeof(pkt_wrap2), 2000000ULL));

    uint8_t  out[128] = {};
    size_t   out_len  = 0;
    uint16_t out_seq  = 0;
    uint32_t out_ts   = 0;

    // Pop 65535
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(65535, out_seq);

    // Sequence 0 arrives out of order
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt_wrap1, sizeof(pkt_wrap1), 3000000ULL));

    // Pop 0
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(0, out_seq);

    // Pop 1
    TEST_ASSERT_EQUAL_INT(
        JB_POP_OK,
        jitter_buffer_pop(&jb, out, sizeof(out), &out_len, &out_seq, &out_ts));
    TEST_ASSERT_EQUAL_UINT16(1, out_seq);
}

static void test_jitter_flush(void) {
    jitter_buffer_t jb = {};
    jitter_buffer_init(&jb, 40);

    uint8_t pkt[64] = {};
    make_test_rtp(pkt, 20, 10, 1000, 0x1234, 0);
    TEST_ASSERT_TRUE(jitter_buffer_insert(&jb, pkt, sizeof(pkt), 1000000ULL));
    TEST_ASSERT_EQUAL_UINT16(1, jb.occupancy);

    size_t const flushed = jitter_buffer_flush(&jb);
    TEST_ASSERT_EQUAL_size_t(1, flushed);
    TEST_ASSERT_EQUAL_UINT16(0, jb.occupancy);
}

static void test_jitter_pool_pop_and_push(void) {
    jitter_pool_t *const pool = jitter_pool_create();
    TEST_ASSERT_NOT_NULL(pool);

    jitter_buffer_t *buffers[JITTER_POOL_CAPACITY] = {};
    for (size_t i = 0; i < JITTER_POOL_CAPACITY; ++i) {
        buffers[i] = jitter_pool_pop(pool);
        TEST_ASSERT_NOT_NULL(buffers[i]);
    }

    // Exhausted
    TEST_ASSERT_NULL(jitter_pool_pop(pool));

    // Push back one and pop it
    jitter_pool_push(pool, buffers[5]);
    jitter_buffer_t *const recycled = jitter_pool_pop(pool);
    TEST_ASSERT_EQUAL_PTR(buffers[5], recycled);

    jitter_pool_destroy(pool);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_jitter_init_and_reset);
    RUN_TEST(test_jitter_in_order_playout);
    RUN_TEST(test_jitter_out_of_order_reorder);
    RUN_TEST(test_jitter_duplicate_and_late_drops);
    RUN_TEST(test_jitter_plc_gap_trigger);
    RUN_TEST(test_jitter_seq_wraparound);
    RUN_TEST(test_jitter_flush);
    RUN_TEST(test_jitter_pool_pop_and_push);
    return UNITY_END();
}
