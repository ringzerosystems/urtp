#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "crypto/srtp_session.h"
#include "net/rtp.h"
#include "net/session.h"
#include "net/udp.h"
#include "ring/ring.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_endpoint_parsing(void) {
    struct sockaddr_storage addr = {};
    socklen_t               len  = 0;

    TEST_ASSERT_TRUE(udp_parse_endpoint("127.0.0.1", 10000, &addr, &len));
    TEST_ASSERT_EQUAL_UINT(sizeof(struct sockaddr_in), len);

    char     buf[INET6_ADDRSTRLEN] = {};
    uint16_t port                  = 0;
    TEST_ASSERT_TRUE(udp_format_endpoint(&addr, buf, sizeof(buf), &port));
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", buf);
    TEST_ASSERT_EQUAL_UINT16(10000, port);

    TEST_ASSERT_TRUE(udp_parse_endpoint("::1", 20000, &addr, &len));
    TEST_ASSERT_EQUAL_UINT(sizeof(struct sockaddr_in6), len);
    TEST_ASSERT_TRUE(udp_format_endpoint(&addr, buf, sizeof(buf), &port));
    TEST_ASSERT_EQUAL_STRING("::1", buf);
    TEST_ASSERT_EQUAL_UINT16(20000, port);

    TEST_ASSERT_FALSE(udp_parse_endpoint("invalid.ip.address", 10000, &addr, &len));
}

static void test_session_lifecycle(void) {
    session_table_t table = {};
    session_table_init(&table);
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);

    auto const s1 = session_create(&table, "127.0.0.1", 33000, "127.0.0.1", 33001);
    TEST_ASSERT_NOT_NULL(s1);
    TEST_ASSERT_TRUE(s1->active);
    TEST_ASSERT_EQUAL_UINT16(33000, s1->bind_port);
    TEST_ASSERT_EQUAL_UINT16(33001, s1->dest_port);
    TEST_ASSERT_EQUAL_size_t(1, table.active_count);

    // Cannot bind same port twice
    auto const s1_dup = session_create(&table, "127.0.0.1", 33000, "127.0.0.1", 33002);
    TEST_ASSERT_NULL(s1_dup);

    auto const found = session_find_by_port(&table, 33000);
    TEST_ASSERT_EQUAL_PTR(s1, found);

    auto const sidx = session_get_index(&table, s1);
    TEST_ASSERT_TRUE(sidx >= 0);

    TEST_ASSERT_TRUE(session_delete_by_port(&table, 33000, nullptr));
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);
    TEST_ASSERT_NULL(session_find_by_port(&table, 33000));
}

static void test_rtp_header_validation(void) {
    uint8_t garbage[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    TEST_ASSERT_FALSE(rtp_is_valid_packet(garbage, sizeof(garbage)));

    rtp_header_t rtp = {
        .v_p_x_cc  = 0x80, // V=2
        .m_pt      = 96,
        .seq       = htons(100),
        .timestamp = htonl(200),
        .ssrc      = htonl(300),
    };
    TEST_ASSERT_TRUE(rtp_is_valid_packet(&rtp, sizeof(rtp)));
    TEST_ASSERT_EQUAL_UINT8(2, rtp_get_version(&rtp));
    TEST_ASSERT_EQUAL_UINT8(96, rtp_get_payload_type(&rtp));

    // Version 1 packet should be rejected
    rtp.v_p_x_cc = 0x40; // V=1
    TEST_ASSERT_FALSE(rtp_is_valid_packet(&rtp, sizeof(rtp)));
}

static void test_nat_latching_api(void) {
    session_table_t table = {};
    session_table_init(&table);

    auto const s1 = session_create(&table, "127.0.0.1", 34500, nullptr, 0);
    TEST_ASSERT_NOT_NULL(s1);
    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_WAITING, s1->latch_mode);

    struct sockaddr_storage peer_addr = {};
    socklen_t               peer_len  = 0;
    TEST_ASSERT_TRUE(udp_parse_endpoint("198.51.100.25", 45678, &peer_addr, &peer_len));

    session_latch_endpoint(s1, &peer_addr, peer_len);
    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_LATCHED, s1->latch_mode);
    TEST_ASSERT_EQUAL_STRING("198.51.100.25", s1->dest_ip);
    TEST_ASSERT_EQUAL_UINT16(45678, s1->dest_port);
    TEST_ASSERT_EQUAL_STRING("198.51.100.25", s1->latched_ip);
    TEST_ASSERT_EQUAL_UINT16(45678, s1->latched_port);
    TEST_ASSERT_EQUAL_UINT64(1, s1->packets_latched);

    auto const s2 = session_create(&table, "127.0.0.1", 34502, "127.0.0.1", 34504);
    TEST_ASSERT_NOT_NULL(s2);

    TEST_ASSERT_TRUE(session_bridge_pair(&table, 34500, 34502));
    TEST_ASSERT_EQUAL_INT32(session_get_index(&table, s2), s1->peer_idx);
    TEST_ASSERT_EQUAL_INT32(session_get_index(&table, s1), s2->peer_idx);

    TEST_ASSERT_TRUE(session_unbridge(&table, 34500));
    TEST_ASSERT_EQUAL_INT32(-1, s1->peer_idx);
    TEST_ASSERT_EQUAL_INT32(-1, s2->peer_idx);

    session_table_destroy(&table, nullptr);
}

static void test_multishot_udp_relay(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    // Create destination listener socket on port 34001
    int const dest_fd = udp_bind_socket("127.0.0.1", 34001);
    TEST_ASSERT_TRUE(dest_fd >= 0);

    // Create session relaying 34000 -> 34001
    auto const session = session_create(&table, "127.0.0.1", 34000, "127.0.0.1", 34001);
    TEST_ASSERT_NOT_NULL(session);

    auto const sidx = session_get_index(&table, session);
    TEST_ASSERT_TRUE(sidx >= 0);

    TEST_ASSERT_TRUE(session_arm_multishot(session, (size_t)sidx, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Send UDP packet from client to port 34000
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in target = {};
    target.sin_family         = AF_INET;
    target.sin_port           = htons(34000);
    inet_pton(AF_INET, "127.0.0.1", &(target.sin_addr));

    char const    payload[]   = "URTP_TEST_RTP_PACKET_CONTENT_42";
    size_t const  payload_len = sizeof(payload);
    ssize_t const sent        = sendto(
        client_fd,
        payload,
        payload_len,
        0,
        (struct sockaddr const *)&target,
        sizeof(target));
    TEST_ASSERT_EQUAL_INT((int)payload_len, (int)sent);

    // Wait for CQE on ring
    int const wait_res = ring_engine_submit_and_wait(&engine, 1);
    TEST_ASSERT_TRUE(wait_res >= 0);

    struct io_uring_cqe *cqes[8] = {};
    unsigned int const   count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        TEST_ASSERT_EQUAL_UINT16(OP_TYPE_UDP_RECV, tag.fields.op_type);
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit the forward send SQE generated by rx handler
    int const forward_sub = ring_engine_submit_and_wait(&engine, 1);
    TEST_ASSERT_TRUE(forward_sub >= 0);

    unsigned int const tx_count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(tx_count >= 1);

    for (unsigned int i = 0; i < tx_count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        TEST_ASSERT_EQUAL_UINT16(OP_TYPE_UDP_SEND, tag.fields.op_type);
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), tx_count);

    // Verify destination socket received the packet
    char          recv_buf[128] = {};
    ssize_t const n_recv        = recv(dest_fd, recv_buf, sizeof(recv_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)payload_len, (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(payload, recv_buf, payload_len);

    // Verify session stats
    TEST_ASSERT_EQUAL_UINT64(1, session->packets_relayed);
    TEST_ASSERT_EQUAL_UINT64(payload_len, session->bytes_relayed);
    TEST_ASSERT_EQUAL_UINT64(0, session->packets_dropped);

    close(client_fd);
    close(dest_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_symmetric_rtp_nat_latching(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    // Allocate session with private SDP IP (192.168.1.5:20000) and latching enabled
    auto const session = session_create(&table, "127.0.0.1", 35000, "192.168.1.5", 20000);
    TEST_ASSERT_NOT_NULL(session);
    session_enable_latching(session, false, false);
    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_WAITING, session->latch_mode);

    auto const sidx = session_get_index(&table, session);
    TEST_ASSERT_TRUE(session_arm_multishot(session, (size_t)sidx, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Client binds to an arbitrary local port
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in client_bind = {
        .sin_family = AF_INET,
        .sin_port   = 0,
    };
    inet_pton(AF_INET, "127.0.0.1", &(client_bind.sin_addr));
    TEST_ASSERT_EQUAL_INT(
        0,
        bind(client_fd, (struct sockaddr const *)&client_bind, sizeof(client_bind)));

    socklen_t clen = sizeof(client_bind);
    TEST_ASSERT_EQUAL_INT(0, getsockname(client_fd, (struct sockaddr *)&client_bind, &clen));
    uint16_t const client_port = ntohs(client_bind.sin_port);

    // Prepare valid RFC 3550 RTP packet
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } rtp_pkt = {
        .hdr =
            {
                .v_p_x_cc  = 0x80, // Version 2
                .m_pt      = 0,    // PCMU
                .seq       = htons(1),
                .timestamp = htonl(160),
                .ssrc      = htonl(0xCAFE),
            },
        .payload = "HELLO_RTP_LATCH",
    };

    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port   = htons(35000),
    };
    inet_pton(AF_INET, "127.0.0.1", &(target.sin_addr));

    ssize_t const sent = sendto(
        client_fd,
        &rtp_pkt,
        sizeof(rtp_pkt),
        0,
        (struct sockaddr const *)&target,
        sizeof(target));
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_pkt), (int)sent);

    // Process RX CQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);

    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        TEST_ASSERT_EQUAL_UINT16(OP_TYPE_UDP_RECV, tag.fields.op_type);
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Verify NAT latching occurred: destination updated from 192.168.1.5:20000 to client's actual
    // public endpoint!
    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_LATCHED, session->latch_mode);
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", session->dest_ip);
    TEST_ASSERT_EQUAL_UINT16(client_port, session->dest_port);
    TEST_ASSERT_EQUAL_UINT64(1, session->packets_latched);

    // Submit the forward send SQE generated by rx handler
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        TEST_ASSERT_EQUAL_UINT16(OP_TYPE_UDP_SEND, tag.fields.op_type);
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Client receives media back at its latched endpoint (Symmetric RTP reflection)
    char          recv_buf[128] = {};
    ssize_t const n_recv        = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_pkt), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&rtp_pkt, recv_buf, sizeof(rtp_pkt));
    TEST_ASSERT_EQUAL_UINT64(1, session->packets_relayed);

    close(client_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_bridged_session_nat_latching(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    // Session A: Client facing (port 36100, LATCH enabled)
    auto const s_a = session_create(&table, "127.0.0.1", 36100, nullptr, 0);
    TEST_ASSERT_NOT_NULL(s_a);
    session_enable_latching(s_a, false, false);

    // Session B: Peer/PBX facing (port 36102, dest = 127.0.0.1:36104)
    auto const s_b = session_create(&table, "127.0.0.1", 36102, "127.0.0.1", 36104);
    TEST_ASSERT_NOT_NULL(s_b);

    TEST_ASSERT_TRUE(session_bridge_pair(&table, 36100, 36102));

    auto const idx_a = session_get_index(&table, s_a);
    auto const idx_b = session_get_index(&table, s_b);
    TEST_ASSERT_TRUE(session_arm_multishot(s_a, (size_t)idx_a, &engine));
    TEST_ASSERT_TRUE(session_arm_multishot(s_b, (size_t)idx_b, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Destination PBX receiver on 36104
    int const pbx_fd = udp_bind_socket("127.0.0.1", 36104);
    TEST_ASSERT_TRUE(pbx_fd >= 0);

    // Client socket
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in client_bind = {
        .sin_family = AF_INET,
        .sin_port   = 0,
    };
    inet_pton(AF_INET, "127.0.0.1", &(client_bind.sin_addr));
    TEST_ASSERT_EQUAL_INT(
        0,
        bind(client_fd, (struct sockaddr const *)&client_bind, sizeof(client_bind)));
    socklen_t clen = sizeof(client_bind);
    TEST_ASSERT_EQUAL_INT(0, getsockname(client_fd, (struct sockaddr *)&client_bind, &clen));
    uint16_t const client_port = ntohs(client_bind.sin_port);

    // Client sends RTP packet to Session A (36100)
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } pkt1 = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(10),
                .timestamp = htonl(1000),
                .ssrc      = htonl(0x1111),
            },
        .payload = "CLIENT_TO_PBX",
    };

    struct sockaddr_in target_a = {
        .sin_family = AF_INET,
        .sin_port   = htons(36100),
    };
    inet_pton(AF_INET, "127.0.0.1", &(target_a.sin_addr));

    ssize_t sent = sendto(
        client_fd,
        &pkt1,
        sizeof(pkt1),
        0,
        (struct sockaddr const *)&target_a,
        sizeof(target_a));
    TEST_ASSERT_EQUAL_INT((int)sizeof(pkt1), (int)sent);

    // Process RX on Session A
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Verify Session A latched client's endpoint
    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_LATCHED, s_a->latch_mode);
    TEST_ASSERT_EQUAL_UINT16(client_port, s_a->dest_port);

    // Submit send SQE (Session A bridged forward out Session B to PBX on 36104)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // PBX receives packet from Session B
    char    pbx_buf[128] = {};
    ssize_t n_recv       = recv(pbx_fd, pbx_buf, sizeof(pbx_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(pkt1), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&pkt1, pbx_buf, sizeof(pkt1));

    // Now PBX sends reply packet to Session B (36102)
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } pkt2 = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(20),
                .timestamp = htonl(2000),
                .ssrc      = htonl(0x2222),
            },
        .payload = "PBX_TO_CLIENT",
    };

    struct sockaddr_in target_b = {
        .sin_family = AF_INET,
        .sin_port   = htons(36102),
    };
    inet_pton(AF_INET, "127.0.0.1", &(target_b.sin_addr));

    sent = sendto(
        pbx_fd,
        &pkt2,
        sizeof(pkt2),
        0,
        (struct sockaddr const *)&target_b,
        sizeof(target_b));
    TEST_ASSERT_EQUAL_INT((int)sizeof(pkt2), (int)sent);

    // Process RX on Session B
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit send SQE (Session B forwarded out Session A to client's latched address!)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Client receives PBX packet from Session A!
    char client_buf[128] = {};
    n_recv               = recv(client_fd, client_buf, sizeof(client_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(pkt2), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&pkt2, client_buf, sizeof(pkt2));

    close(client_fd);
    close(pbx_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_rtcp_packet_classification(void) {
    // 1. Valid RTCP Sender Report (SR, PT=200)
    struct {
        rtcp_header_t hdr;
        uint32_t      ntp_sec;
        uint32_t      ntp_frac;
        uint32_t      rtp_ts;
        uint32_t      pkt_count;
        uint32_t      octet_count;
    } rtcp_sr = {
        .hdr =
            {
                .v_p_rc = 0x80, // V=2, P=0, RC=0
                .pt     = RTCP_PT_SR,
                .length = htons(6), // (6+1)*4 = 28 bytes
                .ssrc   = htonl(0xDEADBEEF),
            },
        .ntp_sec     = htonl(1000),
        .ntp_frac    = htonl(2000),
        .rtp_ts      = htonl(3000),
        .pkt_count   = htonl(50),
        .octet_count = htonl(8000),
    };

    static_assert(sizeof(rtcp_sr) == 28, "rtcp_sr must be 28 bytes");
    TEST_ASSERT_TRUE(rtcp_is_valid_packet(&rtcp_sr, sizeof(rtcp_sr)));
    TEST_ASSERT_EQUAL_UINT8(2, rtcp_get_version(&(rtcp_sr.hdr)));
    TEST_ASSERT_EQUAL_UINT8(200, rtcp_get_packet_type(&(rtcp_sr.hdr)));
    TEST_ASSERT_EQUAL_size_t(28, rtcp_get_length_bytes(&(rtcp_sr.hdr)));
    TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_RTCP, rtp_classify_packet(&rtcp_sr, sizeof(rtcp_sr)));
    TEST_ASSERT_TRUE(rtp_is_rtcp_packet(&rtcp_sr, sizeof(rtcp_sr)));
    TEST_ASSERT_FALSE(rtp_is_rtp_packet(&rtcp_sr, sizeof(rtcp_sr)));

    // 2. Valid RTCP BYE packet (PT=203)
    struct {
        rtcp_header_t hdr;
    } rtcp_bye = {
        .hdr =
            {
                .v_p_rc = 0x81, // V=2, P=0, SC=1
                .pt     = RTCP_PT_BYE,
                .length = htons(1), // (1+1)*4 = 8 bytes
                .ssrc   = htonl(0x12345678),
            },
    };
    TEST_ASSERT_TRUE(rtcp_is_valid_packet(&rtcp_bye, sizeof(rtcp_bye)));
    TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_RTCP, rtp_classify_packet(&rtcp_bye, sizeof(rtcp_bye)));

    // 3. Valid RTP packet with Marker bit = 0
    rtp_header_t rtp_m0 = {
        .v_p_x_cc  = 0x80, // V=2
        .m_pt      = 0,    // M=0, PT=0 (PCMU)
        .seq       = htons(1),
        .timestamp = htonl(160),
        .ssrc      = htonl(0xABCDEF),
    };
    TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_RTP, rtp_classify_packet(&rtp_m0, sizeof(rtp_m0)));
    TEST_ASSERT_TRUE(rtp_is_rtp_packet(&rtp_m0, sizeof(rtp_m0)));
    TEST_ASSERT_FALSE(rtp_is_rtcp_packet(&rtp_m0, sizeof(rtp_m0)));

    // 4. Valid RTP packet with Marker bit = 1
    rtp_header_t rtp_m1 = {
        .v_p_x_cc  = 0x80,       // V=2
        .m_pt      = 0x80 | 111, // M=1, PT=111 (Opus) -> byte 1 = 239 (outside 200-223)
        .seq       = htons(2),
        .timestamp = htonl(320),
        .ssrc      = htonl(0xABCDEF),
    };
    TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_RTP, rtp_classify_packet(&rtp_m1, sizeof(rtp_m1)));

    // 5. Invalid / truncated packets
    uint8_t short_bytes[4] = {0x80, 200, 0, 1};
    TEST_ASSERT_EQUAL_UINT8(
        PACKET_TYPE_UNKNOWN,
        rtp_classify_packet(short_bytes, sizeof(short_bytes)));

    // Wrong version (V=1)
    rtcp_sr.hdr.v_p_rc = 0x40;
    TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_UNKNOWN, rtp_classify_packet(&rtcp_sr, sizeof(rtcp_sr)));
}

static void test_rtcp_mux_single_port_relay(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    // Destination socket listening on 37201 for both RTP and RTCP
    int const dest_fd = udp_bind_socket("127.0.0.1", 37201);
    TEST_ASSERT_TRUE(dest_fd >= 0);

    // Create session on 37200 -> forwarding to 37201 with RTCP-MUX enabled
    auto const session = session_create(&table, "127.0.0.1", 37200, "127.0.0.1", 37201);
    TEST_ASSERT_NOT_NULL(session);
    session_set_rtcp_mux(session, true);
    TEST_ASSERT_TRUE(session->rtcp_mux);

    auto const sidx = session_get_index(&table, session);
    TEST_ASSERT_TRUE(session_arm_multishot(session, (size_t)sidx, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port   = htons(37200),
    };
    inet_pton(AF_INET, "127.0.0.1", &(target.sin_addr));

    // 1. Send RTP packet to multiplexed port 37200
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } rtp_pkt = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(1),
                .timestamp = htonl(100),
                .ssrc      = htonl(0x1111),
            },
        .payload = "RTP_MEDIA_DATA",
    };

    ssize_t sent = sendto(
        client_fd,
        &rtp_pkt,
        sizeof(rtp_pkt),
        0,
        (struct sockaddr const *)&target,
        sizeof(target));
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_pkt), (int)sent);

    // Process RX CQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit send SQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Destination receives RTP packet on port 37201
    char    recv_buf[128] = {};
    ssize_t n_recv        = recv(dest_fd, recv_buf, sizeof(recv_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_pkt), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&rtp_pkt, recv_buf, sizeof(rtp_pkt));

    // 2. Send RTCP packet (Sender Report) to SAME multiplexed port 37200
    struct {
        rtcp_header_t hdr;
        uint32_t      data[6];
    } rtcp_pkt = {
        .hdr =
            {
                .v_p_rc = 0x80,
                .pt     = RTCP_PT_SR,
                .length = htons(7), // (7+1)*4 = 32 bytes
                .ssrc   = htonl(0x1111),
            },
        .data = {1, 2, 3, 4, 5, 6},
    };

    sent = sendto(
        client_fd,
        &rtcp_pkt,
        sizeof(rtcp_pkt),
        0,
        (struct sockaddr const *)&target,
        sizeof(target));
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtcp_pkt), (int)sent);

    // Process RX CQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit send SQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Destination receives RTCP packet on port 37201 as well!
    n_recv = recv(dest_fd, recv_buf, sizeof(recv_buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtcp_pkt), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&rtcp_pkt, recv_buf, sizeof(rtcp_pkt));

    // Verify separate per-type statistics
    TEST_ASSERT_EQUAL_UINT64(1, session->rtp_packets_relayed);
    TEST_ASSERT_EQUAL_UINT64(sizeof(rtp_pkt), session->rtp_bytes_relayed);
    TEST_ASSERT_EQUAL_UINT64(1, session->rtcp_packets_relayed);
    TEST_ASSERT_EQUAL_UINT64(sizeof(rtcp_pkt), session->rtcp_bytes_relayed);
    TEST_ASSERT_EQUAL_UINT64(2, session->packets_relayed);

    close(client_fd);
    close(dest_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_rtcp_mux_demux_bridging(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    // Session A: WebRTC client facing on port 38500 (RTCP-MUX enabled, LATCH enabled)
    auto const s_a = session_create(&table, "127.0.0.1", 38500, nullptr, 0);
    TEST_ASSERT_NOT_NULL(s_a);
    session_set_rtcp_mux(s_a, true);
    session_enable_latching(s_a, false, false);

    // Session B: Legacy PBX facing on port 38502 (non-MUX: RTP -> 38504, RTCP -> 38505)
    auto const s_b = session_create(&table, "127.0.0.1", 38502, "127.0.0.1", 38504);
    TEST_ASSERT_NOT_NULL(s_b);
    TEST_ASSERT_TRUE(session_set_rtcp_dest(s_b, "127.0.0.1", 38505));
    TEST_ASSERT_FALSE(s_b->rtcp_mux);

    TEST_ASSERT_TRUE(session_bridge_pair(&table, 38500, 38502));

    auto const idx_a = session_get_index(&table, s_a);
    auto const idx_b = session_get_index(&table, s_b);
    TEST_ASSERT_TRUE(session_arm_multishot(s_a, (size_t)idx_a, &engine));
    TEST_ASSERT_TRUE(session_arm_multishot(s_b, (size_t)idx_b, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // PBX sockets: separate RTP (38504) and RTCP (38505)
    int const pbx_rtp_fd  = udp_bind_socket("127.0.0.1", 38504);
    int const pbx_rtcp_fd = udp_bind_socket("127.0.0.1", 38505);
    TEST_ASSERT_TRUE(pbx_rtp_fd >= 0);
    TEST_ASSERT_TRUE(pbx_rtcp_fd >= 0);

    // Client socket sending both RTP and RTCP from single client port
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in client_bind = {
        .sin_family = AF_INET,
        .sin_port   = 0,
    };
    inet_pton(AF_INET, "127.0.0.1", &(client_bind.sin_addr));
    TEST_ASSERT_EQUAL_INT(
        0,
        bind(client_fd, (struct sockaddr const *)&client_bind, sizeof(client_bind)));
    socklen_t clen = sizeof(client_bind);
    TEST_ASSERT_EQUAL_INT(0, getsockname(client_fd, (struct sockaddr *)&client_bind, &clen));
    uint16_t const client_port = ntohs(client_bind.sin_port);

    struct sockaddr_in target_a = {
        .sin_family = AF_INET,
        .sin_port   = htons(38500),
    };
    inet_pton(AF_INET, "127.0.0.1", &(target_a.sin_addr));

    // 1. Client sends RTP packet to Session A
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } rtp_msg = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(1),
                .timestamp = htonl(10),
                .ssrc      = htonl(0x9999),
            },
        .payload = "MEDIA_DATA",
    };

    ssize_t sent = sendto(
        client_fd,
        &rtp_msg,
        sizeof(rtp_msg),
        0,
        (struct sockaddr const *)&target_a,
        sizeof(target_a));
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_msg), (int)sent);

    // Process RX on Session A
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    TEST_ASSERT_EQUAL_UINT8(LATCH_MODE_LATCHED, s_a->latch_mode);
    TEST_ASSERT_EQUAL_UINT16(client_port, s_a->dest_port);

    // Submit send SQE (forwarded out Session B to PBX RTP port 38504)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // PBX receives RTP packet on RTP port 38504!
    char    buf[128] = {};
    ssize_t n_recv   = recv(pbx_rtp_fd, buf, sizeof(buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtp_msg), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&rtp_msg, buf, sizeof(rtp_msg));

    // 2. Client sends RTCP packet (Sender Report) to SAME port 38500
    struct {
        rtcp_header_t hdr;
        uint32_t      data[6];
    } rtcp_msg = {
        .hdr =
            {
                .v_p_rc = 0x80,
                .pt     = RTCP_PT_SR,
                .length = htons(7),
                .ssrc   = htonl(0x9999),
            },
        .data = {10, 20, 30, 40, 50, 60},
    };

    sent = sendto(
        client_fd,
        &rtcp_msg,
        sizeof(rtcp_msg),
        0,
        (struct sockaddr const *)&target_a,
        sizeof(target_a));
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtcp_msg), (int)sent);

    // Process RX on Session A
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit send SQE (Session B demultiplexes and routes RTCP to PBX RTCP port 38505!)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // PBX receives RTCP on separate RTCP port 38505!
    n_recv = recv(pbx_rtcp_fd, buf, sizeof(buf), 0);
    TEST_ASSERT_EQUAL_INT((int)sizeof(rtcp_msg), (int)n_recv);
    TEST_ASSERT_EQUAL_MEMORY(&rtcp_msg, buf, sizeof(rtcp_msg));

    close(client_fd);
    close(pbx_rtp_fd);
    close(pbx_rtcp_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_bridged_srtp_to_rtp_relay(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    uint8_t const client_key[30] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e};
    uint8_t const proxy_key[30]  = {0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
                                    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
                                    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe};

    // Client crypto contexts
    urtp_srtp_ctx_t client_tx = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &client_tx,
        SRTP_DIR_OUTBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        client_key,
        sizeof(client_key)));

    urtp_srtp_ctx_t client_rx = {};
    TEST_ASSERT_TRUE(urtp_srtp_ctx_init(
        &client_rx,
        SRTP_DIR_INBOUND,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        proxy_key,
        sizeof(proxy_key)));

    // Session A: Client facing (port 39200, NAT latching enabled, SRTP enabled)
    auto const s_a = session_create(&table, "127.0.0.1", 39200, nullptr, 0);
    TEST_ASSERT_NOT_NULL(s_a);
    session_enable_latching(s_a, false, false);
    TEST_ASSERT_TRUE(session_set_inbound_srtp(
        s_a,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        client_key,
        sizeof(client_key)));
    TEST_ASSERT_TRUE(session_set_outbound_srtp(
        s_a,
        SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80,
        proxy_key,
        sizeof(proxy_key)));

    // Session B: PBX facing (port 39202, dest = 127.0.0.1:39204, Plain RTP)
    auto const s_b = session_create(&table, "127.0.0.1", 39202, "127.0.0.1", 39204);
    TEST_ASSERT_NOT_NULL(s_b);

    TEST_ASSERT_TRUE(session_bridge_pair(&table, 39200, 39202));

    auto const idx_a = session_get_index(&table, s_a);
    auto const idx_b = session_get_index(&table, s_b);
    TEST_ASSERT_TRUE(session_arm_multishot(s_a, (size_t)idx_a, &engine));
    TEST_ASSERT_TRUE(session_arm_multishot(s_b, (size_t)idx_b, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Destination PBX socket on 39204
    int const pbx_fd = udp_bind_socket("127.0.0.1", 39204);
    TEST_ASSERT_TRUE(pbx_fd >= 0);

    // Client socket
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in target_a = {};
    target_a.sin_family         = AF_INET;
    target_a.sin_port           = htons(39200);
    inet_pton(AF_INET, "127.0.0.1", &(target_a.sin_addr));

    struct sockaddr_in target_b = {};
    target_b.sin_family         = AF_INET;
    target_b.sin_port           = htons(39202);
    inet_pton(AF_INET, "127.0.0.1", &(target_b.sin_addr));

    // 1. Client sends encrypted SRTP packet to Session A
    struct {
        rtp_header_t hdr;
        char         payload[16];
        uint8_t      auth_tag[10];
    } pkt1 = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(1),
                .timestamp = htonl(1000),
                .ssrc      = htonl(0x12345678),
            },
    };
    __builtin_memcpy(pkt1.payload, "HELLO_SRTP_MEDIA", 16);

    size_t enc_len1 = 0;
    TEST_ASSERT_TRUE(urtp_srtp_protect_rtp(
        &client_tx,
        &pkt1,
        sizeof(rtp_header_t) + 16,
        sizeof(pkt1),
        &enc_len1));
    TEST_ASSERT_EQUAL_size_t(sizeof(rtp_header_t) + 16 + 10, enc_len1);

    ssize_t sent =
        sendto(client_fd, &pkt1, enc_len1, 0, (struct sockaddr const *)&target_a, sizeof(target_a));
    TEST_ASSERT_EQUAL_INT((int)enc_len1, (int)sent);

    // Process RX on Session A (decrypts SRTP in-place, forwards to Session B)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit and process TX on Session B (sends plain RTP to PBX)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // PBX receives Plain RTP packet on 39204
    char          buf[1024] = {};
    ssize_t const n_recv1   = recv(pbx_fd, buf, sizeof(buf), 0);
    TEST_ASSERT_EQUAL_INT((int)(sizeof(rtp_header_t) + 16), (int)n_recv1);
    TEST_ASSERT_EQUAL_MEMORY("HELLO_SRTP_MEDIA", buf + sizeof(rtp_header_t), 16);
    TEST_ASSERT_EQUAL_UINT64(1, s_a->srtp_packets_decrypted);

    // 2. PBX sends Plain RTP packet to Session B
    struct {
        rtp_header_t hdr;
        char         payload[16];
    } pkt2 = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(2),
                .timestamp = htonl(2000),
                .ssrc      = htonl(0x87654321),
            },
    };
    __builtin_memcpy(pkt2.payload, "REPLY_PLAIN_RTP!", 16);

    sent = sendto(
        pbx_fd,
        &pkt2,
        sizeof(pkt2),
        0,
        (struct sockaddr const *)&target_b,
        sizeof(target_b));
    TEST_ASSERT_EQUAL_INT((int)sizeof(pkt2), (int)sent);

    // Process RX on Session B (forwards to Session A; Session A encrypts in-place)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit and process TX on Session A (sends encrypted SRTP to Client)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_tx_cqe(
            &table,
            &engine,
            cqe,
            tag.fields.index,
            tag.fields.bid,
            tag.fields.flags);
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Client receives Encrypted SRTP packet
    ssize_t const n_recv2 = recv(client_fd, buf, sizeof(buf), 0);
    TEST_ASSERT_EQUAL_INT((int)(sizeof(rtp_header_t) + 16 + 10), (int)n_recv2);
    TEST_ASSERT_EQUAL_UINT64(1, s_a->srtp_packets_encrypted);

    // Client decrypts packet with client_rx
    size_t dec_len2 = 0;
    TEST_ASSERT_TRUE(urtp_srtp_unprotect_rtp(&client_rx, buf, (size_t)n_recv2, &dec_len2));
    TEST_ASSERT_EQUAL_size_t(sizeof(rtp_header_t) + 16, dec_len2);
    TEST_ASSERT_EQUAL_MEMORY("REPLY_PLAIN_RTP!", buf + sizeof(rtp_header_t), 16);

    // 3. Tamper detection / Auth failure test
    struct {
        rtp_header_t hdr;
        char         payload[16];
        uint8_t      auth_tag[10];
    } pkt3 = {
        .hdr =
            {
                .v_p_x_cc  = 0x80,
                .m_pt      = 0,
                .seq       = htons(3),
                .timestamp = htonl(3000),
                .ssrc      = htonl(0x12345678),
            },
    };
    __builtin_memcpy(pkt3.payload, "TAMPERED_PAYLOAD", 16);

    size_t enc_len3 = 0;
    TEST_ASSERT_TRUE(urtp_srtp_protect_rtp(
        &client_tx,
        &pkt3,
        sizeof(rtp_header_t) + 16,
        sizeof(pkt3),
        &enc_len3));

    // Corrupt auth tag
    pkt3.auth_tag[9] ^= 0xff;

    sent =
        sendto(client_fd, &pkt3, enc_len3, 0, (struct sockaddr const *)&target_a, sizeof(target_a));
    TEST_ASSERT_EQUAL_INT((int)enc_len3, (int)sent);

    // Process RX on Session A (fails auth and drops buffer)
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        session_handle_rx_cqe(&table, &engine, cqe, tag.fields.index);
    }
    io_uring_cq_advance(&(engine.ring), count);

    TEST_ASSERT_EQUAL_UINT64(1, s_a->srtp_auth_failures);

    urtp_srtp_ctx_destroy(&client_tx);
    urtp_srtp_ctx_destroy(&client_rx);
    close(client_fd);
    close(pbx_fd);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_rtcp_pli_synthesis(void) {
    rtcp_pli_packet_t pli = {};
    size_t const      len = rtcp_build_pli(0x12345678, 0x9ABCDEF0, &pli);
    TEST_ASSERT_EQUAL_size_t(12, len);
    TEST_ASSERT_EQUAL_UINT8(RTP_VERSION_2, rtcp_get_version(&(pli.hdr)));
    TEST_ASSERT_EQUAL_UINT8(RTCP_PT_PSFB, rtcp_get_packet_type(&(pli.hdr)));
    TEST_ASSERT_EQUAL_UINT8(1, pli.hdr.v_p_rc & 0x1F); // FMT=1 (PLI)
    TEST_ASSERT_EQUAL_UINT32(0x12345678, ntohl(pli.hdr.ssrc));
    TEST_ASSERT_EQUAL_UINT32(0x9ABCDEF0, ntohl(pli.media_ssrc));
    TEST_ASSERT_EQUAL_size_t(12, rtcp_get_length_bytes(&(pli.hdr)));
    TEST_ASSERT_TRUE(rtcp_is_valid_packet(&pli, sizeof(pli)));
}

static void test_session_video_demux_and_pli(void) {
    session_table_t table = {};
    session_table_init(&table);

    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    auto const s_webrtc = session_create(&table, "127.0.0.1", 34600, nullptr, 0);
    auto const s_audio  = session_create(&table, "127.0.0.1", 34602, "127.0.0.1", 34612);
    auto const s_video  = session_create(&table, "127.0.0.1", 34604, "127.0.0.1", 34614);
    TEST_ASSERT_NOT_NULL(s_webrtc);
    TEST_ASSERT_NOT_NULL(s_audio);
    TEST_ASSERT_NOT_NULL(s_video);

    s_video->media_type     = SDP_MEDIA_VIDEO;
    int64_t const idx_audio = session_get_index(&table, s_audio);
    int64_t const idx_video = session_get_index(&table, s_video);

    // Route audio PT 111 to s_audio, video PT 96 to s_video
    TEST_ASSERT_TRUE(session_add_route(s_webrtc, 0, 111, SDP_MEDIA_AUDIO, (int32_t)idx_audio));
    TEST_ASSERT_TRUE(session_add_route(s_webrtc, 0, 96, SDP_MEDIA_VIDEO, (int32_t)idx_video));
    TEST_ASSERT_EQUAL_size_t(2, s_webrtc->route_table.count);

    // Latch s_webrtc to a test endpoint
    struct sockaddr_storage peer_addr = {};
    socklen_t               peer_len  = 0;
    TEST_ASSERT_TRUE(udp_parse_endpoint("127.0.0.1", 50000, &peer_addr, &peer_len));
    session_latch_endpoint(s_webrtc, &peer_addr, peer_len);

    // Verify PLI submission via io_uring
    TEST_ASSERT_TRUE(session_send_pli(s_webrtc, 0x11112222, 0x33334444, &engine));

    session_clear_routes(s_webrtc);
    TEST_ASSERT_EQUAL_size_t(0, s_webrtc->route_table.count);

    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

int main(void) {
    (void)urtp_srtp_global_init();
    UNITY_BEGIN();
    RUN_TEST(test_endpoint_parsing);
    RUN_TEST(test_session_lifecycle);
    RUN_TEST(test_rtp_header_validation);
    RUN_TEST(test_rtcp_packet_classification);
    RUN_TEST(test_nat_latching_api);
    RUN_TEST(test_multishot_udp_relay);
    RUN_TEST(test_symmetric_rtp_nat_latching);
    RUN_TEST(test_bridged_session_nat_latching);
    RUN_TEST(test_rtcp_mux_single_port_relay);
    RUN_TEST(test_rtcp_mux_demux_bridging);
    RUN_TEST(test_bridged_srtp_to_rtp_relay);
    RUN_TEST(test_rtcp_pli_synthesis);
    RUN_TEST(test_session_video_demux_and_pli);
    auto const res = UNITY_END();
    urtp_srtp_global_cleanup();
    return res;
}
