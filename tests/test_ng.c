#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "control/control.h"
#include "control/ng.h"
#include "crypto/dtls.h"
#include "crypto/srtp_session.h"
#include "unity.h"

void setUp(void) {
    (void)urtp_srtp_global_init();
    (void)urtp_dtls_global_init();
}

void tearDown(void) {
    urtp_dtls_global_cleanup();
    urtp_srtp_global_cleanup();
}

static void test_ng_ping(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const req[]                     = "5323_1 d7:command4:pinge";
    char       resp[CONTROL_BUFFER_SIZE] = {};
    size_t     resp_len                  = 0;

    TEST_ASSERT_TRUE(ng_process_message(
        req,
        strlen(req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_EQUAL_STRING("5323_1 d6:result4:ponge", resp);

    // Ping without cookie
    char const req_no_cookie[] = "d7:command4:pinge";
    resp[0]                    = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        req_no_cookie,
        strlen(req_no_cookie),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_EQUAL_STRING("d6:result4:ponge", resp);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_offer_and_answer(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_caller[] = "v=0\r\n"
                              "o=alice 100 100 IN IP4 192.168.1.10\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.10\r\n"
                              "t=0 0\r\n"
                              "m=audio 10000 RTP/AVP 0 8\r\n";

    // 1. Send offer
    char          offer_req[1024] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_xyz123"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "alice_tag"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_caller));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char req_with_cookie[1200] = {};
    snprintf(req_with_cookie, sizeof(req_with_cookie), "cook_1 %s", offer_req);

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        req_with_cookie,
        strlen(req_with_cookie),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_1 d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "c=IN IP4 127.0.0.1\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_EQUAL_size_t(1, table.active_count);

    auto const call = ng_call_find(&call_table, SV_PSZ("call_xyz123"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_EQUAL_UINT16(30000, call->caller_port);

    // 2. Send answer
    char const sdp_callee[] = "v=0\r\n"
                              "o=bob 200 200 IN IP4 192.168.1.20\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.20\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/AVP 0 8\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_xyz123"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "alice_tag"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "bob_tag"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_callee));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    snprintf(req_with_cookie, sizeof(req_with_cookie), "cook_2 %s", answer_req);
    resp[0] = '\0';

    TEST_ASSERT_TRUE(ng_process_message(
        req_with_cookie,
        strlen(req_with_cookie),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_2 d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30002 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_EQUAL_size_t(2, table.active_count);
    TEST_ASSERT_EQUAL_UINT16(30002, call->callee_port);

    // Verify sessions are bridged bidirectionally
    auto const s_caller = session_find_by_port(&table, 30000);
    auto const s_callee = session_find_by_port(&table, 30002);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_EQUAL_INT32((int32_t)session_get_index(&table, s_callee), s_caller->peer_idx);
    TEST_ASSERT_EQUAL_INT32((int32_t)session_get_index(&table, s_caller), s_callee->peer_idx);

    // 3. Query stats
    char const query_req[] = "cook_3 d7:command5:query7:call-id11:call_xyz123e";
    resp[0]                = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        query_req,
        strlen(query_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_3 d6:result2:ok7:packetsi0e5:bytesi0ee"));

    // 4. List calls
    char const list_req[] = "cook_4 d7:command4:liste";
    resp[0]               = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        list_req,
        strlen(list_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_4 d6:result2:ok5:callsl11:call_xyz123ee"));

    // 5. Delete call
    char const delete_req[] = "cook_5 d7:command6:delete7:call-id11:call_xyz123e";
    resp[0]                 = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        delete_req,
        strlen(delete_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_EQUAL_STRING("cook_5 d6:result2:oke", resp);
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);
    TEST_ASSERT_NULL(ng_call_find(&call_table, SV_PSZ("call_xyz123")));

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_error_handling(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;

    // Unknown command
    char const unknown_cmd[] = "cook_err d7:command7:invalid7:call-id4:nonee";
    TEST_ASSERT_TRUE(ng_process_message(
        unknown_cmd,
        strlen(unknown_cmd),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(
        strstr(resp, "cook_err d6:result5:error12:error-reason15:Unknown commande"));

    // Answer for nonexistent call
    char          answer_buf[512] = {};
    bencode_buf_t b_ans           = {};
    bencode_buf_init(&b_ans, answer_buf, sizeof(answer_buf));
    bencode_write_dict_start(&b_ans);
    bencode_write_kv_str(&b_ans, "command", "answer");
    bencode_write_kv_str(&b_ans, "call-id", "nocall");
    bencode_write_kv_str(&b_ans, "to-tag", "tag");
    bencode_write_kv_str(&b_ans, "sdp", "v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 1000 RTP/AVP 0\r\n");
    bencode_write_dict_end(&b_ans);

    char answer_cmd[600] = {};
    snprintf(answer_cmd, sizeof(answer_cmd), "cook_err2 %s", answer_buf);

    TEST_ASSERT_TRUE(ng_process_message(
        answer_cmd,
        strlen(answer_cmd),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(
        strstr(resp, "cook_err2 d6:result5:error12:error-reason14:Call not founde"));

    // Delete nonexistent call
    char          del_buf[256] = {};
    bencode_buf_t b_del        = {};
    bencode_buf_init(&b_del, del_buf, sizeof(del_buf));
    bencode_write_dict_start(&b_del);
    bencode_write_kv_str(&b_del, "command", "delete");
    bencode_write_kv_str(&b_del, "call-id", "nocall");
    bencode_write_dict_end(&b_del);

    char del_cmd[300] = {};
    snprintf(del_cmd, sizeof(del_cmd), "cook_err3 %s", del_buf);

    TEST_ASSERT_TRUE(ng_process_message(
        del_cmd,
        strlen(del_cmd),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(
        strstr(resp, "cook_err3 d6:result5:error12:error-reason14:Call not founde"));

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_udp_control_server(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    control_server_t   server   = {};
    constexpr uint16_t UDP_PORT = 32222;
    TEST_ASSERT_TRUE(control_server_init_udp(&server, "127.0.0.1", UDP_PORT, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Client opens UDP socket
    int const client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_in srv_addr = {};
    srv_addr.sin_family         = AF_INET;
    srv_addr.sin_port           = htons(UDP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &(srv_addr.sin_addr));

    // Send NG ping via UDP
    char const    ng_ping[] = "udp_cookie_123 d7:command4:pinge";
    ssize_t const sent      = sendto(
        client_fd,
        ng_ping,
        strlen(ng_ping),
        0,
        (struct sockaddr const *)&srv_addr,
        sizeof(srv_addr));
    TEST_ASSERT_EQUAL_INT((int)strlen(ng_ping), (int)sent);

    // Process UDP RX CQE on ring
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        if (tag.fields.op_type == OP_TYPE_CONTROL_UDP_RECV) {
            control_server_handle_udp_rx_cqe(&server, &table, &engine, cqe);
        }
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit the response send SQE and wait for TX CQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        if (tag.fields.op_type == OP_TYPE_CONTROL_UDP_SEND) {
            control_server_handle_udp_tx_cqe(&server, &engine, cqe);
        }
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Client reads response from UDP socket
    char          resp_buf[128] = {};
    ssize_t const n_recv        = recv(client_fd, resp_buf, sizeof(resp_buf) - 1, 0);
    TEST_ASSERT_TRUE(n_recv > 0);
    resp_buf[n_recv] = '\0';
    TEST_ASSERT_EQUAL_STRING("udp_cookie_123 d6:result4:ponge", resp_buf);

    close(client_fd);
    control_server_destroy(&server, &engine);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_ng_rtcp_mux(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=webrtc_caller 1 1 IN IP4 10.10.10.1\r\n"
                             "s=-\r\n"
                             "c=IN IP4 10.10.10.1\r\n"
                             "t=0 0\r\n"
                             "m=audio 20000 RTP/AVP 111\r\n"
                             "a=rtpmap:111 opus/48000/2\r\n"
                             "a=rtcp:20001\r\n"
                             "a=rtcp-mux\r\n";

    // 1. Offer with a=rtcp-mux in SDP
    char          offer_req[1024] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_mux_456"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "from_tag_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=rtcp-mux\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=rtcp:30000 IN IP4 127.0.0.1\r\n"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_mux_456"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_rtcp_mux);

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_TRUE(s_caller->rtcp_mux);

    // 2. Answer accepting rtcp-mux
    char const sdp_answer[] = "v=0\r\n"
                              "o=webrtc_callee 2 2 IN IP4 10.10.10.2\r\n"
                              "s=-\r\n"
                              "c=IN IP4 10.10.10.2\r\n"
                              "t=0 0\r\n"
                              "m=audio 30000 RTP/AVP 111\r\n"
                              "a=rtpmap:111 opus/48000/2\r\n"
                              "a=rtcp:30001\r\n"
                              "a=rtcp-mux\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_mux_456"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "from_tag_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "to_tag_2"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=rtcp-mux\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=rtcp:30002 IN IP4 127.0.0.1\r\n"));
    TEST_ASSERT_TRUE(call->callee_rtcp_mux);

    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_TRUE(s_callee->rtcp_mux);

    // 3. Query stats shows detailed rtp/rtcp breakdown
    char const query_req[] = "d7:command5:query7:call-id12:call_mux_456e";
    resp[0]                = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        query_req,
        strlen(query_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "11:rtp-packetsi0e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "12:rtcp-packetsi0e"));

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_srtp_to_srtp(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=alice 100 100 IN IP4 192.168.1.10\r\n"
                             "s=-\r\n"
                             "c=IN IP4 192.168.1.10\r\n"
                             "t=0 0\r\n"
                             "m=audio 10000 RTP/SAVP 0 8\r\n"
                             "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                             "inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n";

    char          offer_req[1024] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_srtp_111"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_srtp_111"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_use_srtp);
    TEST_ASSERT_TRUE(call->callee_use_srtp);

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_TRUE(s_caller->has_inbound_srtp);
    TEST_ASSERT_TRUE(s_caller->has_outbound_srtp);

    // Answer with SRTP
    char const sdp_answer[] = "v=0\r\n"
                              "o=bob 200 200 IN IP4 192.168.1.20\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.20\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/SAVP 0 8\r\n"
                              "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                              "inline:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_srtp_111"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "tag_bob"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30002 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));

    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_TRUE(s_callee->has_inbound_srtp);
    TEST_ASSERT_TRUE(s_callee->has_outbound_srtp);

    // Query stats: SRTP stats fields present
    char const query_req[] = "d7:command5:query7:call-id13:call_srtp_111e";
    resp[0]                = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        query_req,
        strlen(query_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "14:srtp-encryptedi0e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "14:srtp-decryptedi0e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "18:srtp-auth-failuresi0e"));

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_srtp_to_rtp_bridging(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=alice 100 100 IN IP4 192.168.1.10\r\n"
                             "s=-\r\n"
                             "c=IN IP4 192.168.1.10\r\n"
                             "t=0 0\r\n"
                             "m=audio 10000 RTP/SAVP 0 8\r\n"
                             "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                             "inline:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn\r\n";

    // Offer with SDES-off flag -> Callee receives Plain RTP
    char          offer_req[1024] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_bridge_222"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "flags", 5));
    TEST_ASSERT_TRUE(bencode_write_list_start(&b));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "SDES-off", 8));
    TEST_ASSERT_TRUE(bencode_write_list_end(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Rewritten offer for Callee must be RTP/AVP without crypto
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NULL(strstr(resp, "a=crypto:"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_bridge_222"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_use_srtp);
    TEST_ASSERT_FALSE(call->callee_use_srtp);

    // Answer with plain RTP
    char const sdp_answer[] = "v=0\r\n"
                              "o=bob 200 200 IN IP4 192.168.1.20\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.20\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/AVP 0 8\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_bridge_222"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "tag_bob"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Rewritten answer for Caller must be RTP/SAVP with crypto
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30002 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_TRUE(s_caller->has_inbound_srtp);
    TEST_ASSERT_TRUE(s_caller->has_outbound_srtp);
    TEST_ASSERT_FALSE(s_callee->has_inbound_srtp);
    TEST_ASSERT_FALSE(s_callee->has_outbound_srtp);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_rtp_to_srtp_bridging(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=alice 100 100 IN IP4 192.168.1.10\r\n"
                             "s=-\r\n"
                             "c=IN IP4 192.168.1.10\r\n"
                             "t=0 0\r\n"
                             "m=audio 10000 RTP/AVP 0 8\r\n";

    // Offer from plain RTP caller, but flags specify offer-crypto for callee
    char          offer_req[1024] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_bridge_333"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "flags", 5));
    TEST_ASSERT_TRUE(bencode_write_list_start(&b));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "offer-crypto", 12));
    TEST_ASSERT_TRUE(bencode_write_list_end(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Rewritten offer for Callee must be RTP/SAVP with crypto
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/SAVP 0 8\r\n"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_bridge_333"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_FALSE(call->caller_use_srtp);
    TEST_ASSERT_TRUE(call->callee_use_srtp);

    // Callee answers with SRTP
    char const sdp_answer[] = "v=0\r\n"
                              "o=bob 200 200 IN IP4 192.168.1.20\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.20\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/SAVP 0 8\r\n"
                              "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
                              "inline:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_bridge_333"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_alice"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "tag_bob"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Rewritten answer for Caller must be RTP/AVP without crypto
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30002 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NULL(strstr(resp, "a=crypto:"));

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_FALSE(s_caller->has_inbound_srtp);
    TEST_ASSERT_FALSE(s_caller->has_outbound_srtp);
    TEST_ASSERT_TRUE(s_callee->has_inbound_srtp);
    TEST_ASSERT_TRUE(s_callee->has_outbound_srtp);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_webrtc_offer_and_answer(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=- 11111 2 IN IP4 192.168.1.50\r\n"
                             "s=-\r\n"
                             "t=0 0\r\n"
                             "c=IN IP4 192.168.1.50\r\n"
                             "m=audio 10000 UDP/TLS/RTP/SAVPF 111 9\r\n"
                             "a=rtcp:10000 IN IP4 192.168.1.50\r\n"
                             "a=ice-ufrag:clientufrag\r\n"
                             "a=ice-pwd:clientpassword1234\r\n"
                             "a=fingerprint:sha-256 "
                             "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
                             "88:99:AA:BB:CC:DD:EE:FF:00\r\n"
                             "a=setup:actpass\r\n"
                             "a=rtcp-mux\r\n";

    // 1. Send WebRTC offer with ICE=force
    char          offer_req[2048] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "webrtc_client_tag"));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "flags", 5));
    TEST_ASSERT_TRUE(bencode_write_list_start(&b));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "ICE=force", 9));
    TEST_ASSERT_TRUE(bencode_write_list_end(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=ice-ufrag:"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=ice-pwd:"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=fingerprint:sha-256"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=setup:"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_webrtc_1"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_is_webrtc);
    TEST_ASSERT_TRUE(call->callee_is_webrtc);

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_TRUE(s_caller->dtls_enabled);
    TEST_ASSERT_TRUE(s_caller->is_webrtc);

    // 2. Send WebRTC answer
    char const sdp_answer[] = "v=0\r\n"
                              "o=- 22222 2 IN IP4 192.168.1.60\r\n"
                              "s=-\r\n"
                              "t=0 0\r\n"
                              "c=IN IP4 192.168.1.60\r\n"
                              "m=audio 20000 UDP/TLS/RTP/SAVPF 111 9\r\n"
                              "a=rtcp:20000 IN IP4 192.168.1.60\r\n"
                              "a=ice-ufrag:calleeufrag\r\n"
                              "a=ice-pwd:calleepassword5678\r\n"
                              "a=fingerprint:sha-256 "
                              "22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:"
                              "88:99:AA:BB:CC:DD:EE:FF:00:11\r\n"
                              "a=setup:active\r\n"
                              "a=rtcp-mux\r\n";

    char answer_req[2048] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "webrtc_client_tag"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "webrtc_callee_tag"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=ice-ufrag:"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=fingerprint:sha-256"));

    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_TRUE(s_callee->dtls_enabled);
    TEST_ASSERT_TRUE(s_callee->is_webrtc);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_webrtc_to_sip_bridging(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=- 33333 2 IN IP4 192.168.1.70\r\n"
                             "s=-\r\n"
                             "t=0 0\r\n"
                             "c=IN IP4 192.168.1.70\r\n"
                             "m=audio 10000 UDP/TLS/RTP/SAVPF 0 8\r\n"
                             "a=rtcp:10000 IN IP4 192.168.1.70\r\n"
                             "a=ice-ufrag:callerice1\r\n"
                             "a=ice-pwd:callerpwd1\r\n"
                             "a=fingerprint:sha-256 "
                             "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:"
                             "11:22:33:44:55:66:77:88:99\r\n"
                             "a=setup:actpass\r\n"
                             "a=rtcp-mux\r\n";

    // Offer forwarded to legacy SIP (ICE=remove)
    char          offer_req[2048] = {};
    bencode_buf_t b               = {};
    bencode_buf_init(&b, offer_req, sizeof(offer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_bridge"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_webrtc"));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "flags", 5));
    TEST_ASSERT_TRUE(bencode_write_list_start(&b));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "ICE=remove", 10));
    TEST_ASSERT_TRUE(bencode_write_str_raw(&b, "SDES-off", 8));
    TEST_ASSERT_TRUE(bencode_write_list_end(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        offer_req,
        strlen(offer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Callee SDP must be RTP/AVP without ICE or DTLS attributes
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/AVP 0 8\r\n"));
    TEST_ASSERT_NULL(strstr(resp, "a=ice-ufrag"));
    TEST_ASSERT_NULL(strstr(resp, "a=fingerprint"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_webrtc_bridge"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_is_webrtc);
    TEST_ASSERT_FALSE(call->callee_is_webrtc);

    // Callee answers with legacy SIP (RTP/AVP)
    char const sdp_answer[] = "v=0\r\n"
                              "o=sipuser 44444 44444 IN IP4 192.168.1.80\r\n"
                              "s=-\r\n"
                              "c=IN IP4 192.168.1.80\r\n"
                              "t=0 0\r\n"
                              "m=audio 20000 RTP/AVP 0 8\r\n";

    char answer_req[1024] = {};
    bencode_buf_init(&b, answer_req, sizeof(answer_req));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_bridge"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_webrtc"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "tag_sip"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        answer_req,
        strlen(answer_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "d6:result2:ok"));
    // Caller SDP returned in answer response must be synthesized WebRTC SDP
    TEST_ASSERT_NOT_NULL(strstr(resp, "UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=ice-ufrag:"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=ice-pwd:"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=fingerprint:sha-256"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=setup:passive"));

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    auto const s_callee = session_find_by_port(&table, call->callee_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_NOT_NULL(s_callee);
    TEST_ASSERT_TRUE(s_caller->dtls_enabled);
    TEST_ASSERT_FALSE(s_callee->dtls_enabled);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_jitter_buffer_negotiation(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_offer[] = "v=0\r\n"
                             "o=- 1000 1 IN IP4 192.168.1.50\r\n"
                             "s=-\r\n"
                             "c=IN IP4 192.168.1.50\r\n"
                             "t=0 0\r\n"
                             "m=audio 5004 RTP/AVP 0\r\n"
                             "a=rtpmap:0 PCMU/8000\r\n";

    // 1. Send offer with jitter-buffer: 40
    char          offer_dict[1024] = {};
    bencode_buf_t b                = {};
    bencode_buf_init(&b, offer_dict, sizeof(offer_dict));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_jb_test"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "tag_from_jb"));
    TEST_ASSERT_TRUE(bencode_write_kv_int(&b, "jitter-buffer", 40));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char req_with_cookie[1200] = {};
    snprintf(req_with_cookie, sizeof(req_with_cookie), "cook_jb %s", offer_dict);

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        req_with_cookie,
        strlen(req_with_cookie),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_jb d6:result2:ok"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_jb_test"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_EQUAL_UINT32(40, call->jitter_buffer_ms);

    auto const s_caller = session_find_by_port(&table, call->caller_port);
    TEST_ASSERT_NOT_NULL(s_caller);
    // Since transcoding is not active yet, jitter buffer is not attached to session yet
    TEST_ASSERT_FALSE(s_caller->transcode_enabled);
    TEST_ASSERT_NULL(s_caller->jitter_buf);

    // Enable transcoding on caller session
    TEST_ASSERT_TRUE(session_set_transcode(
        s_caller,
        TRANSCODER_BACKEND_OPUS,
        MEDIA_CODEC_OPUS,
        MEDIA_CODEC_PCMU));
    TEST_ASSERT_TRUE(session_set_jitter_buffer(s_caller, call->jitter_buffer_ms));
    TEST_ASSERT_TRUE(s_caller->jitter_enabled);
    TEST_ASSERT_NOT_NULL(s_caller->jitter_buf);

    // Simulate jitter statistics
    s_caller->jitter_buf->packets_reordered    = 5;
    s_caller->jitter_buf->packets_dropped_late = 2;
    s_caller->jitter_buf->loss_concealments    = 1;

    // 2. Query call stats
    char const query_req[] = "cook_q d7:command5:query7:call-id12:call_jb_teste";
    resp[0]                = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        query_req,
        strlen(query_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "20:jb-packets-reorderedi5e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "23:jb-packets-dropped-latei2e"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "20:jb-loss-concealmentsi1e"));

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_webrtc_to_sip_multi_stream_video(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_webrtc_offer[] = "v=0\r\n"
                                    "o=- 1000 2 IN IP4 192.168.1.50\r\n"
                                    "s=-\r\n"
                                    "t=0 0\r\n"
                                    "a=group:BUNDLE 0 1\r\n"
                                    "a=msid-semantic: WMS\r\n"
                                    "m=audio 9 RTP/SAVPF 111 0 8\r\n"
                                    "c=IN IP4 192.168.1.50\r\n"
                                    "a=rtcp:9 IN IP4 192.168.1.50\r\n"
                                    "a=ice-ufrag:w123\r\n"
                                    "a=ice-pwd:wpwd123456789012345678901234\r\n"
                                    "a=fingerprint:sha-256 "
                                    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:"
                                    "44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
                                    "a=setup:actpass\r\n"
                                    "a=mid:0\r\n"
                                    "a=rtcp-mux\r\n"
                                    "a=rtpmap:111 opus/48000/2\r\n"
                                    "m=video 9 RTP/SAVPF 96 97\r\n"
                                    "c=IN IP4 192.168.1.50\r\n"
                                    "a=rtcp:9 IN IP4 192.168.1.50\r\n"
                                    "a=ice-ufrag:w123\r\n"
                                    "a=ice-pwd:wpwd123456789012345678901234\r\n"
                                    "a=fingerprint:sha-256 "
                                    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:"
                                    "44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
                                    "a=setup:actpass\r\n"
                                    "a=mid:1\r\n"
                                    "a=rtcp-mux\r\n"
                                    "a=rtpmap:96 VP8/90000\r\n"
                                    "a=rtpmap:97 rtx/90000\r\n"
                                    "a=simulcast:send q;h;f\r\n";

    // 1. Send WebRTC multi-stream offer (translating to unbundled SIP)
    char          offer_dict[2048] = {};
    bencode_buf_t b                = {};
    bencode_buf_init(&b, offer_dict, sizeof(offer_dict));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_video_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "alice_webrtc"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "transport-protocol", "RTP/AVP"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "ICE", "remove"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_webrtc_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char req_buf[2400] = {};
    (void)snprintf(req_buf, sizeof(req_buf), "cook_w2s %s", offer_dict);

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        req_buf,
        strlen(req_buf),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_w2s d6:result2:ok"));

    // Verify unbundled SIP SDP output: distinct audio and video ports, no BUNDLE, no simulcast
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 RTP/AVP"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=video 30002 RTP/AVP"));
    TEST_ASSERT_NULL(strstr(resp, "a=group:BUNDLE"));
    TEST_ASSERT_NULL(strstr(resp, "a=simulcast"));
    TEST_ASSERT_NULL(strstr(resp, "a=fingerprint"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_webrtc_video_1"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_TRUE(call->caller_is_webrtc);
    TEST_ASSERT_FALSE(call->callee_is_webrtc);
    TEST_ASSERT_EQUAL_UINT32(2, call->stream_count);
    TEST_ASSERT_EQUAL_UINT16(30000, call->streams[0].caller_port);
    TEST_ASSERT_EQUAL_UINT16(30002, call->streams[1].caller_port);

    auto const s_audio = session_find_by_port(&table, 30000);
    auto const s_video = session_find_by_port(&table, 30002);
    TEST_ASSERT_NOT_NULL(s_audio);
    TEST_ASSERT_NOT_NULL(s_video);
    TEST_ASSERT_EQUAL(SDP_MEDIA_AUDIO, s_audio->media_type);
    TEST_ASSERT_EQUAL(SDP_MEDIA_VIDEO, s_video->media_type);

    // 2. Callee answers with unbundled dual-stream SIP SDP
    char const sdp_sip_answer[] = "v=0\r\n"
                                  "o=bob 5000 2 IN IP4 192.168.1.88\r\n"
                                  "s=-\r\n"
                                  "c=IN IP4 192.168.1.88\r\n"
                                  "t=0 0\r\n"
                                  "m=audio 20000 RTP/AVP 0 8\r\n"
                                  "m=video 20002 RTP/AVP 96\r\n";

    char answer_dict[2048] = {};
    bencode_buf_init(&b, answer_dict, sizeof(answer_dict));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_webrtc_video_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "alice_webrtc"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "bob_sip"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_sip_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    (void)snprintf(req_buf, sizeof(req_buf), "cook_ans %s", answer_dict);
    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        req_buf,
        strlen(req_buf),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_ans d6:result2:ok"));

    // Rewritten answer SDP for WebRTC caller must bundle into single port (30004)
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=group:BUNDLE 0 1"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30004 UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=video 30004 UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=fingerprint:sha-256"));

    auto const s_bundle = session_find_by_port(&table, 30004);
    TEST_ASSERT_NOT_NULL(s_bundle);
    TEST_ASSERT_TRUE(s_bundle->is_webrtc);

    // Verify session linking and routing
    TEST_ASSERT_EQUAL_INT32(session_get_index(&table, s_bundle), s_video->peer_idx);
    TEST_ASSERT_EQUAL_PTR(&(s_bundle->outbound_srtp), s_video->shared_outbound_srtp);
    TEST_ASSERT_EQUAL(SDP_MEDIA_VIDEO, s_video->media_type);

    // Verify route table on WebRTC bundled session
    TEST_ASSERT_TRUE(s_bundle->route_table.count >= 2);
    int32_t audio_idx         = (int32_t)session_get_index(&table, s_audio);
    int32_t video_idx         = (int32_t)session_get_index(&table, s_video);
    bool    found_audio_route = false;
    bool    found_video_route = false;
    for (size_t i = 0; i < s_bundle->route_table.count; ++i) {
        if ((s_bundle->route_table.entries[i].target_session_idx == audio_idx) &&
            (s_bundle->route_table.entries[i].media_type == SDP_MEDIA_AUDIO))
        {
            found_audio_route = true;
        }
        if ((s_bundle->route_table.entries[i].target_session_idx == video_idx) &&
            (s_bundle->route_table.entries[i].media_type == SDP_MEDIA_VIDEO))
        {
            found_video_route = true;
        }
    }
    TEST_ASSERT_TRUE(found_audio_route);
    TEST_ASSERT_TRUE(found_video_route);

    // 3. Delete call and verify all 3 sessions are deleted
    char const del_req[] = "cook_del d7:command6:delete7:call-id19:call_webrtc_video_1e";
    resp[0]              = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        del_req,
        strlen(del_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_del d6:result2:ok"));

    TEST_ASSERT_NULL(session_find_by_port(&table, 30000));
    TEST_ASSERT_NULL(session_find_by_port(&table, 30002));
    TEST_ASSERT_NULL(session_find_by_port(&table, 30004));
    TEST_ASSERT_EQUAL_UINT32(0, table.active_count);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

static void test_ng_sip_to_webrtc_multi_stream_video(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char const sdp_sip_offer[] = "v=0\r\n"
                                 "o=sipcaller 1000 2 IN IP4 192.168.1.10\r\n"
                                 "s=-\r\n"
                                 "c=IN IP4 192.168.1.10\r\n"
                                 "t=0 0\r\n"
                                 "m=audio 10000 RTP/AVP 0 8\r\n"
                                 "m=video 10002 RTP/AVP 96\r\n";

    // 1. Send SIP offer to WebRTC callee (mediating to bundled WebRTC)
    char          offer_dict[2048] = {};
    bencode_buf_t b                = {};
    bencode_buf_init(&b, offer_dict, sizeof(offer_dict));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "offer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_sip_video_2"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "sip_tag_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "transport-protocol", "UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "ICE", "force"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_sip_offer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    char req_buf[2400] = {};
    (void)snprintf(req_buf, sizeof(req_buf), "cook_s2w %s", offer_dict);

    char   resp[CONTROL_BUFFER_SIZE] = {};
    size_t resp_len                  = 0;
    TEST_ASSERT_TRUE(ng_process_message(
        req_buf,
        strlen(req_buf),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_s2w d6:result2:ok"));

    // Rewritten offer SDP for WebRTC callee must be bundled into single port (30000)
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=group:BUNDLE"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30000 UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=video 30000 UDP/TLS/RTP/SAVPF"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "a=fingerprint:sha-256"));

    auto const call = ng_call_find(&call_table, SV_PSZ("call_sip_video_2"));
    TEST_ASSERT_NOT_NULL(call);
    TEST_ASSERT_FALSE(call->caller_is_webrtc);
    TEST_ASSERT_TRUE(call->callee_is_webrtc);

    auto const s_bundle = session_find_by_port(&table, 30000);
    TEST_ASSERT_NOT_NULL(s_bundle);
    TEST_ASSERT_TRUE(s_bundle->is_webrtc);

    // 2. WebRTC Callee answers with bundled SDP
    char const sdp_webrtc_answer[] = "v=0\r\n"
                                     "o=- 2000 2 IN IP4 192.168.1.55\r\n"
                                     "s=-\r\n"
                                     "t=0 0\r\n"
                                     "a=group:BUNDLE 0 1\r\n"
                                     "m=audio 9 RTP/SAVPF 0 8\r\n"
                                     "c=IN IP4 192.168.1.55\r\n"
                                     "a=mid:0\r\n"
                                     "a=rtcp-mux\r\n"
                                     "a=ice-ufrag:ans_ufrag\r\n"
                                     "a=ice-pwd:ans_pwd_123456789012345678901234\r\n"
                                     "a=fingerprint:sha-256 "
                                     "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:"
                                     "44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
                                     "a=setup:active\r\n"
                                     "m=video 9 RTP/SAVPF 96\r\n"
                                     "c=IN IP4 192.168.1.55\r\n"
                                     "a=mid:1\r\n"
                                     "a=rtcp-mux\r\n"
                                     "a=ice-ufrag:ans_ufrag\r\n"
                                     "a=ice-pwd:ans_pwd_123456789012345678901234\r\n"
                                     "a=fingerprint:sha-256 "
                                     "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:"
                                     "44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
                                     "a=setup:active\r\n";

    char answer_dict[2048] = {};
    bencode_buf_init(&b, answer_dict, sizeof(answer_dict));
    TEST_ASSERT_TRUE(bencode_write_dict_start(&b));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "command", "answer"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "call-id", "call_sip_video_2"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "from-tag", "sip_tag_1"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "to-tag", "webrtc_tag_2"));
    TEST_ASSERT_TRUE(bencode_write_kv_str(&b, "sdp", sdp_webrtc_answer));
    TEST_ASSERT_TRUE(bencode_write_dict_end(&b));

    (void)snprintf(req_buf, sizeof(req_buf), "cook_ans2 %s", answer_dict);
    resp[0] = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        req_buf,
        strlen(req_buf),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_ans2 d6:result2:ok"));

    // Rewritten answer SDP for SIP caller must unbundle into distinct ports (30002 for audio, 30004
    // for video)
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=audio 30002 RTP/AVP"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "m=video 30004 RTP/AVP"));
    TEST_ASSERT_NULL(strstr(resp, "a=group:BUNDLE"));

    auto const s_audio = session_find_by_port(&table, 30002);
    auto const s_video = session_find_by_port(&table, 30004);
    TEST_ASSERT_NOT_NULL(s_audio);
    TEST_ASSERT_NOT_NULL(s_video);
    TEST_ASSERT_EQUAL(SDP_MEDIA_AUDIO, s_audio->media_type);
    TEST_ASSERT_EQUAL(SDP_MEDIA_VIDEO, s_video->media_type);

    // 3. Cleanup call
    char const del_req[] = "cook_del2 d7:command6:delete7:call-id16:call_sip_video_2e";
    resp[0]              = '\0';
    TEST_ASSERT_TRUE(ng_process_message(
        del_req,
        strlen(del_req),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));
    TEST_ASSERT_NOT_NULL(strstr(resp, "cook_del2 d6:result2:ok"));

    TEST_ASSERT_NULL(session_find_by_port(&table, 30000));
    TEST_ASSERT_NULL(session_find_by_port(&table, 30002));
    TEST_ASSERT_NULL(session_find_by_port(&table, 30004));
    TEST_ASSERT_EQUAL_UINT32(0, table.active_count);

    ng_call_table_destroy(&call_table, &table, nullptr);
    session_table_destroy(&table, nullptr);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ng_ping);
    RUN_TEST(test_ng_offer_and_answer);
    RUN_TEST(test_ng_rtcp_mux);
    RUN_TEST(test_ng_error_handling);
    RUN_TEST(test_ng_udp_control_server);
    RUN_TEST(test_ng_srtp_to_srtp);
    RUN_TEST(test_ng_srtp_to_rtp_bridging);
    RUN_TEST(test_ng_rtp_to_srtp_bridging);
    RUN_TEST(test_ng_webrtc_offer_and_answer);
    RUN_TEST(test_ng_webrtc_to_sip_bridging);
    RUN_TEST(test_ng_jitter_buffer_negotiation);
    RUN_TEST(test_ng_webrtc_to_sip_multi_stream_video);
    RUN_TEST(test_ng_sip_to_webrtc_multi_stream_video);
    return UNITY_END();
}
