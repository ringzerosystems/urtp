#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "control/control.h"
#include "control/ng.h"
#include "net/pcap.h"
#include "net/rtp.h"
#include "net/session.h"
#include "ring/ring.h"
#include "server.h"
#include "unity.h"

static char const *const TEST_PCAP_DIR = "/tmp/urtp_pcap_test_vol";

void setUp(void) { (void)mkdir(TEST_PCAP_DIR, 0755); }

void tearDown(void) {
    // Cleanup any created pcap files in test dir
    (void)unlink("/tmp/urtp_pcap_test_vol/test-call-1.pcap");
    (void)unlink("/tmp/urtp_pcap_test_vol/session_12000.pcap");
    (void)unlink("/tmp/urtp_pcap_test_vol/session_12002.pcap");
    (void)unlink("/tmp/urtp_pcap_test_vol/ng-test-call.pcap");
    (void)unlink("/tmp/urtp_pcap_test_vol/ctrl-call-1.pcap");
    (void)rmdir(TEST_PCAP_DIR);
}

static void test_pcap_struct_sizes_and_constants(void) {
    TEST_ASSERT_EQUAL_size_t(24, sizeof(pcap_file_hdr_t));
    TEST_ASSERT_EQUAL_size_t(16, sizeof(pcap_packet_hdr_t));
    TEST_ASSERT_EQUAL_size_t(14, sizeof(pcap_eth_hdr_t));
    TEST_ASSERT_EQUAL_size_t(20, sizeof(pcap_ipv4_hdr_t));
    TEST_ASSERT_EQUAL_size_t(40, sizeof(pcap_ipv6_hdr_t));
    TEST_ASSERT_EQUAL_size_t(8, sizeof(pcap_udp_hdr_t));

    TEST_ASSERT_EQUAL_HEX32(0xa1b2c3d4, PCAP_MAGIC_USEC);
    TEST_ASSERT_EQUAL_UINT16(2, PCAP_VERSION_MAJOR);
    TEST_ASSERT_EQUAL_UINT16(4, PCAP_VERSION_MINOR);
    TEST_ASSERT_EQUAL_UINT32(1, PCAP_LINKTYPE_ETHERNET);
}

static void test_pcap_table_init_and_dir_config(void) {
    pcap_table_t table = {};
    pcap_table_init(&table);

    TEST_ASSERT_FALSE(table.enabled);
    TEST_ASSERT_EQUAL_size_t(0, table.active_recorders);

    TEST_ASSERT_TRUE(pcap_table_set_record_dir(&table, TEST_PCAP_DIR));
    TEST_ASSERT_TRUE(table.enabled);
    TEST_ASSERT_EQUAL_STRING(TEST_PCAP_DIR, table.record_dir);

    // Invalid arguments
    TEST_ASSERT_FALSE(pcap_table_set_record_dir(nullptr, TEST_PCAP_DIR));
    TEST_ASSERT_FALSE(pcap_table_set_record_dir(&table, nullptr));
    TEST_ASSERT_FALSE(pcap_table_set_record_dir(&table, ""));

    pcap_table_destroy(&table);
    TEST_ASSERT_FALSE(table.enabled);
}

static void test_pcap_file_write_and_verification(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    pcap_table_t table = {};
    pcap_table_init(&table);
    TEST_ASSERT_TRUE(pcap_table_set_record_dir(&table, TEST_PCAP_DIR));

    int32_t const rec_idx = pcap_recorder_start(&table, "test-call-1", 12000, 12002);
    TEST_ASSERT_GREATER_OR_EQUAL_INT32(0, rec_idx);
    TEST_ASSERT_EQUAL_size_t(1, table.active_recorders);

    pcap_recorder_t *const rec = pcap_recorder_get(&table, rec_idx);
    TEST_ASSERT_NOT_NULL(rec);
    TEST_ASSERT_TRUE(rec->active);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, rec->fd);
    TEST_ASSERT_EQUAL_STRING("test-call-1", rec->call_id);

    // Create synthetic RTP packet
    uint8_t payload[172] = {};
    // RTP header: V=2, PT=0 (PCMU), Seq=1001, TS=160000, SSRC=0x12345678
    payload[0] = 0x80;
    payload[1] = 0x00;
    payload[2] = 0x03;
    payload[3] = 0xe9; // seq = 1001
    // fill some audio sample bytes
    for (size_t i = 12; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)(i & 0xff);
    }

    struct sockaddr_storage   src_addr = {};
    struct sockaddr_in *const sin_src  = (struct sockaddr_in *)&src_addr;
    sin_src->sin_family                = AF_INET;
    sin_src->sin_port                  = htons(50000);
    inet_pton(AF_INET, "192.168.1.10", &(sin_src->sin_addr));

    struct sockaddr_storage   dst_addr = {};
    struct sockaddr_in *const sin_dst  = (struct sockaddr_in *)&dst_addr;
    sin_dst->sin_family                = AF_INET;
    sin_dst->sin_port                  = htons(12000);
    inet_pton(AF_INET, "10.0.0.1", &(sin_dst->sin_addr));

    // Submit packet write
    TEST_ASSERT_TRUE(pcap_record_packet(
        &table,
        &engine,
        rec_idx,
        payload,
        sizeof(payload),
        &src_addr,
        &dst_addr,
        0,
        false));

    TEST_ASSERT_EQUAL_UINT64(1, rec->packets_recorded);

    // Submit to io_uring and reap CQE
    int const ret = ring_engine_submit_and_wait(&engine, 1);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);

    struct io_uring_cqe *cqe = nullptr;
    TEST_ASSERT_EQUAL_INT(0, io_uring_peek_cqe(&(engine.ring), &cqe));
    TEST_ASSERT_NOT_NULL(cqe);

    user_data_tag_t const tag = {.raw = cqe->user_data};
    TEST_ASSERT_EQUAL_UINT16(OP_TYPE_PCAP_WRITE, tag.fields.op_type);
    TEST_ASSERT_GREATER_THAN_INT(0, cqe->res);

    pcap_handle_write_cqe(&table, &engine, cqe, tag.fields.index, tag.fields.bid);
    io_uring_cqe_seen(&(engine.ring), cqe);

    // Stop recorder
    TEST_ASSERT_TRUE(pcap_recorder_stop_by_index(&table, rec_idx));
    TEST_ASSERT_EQUAL_size_t(0, table.active_recorders);

    // Verify written PCAP file on disk
    int const fd = open(rec->file_path, O_RDONLY);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd);

    // 1. Read and verify PCAP global header
    pcap_file_hdr_t fhdr = {};
    TEST_ASSERT_EQUAL_INT(sizeof(fhdr), read(fd, &fhdr, sizeof(fhdr)));
    TEST_ASSERT_EQUAL_HEX32(PCAP_MAGIC_USEC, fhdr.magic_number);
    TEST_ASSERT_EQUAL_UINT16(2, fhdr.version_major);
    TEST_ASSERT_EQUAL_UINT16(4, fhdr.version_minor);
    TEST_ASSERT_EQUAL_UINT32(1, fhdr.network); // LINKTYPE_ETHERNET

    // 2. Read and verify PCAP packet header
    pcap_packet_hdr_t phdr = {};
    TEST_ASSERT_EQUAL_INT(sizeof(phdr), read(fd, &phdr, sizeof(phdr)));
    uint32_t const expected_len =
        sizeof(pcap_eth_hdr_t) + sizeof(pcap_ipv4_hdr_t) + sizeof(pcap_udp_hdr_t) + sizeof(payload);
    TEST_ASSERT_EQUAL_UINT32(expected_len, phdr.incl_len);
    TEST_ASSERT_EQUAL_UINT32(expected_len, phdr.orig_len);

    // 3. Read and verify Ethernet header
    pcap_eth_hdr_t eth = {};
    TEST_ASSERT_EQUAL_INT(sizeof(eth), read(fd, &eth, sizeof(eth)));
    TEST_ASSERT_EQUAL_HEX16(htons(0x0800), eth.ethertype);

    // 4. Read and verify IPv4 header
    pcap_ipv4_hdr_t ip4 = {};
    TEST_ASSERT_EQUAL_INT(sizeof(ip4), read(fd, &ip4, sizeof(ip4)));
    TEST_ASSERT_EQUAL_HEX8(0x45, ip4.ver_ihl);
    TEST_ASSERT_EQUAL_HEX8(17, ip4.proto); // UDP
    TEST_ASSERT_EQUAL_HEX32(sin_src->sin_addr.s_addr, ip4.saddr);
    TEST_ASSERT_EQUAL_HEX32(sin_dst->sin_addr.s_addr, ip4.daddr);

    // 5. Read and verify UDP header
    pcap_udp_hdr_t udp = {};
    TEST_ASSERT_EQUAL_INT(sizeof(udp), read(fd, &udp, sizeof(udp)));
    TEST_ASSERT_EQUAL_HEX16(htons(50000), udp.source);
    TEST_ASSERT_EQUAL_HEX16(htons(12000), udp.dest);
    TEST_ASSERT_EQUAL_HEX16(htons(sizeof(pcap_udp_hdr_t) + sizeof(payload)), udp.len);

    // 6. Read and verify RTP Payload
    uint8_t read_payload[sizeof(payload)] = {};
    TEST_ASSERT_EQUAL_INT(sizeof(payload), read(fd, read_payload, sizeof(payload)));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, read_payload, sizeof(payload));

    close(fd);
    pcap_table_destroy(&table);
    ring_engine_destroy(&engine);
}

static void test_pcap_zero_copy_scatter_gather(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    pcap_table_t table = {};
    pcap_table_init(&table);
    TEST_ASSERT_TRUE(pcap_table_set_record_dir(&table, TEST_PCAP_DIR));

    int32_t const rec_idx = pcap_recorder_start(&table, nullptr, 12000, 0);
    TEST_ASSERT_GREATER_OR_EQUAL_INT32(0, rec_idx);

    uint16_t const bid = 5;
    uint8_t *const buf = ring_engine_get_buf(&engine, bid);
    TEST_ASSERT_NOT_NULL(buf);
    __builtin_memset(buf, 0xaa, 100);

    engine.buf_refcounts[bid] = 1;

    struct sockaddr_storage src = {};
    struct sockaddr_storage dst = {};

    // Submit zero-copy write
    TEST_ASSERT_TRUE(pcap_record_packet(&table, &engine, rec_idx, buf, 100, &src, &dst, bid, true));

    // Buffer refcount must have been incremented to 2
    TEST_ASSERT_EQUAL_UINT8(2, engine.buf_refcounts[bid]);

    // Submit to io_uring
    int const ret = ring_engine_submit_and_wait(&engine, 1);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);

    struct io_uring_cqe *cqe = nullptr;
    TEST_ASSERT_EQUAL_INT(0, io_uring_peek_cqe(&(engine.ring), &cqe));
    TEST_ASSERT_NOT_NULL(cqe);

    user_data_tag_t const tag = {.raw = cqe->user_data};
    TEST_ASSERT_EQUAL_UINT16(OP_TYPE_PCAP_WRITE, tag.fields.op_type);

    pcap_handle_write_cqe(&table, &engine, cqe, tag.fields.index, tag.fields.bid);
    io_uring_cqe_seen(&(engine.ring), cqe);

    // Refcount decrements to 1 on PCAP write completion
    TEST_ASSERT_EQUAL_UINT8(1, engine.buf_refcounts[bid]);

    // Releasing the network TX reference returns buffer to 0
    ring_engine_buf_release(&engine, bid);
    TEST_ASSERT_EQUAL_UINT8(0, engine.buf_refcounts[bid]);

    pcap_table_destroy(&table);
    ring_engine_destroy(&engine);
}

static void test_pcap_control_protocol_commands(void) {
    session_table_t table = {};
    session_table_init(&table);
    TEST_ASSERT_TRUE(pcap_table_set_record_dir(&(table.pcap_table), TEST_PCAP_DIR));

    auto const session = session_create(&table, "127.0.0.1", 12000, "127.0.0.1", 20000);
    TEST_ASSERT_NOT_NULL(session);

    char resp[1024] = {};

    // RECORD STATUS
    TEST_ASSERT_TRUE(control_process_command("RECORD STATUS", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK RECORD"));

    // RECORD START PORT 12000
    TEST_ASSERT_TRUE(
        control_process_command("RECORD START PORT 12000", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK RECORDING STARTED PORT 12000"));
    TEST_ASSERT_GREATER_OR_EQUAL_INT32(0, session->record_idx);

    // STATUS output should reflect record=yes
    TEST_ASSERT_TRUE(control_process_command("STATUS", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "record=yes"));

    // RECORD STOP PORT 12000
    TEST_ASSERT_TRUE(
        control_process_command("RECORD STOP PORT 12000", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK RECORDING STOPPED PORT 12000"));
    TEST_ASSERT_EQUAL_INT32(-1, session->record_idx);

    // RECORD START CALL ctrl-call-1
    TEST_ASSERT_TRUE(control_process_command(
        "RECORD START CALL ctrl-call-1",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK RECORDING STARTED CALL ctrl-call-1"));

    // RECORD STOP CALL ctrl-call-1
    TEST_ASSERT_TRUE(control_process_command(
        "RECORD STOP CALL ctrl-call-1",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK RECORDING STOPPED CALL ctrl-call-1"));

    session_table_destroy(&table, nullptr);
}

static void test_pcap_ng_protocol_commands(void) {
    session_table_t session_table = {};
    session_table_init(&session_table);
    TEST_ASSERT_TRUE(pcap_table_set_record_dir(&(session_table.pcap_table), TEST_PCAP_DIR));

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    // Create an active call in call_table
    ng_call_t *const call =
        ng_call_find_or_create(&call_table, SV_PSZ("ng-test-call"), SV_PSZ("from1"));
    TEST_ASSERT_NOT_NULL(call);
    call->caller_port = 30000;
    call->callee_port = 30002;

    auto const s_caller = session_create(&session_table, "127.0.0.1", 30000, "127.0.0.1", 40000);
    auto const s_callee = session_create(&session_table, "127.0.0.1", 30002, "127.0.0.1", 40002);
    TEST_ASSERT_NOT_NULL(s_caller);
    TEST_ASSERT_NOT_NULL(s_callee);

    char   resp[1024] = {};
    size_t resp_len   = 0;

    // Send "start recording" NG message: cookie + d7:call-id12:ng-test-call7:command15:start
    // recordinge
    char const *const start_msg = "cookie123 d7:call-id12:ng-test-call7:command15:start recordinge";
    TEST_ASSERT_TRUE(ng_process_message(
        start_msg,
        __builtin_strlen(start_msg),
        &session_table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "result2:ok"));
    TEST_ASSERT_GREATER_OR_EQUAL_INT32(0, call->record_idx);
    TEST_ASSERT_EQUAL_INT32(call->record_idx, s_caller->record_idx);
    TEST_ASSERT_EQUAL_INT32(call->record_idx, s_callee->record_idx);

    // Send "stop recording" NG message
    char const *const stop_msg = "cookie123 d7:call-id12:ng-test-call7:command14:stop recordinge";
    TEST_ASSERT_TRUE(ng_process_message(
        stop_msg,
        __builtin_strlen(stop_msg),
        &session_table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp),
        &resp_len));

    TEST_ASSERT_NOT_NULL(strstr(resp, "result2:ok"));
    TEST_ASSERT_EQUAL_INT32(-1, call->record_idx);
    TEST_ASSERT_EQUAL_INT32(-1, s_caller->record_idx);
    TEST_ASSERT_EQUAL_INT32(-1, s_callee->record_idx);

    ng_call_table_destroy(&call_table, &session_table, nullptr);
    session_table_destroy(&session_table, nullptr);
}

static void test_pcap_cli_args_parsing(void) {
    server_config_t config = {};
    char            a0[]   = "urtp";
    char            a1[]   = "-r";
    char            a2[]   = "/var/recordings/volume";
    char            a3[]   = "-R";
    char           *argv[] = {a0, a1, a2, a3, nullptr};
    int const       argc   = 4;

    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config, argc, argv));
    TEST_ASSERT_EQUAL_STRING("/var/recordings/volume", config.record_dir);
    TEST_ASSERT_TRUE(config.record_all);

    // Long options test
    server_config_t config2 = {};
    char            b0[]    = "urtp";
    char            b1[]    = "--record-dir";
    char            b2[]    = "/mnt/pcap_vol";
    char            b3[]    = "--record-all";
    char           *argv2[] = {b0, b1, b2, b3, nullptr};
    int const       argc2   = 4;

    TEST_ASSERT_EQUAL_INT(SERVER_CONFIG_OK, server_config_parse(&config2, argc2, argv2));
    TEST_ASSERT_EQUAL_STRING("/mnt/pcap_vol", config2.record_dir);
    TEST_ASSERT_TRUE(config2.record_all);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_pcap_struct_sizes_and_constants);
    RUN_TEST(test_pcap_table_init_and_dir_config);
    RUN_TEST(test_pcap_file_write_and_verification);
    RUN_TEST(test_pcap_zero_copy_scatter_gather);
    RUN_TEST(test_pcap_control_protocol_commands);
    RUN_TEST(test_pcap_ng_protocol_commands);
    RUN_TEST(test_pcap_cli_args_parsing);
    return UNITY_END();
}
