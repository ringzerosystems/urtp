#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "control/control.h"
#include "net/session.h"
#include "ring/ring.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_command_parsing(void) {
    session_table_t table = {};
    session_table_init(&table);

    char resp[CONTROL_BUFFER_SIZE] = {};

    // PING
    TEST_ASSERT_TRUE(control_process_command("PING\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("PONG\n", resp);

    // QUIT
    TEST_ASSERT_TRUE(control_process_command("QUIT\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("BYE\n", resp);

    // ALLOCATE
    TEST_ASSERT_TRUE(control_process_command(
        "ALLOCATE PORT 36000 -> FORWARD TO 127.0.0.1:36001\r\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK ALLOCATED PORT 36000 FORWARD TO 127.0.0.1:36001\n", resp);
    TEST_ASSERT_EQUAL_size_t(1, table.active_count);

    // STATUS
    TEST_ASSERT_TRUE(control_process_command("STATUS\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK SESSIONS active=1"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "port=36000"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "latch=none"));

    // ALLOCATE with LATCH (standalone)
    TEST_ASSERT_TRUE(control_process_command(
        "ALLOCATE PORT 37000 LATCH\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK ALLOCATED PORT 37000 LATCH WAITING\n", resp);

    // ALLOCATE with LATCH and private SDP dest
    TEST_ASSERT_TRUE(control_process_command(
        "ALLOCATE PORT 37002 -> FORWARD TO 192.168.1.50:5000 LATCH\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING(
        "OK ALLOCATED PORT 37002 LATCH WAITING (FORWARD TO 192.168.1.50:5000)\n",
        resp);

    // BRIDGE
    TEST_ASSERT_TRUE(control_process_command(
        "BRIDGE PORT 37000 <-> PORT 37002\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK BRIDGED PORT 37000 <-> PORT 37002\n", resp);

    // Explicit LATCH command
    TEST_ASSERT_TRUE(
        control_process_command("LATCH PORT 36000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK LATCH ENABLED PORT 36000\n", resp);

    // STATUS shows latching and peer
    TEST_ASSERT_TRUE(control_process_command("STATUS\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "port=37000"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "latch=waiting"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "peer=37002"));

    // Clean up allocated test ports
    TEST_ASSERT_TRUE(
        control_process_command("DELETE 37000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_TRUE(
        control_process_command("DELETE 37002\n", &table, nullptr, resp, sizeof(resp)));

    // DELETE
    TEST_ASSERT_TRUE(
        control_process_command("DELETE 36000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("OK DELETED PORT 36000\n", resp);
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);

    // DELETE nonexistent
    TEST_ASSERT_FALSE(
        control_process_command("DELETE 36000\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("ERROR PORT_NOT_FOUND\n", resp);

    // UNKNOWN
    TEST_ASSERT_FALSE(control_process_command("FOOBAR\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_EQUAL_STRING("ERROR UNKNOWN_COMMAND\n", resp);

    session_table_destroy(&table, nullptr);
}

static void test_control_server_unix_socket(void) {
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));

    session_table_t table = {};
    session_table_init(&table);

    control_server_t  server    = {};
    char const *const sock_path = "/tmp/test_urtp_control.sock";
    TEST_ASSERT_TRUE(control_server_init_unix(&server, sock_path, &engine));
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Client connects
    int const client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_ASSERT_TRUE(client_fd >= 0);

    struct sockaddr_un un = {};
    un.sun_family         = AF_UNIX;
    strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);

    TEST_ASSERT_EQUAL_INT(0, connect(client_fd, (struct sockaddr const *)&un, sizeof(un)));

    // Process accept CQE on ring
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    struct io_uring_cqe *cqes[8] = {};
    unsigned int         count   = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        if (tag.fields.op_type == OP_TYPE_CONTROL_ACCEPT) {
            control_server_handle_accept_cqe(&server, &engine, cqe);
        }
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit the newly armed rx_sqe for accepted client
    TEST_ASSERT_TRUE(ring_engine_submit(&engine) >= 0);

    // Send command from client
    char const cmd[] = "PING\n";
    TEST_ASSERT_EQUAL_INT((int)strlen(cmd), (int)write(client_fd, cmd, strlen(cmd)));

    // Process rx CQE
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    TEST_ASSERT_TRUE(count >= 1);

    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        if (tag.fields.op_type == OP_TYPE_CONTROL_RECV) {
            control_server_handle_rx_cqe(&server, &table, &engine, cqe, tag.fields.index);
        }
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Submit the tx_sqe response
    TEST_ASSERT_TRUE(ring_engine_submit_and_wait(&engine, 1) >= 0);
    count = io_uring_peek_batch_cqe(&(engine.ring), cqes, 8);
    for (unsigned int i = 0; i < count; ++i) {
        struct io_uring_cqe const *const cqe = cqes[i];
        user_data_tag_t const            tag = {.raw = cqe->user_data};
        if (tag.fields.op_type == OP_TYPE_CONTROL_SEND) {
            control_server_handle_tx_cqe(&server, &engine, cqe, tag.fields.index);
        }
    }
    io_uring_cq_advance(&(engine.ring), count);

    // Read response on client
    char          resp_buf[64] = {};
    ssize_t const n_read       = read(client_fd, resp_buf, sizeof(resp_buf) - 1);
    TEST_ASSERT_TRUE(n_read > 0);
    TEST_ASSERT_EQUAL_STRING("PONG\n", resp_buf);

    close(client_fd);
    control_server_destroy(&server, &engine);
    session_table_destroy(&table, &engine);
    ring_engine_destroy(&engine);
}

static void test_control_draining_mode(void) {
    session_table_t table = {};
    session_table_init(&table);

    ng_call_table_t call_table = {};
    ng_call_table_init(&call_table, "127.0.0.1");

    char resp[256] = {};

    // In normal mode: ALLOCATE succeeds
    TEST_ASSERT_TRUE(control_process_command_ex(
        "ALLOCATE 39000 127.0.0.1 5000\n",
        30,
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_size_t(1, table.active_count);

    // Set draining mode
    call_table.draining = true;

    // ALLOCATE should fail with error server is draining
    TEST_ASSERT_FALSE(control_process_command_ex(
        "ALLOCATE 39002 127.0.0.1 5002\n",
        30,
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "ERROR server is draining"));
    TEST_ASSERT_EQUAL_size_t(1, table.active_count);

    // STATUS should still work
    TEST_ASSERT_TRUE(control_process_command_ex(
        "STATUS\n",
        7,
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "OK SESSIONS active=1"));

    // DELETE should still work
    TEST_ASSERT_TRUE(control_process_command_ex(
        "DELETE 39000\n",
        13,
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);

    // NG offer should return error response in draining mode
    char const *const ng_offer = "d7:command5:offer7:call-id4:c123e";
    TEST_ASSERT_TRUE(control_process_command_ex(
        ng_offer,
        __builtin_strlen(ng_offer),
        &table,
        &call_table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "Server is draining"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "result5:error"));
    TEST_ASSERT_EQUAL_size_t(0, table.active_count);

    // Test control_server_stop_listen
    ring_engine_t engine = {};
    TEST_ASSERT_TRUE(ring_engine_init(&engine, 64, 64, 2048, 1, false));
    control_server_t  server    = {};
    char const *const sock_path = "/tmp/test_urtp_drain.sock";
    TEST_ASSERT_TRUE(control_server_init_unix(&server, sock_path, &engine));
    TEST_ASSERT_TRUE(server.listen_fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, access(sock_path, F_OK));

    control_server_stop_listen(&server, &engine);
    TEST_ASSERT_TRUE(server.draining);
    TEST_ASSERT_TRUE(server.call_table.draining);
    TEST_ASSERT_EQUAL_INT(-1, server.listen_fd);
    TEST_ASSERT_EQUAL_INT(-1, access(sock_path, F_OK));

    control_server_destroy(&server, &engine);
    ring_engine_destroy(&engine);
    session_table_destroy(&table, nullptr);
}

static void test_control_http_metrics(void) {
    session_table_t  table   = {};
    server_metrics_t metrics = {};
    session_table_init(&table);
    metrics_init(&metrics);
    table.metrics = &metrics;

    metrics.cumulative.rx_packets = 500;
    metrics.cumulative.tx_packets = 450;
    metrics_rollup(&metrics, 1);

    char resp[CONTROL_BUFFER_SIZE] = {};

    // Standard Prometheus scrape HTTP GET
    TEST_ASSERT_TRUE(control_process_command(
        "GET /metrics HTTP/1.1\r\nHost: urtp:22222\r\nUser-Agent: Prometheus/2.54.0\r\n\r\n",
        &table,
        nullptr,
        resp,
        sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "HTTP/1.1 200 OK"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "Content-Type: text/plain; version=0.0.4; charset=utf-8"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "urtp_rx_packets_total 500"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "urtp_tx_packets_total 450"));

    // Root GET /
    __builtin_memset(resp, 0, sizeof(resp));
    TEST_ASSERT_TRUE(
        control_process_command("GET / HTTP/1.1\r\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "HTTP/1.1 200 OK"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "urtp_rx_packets_total 500"));

    // Health check endpoint
    __builtin_memset(resp, 0, sizeof(resp));
    TEST_ASSERT_TRUE(
        control_process_command("GET /health HTTP/1.1\r\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "HTTP/1.1 200 OK"));
    TEST_ASSERT_NOT_NULL(strstr(resp, "\r\n\r\nOK\n"));

    // Unknown HTTP GET endpoint returns 404
    __builtin_memset(resp, 0, sizeof(resp));
    TEST_ASSERT_FALSE(
        control_process_command("GET /invalid HTTP/1.1\r\n", &table, nullptr, resp, sizeof(resp)));
    TEST_ASSERT_NOT_NULL(strstr(resp, "HTTP/1.1 404 Not Found"));

    session_table_destroy(&table, nullptr);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_command_parsing);
    RUN_TEST(test_control_server_unix_socket);
    RUN_TEST(test_control_draining_mode);
    RUN_TEST(test_control_http_metrics);
    return UNITY_END();
}
