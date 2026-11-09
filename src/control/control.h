#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "control/ng.h"
#include "net/session.h"
#include "ring/ring.h"

/**
 * @file control.h
 * @brief Control server engine supporting UNIX domain, TCP, and UDP NG (Kamailio) interfaces.
 */

/** @brief Maximum concurrent connected control clients (UNIX / TCP). */
constexpr size_t MAX_CONTROL_CLIENTS = 16;
/** @brief Size in bytes of control receive and transmit buffers. */
constexpr size_t CONTROL_BUFFER_SIZE = 8192;

/**
 * @brief Connected stream control client context (UNIX socket or TCP).
 */
typedef struct {
    alignas(64) int client_fd;               /**< Connected client stream socket file descriptor. */
    bool     active;                         /**< True if client slot is active. */
    uint32_t buf_len;                        /**< Current valid bytes stored in rx_buffer. */
    char     rx_buffer[CONTROL_BUFFER_SIZE]; /**< Receive buffer for stream command framing. */
    char     tx_buffer[CONTROL_BUFFER_SIZE]; /**< Transmit buffer for response output. */
    uint32_t tx_len;                         /**< Length of queued response in tx_buffer. */
} control_client_t;

/**
 * @brief Multi-transport control server state container.
 */
typedef struct {
    alignas(64) int listen_fd; /**< Stream listener socket file descriptor (UNIX or TCP). */
    int  udp_fd;               /**< Datagram socket file descriptor for UDP NG protocol. */
    bool is_unix;              /**< True if listener is a UNIX domain socket. */
    bool has_udp;              /**< True if UDP NG interface is initialized. */
    bool draining;             /**< True if listener is in graceful draining shutdown mode. */
    char unix_path[108];       /**< Filesystem path to UNIX domain socket. */

    uint16_t         tcp_port;                     /**< Configured TCP listening port. */
    uint16_t         udp_port;                     /**< Configured UDP NG listening port. */
    char             media_ip[INET6_ADDRSTRLEN];   /**< Advertised media IP for SDP rewrites. */
    control_client_t clients[MAX_CONTROL_CLIENTS]; /**< Array of stream client connection slots. */
    ng_call_table_t  call_table;                   /**< Call table storing NG protocol sessions. */

    // UDP NG control server state
    struct sockaddr_storage
                  udp_peer_addr; /**< Address of remote peer that sent latest UDP request. */
    socklen_t     udp_peer_len;  /**< Length of udp_peer_addr. */
    struct msghdr udp_rx_msghdr; /**< Pre-allocated msghdr for UDP receive. */
    struct iovec  udp_rx_iov;    /**< Pre-allocated iovec for UDP receive. */
    char          udp_rx_buffer[CONTROL_BUFFER_SIZE]; /**< Receive buffer for UDP NG datagrams. */
    struct msghdr udp_tx_msghdr; /**< Pre-allocated msghdr for UDP response transmission. */
    struct iovec  udp_tx_iov;    /**< Pre-allocated iovec for UDP response transmission. */
    char          udp_tx_buffer[CONTROL_BUFFER_SIZE]; /**< Transmit buffer for UDP NG responses. */
    uint32_t      udp_tx_len; /**< Length of queued response in udp_tx_buffer. */
} control_server_t;

/**
 * @brief Parses and executes a single control command string or NG protocol message.
 *
 * Supports commands such as:
 * - ALLOCATE PORT 10000 -> FORWARD TO 1.2.3.4:20000
 * - ALLOCATE 10000 1.2.3.4 20000
 * - DELETE 10000
 * - STATUS
 * - PING
 * - Bencode NG protocol commands ('ping', 'offer', 'answer', 'delete', 'query', 'list')
 *
 * @param cmd_str Command string (null-terminated).
 * @param table Pointer to session table.
 * @param engine Pointer to ring engine.
 * @param resp_buf Output buffer to store response.
 * @param resp_max Capacity of output buffer.
 * @return true if command parsed and executed, false on syntax/execution error.
 */
bool control_process_command(
    char const *const cmd_str,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max);

/**
 * @brief Extended control command processor that provides access to NG call state.
 *
 * @param cmd_str Command string or NG protocol payload.
 * @param cmd_len Length of payload in bytes.
 * @param table Pointer to session table.
 * @param call_table Pointer to NG call table (can be nullptr to use fallback).
 * @param engine Pointer to ring engine.
 * @param resp_buf Output buffer.
 * @param resp_max Capacity of output buffer.
 * @return true on success, false on error.
 */
bool control_process_command_ex(
    char const *const cmd_str,
    size_t const      cmd_len,
    session_table_t *restrict const table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max);

/**
 * @brief Sets the media IP advertised in rewritten SDPs.
 *
 * @param server Pointer to control server state.
 * @param media_ip Advertised IP address string.
 */
void control_server_set_media_ip(
    control_server_t *restrict const server,
    char const *const media_ip);

/**
 * @brief Initializes a UNIX domain control socket and arms accept on the ring.
 *
 * @param server Pointer to control server state.
 * @param socket_path File path for UNIX domain socket.
 * @param engine Pointer to ring engine.
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool control_server_init_unix(
    control_server_t *restrict const server,
    char const *const socket_path,
    ring_engine_t *restrict const engine);

/**
 * @brief Initializes a TCP control socket and arms accept on the ring.
 *
 * @param server Pointer to control server state.
 * @param ip Bind IP address string (e.g. "127.0.0.1"), or nullptr for ANY.
 * @param port TCP port.
 * @param engine Pointer to ring engine.
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool control_server_init_tcp(
    control_server_t *restrict const server,
    char const *const ip,
    uint16_t const    port,
    ring_engine_t *restrict const engine);

/**
 * @brief Initializes a UDP NG control socket (standard Kamailio rtpengine interface) and arms recv
 * on ring.
 *
 * @param server Pointer to control server state.
 * @param ip Bind IP address string (e.g. "127.0.0.1" or "0.0.0.0").
 * @param port UDP port (e.g. 22222).
 * @param engine Pointer to ring engine.
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool control_server_init_udp(
    control_server_t *restrict const server,
    char const *const ip,
    uint16_t const    port,
    ring_engine_t *restrict const engine);

/**
 * @brief Shuts down the control server, closes sockets and unlinks UNIX path if applicable.
 *
 * @param server Pointer to control server state.
 * @param session_table Pointer to session table (can be nullptr).
 * @param engine Pointer to ring engine.
 */
void control_server_destroy(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine);

/**
 * @brief Stops accepting new control connections, closing listen_fd and unlinking UNIX socket path.
 *
 * @param server Pointer to control server state.
 * @param engine Pointer to ring engine.
 */
void control_server_stop_listen(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine);

/**
 * @brief Handles a completion queue entry for a new client connection accept.
 *
 * @param server Pointer to control server state.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 */
void control_server_handle_accept_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe);

/**
 * @brief Handles a completion queue entry for client stream data reception.
 *
 * @param server Pointer to control server state.
 * @param table Pointer to media session table.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 * @param client_idx Index of client in clients array.
 */
void control_server_handle_rx_cqe(
    control_server_t *restrict const server,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   client_idx);

/**
 * @brief Handles a completion queue entry for client response send completion.
 *
 * @param server Pointer to control server state.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 * @param client_idx Index of client in clients array.
 */
void control_server_handle_tx_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   client_idx);

/**
 * @brief Handles a completion queue entry for UDP NG control datagram reception.
 *
 * @param server Pointer to control server state.
 * @param table Pointer to media session table.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 */
void control_server_handle_udp_rx_cqe(
    control_server_t *restrict const server,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe);

/**
 * @brief Handles a completion queue entry for UDP NG control datagram send completion.
 *
 * @param server Pointer to control server state.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 */
void control_server_handle_udp_tx_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe);
