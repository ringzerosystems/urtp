#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/**
 * @file udp.h
 * @brief Zero-allocation UDP socket management and network endpoint formatting helpers.
 */

/**
 * @brief Parses an IP address string and port into a sockaddr_storage structure.
 *
 * @param ip_str String containing IPv4 or IPv6 address.
 * @param port Network port (host byte order).
 * @param out_addr Pointer to destination sockaddr_storage.
 * @param out_len Pointer to receive the address length.
 * @return true if parsing succeeded, false otherwise.
 */
[[nodiscard]] bool udp_parse_endpoint(
    char const *const ip_str,
    uint16_t const    port,
    struct sockaddr_storage *restrict const out_addr,
    socklen_t *restrict const out_len);

/**
 * @brief Formats a sockaddr_storage structure into a human-readable IP string.
 *
 * @param addr Pointer to source sockaddr_storage.
 * @param buf Output buffer for IP string.
 * @param buf_size Size of output buffer.
 * @param out_port Pointer to receive port in host byte order (optional, can be nullptr).
 * @return true if formatted successfully, false otherwise.
 */
[[nodiscard]] bool udp_format_endpoint(
    struct sockaddr_storage const *restrict const addr,
    char *restrict const buf,
    size_t const buf_size,
    uint16_t *restrict const out_port);

/**
 * @brief Creates, configures, and binds a non-blocking UDP socket.
 *
 * @param ip IP address string to bind to (e.g., "0.0.0.0" or "127.0.0.1"), or nullptr for ANY.
 * @param port Port to bind to.
 * @return Socket file descriptor on success, or -1 on failure.
 */
[[nodiscard]] int udp_bind_socket(char const *const ip, uint16_t const port);

/**
 * @brief Safely closes a UDP socket.
 *
 * @param fd Socket file descriptor.
 */
void udp_close_socket(int const fd);
