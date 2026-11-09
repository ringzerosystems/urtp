#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

/**
 * @file watchdog.h
 * @brief Zero-dependency systemd watchdog notification and event loop keepalive.
 */

/** @brief Default reactor stall threshold in milliseconds before triggering warnings. */
constexpr uint64_t DEFAULT_STALL_THRESHOLD_MS = 100;

/**
 * @brief Systemd watchdog notification state and socket configuration.
 */
typedef struct {
    alignas(64) int notify_fd; /**< UNIX datagram socket connected to supervisor NOTIFY_SOCKET. */
    struct sockaddr_un notify_addr;     /**< Destination address parsed from NOTIFY_SOCKET. */
    socklen_t          notify_addr_len; /**< Length of sockaddr_un address. */
    uint64_t watchdog_interval_sec; /**< Half the supervisor WATCHDOG_USEC timeout in seconds. */
    uint64_t last_ping_sec;         /**< Monotonic timestamp of last WATCHDOG=1 ping sent. */
    bool     enabled; /**< True if watchdog is active and configured in environment. */
} systemd_watchdog_t;

/**
 * @brief Initializes zero-dependency systemd watchdog from NOTIFY_SOCKET and WATCHDOG_USEC.
 *
 * @param watchdog Pointer to systemd watchdog instance.
 * @return true if watchdog was detected and enabled, false if inactive or error.
 */
[[nodiscard]] bool watchdog_init(systemd_watchdog_t *restrict const watchdog);

/**
 * @brief Closes notification socket and resets watchdog instance.
 *
 * @param watchdog Pointer to watchdog instance.
 */
void watchdog_destroy(systemd_watchdog_t *restrict const watchdog);

/**
 * @brief Sends READY=1 notification to supervisor if enabled.
 *
 * @param watchdog Pointer to watchdog instance.
 */
void watchdog_notify_ready(systemd_watchdog_t *restrict const watchdog);

/**
 * @brief Sends STOPPING=1 notification to supervisor if enabled.
 *
 * @param watchdog Pointer to watchdog instance.
 */
void watchdog_notify_stopping(systemd_watchdog_t *restrict const watchdog);

/**
 * @brief Emits periodic WATCHDOG=1 keepalive ping to supervisor when interval elapsed.
 *
 * @param watchdog Pointer to watchdog instance.
 * @param now_sec Current monotonic timestamp in seconds.
 */
void watchdog_ping(systemd_watchdog_t *restrict const watchdog, uint64_t const now_sec);
