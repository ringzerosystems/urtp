#pragma once

#include <liburing.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include "ring/ring.h"

/**
 * @file timer.h
 * @brief Periodic timerfd event integration with the io_uring reactor loop.
 */

/** @brief Default periodic timer tick interval in seconds. */
constexpr uint32_t TIMER_DEFAULT_INTERVAL_SEC = 1;

/**
 * @brief Periodic timerfd state integrated with io_uring.
 */
typedef struct {
    alignas(64) int timer_fd; /**< Monotonic non-blocking timer file descriptor. */
    uint64_t tick_buf;        /**< 8-byte buffer to receive timer expirations from timerfd. */
    uint32_t interval_sec;    /**< Periodic tick interval in seconds. */
    bool     armed;           /**< True if read operation is currently armed on io_uring. */
    bool     initialized;     /**< True if timerfd has been successfully created. */
} timer_engine_t;

/**
 * @brief Initializes a monotonic non-blocking timerfd with periodic interval.
 *
 * @param timer Pointer to timer engine instance.
 * @param interval_sec Periodic tick interval in seconds (e.g. 1).
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool
timer_engine_init(timer_engine_t *restrict const timer, uint32_t const interval_sec);

/**
 * @brief Closes the timerfd and resets the timer engine.
 *
 * @param timer Pointer to timer engine instance.
 */
void timer_engine_destroy(timer_engine_t *restrict const timer);

/**
 * @brief Submits an io_uring_prep_read on timer_fd with OP_TYPE_TIMER_TICK tag.
 *
 * @param timer Pointer to timer engine instance.
 * @param ring Pointer to ring engine.
 * @return true if SQE successfully prepared, false on exhaustion.
 */
[[nodiscard]] bool
timer_engine_arm(timer_engine_t *restrict const timer, ring_engine_t *restrict const ring);

/**
 * @brief Re-arms the timer on the ring for the next periodic tick.
 *
 * @param timer Pointer to timer engine instance.
 * @param ring Pointer to ring engine.
 * @return true if SQE successfully prepared, false on exhaustion.
 */
[[nodiscard]] bool
timer_engine_rearm(timer_engine_t *restrict const timer, ring_engine_t *restrict const ring);
