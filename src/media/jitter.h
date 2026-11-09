#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/macros.h"

/**
 * @file jitter.h
 * @brief Fixed-size zero-allocation circular jitter buffer and RFC 3550 interarrival jitter
 * estimation.
 */

/** @brief Maximum slots in circular jitter buffer ring (power of two). */
constexpr size_t JITTER_BUFFER_MAX_SLOTS = 16; // Power of two for fast bitmask modulo
/** @brief Maximum buffer capacity per slot in bytes to hold an MTU-sized RTP packet. */
constexpr size_t JITTER_SLOT_MAX_SIZE = 1600; // Fits maximum RTP packet / MTU
/** @brief Default target playout delay in milliseconds (40ms, 2 frames). */
constexpr uint32_t JITTER_DEFAULT_DELAY_MS = 40; // 2 frames at 20ms
/** @brief Minimum allowed target playout delay in milliseconds. */
constexpr uint32_t JITTER_MIN_DELAY_MS = 10;
/** @brief Maximum allowed target playout delay in milliseconds. */
constexpr uint32_t JITTER_MAX_DELAY_MS = 200;
/** @brief Default target packet depth before releasing playout. */
constexpr uint16_t JITTER_DEFAULT_TARGET_DEPTH = 2;
/** @brief Maximum packet drift before triggering Packet Loss Concealment (PLC). */
constexpr uint16_t JITTER_DEFAULT_MAX_DEPTH = 4;

/**
 * @brief Storage slot holding an RTP packet within the circular jitter buffer.
 */
typedef struct {
    uint8_t  payload[JITTER_SLOT_MAX_SIZE]; /**< Raw RTP packet data buffer. */
    uint16_t length;                        /**< Length in bytes of stored RTP packet. */
    uint16_t seq;                           /**< Extracted RTP sequence number. */
    uint32_t timestamp;                     /**< Extracted RTP timestamp. */
    uint64_t arrival_ns;                    /**< Monotonic arrival timestamp in nanoseconds. */
    bool     occupied;                      /**< True if slot contains a valid unplayed packet. */
} jitter_slot_t;

/**
 * @brief Adaptive fixed-depth circular jitter buffer state.
 */
typedef struct jitter_buffer_s {
    alignas(64) jitter_slot_t slots[JITTER_BUFFER_MAX_SLOTS]; /**< Fixed array of packet slots. */
    uint16_t next_playout_seq; /**< Next expected in-order sequence number to play. */
    uint16_t highest_rx_seq;   /**< Highest sequence number received so far. */
    uint16_t target_depth;     /**< Target packet count to pre-buffer before playout. */
    uint16_t max_depth;        /**< Maximum sequence drift before declaring loss (PLC). */
    uint16_t occupancy;        /**< Current count of occupied slots. */
    uint16_t plc_until_seq;    /**< Sequence boundary to catch up to during burst loss PLC. */
    uint32_t target_delay_ms;  /**< Configured target playout delay in ms. */
    bool     seq_initialized;  /**< True once initial sequence number is anchored. */
    bool     buffering;        /**< True during initial pre-buffering phase. */
    bool     enabled;          /**< True if jitter buffering is enabled. */

    // Stream telemetry and RFC 3550 interarrival jitter estimation
    uint32_t transit_jitter;       /**< RFC 3550 interarrival jitter estimate in timestamp units. */
    uint32_t last_transit_ts;      /**< Timestamp of previous packet for jitter calculation. */
    uint64_t last_arrival_ns;      /**< Monotonic arrival timestamp of previous packet. */
    uint64_t packets_inserted;     /**< Total packets successfully inserted into buffer. */
    uint64_t packets_played;       /**< Total packets popped and played out. */
    uint64_t packets_dropped_late; /**< Packets arriving past playout deadline. */
    uint64_t packets_dropped_dup;  /**< Duplicate sequence number packets dropped. */
    uint64_t packets_dropped_overflow; /**< Packets dropped because target slot was occupied. */
    uint64_t packets_reordered;        /**< Out-of-order packets successfully reordered. */
    uint64_t loss_concealments;        /**< Count of PLC concealment triggers executed. */
} jitter_buffer_t;

/**
 * @brief Result status returned by jitter_buffer_pop.
 */
typedef enum : uint8_t {
    JB_POP_EMPTY = 0, /**< No packet ready / still buffering / waiting for packet. */
    JB_POP_OK    = 1, /**< Valid in-order packet popped into output buffer. */
    JB_POP_PLC =
        2, /**< Packet missing and exceeded max depth; synthetic concealment frame needed. */
} jitter_pop_status_t;

/**
 * @brief Computes the signed RFC 3550 sequence difference (s1 - s2).
 *
 * Handles 16-bit unsigned integer wrap-around cleanly.
 *
 * @param s1 First sequence number.
 * @param s2 Second sequence number.
 * @return Positive if s1 > s2, negative if s1 < s2, zero if equal.
 */
[[nodiscard]] static inline int16_t jitter_seq_diff(uint16_t const s1, uint16_t const s2) {
    return (int16_t)(s1 - s2);
}

/**
 * @brief Initializes a jitter buffer instance with the specified target delay.
 *
 * @param jb Pointer to jitter buffer struct.
 * @param target_delay_ms Target playout delay in milliseconds (e.g. 40).
 */
void jitter_buffer_init(jitter_buffer_t *restrict const jb, uint32_t const target_delay_ms);

/**
 * @brief Resets slot states and sequence numbers without altering configuration.
 *
 * @param jb Pointer to jitter buffer struct.
 */
void jitter_buffer_reset(jitter_buffer_t *restrict const jb);

/**
 * @brief Inserts an incoming raw RTP packet into the jitter buffer.
 *
 * Validates the packet header, performs out-of-order slot placement, drops duplicates
 * or excessively late arrivals, and updates RFC 3550 interarrival jitter metrics.
 *
 * @param jb Pointer to active jitter buffer struct.
 * @param packet_data Pointer to raw RTP packet buffer.
 * @param packet_len Length in bytes of the RTP packet.
 * @param now_ns Monotonic arrival timestamp in nanoseconds.
 * @return true if packet was successfully stored, false if dropped (late/dup/overflow/invalid).
 */
[[nodiscard]] bool jitter_buffer_insert(
    jitter_buffer_t *restrict const jb,
    void const *restrict const packet_data,
    size_t const   packet_len,
    uint64_t const now_ns);

/**
 * @brief Attempts to pop the next in-order packet or triggers loss concealment.
 *
 * @param jb Pointer to active jitter buffer struct.
 * @param out_buf Buffer to receive the popped RTP packet.
 * @param out_cap Maximum capacity in bytes of out_buf.
 * @param out_len Pointer to receive resulting byte count of popped packet.
 * @param out_seq Pointer to receive sequence number of popped or missing packet.
 * @param out_ts Pointer to receive RTP timestamp of popped packet.
 * @return JB_POP_OK if packet was copied out, JB_POP_PLC if a gap triggered concealment,
 *         or JB_POP_EMPTY if waiting for packets or still buffering.
 */
[[nodiscard]] jitter_pop_status_t jitter_buffer_pop(
    jitter_buffer_t *restrict const jb,
    void *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len,
    uint16_t *restrict const out_seq,
    uint32_t *restrict const out_ts);

/**
 * @brief Flushes all currently buffered packets, resetting occupancy to zero.
 *
 * @param jb Pointer to jitter buffer struct.
 * @return Number of packets discarded during flush.
 */
size_t jitter_buffer_flush(jitter_buffer_t *restrict const jb);

/** @brief Maximum concurrent jitter buffers in the fixed pool. */
constexpr size_t JITTER_POOL_CAPACITY = 64;

/**
 * @brief Fixed-size cacheline-aligned pool allocator for jitter buffer instances.
 */
typedef struct jitter_pool_s {
    alignas(64) jitter_buffer_t buffers[JITTER_POOL_CAPACITY];
    uint8_t  free_indices[JITTER_POOL_CAPACITY];
    uint32_t top;
} jitter_pool_t;

/**
 * @brief Allocates and initializes a fixed jitter buffer pool.
 *
 * @return Pointer to newly allocated jitter_pool_t, or nullptr on failure.
 */
[[nodiscard]] jitter_pool_t *jitter_pool_create(void);

/**
 * @brief Destroys a jitter buffer pool and frees backing memory.
 *
 * @param pool Pointer to pool to destroy.
 */
void jitter_pool_destroy(jitter_pool_t *restrict const pool);

/**
 * @brief Pops an unused jitter buffer from the pool.
 *
 * @param pool Pointer to jitter buffer pool.
 * @return Pointer to free jitter_buffer_t, or nullptr if pool exhausted.
 */
[[nodiscard]] jitter_buffer_t *jitter_pool_pop(jitter_pool_t *restrict const pool);

/**
 * @brief Recycles a jitter buffer back into the pool.
 *
 * @param pool Pointer to jitter buffer pool.
 * @param jb Pointer to jitter buffer being returned.
 */
void jitter_pool_push(jitter_pool_t *restrict const pool, jitter_buffer_t *restrict const jb);
