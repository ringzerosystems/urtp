#pragma once

#include <liburing.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file ring.h
 * @brief High-performance io_uring reactor engine with provided buffer rings.
 */

/** @brief Default submission queue ring entries (depth). */
constexpr uint32_t RING_DEFAULT_ENTRIES = 2048;
/** @brief Default number of buffer entries in provided buffer ring. */
constexpr uint32_t RING_DEFAULT_BUF_ENTRIES = 8192;
/** @brief Default size in bytes of each buffer entry in provided buffer ring. */
constexpr uint32_t RING_DEFAULT_BUF_SIZE = 2048;
/** @brief Default buffer group ID for io_uring provided buffer ring. */
constexpr int RING_DEFAULT_BGID = 1;

/**
 * @brief io_uring operation types encoded in SQE/CQE user_data tags.
 */
typedef enum : uint16_t {
    OP_TYPE_NONE             = 0, /**< No operation / invalid. */
    OP_TYPE_UDP_RECV         = 1, /**< Multishot UDP datagram receive completion. */
    OP_TYPE_UDP_SEND         = 2, /**< Asynchronous UDP datagram send completion. */
    OP_TYPE_CONTROL_ACCEPT   = 3, /**< Control listener accept connection completion. */
    OP_TYPE_CONTROL_RECV     = 4, /**< Control client stream receive completion. */
    OP_TYPE_CONTROL_SEND     = 5, /**< Control client stream send completion. */
    OP_TYPE_CONTROL_UDP_RECV = 6, /**< Control UDP datagram receive completion. */
    OP_TYPE_CONTROL_UDP_SEND = 7, /**< Control UDP datagram send completion. */
    OP_TYPE_PCAP_WRITE       = 8, /**< Asynchronous PCAP file write completion. */
    OP_TYPE_TIMER_TICK       = 9, /**< Monotonic periodic timer tick completion. */
} op_type_t;

/** @brief Tag flag indicating payload is an RTP media packet. */
constexpr uint16_t TAG_FLAG_PKT_RTP = 1 << 0;
/** @brief Tag flag indicating payload is an RTCP control packet. */
constexpr uint16_t TAG_FLAG_PKT_RTCP = 1 << 1;
/** @brief Tag flag indicating payload belongs to a video stream. */
constexpr uint16_t TAG_FLAG_PKT_VIDEO = 1 << 2;

/**
 * @brief 64-bit user_data tag passed through io_uring SQEs and CQEs.
 */
typedef union {
    struct {
        uint16_t index;   /**< Session or client table slot index. */
        uint16_t op_type; /**< Operation type (op_type_t). */
        uint16_t bid;     /**< Buffer ID for zero-copy buffer recycling. */
        uint16_t flags;   /**< Packet classification flags (TAG_FLAG_*). */
    } fields;             /**< Bitfield representation of tag. */
    uint64_t raw;         /**< Raw 64-bit integer representation. */
} user_data_tag_t;

static_assert(sizeof(user_data_tag_t) == sizeof(uint64_t), "user_data_tag_t must be 64 bits");

/**
 * @brief Pre-allocated msghdr and iovec context for zero-allocation UDP sends.
 */
typedef struct {
    struct msghdr msg; /**< Message header for sendmsg SQEs. */
    struct iovec  iov; /**< I/O vector pointing to packet payload. */
} ring_send_ctx_t;

/**
 * @brief Central io_uring reactor engine state with provided buffer ring.
 */
typedef struct {
    alignas(64) struct io_uring ring;   /**< Kernel io_uring instance. */
    struct io_uring_buf_ring *buf_ring; /**< Kernel-mapped provided buffer ring. */
    uint8_t                  *buffers;  /**< Contiguous memory backing buffer pool. */
    ring_send_ctx_t
            *send_contexts;    /**< Array of pre-allocated send contexts indexed by buffer ID. */
    uint8_t *buf_refcounts;    /**< Reference count array per buffer ID for zero-copy fans. */
    uint32_t ring_entries;     /**< Submission queue depth. */
    uint32_t buf_ring_entries; /**< Capacity of provided buffer ring. */
    uint32_t buf_size;         /**< Size in bytes of each buffer slot. */
    uint16_t buf_mask;         /**< Mask for circular buffer ring indexing. */
    int      buf_group_id;     /**< Provided buffer group ID. */
    bool     initialized;      /**< Initialization flag. */
} ring_engine_t;

/**
 * @brief Initializes an io_uring reactor engine with provided buffer ring.
 *
 * @param engine Pointer to the ring engine instance to initialize.
 * @param entries Submission queue depth (power of two).
 * @param buf_entries Provided buffer ring capacity (power of two).
 * @param buf_size Size in bytes of each buffer slot.
 * @param bgid Buffer group identifier.
 * @param try_sqpoll Attempt kernel SQPOLL thread if permitted.
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool ring_engine_init(
    ring_engine_t *restrict const engine,
    uint32_t const entries,
    uint32_t const buf_entries,
    uint32_t const buf_size,
    int const      bgid,
    bool const     try_sqpoll);

/**
 * @brief Destroys the io_uring reactor engine and releases all allocated memory.
 *
 * @param engine Pointer to the ring engine to tear down.
 */
void ring_engine_destroy(ring_engine_t *restrict const engine);

/**
 * @brief Obtains a submission queue entry (SQE) from the ring, flushing if full.
 *
 * @param engine Pointer to the ring engine.
 * @return Pointer to available SQE, or nullptr on fatal exhaustion.
 */
[[nodiscard]] struct io_uring_sqe *ring_engine_get_sqe(ring_engine_t *restrict const engine);

/**
 * @brief Recycles a buffer ID back into the provided buffer ring for kernel reception.
 *
 * @param engine Pointer to the ring engine.
 * @param bid The buffer ID to recycle.
 */
void ring_engine_recycle_buf(ring_engine_t *restrict const engine, uint16_t const bid);

/**
 * @brief Increments the reference count of a provided buffer ID.
 *
 * @param engine Pointer to the ring engine.
 * @param bid The buffer ID to retain.
 */
void ring_engine_buf_retain(ring_engine_t *restrict const engine, uint16_t const bid);

/**
 * @brief Decrements the reference count of a provided buffer ID, recycling back to the ring when
 * reaching zero.
 *
 * @param engine Pointer to the ring engine.
 * @param bid The buffer ID to release.
 */
void ring_engine_buf_release(ring_engine_t *restrict const engine, uint16_t const bid);

/**
 * @brief Retrieves the memory pointer for a provided buffer ID.
 *
 * @param engine Pointer to the ring engine.
 * @param bid The buffer ID to look up.
 * @return Pointer to the buffer memory, or nullptr if out of range.
 */
[[nodiscard]] static inline uint8_t *
ring_engine_get_buf(ring_engine_t const *restrict const engine, uint16_t const bid) {
    if ((engine == nullptr) || (bid >= engine->buf_ring_entries)) {
        return nullptr;
    }
    return &(engine->buffers[(size_t)bid * (size_t)engine->buf_size]);
}

/**
 * @brief Retrieves the pre-allocated send context for a provided buffer ID.
 *
 * @param engine Pointer to the ring engine.
 * @param bid The buffer ID.
 * @return Pointer to send context, or nullptr if out of range.
 */
[[nodiscard]] static inline ring_send_ctx_t *
ring_engine_get_send_ctx(ring_engine_t const *restrict const engine, uint16_t const bid) {
    if ((engine == nullptr) || (bid >= engine->buf_ring_entries)) {
        return nullptr;
    }
    return &(engine->send_contexts[bid]);
}

/**
 * @brief Submits queued SQEs to the kernel.
 *
 * @param engine Pointer to the ring engine.
 * @return Number of submitted SQEs or negative errno.
 */
int ring_engine_submit(ring_engine_t *restrict const engine);

/**
 * @brief Submits queued SQEs and blocks until at least wait_nr completions are available.
 *
 * @param engine Pointer to the ring engine.
 * @param wait_nr Minimum number of CQEs to wait for.
 * @return Number of submitted SQEs or negative errno.
 */
int ring_engine_submit_and_wait(ring_engine_t *restrict const engine, uint32_t const wait_nr);

/**
 * @brief Submits queued SQEs and blocks until at least wait_nr completions are available or timeout
 * expires.
 *
 * @param engine Pointer to the ring engine.
 * @param wait_nr Minimum number of CQEs to wait for.
 * @param ts Pointer to kernel timespec structure specifying timeout.
 * @return Number of submitted SQEs, -ETIME on timeout, or negative errno on error.
 */
int ring_engine_submit_and_wait_timeout(
    ring_engine_t *restrict const engine,
    uint32_t const wait_nr,
    struct __kernel_timespec *restrict const ts);
