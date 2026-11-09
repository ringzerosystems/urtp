#include "ring/ring.h"
#include <errno.h>
#include <stdlib.h>
#include "core/macros.h"

bool ring_engine_init(
    ring_engine_t *restrict const engine,
    uint32_t const entries,
    uint32_t const buf_entries,
    uint32_t const buf_size,
    int const      bgid,
    bool const     try_sqpoll) {
    if (unlikely((engine == nullptr) || (entries == 0) || (buf_entries == 0) || (buf_size == 0))) {
        return false;
    }

    *engine = (ring_engine_t){};

    struct io_uring_params params = {};
    if (try_sqpoll) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;
    }

    auto ret = io_uring_queue_init_params(entries, &(engine->ring), &params);
    if ((ret < 0) && try_sqpoll) {
        // Fallback without SQPOLL if unprivileged or unsupported
        params = (struct io_uring_params){};
        ret    = io_uring_queue_init_params(entries, &(engine->ring), &params);
    }

    if (unlikely(ret < 0)) {
        return false;
    }

    int err          = 0;
    engine->buf_ring = io_uring_setup_buf_ring(&(engine->ring), buf_entries, bgid, 0, &err);
    if (unlikely(engine->buf_ring == nullptr)) {
        io_uring_queue_exit(&(engine->ring));
        return false;
    }

    size_t const total_buf_bytes = (size_t)buf_entries * (size_t)buf_size;
    void        *raw_bufs        = nullptr;
    if (unlikely(posix_memalign(&raw_bufs, 64, total_buf_bytes) != 0)) {
        io_uring_free_buf_ring(&(engine->ring), engine->buf_ring, buf_entries, bgid);
        io_uring_queue_exit(&(engine->ring));
        return false;
    }

    size_t const total_sctx_bytes = (size_t)buf_entries * sizeof(ring_send_ctx_t);
    void        *raw_sctx         = nullptr;
    if (unlikely(posix_memalign(&raw_sctx, 64, total_sctx_bytes) != 0)) {
        free(raw_bufs);
        io_uring_free_buf_ring(&(engine->ring), engine->buf_ring, buf_entries, bgid);
        io_uring_queue_exit(&(engine->ring));
        return false;
    }

    uint8_t *const refcounts = (uint8_t *)calloc(buf_entries, sizeof(uint8_t));
    if (unlikely(refcounts == nullptr)) {
        free(raw_sctx);
        free(raw_bufs);
        io_uring_free_buf_ring(&(engine->ring), engine->buf_ring, buf_entries, bgid);
        io_uring_queue_exit(&(engine->ring));
        return false;
    }

    engine->buffers       = (uint8_t *)raw_bufs;
    engine->send_contexts = (ring_send_ctx_t *)raw_sctx;
    engine->buf_refcounts = refcounts;
    __builtin_memset(engine->send_contexts, 0, total_sctx_bytes);

    auto const mask  = (uint16_t)io_uring_buf_ring_mask(buf_entries);
    engine->buf_mask = mask;

    for (uint32_t i = 0; i < buf_entries; ++i) {
        uint8_t *const addr = &(engine->buffers[(size_t)i * (size_t)buf_size]);
        io_uring_buf_ring_add(engine->buf_ring, addr, buf_size, (uint16_t)i, (int)mask, (int)i);
    }
    io_uring_buf_ring_advance(engine->buf_ring, (int)buf_entries);

    engine->ring_entries     = entries;
    engine->buf_ring_entries = buf_entries;
    engine->buf_size         = buf_size;
    engine->buf_group_id     = bgid;
    engine->initialized      = true;

    return true;
}

void ring_engine_destroy(ring_engine_t *restrict const engine) {
    if (unlikely((engine == nullptr) || !(engine->initialized))) {
        return;
    }

    io_uring_free_buf_ring(
        &(engine->ring),
        engine->buf_ring,
        engine->buf_ring_entries,
        engine->buf_group_id);
    io_uring_queue_exit(&(engine->ring));

    free(engine->buffers);
    free(engine->send_contexts);
    free(engine->buf_refcounts);

    *engine = (ring_engine_t){};
}

struct io_uring_sqe *ring_engine_get_sqe(ring_engine_t *restrict const engine) {
    if (unlikely((engine == nullptr) || !(engine->initialized))) {
        return nullptr;
    }

    auto sqe = io_uring_get_sqe(&(engine->ring));
    if (unlikely(sqe == nullptr)) {
        io_uring_submit(&(engine->ring));
        sqe = io_uring_get_sqe(&(engine->ring));
    }
    return sqe;
}

void ring_engine_recycle_buf(ring_engine_t *restrict const engine, uint16_t const bid) {
    if (unlikely(
            (engine == nullptr) || !(engine->initialized) || (bid >= engine->buf_ring_entries)))
    {
        return;
    }

    if (likely(engine->buf_refcounts != nullptr)) {
        engine->buf_refcounts[bid] = 0;
    }

    uint8_t *const addr = &(engine->buffers[(size_t)bid * (size_t)engine->buf_size]);
    io_uring_buf_ring_add(engine->buf_ring, addr, engine->buf_size, bid, (int)engine->buf_mask, 0);
    io_uring_buf_ring_advance(engine->buf_ring, 1);
}

void ring_engine_buf_retain(ring_engine_t *restrict const engine, uint16_t const bid) {
    if (unlikely(
            (engine == nullptr) || !(engine->initialized) || (bid >= engine->buf_ring_entries)))
    {
        return;
    }
    if (likely(engine->buf_refcounts != nullptr)) {
        engine->buf_refcounts[bid]++;
    }
}

void ring_engine_buf_release(ring_engine_t *restrict const engine, uint16_t const bid) {
    if (unlikely(
            (engine == nullptr) || !(engine->initialized) || (bid >= engine->buf_ring_entries)))
    {
        return;
    }
    if (likely(engine->buf_refcounts != nullptr)) {
        if (engine->buf_refcounts[bid] > 1) {
            engine->buf_refcounts[bid]--;
            return;
        }
        engine->buf_refcounts[bid] = 0;
    }
    ring_engine_recycle_buf(engine, bid);
}

int ring_engine_submit(ring_engine_t *restrict const engine) {
    if (unlikely((engine == nullptr) || !(engine->initialized))) {
        return -EINVAL;
    }
    return io_uring_submit(&(engine->ring));
}

int ring_engine_submit_and_wait(ring_engine_t *restrict const engine, uint32_t const wait_nr) {
    if (unlikely((engine == nullptr) || !(engine->initialized))) {
        return -EINVAL;
    }
    return io_uring_submit_and_wait(&(engine->ring), wait_nr);
}

int ring_engine_submit_and_wait_timeout(
    ring_engine_t *restrict const engine,
    uint32_t const wait_nr,
    struct __kernel_timespec *restrict const ts) {
    if (unlikely((engine == nullptr) || !(engine->initialized))) {
        return -EINVAL;
    }
    struct io_uring_cqe *cqe = nullptr;
    return io_uring_submit_and_wait_timeout(&(engine->ring), &cqe, wait_nr, ts, nullptr);
}
