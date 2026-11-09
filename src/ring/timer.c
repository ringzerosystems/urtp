#include "ring/timer.h"
#include <unistd.h>
#include "core/macros.h"

bool timer_engine_init(timer_engine_t *restrict const timer, uint32_t const interval_sec) {
    if (unlikely(timer == nullptr)) {
        return false;
    }

    uint32_t const actual_interval = (interval_sec > 0) ? interval_sec : TIMER_DEFAULT_INTERVAL_SEC;

    int const fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (unlikely(fd < 0)) {
        return false;
    }

    struct itimerspec const its = {
        .it_interval = {.tv_sec = (time_t)actual_interval, .tv_nsec = 0},
        .it_value    = {.tv_sec = (time_t)actual_interval, .tv_nsec = 0},
    };

    if (unlikely(timerfd_settime(fd, 0, &its, nullptr) < 0)) {
        (void)close(fd);
        return false;
    }

    *timer = (timer_engine_t){
        .timer_fd     = fd,
        .tick_buf     = 0,
        .interval_sec = actual_interval,
        .armed        = false,
        .initialized  = true,
    };

    return true;
}

void timer_engine_destroy(timer_engine_t *restrict const timer) {
    if (unlikely(timer == nullptr)) {
        return;
    }

    if (timer->timer_fd >= 0) {
        (void)close(timer->timer_fd);
    }
    *timer = (timer_engine_t){.timer_fd = -1};
}

bool timer_engine_arm(timer_engine_t *restrict const timer, ring_engine_t *restrict const ring) {
    if (unlikely(
            (timer == nullptr) || (ring == nullptr) || !(timer->initialized) ||
            (timer->timer_fd < 0)))
    {
        return false;
    }

    auto const sqe = ring_engine_get_sqe(ring);
    if (unlikely(sqe == nullptr)) {
        return false;
    }

    io_uring_prep_read(sqe, timer->timer_fd, &(timer->tick_buf), sizeof(uint64_t), 0);

    user_data_tag_t const tag = {
        .fields =
            {
                .index   = 0,
                .op_type = OP_TYPE_TIMER_TICK,
                .bid     = 0,
                .flags   = 0,
            },
    };
    io_uring_sqe_set_data64(sqe, tag.raw);
    timer->armed = true;

    return true;
}

bool timer_engine_rearm(timer_engine_t *restrict const timer, ring_engine_t *restrict const ring) {
    if (unlikely(timer == nullptr)) {
        return false;
    }
    timer->armed = false;
    return timer_engine_arm(timer, ring);
}
