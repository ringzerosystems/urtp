#include "media/jitter.h"
#include <arpa/inet.h>
#include "core/macros.h"
#include "core/memory.h"
#include "net/rtp.h"

void jitter_buffer_init(jitter_buffer_t *restrict const jb, uint32_t const target_delay_ms) {
    if (unlikely(jb == nullptr)) {
        return;
    }

    *jb = (jitter_buffer_t){};

    uint32_t delay = target_delay_ms;
    if (delay < JITTER_MIN_DELAY_MS) {
        delay = JITTER_DEFAULT_DELAY_MS;
    } else if (delay > JITTER_MAX_DELAY_MS) {
        delay = JITTER_MAX_DELAY_MS;
    }
    jb->target_delay_ms = delay;

    // Standard audio frame duration is 20ms per packet
    uint16_t depth = (uint16_t)(delay / 20);
    if (depth < 1) {
        depth = 1;
    }
    if (depth > (uint16_t)(JITTER_BUFFER_MAX_SLOTS / 2)) {
        depth = (uint16_t)(JITTER_BUFFER_MAX_SLOTS / 2);
    }
    jb->target_depth = depth;

    // Max depth before declaring packet loss (double target depth, capped below slot capacity)
    uint16_t max_d = (uint16_t)(depth * 2);
    if (max_d < JITTER_DEFAULT_MAX_DEPTH) {
        max_d = JITTER_DEFAULT_MAX_DEPTH;
    }
    if (max_d >= (uint16_t)JITTER_BUFFER_MAX_SLOTS) {
        max_d = (uint16_t)(JITTER_BUFFER_MAX_SLOTS - 1);
    }
    jb->max_depth = max_d;
    jb->enabled   = true;
}

void jitter_buffer_reset(jitter_buffer_t *restrict const jb) {
    if (unlikely(jb == nullptr)) {
        return;
    }

    auto const saved_delay   = jb->target_delay_ms;
    auto const saved_target  = jb->target_depth;
    auto const saved_max     = jb->max_depth;
    auto const saved_enabled = jb->enabled;

    *jb = (jitter_buffer_t){
        .target_delay_ms = saved_delay,
        .target_depth    = saved_target,
        .max_depth       = saved_max,
        .enabled         = saved_enabled,
    };
}

size_t jitter_buffer_flush(jitter_buffer_t *restrict const jb) {
    if (unlikely(jb == nullptr)) {
        return 0;
    }

    size_t flushed = 0;
    for (size_t i = 0; i < JITTER_BUFFER_MAX_SLOTS; ++i) {
        if (jb->slots[i].occupied) {
            jb->slots[i] = (jitter_slot_t){};
            flushed++;
        }
    }

    jb->occupancy       = 0;
    jb->buffering       = true;
    jb->seq_initialized = false;
    jb->plc_until_seq   = 0;
    return flushed;
}

bool jitter_buffer_insert(
    jitter_buffer_t *restrict const jb,
    void const *restrict const packet_data,
    size_t const   packet_len,
    uint64_t const now_ns) {
    if (unlikely(
            (jb == nullptr) || !(jb->enabled) || (packet_data == nullptr) ||
            (packet_len < RTP_HEADER_MIN_SIZE) || (packet_len > JITTER_SLOT_MAX_SIZE)))
    {
        return false;
    }

    auto const rtp_hdr = (rtp_header_t const *)packet_data;
    if (unlikely(rtp_get_version(rtp_hdr) != RTP_VERSION_2)) {
        return false;
    }

    uint16_t const seq = ntohs(rtp_hdr->seq);
    uint32_t const ts  = ntohl(rtp_hdr->timestamp);

    // Initial sequence anchor
    if (unlikely(!(jb->seq_initialized))) {
        jb->next_playout_seq = seq;
        jb->highest_rx_seq   = seq;
        jb->seq_initialized  = true;
        jb->buffering        = true;
        jb->last_arrival_ns  = now_ns;
        jb->last_transit_ts  = ts;
    } else {
        // Estimate transit jitter per RFC 3550 Section 6.4.1:
        // D(i, j) = (R_j - R_i) - (S_j - S_i)
        if ((now_ns > jb->last_arrival_ns) && (ts >= jb->last_transit_ts)) {
            uint64_t const arr_diff_ns = now_ns - jb->last_arrival_ns;
            // Coarse approximation of arrival time in RTP timestamp units (assume 48kHz for
            // timebase)
            uint32_t const arr_ticks = (uint32_t)((arr_diff_ns * 48000ULL) / 1000000000ULL);
            uint32_t const ts_diff   = ts - jb->last_transit_ts;
            int64_t const  d         = (int64_t)arr_ticks - (int64_t)ts_diff;
            uint32_t const abs_d     = (d < 0) ? (uint32_t)(-d) : (uint32_t)d;
            jb->transit_jitter =
                jb->transit_jitter +
                ((abs_d > jb->transit_jitter) ? ((abs_d - jb->transit_jitter) >> 4) : 0);
        }
        jb->last_arrival_ns = now_ns;
        jb->last_transit_ts = ts;
    }

    // Sequence distance relative to current playout target
    int16_t const playout_diff = jitter_seq_diff(seq, jb->next_playout_seq);

    // 1. Late arrival check: packet sequence is behind current playout pointer
    if (playout_diff < 0) {
        jb->packets_dropped_late++;
        return false;
    }

    // 2. Far ahead arrival: sequence jump exceeds buffer capacity
    if (playout_diff >= (int16_t)JITTER_BUFFER_MAX_SLOTS) {
        // Stream may have experienced a sequence jump or restart
        // Flush stale slots and re-anchor playout
        (void)jitter_buffer_flush(jb);
        jb->next_playout_seq = seq;
        jb->highest_rx_seq   = seq;
        jb->seq_initialized  = true;
        jb->buffering        = true;
    }

    // Power-of-two slot indexing: O(1) modulo
    size_t const         slot_idx = (size_t)seq & (JITTER_BUFFER_MAX_SLOTS - 1);
    jitter_slot_t *const slot     = &(jb->slots[slot_idx]);

    // 3. Duplicate packet check
    if (slot->occupied && (slot->seq == seq)) {
        jb->packets_dropped_dup++;
        return false;
    }

    // 4. Collision / slot overflow check (slot occupied by older un-popped packet)
    if (slot->occupied) {
        jb->packets_dropped_overflow++;
        return false;
    }

    // Store packet payload into slot
    __builtin_memcpy(slot->payload, packet_data, packet_len);
    slot->length     = (uint16_t)packet_len;
    slot->seq        = seq;
    slot->timestamp  = ts;
    slot->arrival_ns = now_ns;
    slot->occupied   = true;

    jb->occupancy++;
    jb->packets_inserted++;

    // Track sequence ordering relative to highest received
    int16_t const rx_diff = jitter_seq_diff(seq, jb->highest_rx_seq);
    if (rx_diff > 0) {
        jb->highest_rx_seq = seq;
    } else if (rx_diff < 0) {
        // Arrived out-of-order!
        jb->packets_reordered++;
    }

    return true;
}

jitter_pop_status_t jitter_buffer_pop(
    jitter_buffer_t *restrict const jb,
    void *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len,
    uint16_t *restrict const out_seq,
    uint32_t *restrict const out_ts) {
    if (unlikely(
            (jb == nullptr) || !(jb->enabled) || !(jb->seq_initialized) || (out_buf == nullptr) ||
            (out_len == nullptr) || (out_seq == nullptr) || (out_ts == nullptr)))
    {
        return JB_POP_EMPTY;
    }

    // Check pre-buffering condition
    if (jb->buffering) {
        int16_t const span = jitter_seq_diff(jb->highest_rx_seq, jb->next_playout_seq);
        if ((jb->occupancy < jb->target_depth) && (span < (int16_t)jb->target_depth)) {
            return JB_POP_EMPTY;
        }
        jb->buffering = false;
    }

    size_t const         slot_idx = (size_t)jb->next_playout_seq & (JITTER_BUFFER_MAX_SLOTS - 1);
    jitter_slot_t *const slot     = &(jb->slots[slot_idx]);

    // Case 1: In-order packet is ready in slot
    if (slot->occupied && (slot->seq == jb->next_playout_seq)) {
        if (unlikely(out_cap < slot->length)) {
            return JB_POP_EMPTY;
        }

        __builtin_memcpy(out_buf, slot->payload, slot->length);
        *out_len = (size_t)slot->length;
        *out_seq = slot->seq;
        *out_ts  = slot->timestamp;

        // Clear slot and update occupancy
        *slot = (jitter_slot_t){};
        if (jb->occupancy > 0) {
            jb->occupancy--;
        }

        jb->next_playout_seq++;
        jb->packets_played++;
        if (jb->next_playout_seq == jb->plc_until_seq) {
            jb->plc_until_seq = 0;
        }
        return JB_POP_OK;
    }

    // Case 2: Slot is empty (missing packet)
    // Check if we are currently draining a detected gap
    if ((jb->plc_until_seq != 0) && (jitter_seq_diff(jb->plc_until_seq, jb->next_playout_seq) > 0))
    {
        *out_seq = jb->next_playout_seq;
        *out_ts  = 0;
        *out_len = 0;

        jb->loss_concealments++;
        jb->next_playout_seq++;
        if (jb->next_playout_seq == jb->plc_until_seq) {
            jb->plc_until_seq = 0;
        }
        return JB_POP_PLC;
    }

    int16_t const lag = jitter_seq_diff(jb->highest_rx_seq, jb->next_playout_seq);
    if (lag >= (int16_t)jb->max_depth) {
        // Missing packet has exceeded maximum allowable jitter lag -> initiate PLC catch-up!
        jb->plc_until_seq = jb->highest_rx_seq;
        *out_seq          = jb->next_playout_seq;
        *out_ts           = 0;
        *out_len          = 0;

        jb->loss_concealments++;
        jb->next_playout_seq++;
        if (jb->next_playout_seq == jb->plc_until_seq) {
            jb->plc_until_seq = 0;
        }
        return JB_POP_PLC;
    }

    // Slot is empty, but within allowable jitter wait window -> wait for packet arrival
    return JB_POP_EMPTY;
}

jitter_pool_t *jitter_pool_create(void) {
    auto const pool = (jitter_pool_t *)mem_alloc_aligned(64, sizeof(jitter_pool_t));
    if (unlikely(pool == nullptr)) {
        return nullptr;
    }
    *pool = (jitter_pool_t){};
    for (size_t i = 0; i < JITTER_POOL_CAPACITY; ++i) {
        pool->free_indices[i] = (uint8_t)(JITTER_POOL_CAPACITY - 1 - i);
    }
    pool->top = JITTER_POOL_CAPACITY;
    return pool;
}

void jitter_pool_destroy(jitter_pool_t *restrict const pool) {
    if (unlikely(pool == nullptr)) {
        return;
    }
    mem_free_aligned(pool, sizeof(jitter_pool_t));
}

jitter_buffer_t *jitter_pool_pop(jitter_pool_t *restrict const pool) {
    if (unlikely(pool == nullptr)) {
        return nullptr;
    }
    if (likely(pool->top > 0)) {
        auto const idx = pool->free_indices[--pool->top];
        return &(pool->buffers[idx]);
    }
    return nullptr;
}

void jitter_pool_push(jitter_pool_t *restrict const pool, jitter_buffer_t *restrict const jb) {
    if (unlikely((pool == nullptr) || (jb == nullptr))) {
        return;
    }
    auto const offset = (size_t)(jb - pool->buffers);
    if (likely(offset < JITTER_POOL_CAPACITY)) {
        if (likely(pool->top < JITTER_POOL_CAPACITY)) {
            pool->free_indices[pool->top++] = (uint8_t)offset;
        }
    }
}
