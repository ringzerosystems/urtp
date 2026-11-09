#include <time.h>
#include "control/ng.h"
#include "core/macros.h"
#include "net/session.h"

void ng_call_table_init(ng_call_table_t *restrict const table, char const *const media_ip) {
    if (unlikely(table == nullptr)) {
        return;
    }
    *table = (ng_call_table_t){
        .active_count = 0,
        .next_port    = NG_PORT_POOL_MIN,
    };
    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        table->calls[i].record_idx = -1;
    }
    char const *const ip  = (media_ip != nullptr) ? media_ip : "127.0.0.1";
    auto const        len = __builtin_strlen(ip);
    auto const copylen    = (len < sizeof(table->media_ip) - 1) ? len : sizeof(table->media_ip) - 1;
    __builtin_memcpy(table->media_ip, ip, copylen);
    table->media_ip[copylen] = '\0';
}

void ng_call_table_destroy(
    ng_call_table_t *restrict const table,
    session_table_t *restrict const session_table,
    ring_engine_t *restrict const engine) {
    if (unlikely(table == nullptr)) {
        return;
    }
    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        ng_call_t *const call = &(table->calls[i]);
        if (call->active) {
            if (session_table != nullptr) {
                for (size_t s = 0; s < call->stream_count; ++s) {
                    if (call->streams[s].caller_port > 0) {
                        (void)session_delete_by_port(
                            session_table,
                            call->streams[s].caller_port,
                            engine);
                    }
                    if (call->streams[s].callee_port > 0) {
                        (void)session_delete_by_port(
                            session_table,
                            call->streams[s].callee_port,
                            engine);
                    }
                }
                if (call->caller_port > 0) {
                    (void)session_delete_by_port(session_table, call->caller_port, engine);
                }
                if (call->callee_port > 0) {
                    (void)session_delete_by_port(session_table, call->callee_port, engine);
                }
            }
            *call = (ng_call_t){};
        }
    }
    table->active_count = 0;
}

ng_call_t *ng_call_find(ng_call_table_t *restrict const table, sv_t const call_id) {
    if (unlikely((table == nullptr) || SV_IS_EMPTY(call_id))) {
        return nullptr;
    }
    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        ng_call_t *const call = &(table->calls[i]);
        if (call->active) {
            sv_t const cid = SV_PSZ(call->call_id);
            if (sv_equals(cid, call_id)) {
                return call;
            }
        }
    }
    return nullptr;
}

ng_call_t *ng_call_find_or_create(
    ng_call_table_t *restrict const table,
    sv_t const call_id,
    sv_t const from_tag) {
    if (unlikely((table == nullptr) || SV_IS_EMPTY(call_id))) {
        return nullptr;
    }

    auto const existing = ng_call_find(table, call_id);
    if (existing != nullptr) {
        return existing;
    }

    if (table->active_count >= NG_MAX_CALLS) {
        return nullptr;
    }

    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        ng_call_t *const call = &(table->calls[i]);
        if (!(call->active)) {
            *call            = (ng_call_t){};
            call->active     = true;
            call->record_idx = -1;

            auto const id_len = (call_id.length < sizeof(call->call_id) - 1)
                                    ? call_id.length
                                    : sizeof(call->call_id) - 1;
            __builtin_memcpy(call->call_id, call_id.data, id_len);
            call->call_id[id_len] = '\0';

            if (!SV_IS_EMPTY(from_tag)) {
                auto const tag_len = (from_tag.length < sizeof(call->from_tag) - 1)
                                         ? from_tag.length
                                         : sizeof(call->from_tag) - 1;
                __builtin_memcpy(call->from_tag, from_tag.data, tag_len);
                call->from_tag[tag_len] = '\0';
            }

            struct timespec ts = {};
            (void)clock_gettime(CLOCK_MONOTONIC, &ts);
            call->created_ts = (uint64_t)((ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec);

            table->active_count++;
            return call;
        }
    }
    return nullptr;
}

void ng_call_destroy(ng_call_table_t *restrict const table, ng_call_t *restrict const call) {
    if (unlikely((table == nullptr) || (call == nullptr) || !(call->active))) {
        return;
    }
    *call = (ng_call_t){.record_idx = -1};
    if (table->active_count > 0) {
        table->active_count--;
    }
}

void ng_call_table_remove_by_port(ng_call_table_t *restrict const table, uint16_t const port) {
    if (unlikely((table == nullptr) || (port == 0))) {
        return;
    }
    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        ng_call_t *const call = &(table->calls[i]);
        if (call->active) {
            bool matches = (call->caller_port == port) || (call->callee_port == port);
            if (!matches) {
                for (size_t s = 0; s < call->stream_count; ++s) {
                    if ((call->streams[s].caller_port == port) ||
                        (call->streams[s].callee_port == port))
                    {
                        matches = true;
                        break;
                    }
                }
            }
            if (matches) {
                ng_call_destroy(table, call);
                return;
            }
        }
    }
}

uint16_t ng_call_table_alloc_port(
    ng_call_table_t *restrict const table,
    session_table_t *restrict const session_table) {
    if (unlikely(table == nullptr)) {
        return 0;
    }

    constexpr size_t total_ports = (NG_PORT_POOL_MAX - NG_PORT_POOL_MIN) / 2;
    uint16_t         candidate   = table->next_port & (uint16_t)~1;
    if ((candidate < NG_PORT_POOL_MIN) || (candidate >= NG_PORT_POOL_MAX)) {
        candidate = NG_PORT_POOL_MIN;
    }

    for (size_t i = 0; i < total_ports; ++i) {
        if ((session_table == nullptr) ||
            (session_find_by_port(session_table, candidate) == nullptr))
        {
            table->next_port =
                ((candidate + 2) >= NG_PORT_POOL_MAX) ? NG_PORT_POOL_MIN : (candidate + 2);
            return candidate;
        }
        candidate += 2;
        if (candidate >= NG_PORT_POOL_MAX) {
            candidate = NG_PORT_POOL_MIN;
        }
    }
    return 0;
}
