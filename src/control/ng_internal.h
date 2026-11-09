#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "control/bencode.h"
#include "control/ng.h"
#include "core/macros.h"
#include "core/string_view.h"
#include "net/session.h"
#include "ring/ring.h"

/**
 * @file ng_internal.h
 * @brief Internal declarations and helpers shared across NG protocol implementation modules.
 */

static inline void ng_write_header_cookie(bencode_buf_t *restrict const b, sv_t const cookie) {
    if (unlikely((b == nullptr) || (b->buf == nullptr))) {
        return;
    }
    b->len    = 0;
    b->buf[0] = '\0';
    if (!SV_IS_EMPTY(cookie)) {
        if ((cookie.length + 2) <= b->cap) {
            __builtin_memcpy(b->buf, cookie.data, cookie.length);
            b->buf[cookie.length] = ' ';
            b->len                = cookie.length + 1;
            b->buf[b->len]        = '\0';
        } else {
            b->overflow = true;
        }
    }
}

typedef struct {
    sv_t     cookie;
    sv_t     call_id;
    sv_t     from_tag;
    sv_t     to_tag;
    sv_t     sdp;
    bool     is_offer;
    bool     trust_address;
    bool     want_rtcp_mux;
    bool     sdes_off;
    bool     want_savp;
    bool     force_ice;
    bool     strip_ice;
    bool     dtls_passive;
    bool     dtls_active;
    bool     record_call;
    uint32_t jitter_buffer_ms;
    bool     has_transport;
    char     transport_proto[32];
    bool     replace_origin;
    bool     replace_session_conn;
} ng_call_req_t;

bool ng_parse_call_req(
    sv_t const dict,
    bool const is_offer,
    sv_t const cookie,
    ng_call_req_t *restrict const req,
    session_table_t const *restrict const session_table,
    bencode_buf_t *restrict const b);

bool ng_execute_negotiation(
    ng_call_req_t const *restrict const req,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b);

bool ng_handle_ping(sv_t const cookie, bencode_buf_t *restrict const b);

bool ng_handle_offer(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b);

bool ng_handle_answer(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b);

bool ng_handle_delete(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b);

bool ng_handle_query(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b);

bool ng_handle_list(
    sv_t const cookie,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b);

bool ng_handle_start_recording(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b);

bool ng_handle_stop_recording(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b);

bool ng_handle_record(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b);

bool ng_handle_stats(
    sv_t const cookie,
    session_table_t const *restrict const session_table,
    ng_call_table_t const *restrict const call_table,
    bencode_buf_t *restrict const b);
