#include "control/ng_internal.h"
#include "core/macros.h"
#include "net/pcap.h"
#include "net/session.h"
#include "ring/ring.h"

bool ng_handle_ping(sv_t const cookie, bencode_buf_t *restrict const b) {
    ng_write_header_cookie(b, cookie);
    return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "pong") &&
           bencode_write_dict_end(b);
}

bool ng_handle_delete(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b) {
    sv_t call_id = SV_EMPTY;
    (void)bencode_dict_get_str(dict, SV_PSZ("call-id"), &call_id);

    if (SV_IS_EMPTY(call_id)) {
        ng_write_header_cookie(b, cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Missing call-id") &&
               bencode_write_dict_end(b);
    }

    auto const call = ng_call_find(call_table, call_id);
    if (call == nullptr) {
        ng_write_header_cookie(b, cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Call not found") &&
               bencode_write_dict_end(b);
    }

    if (session_table != nullptr) {
        for (size_t s = 0; s < call->stream_count; ++s) {
            if (call->streams[s].caller_port > 0) {
                (void)session_delete_by_port(session_table, call->streams[s].caller_port, engine);
            }
            if (call->streams[s].callee_port > 0) {
                (void)session_delete_by_port(session_table, call->streams[s].callee_port, engine);
            }
        }
    }
    if (call->caller_port > 0) {
        (void)session_delete_by_port(session_table, call->caller_port, engine);
    }
    if (call->callee_port > 0) {
        (void)session_delete_by_port(session_table, call->callee_port, engine);
    }
    if (call->record_idx >= 0) {
        if (session_table != nullptr) {
            (void)pcap_recorder_stop_by_index(&(session_table->pcap_table), call->record_idx);
        }
        call->record_idx = -1;
    }
    ng_call_destroy(call_table, call);

    ng_write_header_cookie(b, cookie);
    return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "ok") &&
           bencode_write_dict_end(b);
}

bool ng_handle_query(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b) {
    sv_t call_id = SV_EMPTY;
    (void)bencode_dict_get_str(dict, SV_PSZ("call-id"), &call_id);

    if (SV_IS_EMPTY(call_id)) {
        ng_write_header_cookie(b, cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Missing call-id") &&
               bencode_write_dict_end(b);
    }

    auto const call = ng_call_find(call_table, call_id);
    if (call == nullptr) {
        ng_write_header_cookie(b, cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Call not found") &&
               bencode_write_dict_end(b);
    }

    uint64_t pkts            = 0;
    uint64_t bytes           = 0;
    uint64_t rtp_pkts        = 0;
    uint64_t rtp_bytes       = 0;
    uint64_t rtcp_pkts       = 0;
    uint64_t rtcp_bytes      = 0;
    uint64_t srtp_enc_pkts   = 0;
    uint64_t srtp_dec_pkts   = 0;
    uint64_t srtp_auth_errs  = 0;
    uint32_t caller_ssrc     = 0;
    uint64_t caller_idle_sec = 0;
    uint32_t callee_ssrc     = 0;
    uint64_t callee_idle_sec = 0;
    uint64_t jb_reordered    = 0;
    uint64_t jb_late         = 0;
    uint64_t jb_plc          = 0;
    bool     has_jb          = false;
    if (session_table != nullptr) {
        if (call->caller_port > 0) {
            auto const s = session_find_by_port(session_table, call->caller_port);
            if (s != nullptr) {
                pkts += s->packets_relayed;
                bytes += s->bytes_relayed;
                rtp_pkts += s->rtp_packets_relayed;
                rtp_bytes += s->rtp_bytes_relayed;
                rtcp_pkts += s->rtcp_packets_relayed;
                rtcp_bytes += s->rtcp_bytes_relayed;
                srtp_enc_pkts += s->srtp_packets_encrypted;
                srtp_dec_pkts += s->srtp_packets_decrypted;
                srtp_auth_errs += s->srtp_auth_failures;
                if (s->last_ssrc != 0) {
                    caller_ssrc     = s->last_ssrc;
                    caller_idle_sec = (session_table->cached_monotonic_sec >= s->last_ssrc_sec)
                                          ? (session_table->cached_monotonic_sec - s->last_ssrc_sec)
                                          : 0;
                }
                if (s->jitter_buf != nullptr) {
                    jb_reordered += s->jitter_buf->packets_reordered;
                    jb_late += s->jitter_buf->packets_dropped_late;
                    jb_plc += s->jitter_buf->loss_concealments;
                    has_jb = true;
                }
            }
        }
        if (call->callee_port > 0) {
            auto const s = session_find_by_port(session_table, call->callee_port);
            if (s != nullptr) {
                pkts += s->packets_relayed;
                bytes += s->bytes_relayed;
                rtp_pkts += s->rtp_packets_relayed;
                rtp_bytes += s->rtp_bytes_relayed;
                rtcp_pkts += s->rtcp_packets_relayed;
                rtcp_bytes += s->rtcp_bytes_relayed;
                srtp_enc_pkts += s->srtp_packets_encrypted;
                srtp_dec_pkts += s->srtp_packets_decrypted;
                srtp_auth_errs += s->srtp_auth_failures;
                if (s->last_ssrc != 0) {
                    callee_ssrc     = s->last_ssrc;
                    callee_idle_sec = (session_table->cached_monotonic_sec >= s->last_ssrc_sec)
                                          ? (session_table->cached_monotonic_sec - s->last_ssrc_sec)
                                          : 0;
                }
                if (s->jitter_buf != nullptr) {
                    jb_reordered += s->jitter_buf->packets_reordered;
                    jb_late += s->jitter_buf->packets_dropped_late;
                    jb_plc += s->jitter_buf->loss_concealments;
                    has_jb = true;
                }
            }
        }
    }

    ng_write_header_cookie(b, cookie);
    if (!bencode_write_dict_start(b) || !bencode_write_kv_str(b, "result", "ok") ||
        !bencode_write_kv_int(b, "packets", (int64_t)pkts) ||
        !bencode_write_kv_int(b, "bytes", (int64_t)bytes))
    {
        return false;
    }

    if (caller_ssrc != 0) {
        if (!bencode_write_kv_int(b, "caller-ssrc", (int64_t)caller_ssrc) ||
            !bencode_write_kv_int(b, "caller-ssrc-idle-sec", (int64_t)caller_idle_sec))
        {
            return false;
        }
    }
    if (callee_ssrc != 0) {
        if (!bencode_write_kv_int(b, "callee-ssrc", (int64_t)callee_ssrc) ||
            !bencode_write_kv_int(b, "callee-ssrc-idle-sec", (int64_t)callee_idle_sec))
        {
            return false;
        }
    }

    if (call->caller_rtcp_mux || call->callee_rtcp_mux || (rtcp_pkts > 0)) {
        if (!bencode_write_kv_int(b, "rtp-packets", (int64_t)rtp_pkts) ||
            !bencode_write_kv_int(b, "rtp-bytes", (int64_t)rtp_bytes) ||
            !bencode_write_kv_int(b, "rtcp-packets", (int64_t)rtcp_pkts) ||
            !bencode_write_kv_int(b, "rtcp-bytes", (int64_t)rtcp_bytes))
        {
            return false;
        }
    }

    if (call->caller_use_srtp || call->callee_use_srtp || (srtp_enc_pkts > 0) ||
        (srtp_dec_pkts > 0))
    {
        if (!bencode_write_kv_int(b, "srtp-encrypted", (int64_t)srtp_enc_pkts) ||
            !bencode_write_kv_int(b, "srtp-decrypted", (int64_t)srtp_dec_pkts) ||
            !bencode_write_kv_int(b, "srtp-auth-failures", (int64_t)srtp_auth_errs))
        {
            return false;
        }
    }

    if (has_jb || (call->jitter_buffer_ms > 0) || (jb_reordered > 0) || (jb_late > 0) ||
        (jb_plc > 0))
    {
        if (!bencode_write_kv_int(b, "jb-packets-reordered", (int64_t)jb_reordered) ||
            !bencode_write_kv_int(b, "jb-packets-dropped-late", (int64_t)jb_late) ||
            !bencode_write_kv_int(b, "jb-loss-concealments", (int64_t)jb_plc))
        {
            return false;
        }
    }

    return bencode_write_dict_end(b);
}

bool ng_handle_list(
    sv_t const cookie,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b) {
    ng_write_header_cookie(b, cookie);
    if (!bencode_write_dict_start(b) || !bencode_write_kv_str(b, "result", "ok")) {
        return false;
    }

    if (!bencode_write_str_raw(b, "calls", 5) || !bencode_write_list_start(b)) {
        return false;
    }

    for (size_t i = 0; i < NG_MAX_CALLS; ++i) {
        if (call_table->calls[i].active) {
            if (!bencode_write_str_raw(
                    b,
                    call_table->calls[i].call_id,
                    __builtin_strlen(call_table->calls[i].call_id)))
            {
                return false;
            }
        }
    }

    return bencode_write_list_end(b) && bencode_write_dict_end(b);
}

bool ng_handle_start_recording(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b) {
    ng_write_header_cookie(b, cookie);

    if (unlikely((session_table == nullptr) || (call_table == nullptr))) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Internal error") &&
               bencode_write_dict_end(b);
    }

    sv_t call_id = SV_EMPTY;
    (void)bencode_dict_get_str(dict, SV_PSZ("call-id"), &call_id);
    if (SV_IS_EMPTY(call_id)) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Missing call-id") &&
               bencode_write_dict_end(b);
    }

    auto const call = ng_call_find(call_table, call_id);
    if (call == nullptr) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Call not found") &&
               bencode_write_dict_end(b);
    }

    if (!(session_table->pcap_table.enabled)) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "PCAP recording volume not configured") &&
               bencode_write_dict_end(b);
    }

    if (call->record_idx < 0) {
        call->record_idx = pcap_recorder_start(
            &(session_table->pcap_table),
            call->call_id,
            call->caller_port,
            call->callee_port);
        if (call->record_idx < 0) {
            return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
                   bencode_write_kv_str(b, "error-reason", "Failed to start recorder") &&
                   bencode_write_dict_end(b);
        }
        if (call->caller_port > 0) {
            auto const s = session_find_by_port(session_table, call->caller_port);
            if (s != nullptr) {
                s->record_idx = call->record_idx;
            }
        }
        if (call->callee_port > 0) {
            auto const s = session_find_by_port(session_table, call->callee_port);
            if (s != nullptr) {
                s->record_idx = call->record_idx;
            }
        }
    }

    auto const        rec  = pcap_recorder_get(&(session_table->pcap_table), call->record_idx);
    char const *const path = (rec != nullptr) ? rec->file_path : "";

    return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "ok") &&
           bencode_write_kv_str(b, "file", path) && bencode_write_dict_end(b);
}

bool ng_handle_stop_recording(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b) {
    ng_write_header_cookie(b, cookie);

    if (unlikely((session_table == nullptr) || (call_table == nullptr))) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Internal error") &&
               bencode_write_dict_end(b);
    }

    sv_t call_id = SV_EMPTY;
    (void)bencode_dict_get_str(dict, SV_PSZ("call-id"), &call_id);
    if (SV_IS_EMPTY(call_id)) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Missing call-id") &&
               bencode_write_dict_end(b);
    }

    auto const call = ng_call_find(call_table, call_id);
    if (call == nullptr) {
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "Call not found") &&
               bencode_write_dict_end(b);
    }

    if (call->record_idx >= 0) {
        (void)pcap_recorder_stop_by_index(&(session_table->pcap_table), call->record_idx);
        if (call->caller_port > 0) {
            auto const s = session_find_by_port(session_table, call->caller_port);
            if (s != nullptr) {
                s->record_idx = -1;
            }
        }
        if (call->callee_port > 0) {
            auto const s = session_find_by_port(session_table, call->callee_port);
            if (s != nullptr) {
                s->record_idx = -1;
            }
        }
        call->record_idx = -1;
    }

    return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "ok") &&
           bencode_write_dict_end(b);
}

bool ng_handle_record(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    bencode_buf_t *restrict const b) {
    sv_t action = SV_EMPTY;
    (void)bencode_dict_get_str(dict, SV_PSZ("action"), &action);
    if (sv_equals(action, SV_PSZ("stop"))) {
        return ng_handle_stop_recording(cookie, dict, session_table, call_table, b);
    }
    return ng_handle_start_recording(cookie, dict, session_table, call_table, b);
}

bool ng_handle_stats(
    sv_t const cookie,
    session_table_t const *restrict const session_table,
    ng_call_table_t const *restrict const call_table,
    bencode_buf_t *restrict const b) {
    ng_write_header_cookie(b, cookie);
    if (!bencode_write_dict_start(b) || !bencode_write_kv_str(b, "result", "ok")) {
        return false;
    }

    size_t const active_sessions = (session_table != nullptr) ? session_table->active_count : 0;
    size_t const active_calls    = (call_table != nullptr) ? call_table->active_count : 0;

    if (!bencode_write_kv_int(b, "active-sessions", (int64_t)active_sessions) ||
        !bencode_write_kv_int(b, "active-calls", (int64_t)active_calls))
    {
        return false;
    }

    if ((session_table != nullptr) && (session_table->metrics != nullptr)) {
        auto const c = &(session_table->metrics->cumulative);
        auto const r = &(session_table->metrics->rate_per_sec);

        if (!bencode_write_kv_int(b, "rx-packets", (int64_t)c->rx_packets) ||
            !bencode_write_kv_int(b, "tx-packets", (int64_t)c->tx_packets) ||
            !bencode_write_kv_int(b, "rx-bytes", (int64_t)c->rx_bytes) ||
            !bencode_write_kv_int(b, "tx-bytes", (int64_t)c->tx_bytes) ||
            !bencode_write_kv_int(b, "rtp-packets", (int64_t)c->rtp_packets) ||
            !bencode_write_kv_int(b, "rtcp-packets", (int64_t)c->rtcp_packets) ||
            !bencode_write_kv_int(b, "packets-dropped", (int64_t)c->packets_dropped) ||
            !bencode_write_kv_int(b, "srtp-encrypted", (int64_t)c->srtp_encrypted) ||
            !bencode_write_kv_int(b, "srtp-decrypted", (int64_t)c->srtp_decrypted) ||
            !bencode_write_kv_int(b, "srtp-auth-failures", (int64_t)c->srtp_auth_failures) ||
            !bencode_write_kv_int(b, "transcode-decoded", (int64_t)c->transcode_decoded) ||
            !bencode_write_kv_int(b, "transcode-encoded", (int64_t)c->transcode_encoded) ||
            !bencode_write_kv_int(b, "jb-packets-reordered", (int64_t)c->jb_packets_reordered) ||
            !bencode_write_kv_int(
                b,
                "jb-packets-dropped-late",
                (int64_t)c->jb_packets_dropped_late) ||
            !bencode_write_kv_int(b, "jb-loss-concealments", (int64_t)c->jb_loss_concealments) ||
            !bencode_write_kv_int(
                b,
                "buffer-ring-exhaustions",
                (int64_t)c->buffer_ring_exhaustions) ||
            !bencode_write_kv_int(b, "sessions-reaped", (int64_t)c->sessions_reaped) ||
            !bencode_write_kv_int(b, "rate-rx-packets", (int64_t)r->rx_packets) ||
            !bencode_write_kv_int(b, "rate-tx-packets", (int64_t)r->tx_packets) ||
            !bencode_write_kv_int(b, "rate-rx-bytes", (int64_t)r->rx_bytes) ||
            !bencode_write_kv_int(b, "rate-tx-bytes", (int64_t)r->tx_bytes))
        {
            return false;
        }
    }

    return bencode_write_dict_end(b);
}
