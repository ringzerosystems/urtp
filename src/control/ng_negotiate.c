#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "control/bencode.h"
#include "control/ng_internal.h"
#include "core/macros.h"
#include "crypto/dtls.h"
#include "crypto/sdes.h"
#include "net/session.h"
#include "net/udp.h"
#include "ring/ring.h"

bool ng_parse_call_req(
    sv_t const dict,
    bool const is_offer,
    sv_t const cookie,
    ng_call_req_t *restrict const req,
    session_table_t const *restrict const session_table,
    bencode_buf_t *restrict const b) {
    if (unlikely(req == nullptr)) {
        return false;
    }

    *req = (ng_call_req_t){
        .cookie      = cookie,
        .is_offer    = is_offer,
        .record_call = (session_table != nullptr) && session_table->pcap_table.record_all,
    };

    (void)bencode_dict_get_str(dict, SV_PSZ("call-id"), &(req->call_id));
    (void)bencode_dict_get_str(dict, SV_PSZ("from-tag"), &(req->from_tag));
    (void)bencode_dict_get_str(dict, SV_PSZ("to-tag"), &(req->to_tag));
    (void)bencode_dict_get_str(dict, SV_PSZ("sdp"), &(req->sdp));

    if (SV_IS_EMPTY(req->call_id) || SV_IS_EMPTY(req->sdp) ||
        (is_offer && SV_IS_EMPTY(req->from_tag)) || (!is_offer && SV_IS_EMPTY(req->to_tag)))
    {
        ng_write_header_cookie(b, cookie);
        (void)bencode_write_dict_start(b);
        (void)bencode_write_kv_str(b, "result", "error");
        (void)bencode_write_kv_str(b, "error-reason", "Missing mandatory parameters");
        (void)bencode_write_dict_end(b);
        return false;
    }

    // Flags parsing (list or single string)
    bencode_val_t flags_val = {};
    if (bencode_dict_find(dict, SV_PSZ("flags"), &flags_val)) {
        if (flags_val.type == BENCODE_TYPE_LIST) {
            req->trust_address = bencode_list_contains_str(flags_val.raw, SV_PSZ("trust-address"));
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("rtcp-mux")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("offer-mux")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("accept-mux")))
            {
                req->want_rtcp_mux = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("SDES-off")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("strip-crypto")))
            {
                req->sdes_off = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("offer-crypto")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("RTP/SAVP")))
            {
                req->want_savp = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("ICE=force")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("ICE=offer")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("ICE=accept")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("force-ice")))
            {
                req->force_ice = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("ICE=remove")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("strip-ice")))
            {
                req->strip_ice = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("DTLS=passive"))) {
                req->dtls_passive = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("DTLS=active"))) {
                req->dtls_active = true;
            }
            if (bencode_list_contains_str(flags_val.raw, SV_PSZ("record-call")) ||
                bencode_list_contains_str(flags_val.raw, SV_PSZ("record")))
            {
                req->record_call = true;
            }
        } else if (flags_val.type == BENCODE_TYPE_STR) {
            req->trust_address = sv_equals(flags_val.str, SV_PSZ("trust-address"));
            if (sv_equals(flags_val.str, SV_PSZ("rtcp-mux")) ||
                sv_equals(flags_val.str, SV_PSZ("offer-mux")) ||
                sv_equals(flags_val.str, SV_PSZ("accept-mux")))
            {
                req->want_rtcp_mux = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("SDES-off")) ||
                sv_equals(flags_val.str, SV_PSZ("strip-crypto")))
            {
                req->sdes_off = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("offer-crypto")) ||
                sv_equals(flags_val.str, SV_PSZ("RTP/SAVP")))
            {
                req->want_savp = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("ICE=force")) ||
                sv_equals(flags_val.str, SV_PSZ("ICE=offer")) ||
                sv_equals(flags_val.str, SV_PSZ("ICE=accept")) ||
                sv_equals(flags_val.str, SV_PSZ("force-ice")))
            {
                req->force_ice = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("ICE=remove")) ||
                sv_equals(flags_val.str, SV_PSZ("strip-ice")))
            {
                req->strip_ice = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("DTLS=passive"))) {
                req->dtls_passive = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("DTLS=active"))) {
                req->dtls_active = true;
            }
            if (sv_equals(flags_val.str, SV_PSZ("record-call")) ||
                sv_equals(flags_val.str, SV_PSZ("record")))
            {
                req->record_call = true;
            }
        }
    }

    sv_t rec_str = SV_EMPTY;
    if (bencode_dict_get_str(dict, SV_PSZ("record-call"), &rec_str) ||
        bencode_dict_get_str(dict, SV_PSZ("record"), &rec_str))
    {
        if (sv_equals(rec_str, SV_PSZ("yes")) || sv_equals(rec_str, SV_PSZ("true")) ||
            sv_equals(rec_str, SV_PSZ("all")) || sv_equals(rec_str, SV_PSZ("start")))
        {
            req->record_call = true;
        }
    }

    int64_t jb_ms = 0;
    if (!bencode_dict_get_int(dict, SV_PSZ("jitter-buffer"), &jb_ms)) {
        sv_t jb_str = SV_EMPTY;
        if (bencode_dict_get_str(dict, SV_PSZ("jitter-buffer"), &jb_str) && !SV_IS_EMPTY(jb_str)) {
            jb_ms = atoi(jb_str.data);
        }
    }
    if (jb_ms > 0) {
        req->jitter_buffer_ms = (uint32_t)jb_ms;
    }

    bencode_val_t ice_val = {};
    if (bencode_dict_find(dict, SV_PSZ("ICE"), &ice_val) ||
        bencode_dict_find(dict, SV_PSZ("ice"), &ice_val))
    {
        if (ice_val.type == BENCODE_TYPE_STR) {
            if (sv_equals(ice_val.str, SV_PSZ("force")) ||
                sv_equals(ice_val.str, SV_PSZ("offer")) || sv_equals(ice_val.str, SV_PSZ("accept")))
            {
                req->force_ice = true;
            } else if (
                sv_equals(ice_val.str, SV_PSZ("remove")) || sv_equals(ice_val.str, SV_PSZ("strip")))
            {
                req->strip_ice = true;
            }
        }
    }

    bencode_val_t proto_val = {};
    if (bencode_dict_find(dict, SV_PSZ("transport-protocol"), &proto_val) ||
        bencode_dict_find(dict, SV_PSZ("transport protocol"), &proto_val))
    {
        if (proto_val.type == BENCODE_TYPE_STR) {
            if (sv_equals(proto_val.str, SV_PSZ("RTP/SAVP")) ||
                sv_equals(proto_val.str, SV_PSZ("RTP/SAVPF")))
            {
                req->want_savp = true;
            } else if (
                sv_equals(proto_val.str, SV_PSZ("UDP/TLS/RTP/SAVPF")) ||
                sv_equals(proto_val.str, SV_PSZ("UDP/TLS/RTP/SAVP")))
            {
                req->want_savp = true;
                req->force_ice = true;
            } else if (sv_equals(proto_val.str, SV_PSZ("RTP/AVP"))) {
                req->sdes_off  = true;
                req->want_savp = false;
            }
            auto const plen = (proto_val.str.length < (sizeof(req->transport_proto) - 1))
                                  ? proto_val.str.length
                                  : (sizeof(req->transport_proto) - 1);
            __builtin_memcpy(req->transport_proto, proto_val.str.data, plen);
            req->transport_proto[plen] = '\0';
            req->has_transport         = true;
        }
    }

    bencode_val_t mux_val = {};
    if (bencode_dict_find(dict, SV_PSZ("rtcp-mux"), &mux_val)) {
        if (mux_val.type == BENCODE_TYPE_LIST) {
            if (bencode_list_contains_str(mux_val.raw, SV_PSZ("reject"))) {
                req->want_rtcp_mux = false;
            } else if (
                bencode_list_contains_str(mux_val.raw, SV_PSZ("offer")) ||
                bencode_list_contains_str(mux_val.raw, SV_PSZ("require")) ||
                bencode_list_contains_str(mux_val.raw, SV_PSZ("accept")))
            {
                req->want_rtcp_mux = true;
            }
        } else if (mux_val.type == BENCODE_TYPE_STR) {
            if (sv_equals(mux_val.str, SV_PSZ("reject"))) {
                req->want_rtcp_mux = false;
            } else if (
                sv_equals(mux_val.str, SV_PSZ("offer")) ||
                sv_equals(mux_val.str, SV_PSZ("require")) ||
                sv_equals(mux_val.str, SV_PSZ("accept")))
            {
                req->want_rtcp_mux = true;
            }
        }
    }

    bencode_val_t rep_val = {};
    if (bencode_dict_find(dict, SV_PSZ("replace"), &rep_val)) {
        if (rep_val.type == BENCODE_TYPE_LIST) {
            req->replace_origin = bencode_list_contains_str(rep_val.raw, SV_PSZ("origin"));
            req->replace_session_conn =
                bencode_list_contains_str(rep_val.raw, SV_PSZ("session-connection"));
        } else if (rep_val.type == BENCODE_TYPE_STR) {
            if (sv_equals(rep_val.str, SV_PSZ("origin"))) {
                req->replace_origin = true;
            } else if (sv_equals(rep_val.str, SV_PSZ("session-connection"))) {
                req->replace_session_conn = true;
            }
        }
    }

    return true;
}

bool ng_execute_negotiation(
    ng_call_req_t const *restrict const req,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b) {
    if (unlikely(
            (req == nullptr) || (session_table == nullptr) || (call_table == nullptr) ||
            (b == nullptr)))
    {
        return false;
    }

    sdp_session_t sdp_session = {};
    if (!sdp_parse(req->sdp, &sdp_session)) {
        ng_write_header_cookie(b, req->cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
               bencode_write_kv_str(b, "error-reason", "SDP parse failed") &&
               bencode_write_dict_end(b);
    }

    ng_call_t *call = nullptr;
    if (req->is_offer) {
        call = ng_call_find_or_create(call_table, req->call_id, req->from_tag);
        if (call == nullptr) {
            ng_write_header_cookie(b, req->cookie);
            return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
                   bencode_write_kv_str(b, "error-reason", "Call limit reached") &&
                   bencode_write_dict_end(b);
        }
    } else {
        call = ng_call_find(call_table, req->call_id);
        if (call == nullptr) {
            ng_write_header_cookie(b, req->cookie);
            return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
                   bencode_write_kv_str(b, "error-reason", "Call not found") &&
                   bencode_write_dict_end(b);
        }
        auto const tag_len = (req->to_tag.length < sizeof(call->to_tag) - 1)
                                 ? req->to_tag.length
                                 : sizeof(call->to_tag) - 1;
        __builtin_memcpy(call->to_tag, req->to_tag.data, tag_len);
        call->to_tag[tag_len] = '\0';
        call->has_to_tag      = true;
    }

    if (req->jitter_buffer_ms > 0) {
        call->jitter_buffer_ms = req->jitter_buffer_ms;
    }

    bool want_rtcp_mux = req->want_rtcp_mux || sdp_session.has_rtcp_mux;
    if (!req->is_offer) {
        want_rtcp_mux = (call->caller_rtcp_mux && sdp_session.has_rtcp_mux) || req->want_rtcp_mux;
    }

    if (req->is_offer) {
        call->caller_rtcp_mux = want_rtcp_mux;
    } else {
        call->callee_rtcp_mux = want_rtcp_mux;
    }

    // SRTP / SDES key management
    bool const has_srtp = (sdp_session.is_savp || sdp_session.has_crypto);
    if (req->is_offer) {
        if (has_srtp) {
            call->caller_use_srtp     = true;
            call->caller_crypto_suite = (sdp_session.has_crypto && (sdp_session.crypto_count > 0))
                                            ? sdp_session.crypto_attrs[0].suite
                                            : SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80;
            if (sdp_session.has_crypto && (sdp_session.crypto_count > 0)) {
                call->caller_inbound_key_len = sdp_session.crypto_attrs[0].master_key_len;
                __builtin_memcpy(
                    call->caller_inbound_key,
                    sdp_session.crypto_attrs[0].master_key,
                    sdp_session.crypto_attrs[0].master_key_len);
            }
            if (call->caller_outbound_key_len == 0) {
                size_t b64_len = 0;
                (void)sdes_generate_key(
                    call->caller_crypto_suite,
                    call->caller_outbound_key,
                    sizeof(call->caller_outbound_key),
                    &(call->caller_outbound_key_len),
                    call->caller_outbound_b64,
                    sizeof(call->caller_outbound_b64),
                    &b64_len);
            }
        }

        if (req->sdes_off) {
            call->callee_use_srtp = false;
        } else if (req->want_savp || has_srtp) {
            call->callee_use_srtp     = true;
            call->callee_crypto_suite = call->caller_use_srtp
                                            ? call->caller_crypto_suite
                                            : SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80;
            if (call->callee_outbound_key_len == 0) {
                size_t b64_len = 0;
                (void)sdes_generate_key(
                    call->callee_crypto_suite,
                    call->callee_outbound_key,
                    sizeof(call->callee_outbound_key),
                    &(call->callee_outbound_key_len),
                    call->callee_outbound_b64,
                    sizeof(call->callee_outbound_b64),
                    &b64_len);
            }
        }
    } else {
        // Answer SRTP handling
        if (has_srtp) {
            call->callee_use_srtp     = true;
            call->callee_crypto_suite = (sdp_session.has_crypto && (sdp_session.crypto_count > 0))
                                            ? sdp_session.crypto_attrs[0].suite
                                            : SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80;
            if (sdp_session.has_crypto && (sdp_session.crypto_count > 0)) {
                call->callee_inbound_key_len = sdp_session.crypto_attrs[0].master_key_len;
                __builtin_memcpy(
                    call->callee_inbound_key,
                    sdp_session.crypto_attrs[0].master_key,
                    sdp_session.crypto_attrs[0].master_key_len);
            }
        }
        if (req->sdes_off) {
            call->callee_use_srtp = false;
        } else if (req->want_savp) {
            call->callee_use_srtp = true;
        }
        if (call->callee_use_srtp && (call->callee_outbound_key_len == 0)) {
            size_t b64_len = 0;
            (void)sdes_generate_key(
                call->callee_crypto_suite,
                call->callee_outbound_key,
                sizeof(call->callee_outbound_key),
                &(call->callee_outbound_key_len),
                call->callee_outbound_b64,
                sizeof(call->callee_outbound_b64),
                &b64_len);
        }
        if (call->caller_use_srtp && (call->caller_outbound_key_len == 0)) {
            size_t b64_len = 0;
            (void)sdes_generate_key(
                call->caller_crypto_suite,
                call->caller_outbound_key,
                sizeof(call->caller_outbound_key),
                &(call->caller_outbound_key_len),
                call->caller_outbound_b64,
                sizeof(call->caller_outbound_b64),
                &b64_len);
        }
    }

    // ICE / WebRTC initialization
    if (req->is_offer) {
        if (sdp_session.is_webrtc) {
            call->caller_is_webrtc = true;
            call->caller_rtcp_mux  = true;
            want_rtcp_mux          = true;
            if (sdp_session.has_ice) {
                auto const ulen  = __builtin_strlen(sdp_session.ice_ufrag);
                auto const ucopy = (ulen < sizeof(call->caller_ice_ufrag) - 1)
                                       ? ulen
                                       : sizeof(call->caller_ice_ufrag) - 1;
                __builtin_memcpy(call->caller_ice_ufrag, sdp_session.ice_ufrag, ucopy);
                call->caller_ice_ufrag[ucopy] = '\0';

                auto const plen  = __builtin_strlen(sdp_session.ice_pwd);
                auto const pcopy = (plen < sizeof(call->caller_ice_pwd) - 1)
                                       ? plen
                                       : sizeof(call->caller_ice_pwd) - 1;
                __builtin_memcpy(call->caller_ice_pwd, sdp_session.ice_pwd, pcopy);
                call->caller_ice_pwd[pcopy] = '\0';
            }
        }
        if (call->local_ice_ufrag[0] == '\0') {
            (void)snprintf(
                call->local_ice_ufrag,
                sizeof(call->local_ice_ufrag),
                "urtp%08x",
                (unsigned int)call->created_ts);
            (void)snprintf(
                call->local_ice_pwd,
                sizeof(call->local_ice_pwd),
                "urtp_pwd_%016lx",
                (unsigned long)call->created_ts);
        }
    } else {
        if (sdp_session.is_webrtc || (req->force_ice && !req->strip_ice)) {
            call->callee_is_webrtc = true;
            call->callee_rtcp_mux  = true;
            want_rtcp_mux          = true;
            if (sdp_session.has_ice) {
                auto const ulen  = __builtin_strlen(sdp_session.ice_ufrag);
                auto const ucopy = (ulen < sizeof(call->callee_ice_ufrag) - 1)
                                       ? ulen
                                       : sizeof(call->callee_ice_ufrag) - 1;
                __builtin_memcpy(call->callee_ice_ufrag, sdp_session.ice_ufrag, ucopy);
                call->callee_ice_ufrag[ucopy] = '\0';

                auto const plen  = __builtin_strlen(sdp_session.ice_pwd);
                auto const pcopy = (plen < sizeof(call->callee_ice_pwd) - 1)
                                       ? plen
                                       : sizeof(call->callee_ice_pwd) - 1;
                __builtin_memcpy(call->callee_ice_pwd, sdp_session.ice_pwd, pcopy);
                call->callee_ice_pwd[pcopy] = '\0';
            }
        }
    }

    bool const is_multi = (sdp_session.stream_count > 1) || (call->stream_count > 1);

    if (req->is_offer) {
        call->stream_count = sdp_session.stream_count;
        call->is_bundled   = sdp_session.has_bundle;
        for (size_t i = 0; i < sdp_session.stream_count; ++i) {
            call->streams[i].active            = true;
            call->streams[i].type              = sdp_session.streams[i].type;
            call->streams[i].caller_media_port = sdp_session.streams[i].port;
            call->streams[i].rtcp_mux          = sdp_session.streams[i].rtcp_mux || want_rtcp_mux;
            call->streams[i].pt_count          = sdp_session.streams[i].payload_type_count;
            for (size_t p = 0; p < sdp_session.streams[i].payload_type_count; ++p) {
                call->streams[i].payload_types[p] = sdp_session.streams[i].payload_types[p];
            }
        }
        auto const iplen = __builtin_strlen(sdp_session.connection_ip);
        auto const copy_len =
            (iplen < sizeof(call->caller_ip) - 1) ? iplen : sizeof(call->caller_ip) - 1;
        __builtin_memcpy(call->caller_ip, sdp_session.connection_ip, copy_len);
        call->caller_ip[copy_len] = '\0';
        call->caller_media_port = (sdp_session.stream_count > 0) ? sdp_session.streams[0].port : 0;

        bool const callee_is_webrtc = (req->force_ice && !req->strip_ice);
        call->callee_is_webrtc      = callee_is_webrtc;

        if (call->caller_port == 0) {
            if (callee_is_webrtc && is_multi) {
                // Multi-stream bundled WebRTC callee
                uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                if (port == 0) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                           bencode_write_dict_end(b);
                }
                call->caller_port = port;
                for (size_t i = 0; i < call->stream_count; ++i) {
                    call->streams[i].caller_port = port;
                }
                auto const session = session_create(
                    session_table,
                    "0.0.0.0",
                    port,
                    sdp_session.connection_ip,
                    (sdp_session.stream_count > 0) ? sdp_session.streams[0].port : 0);
                if (session == nullptr) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Session creation failed") &&
                           bencode_write_dict_end(b);
                }
                session_set_rtcp_mux(session, true);
                if (!req->trust_address) {
                    session_enable_latching(session, true, false);
                }
                (void)session_enable_dtls(session, DTLS_ROLE_SERVER);
                session_set_ice_credentials(session, call->local_ice_ufrag, call->local_ice_pwd);
                session->is_webrtc = true;
                if (call->caller_use_srtp && (call->caller_inbound_key_len > 0)) {
                    (void)session_set_inbound_srtp(
                        session,
                        call->caller_crypto_suite,
                        call->caller_inbound_key,
                        call->caller_inbound_key_len);
                }
                if (call->caller_use_srtp && (call->caller_outbound_key_len > 0)) {
                    (void)session_set_outbound_srtp(
                        session,
                        call->caller_crypto_suite,
                        call->caller_outbound_key,
                        call->caller_outbound_key_len);
                }
                auto const sidx = session_get_index(session_table, session);
                if ((sidx >= 0) && (engine != nullptr)) {
                    (void)session_arm_multishot(session, (size_t)sidx, engine);
                }
                if (req->record_call && (session_table != nullptr) &&
                    session_table->pcap_table.enabled && (call->record_idx < 0))
                {
                    call->record_idx =
                        pcap_recorder_start(&(session_table->pcap_table), call->call_id, port, 0);
                    if (call->record_idx >= 0) {
                        session->record_idx = call->record_idx;
                    }
                }
            } else {
                // Discrete port allocation (per-stream for multi-stream, or single stream)
                for (size_t i = 0; i < call->stream_count; ++i) {
                    uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                    if (port == 0) {
                        ng_write_header_cookie(b, req->cookie);
                        return bencode_write_dict_start(b) &&
                               bencode_write_kv_str(b, "result", "error") &&
                               bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                               bencode_write_dict_end(b);
                    }
                    call->streams[i].caller_port = port;
                    if (i == 0) {
                        call->caller_port = port;
                    }
                    auto const session = session_create(
                        session_table,
                        "0.0.0.0",
                        port,
                        sdp_session.connection_ip,
                        sdp_session.streams[i].port);
                    if (session == nullptr) {
                        ng_write_header_cookie(b, req->cookie);
                        return bencode_write_dict_start(b) &&
                               bencode_write_kv_str(b, "result", "error") &&
                               bencode_write_kv_str(b, "error-reason", "Session creation failed") &&
                               bencode_write_dict_end(b);
                    }
                    session->media_type = sdp_session.streams[i].type;
                    if (want_rtcp_mux || call->streams[i].rtcp_mux) {
                        session_set_rtcp_mux(session, true);
                    }
                    if (!req->trust_address) {
                        session_enable_latching(session, true, false);
                    }
                    if (call->caller_is_webrtc) {
                        (void)session_enable_dtls(session, DTLS_ROLE_SERVER);
                        session_set_ice_credentials(
                            session,
                            call->local_ice_ufrag,
                            call->local_ice_pwd);
                        session->is_webrtc = true;
                    }
                    if (call->caller_use_srtp && (call->caller_inbound_key_len > 0)) {
                        (void)session_set_inbound_srtp(
                            session,
                            call->caller_crypto_suite,
                            call->caller_inbound_key,
                            call->caller_inbound_key_len);
                    }
                    if (call->caller_use_srtp && (call->caller_outbound_key_len > 0)) {
                        (void)session_set_outbound_srtp(
                            session,
                            call->caller_crypto_suite,
                            call->caller_outbound_key,
                            call->caller_outbound_key_len);
                    }
                    auto const sidx = session_get_index(session_table, session);
                    if ((sidx >= 0) && (engine != nullptr)) {
                        (void)session_arm_multishot(session, (size_t)sidx, engine);
                    }
                    if (req->record_call && (session_table != nullptr) &&
                        session_table->pcap_table.enabled && (call->record_idx < 0))
                    {
                        call->record_idx = pcap_recorder_start(
                            &(session_table->pcap_table),
                            call->call_id,
                            port,
                            0);
                        if (call->record_idx >= 0) {
                            session->record_idx = call->record_idx;
                        }
                    }
                }
            }
        }

        // Configure transcoding if default configured
        auto const caller_sess = session_find_by_port(session_table, call->caller_port);
        if (caller_sess != nullptr) {
            if ((session_table->default_transcoder != TRANSCODER_BACKEND_NONE) &&
                (session_table->default_transcode_codec != MEDIA_CODEC_NONE))
            {
                media_codec_t in_codec = MEDIA_CODEC_PCMU;
                if ((sdp_session.stream_count > 0) &&
                    (sdp_session.streams[0].payload_type_count > 0))
                {
                    uint8_t const pt = sdp_session.streams[0].payload_types[0];
                    if (pt == 0)
                        in_codec = MEDIA_CODEC_PCMU;
                    else if (pt == 8)
                        in_codec = MEDIA_CODEC_PCMA;
                    else if ((pt >= 96) && (pt <= 127))
                        in_codec = MEDIA_CODEC_OPUS;
                }
                (void)session_set_transcode(
                    caller_sess,
                    session_table->default_transcoder,
                    in_codec,
                    session_table->default_transcode_codec);
            }
            if ((call->jitter_buffer_ms > 0) && caller_sess->transcode_enabled) {
                (void)session_set_jitter_buffer(caller_sess, call->jitter_buffer_ms);
            }
        }

        // Rewrite SDP for callee
        char               sdp_buf[4096] = {};
        size_t             sdp_len       = 0;
        sdp_rewrite_opts_t opts          = {
                     .new_ip                  = call_table->media_ip,
                     .bundle_into_single_port = callee_is_webrtc,
                     .strip_simulcast         = true,
                     .enable_rtcp_mux         = want_rtcp_mux,
        };

        for (size_t i = 0; i < call->stream_count; ++i) {
            if (call->streams[i].type == SDP_MEDIA_AUDIO) {
                opts.audio_port = call->streams[i].caller_port;
            } else if (call->streams[i].type == SDP_MEDIA_VIDEO) {
                opts.video_port = call->streams[i].caller_port;
            }
        }
        if (opts.audio_port == 0) {
            opts.audio_port = call->caller_port;
        }
        if (opts.video_port == 0) {
            opts.video_port = opts.audio_port;
        }

        if (callee_is_webrtc) {
            opts.add_ice          = true;
            opts.ice_ufrag        = call->local_ice_ufrag;
            opts.ice_pwd          = call->local_ice_pwd;
            opts.add_dtls         = true;
            opts.dtls_fingerprint = urtp_dtls_get_fingerprint();
            opts.dtls_setup =
                req->dtls_active ? "active" : (req->dtls_passive ? "passive" : "actpass");
            opts.set_transport   = true;
            opts.transport_proto = "UDP/TLS/RTP/SAVPF";
            opts.strip_crypto    = true;
        } else {
            opts.strip_ice  = true;
            opts.strip_dtls = true;
            if (call->callee_use_srtp) {
                opts.add_crypto      = true;
                opts.crypto_suite    = call->callee_crypto_suite;
                opts.crypto_b64_key  = call->callee_outbound_b64;
                opts.set_transport   = true;
                opts.transport_proto = "RTP/SAVP";
            } else {
                opts.strip_crypto    = true;
                opts.set_transport   = true;
                opts.transport_proto = "RTP/AVP";
            }
        }

        if (!sdp_rewrite_opts(req->sdp, &opts, sdp_buf, sizeof(sdp_buf), &sdp_len)) {
            ng_write_header_cookie(b, req->cookie);
            return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
                   bencode_write_kv_str(b, "error-reason", "SDP rewrite buffer overflow") &&
                   bencode_write_dict_end(b);
        }

        ng_write_header_cookie(b, req->cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "ok") &&
               bencode_write_kv_sv(b, "sdp", SV_INIT(sdp_buf, sdp_len)) &&
               bencode_write_dict_end(b);

    } else {
        // Answer handling
        auto const ciplen = __builtin_strlen(sdp_session.connection_ip);
        auto const ccopy_len =
            (ciplen < sizeof(call->callee_ip) - 1) ? ciplen : sizeof(call->callee_ip) - 1;
        __builtin_memcpy(call->callee_ip, sdp_session.connection_ip, ccopy_len);
        call->callee_ip[ccopy_len] = '\0';

        for (size_t i = 0; i < sdp_session.stream_count; ++i) {
            for (size_t s = 0; s < call->stream_count; ++s) {
                if (call->streams[s].type == sdp_session.streams[i].type) {
                    call->streams[s].callee_media_port = sdp_session.streams[i].port;
                    break;
                }
            }
        }

        size_t audio_idx = 0;
        size_t video_idx = 0;
        bool   has_audio = false;
        bool   has_video = false;
        for (size_t i = 0; i < call->stream_count; ++i) {
            if (call->streams[i].type == SDP_MEDIA_AUDIO) {
                audio_idx = i;
                has_audio = true;
            } else if (call->streams[i].type == SDP_MEDIA_VIDEO) {
                video_idx = i;
                has_video = true;
            }
        }

        if (is_multi && call->caller_is_webrtc && !(call->callee_is_webrtc)) {
            // WebRTC Caller (bundled) <-> SIP Callee (unbundled dual ports)
            if (call->callee_port == 0) {
                uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                if (port == 0) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                           bencode_write_dict_end(b);
                }
                call->callee_port = port;
                for (size_t i = 0; i < call->stream_count; ++i) {
                    call->streams[i].callee_port = port;
                }

                auto const s_bundle = session_create(
                    session_table,
                    "0.0.0.0",
                    port,
                    call->caller_ip,
                    call->streams[0].caller_media_port);
                if (s_bundle == nullptr) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Session creation failed") &&
                           bencode_write_dict_end(b);
                }

                session_set_rtcp_mux(s_bundle, true);
                if (!req->trust_address) {
                    session_enable_latching(s_bundle, true, false);
                }
                auto const role = req->dtls_active ? DTLS_ROLE_CLIENT : DTLS_ROLE_SERVER;
                (void)session_enable_dtls(s_bundle, role);
                session_set_ice_credentials(s_bundle, call->local_ice_ufrag, call->local_ice_pwd);
                s_bundle->is_webrtc = true;

                if (call->caller_use_srtp && (call->caller_inbound_key_len > 0)) {
                    (void)session_set_inbound_srtp(
                        s_bundle,
                        call->caller_crypto_suite,
                        call->caller_inbound_key,
                        call->caller_inbound_key_len);
                }
                if (call->caller_use_srtp && (call->caller_outbound_key_len > 0)) {
                    (void)session_set_outbound_srtp(
                        s_bundle,
                        call->caller_crypto_suite,
                        call->caller_outbound_key,
                        call->caller_outbound_key_len);
                }

                auto const b_idx = session_get_index(session_table, s_bundle);
                if ((b_idx >= 0) && (engine != nullptr)) {
                    (void)session_arm_multishot(s_bundle, (size_t)b_idx, engine);
                }
                if (call->record_idx >= 0) {
                    s_bundle->record_idx = call->record_idx;
                }

                relay_session_t *s_audio = nullptr;
                relay_session_t *s_video = nullptr;
                if (has_audio) {
                    s_audio =
                        session_find_by_port(session_table, call->streams[audio_idx].caller_port);
                }
                if (has_video) {
                    s_video =
                        session_find_by_port(session_table, call->streams[video_idx].caller_port);
                }

                if (s_audio != nullptr) {
                    s_audio->dest_port = call->streams[audio_idx].callee_media_port;
                    __builtin_memcpy(s_audio->dest_ip, call->callee_ip, sizeof(s_audio->dest_ip));
                    (void)udp_parse_endpoint(
                        s_audio->dest_ip,
                        s_audio->dest_port,
                        &(s_audio->dest_addr),
                        &(s_audio->dest_addr_len));
                    (void)
                        session_bridge_pair(session_table, s_audio->bind_port, s_bundle->bind_port);
                    int32_t const a_idx = (int32_t)session_get_index(session_table, s_audio);
                    for (size_t p = 0; p < call->streams[audio_idx].pt_count; ++p) {
                        (void)session_add_route(
                            s_bundle,
                            0,
                            call->streams[audio_idx].payload_types[p],
                            SDP_MEDIA_AUDIO,
                            a_idx);
                    }
                }
                if (s_video != nullptr) {
                    s_video->dest_port = call->streams[video_idx].callee_media_port;
                    __builtin_memcpy(s_video->dest_ip, call->callee_ip, sizeof(s_video->dest_ip));
                    (void)udp_parse_endpoint(
                        s_video->dest_ip,
                        s_video->dest_port,
                        &(s_video->dest_addr),
                        &(s_video->dest_addr_len));
                    s_video->peer_idx             = (int32_t)b_idx;
                    s_video->shared_outbound_srtp = &(s_bundle->outbound_srtp);
                    s_video->media_type           = SDP_MEDIA_VIDEO;
                    int32_t const v_idx = (int32_t)session_get_index(session_table, s_video);
                    for (size_t p = 0; p < call->streams[video_idx].pt_count; ++p) {
                        (void)session_add_route(
                            s_bundle,
                            0,
                            call->streams[video_idx].payload_types[p],
                            SDP_MEDIA_VIDEO,
                            v_idx);
                    }
                }
            }
        } else if (is_multi && !(call->caller_is_webrtc) && call->callee_is_webrtc) {
            // SIP Caller (unbundled dual ports) <-> WebRTC Callee (bundled)
            if (call->callee_port == 0) {
                for (size_t i = 0; i < call->stream_count; ++i) {
                    uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                    if (port == 0) {
                        ng_write_header_cookie(b, req->cookie);
                        return bencode_write_dict_start(b) &&
                               bencode_write_kv_str(b, "result", "error") &&
                               bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                               bencode_write_dict_end(b);
                    }
                    call->streams[i].callee_port = port;
                    if (i == 0) {
                        call->callee_port = port;
                    }
                    auto const session = session_create(
                        session_table,
                        "0.0.0.0",
                        port,
                        call->caller_ip,
                        call->streams[i].caller_media_port);
                    if (session == nullptr) {
                        ng_write_header_cookie(b, req->cookie);
                        return bencode_write_dict_start(b) &&
                               bencode_write_kv_str(b, "result", "error") &&
                               bencode_write_kv_str(b, "error-reason", "Session creation failed") &&
                               bencode_write_dict_end(b);
                    }
                    session->media_type = call->streams[i].type;
                    if (want_rtcp_mux) {
                        session_set_rtcp_mux(session, true);
                    }
                    if (!req->trust_address) {
                        session_enable_latching(session, true, false);
                    }
                    if (call->caller_use_srtp && (call->caller_inbound_key_len > 0)) {
                        (void)session_set_inbound_srtp(
                            session,
                            call->caller_crypto_suite,
                            call->caller_inbound_key,
                            call->caller_inbound_key_len);
                    }
                    if (call->caller_use_srtp && (call->caller_outbound_key_len > 0)) {
                        (void)session_set_outbound_srtp(
                            session,
                            call->caller_crypto_suite,
                            call->caller_outbound_key,
                            call->caller_outbound_key_len);
                    }
                    auto const sidx = session_get_index(session_table, session);
                    if ((sidx >= 0) && (engine != nullptr)) {
                        (void)session_arm_multishot(session, (size_t)sidx, engine);
                    }
                    if (call->record_idx >= 0) {
                        session->record_idx = call->record_idx;
                    }
                }

                auto const s_bundle = session_find_by_port(session_table, call->caller_port);
                if (s_bundle != nullptr) {
                    s_bundle->dest_port =
                        (sdp_session.stream_count > 0) ? sdp_session.streams[0].port : 0;
                    __builtin_memcpy(s_bundle->dest_ip, call->callee_ip, sizeof(s_bundle->dest_ip));
                    (void)udp_parse_endpoint(
                        s_bundle->dest_ip,
                        s_bundle->dest_port,
                        &(s_bundle->dest_addr),
                        &(s_bundle->dest_addr_len));
                    if (call->callee_use_srtp && (call->callee_inbound_key_len > 0)) {
                        (void)session_set_inbound_srtp(
                            s_bundle,
                            call->callee_crypto_suite,
                            call->callee_inbound_key,
                            call->callee_inbound_key_len);
                    }
                    if (call->callee_use_srtp && (call->callee_outbound_key_len > 0)) {
                        (void)session_set_outbound_srtp(
                            s_bundle,
                            call->callee_crypto_suite,
                            call->callee_outbound_key,
                            call->callee_outbound_key_len);
                    }

                    relay_session_t *s_audio = nullptr;
                    relay_session_t *s_video = nullptr;
                    if (has_audio) {
                        s_audio = session_find_by_port(
                            session_table,
                            call->streams[audio_idx].callee_port);
                    }
                    if (has_video) {
                        s_video = session_find_by_port(
                            session_table,
                            call->streams[video_idx].callee_port);
                    }

                    if (s_audio != nullptr) {
                        (void)session_bridge_pair(
                            session_table,
                            s_audio->bind_port,
                            s_bundle->bind_port);
                        int32_t const a_idx = (int32_t)session_get_index(session_table, s_audio);
                        if (has_audio && (audio_idx < sdp_session.stream_count)) {
                            for (size_t p = 0;
                                 p < sdp_session.streams[audio_idx].payload_type_count;
                                 ++p)
                            {
                                (void)session_add_route(
                                    s_bundle,
                                    0,
                                    sdp_session.streams[audio_idx].payload_types[p],
                                    SDP_MEDIA_AUDIO,
                                    a_idx);
                            }
                        }
                    }
                    if (s_video != nullptr) {
                        s_video->peer_idx = (int32_t)session_get_index(session_table, s_bundle);
                        s_video->shared_outbound_srtp = &(s_bundle->outbound_srtp);
                        s_video->media_type           = SDP_MEDIA_VIDEO;
                        int32_t const v_idx = (int32_t)session_get_index(session_table, s_video);
                        if (has_video && (video_idx < sdp_session.stream_count)) {
                            for (size_t p = 0;
                                 p < sdp_session.streams[video_idx].payload_type_count;
                                 ++p)
                            {
                                (void)session_add_route(
                                    s_bundle,
                                    0,
                                    sdp_session.streams[video_idx].payload_types[p],
                                    SDP_MEDIA_VIDEO,
                                    v_idx);
                            }
                        }
                    }
                }
            }
        } else if (is_multi && !(call->caller_is_webrtc) && !(call->callee_is_webrtc)) {
            // Both unbundled SIP
            if (call->callee_port == 0) {
                for (size_t i = 0; i < call->stream_count; ++i) {
                    uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                    if (port == 0) {
                        ng_write_header_cookie(b, req->cookie);
                        return bencode_write_dict_start(b) &&
                               bencode_write_kv_str(b, "result", "error") &&
                               bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                               bencode_write_dict_end(b);
                    }
                    call->streams[i].callee_port = port;
                    if (i == 0) {
                        call->callee_port = port;
                    }
                    auto const session = session_create(
                        session_table,
                        "0.0.0.0",
                        port,
                        call->caller_ip,
                        call->streams[i].caller_media_port);
                    if (session != nullptr) {
                        session->media_type = call->streams[i].type;
                        auto const sidx     = session_get_index(session_table, session);
                        if ((sidx >= 0) && (engine != nullptr)) {
                            (void)session_arm_multishot(session, (size_t)sidx, engine);
                        }
                        (void)
                            session_bridge_pair(session_table, call->streams[i].caller_port, port);
                    }
                }
            }
        } else if (is_multi) {
            // Both bundled WebRTC
            if (call->callee_port == 0) {
                uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                call->callee_port   = port;
                for (size_t i = 0; i < call->stream_count; ++i) {
                    call->streams[i].callee_port = port;
                }
                auto const session = session_create(
                    session_table,
                    "0.0.0.0",
                    port,
                    call->caller_ip,
                    call->streams[0].caller_media_port);
                if (session != nullptr) {
                    session->is_webrtc = true;
                    auto const sidx    = session_get_index(session_table, session);
                    if ((sidx >= 0) && (engine != nullptr)) {
                        (void)session_arm_multishot(session, (size_t)sidx, engine);
                    }
                    (void)session_bridge_pair(session_table, call->caller_port, port);
                }
            }
        } else {
            // Standard single-stream session creation
            if (call->callee_port == 0) {
                uint16_t const port = ng_call_table_alloc_port(call_table, session_table);
                if (port == 0) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Port exhaustion") &&
                           bencode_write_dict_end(b);
                }
                auto const session = session_create(
                    session_table,
                    "0.0.0.0",
                    port,
                    sdp_session.connection_ip,
                    sdp_session.media_port);
                if (session == nullptr) {
                    ng_write_header_cookie(b, req->cookie);
                    return bencode_write_dict_start(b) &&
                           bencode_write_kv_str(b, "result", "error") &&
                           bencode_write_kv_str(b, "error-reason", "Session creation failed") &&
                           bencode_write_dict_end(b);
                }

                call->callee_rtcp_mux = want_rtcp_mux;
                if (want_rtcp_mux) {
                    session_set_rtcp_mux(session, true);
                }
                if (!req->trust_address) {
                    session_enable_latching(session, true, false);
                }
                if (call->callee_is_webrtc) {
                    auto const role = req->dtls_active ? DTLS_ROLE_CLIENT : DTLS_ROLE_SERVER;
                    (void)session_enable_dtls(session, role);
                    session_set_ice_credentials(
                        session,
                        call->local_ice_ufrag,
                        call->local_ice_pwd);
                    session->is_webrtc = true;
                }
                if (call->callee_use_srtp && (call->callee_inbound_key_len > 0)) {
                    (void)session_set_inbound_srtp(
                        session,
                        call->callee_crypto_suite,
                        call->callee_inbound_key,
                        call->callee_inbound_key_len);
                }
                if (call->callee_use_srtp && (call->callee_outbound_key_len > 0)) {
                    (void)session_set_outbound_srtp(
                        session,
                        call->callee_crypto_suite,
                        call->callee_outbound_key,
                        call->callee_outbound_key_len);
                }
                auto const sidx = session_get_index(session_table, session);
                if ((sidx >= 0) && (engine != nullptr)) {
                    (void)session_arm_multishot(session, (size_t)sidx, engine);
                }

                call->callee_port       = port;
                call->callee_media_port = sdp_session.media_port;

                // Bridge caller and callee sessions bidirectionally
                (void)session_bridge_pair(session_table, call->caller_port, call->callee_port);
                if (call->record_idx >= 0) {
                    session->record_idx = call->record_idx;
                }
                if ((call->jitter_buffer_ms > 0) && session->transcode_enabled) {
                    (void)session_set_jitter_buffer(session, call->jitter_buffer_ms);
                }
            } else {
                auto const session = session_find_by_port(session_table, call->callee_port);
                if (session != nullptr) {
                    if (call->record_idx >= 0) {
                        session->record_idx = call->record_idx;
                    }
                    if (call->callee_is_webrtc && !(session->dtls_enabled)) {
                        auto const role = req->dtls_active ? DTLS_ROLE_CLIENT : DTLS_ROLE_SERVER;
                        (void)session_enable_dtls(session, role);
                        session_set_ice_credentials(
                            session,
                            call->local_ice_ufrag,
                            call->local_ice_pwd);
                        session->is_webrtc = true;
                    }
                    if (call->callee_use_srtp && (call->callee_inbound_key_len > 0)) {
                        (void)session_set_inbound_srtp(
                            session,
                            call->callee_crypto_suite,
                            call->callee_inbound_key,
                            call->callee_inbound_key_len);
                    }
                    if (call->callee_use_srtp && (call->callee_outbound_key_len > 0)) {
                        (void)session_set_outbound_srtp(
                            session,
                            call->callee_crypto_suite,
                            call->callee_outbound_key,
                            call->callee_outbound_key_len);
                    }
                    if ((call->jitter_buffer_ms > 0) && session->transcode_enabled) {
                        (void)session_set_jitter_buffer(session, call->jitter_buffer_ms);
                    }
                }
            }
        }

        // Configure transcoding if default configured
        auto const callee_sess = session_find_by_port(session_table, call->callee_port);
        if (callee_sess != nullptr) {
            if ((session_table->default_transcoder != TRANSCODER_BACKEND_NONE) &&
                (session_table->default_transcode_codec != MEDIA_CODEC_NONE))
            {
                media_codec_t in_codec = MEDIA_CODEC_PCMU;
                if ((sdp_session.stream_count > 0) &&
                    (sdp_session.streams[0].payload_type_count > 0))
                {
                    uint8_t const pt = sdp_session.streams[0].payload_types[0];
                    if (pt == 0)
                        in_codec = MEDIA_CODEC_PCMU;
                    else if (pt == 8)
                        in_codec = MEDIA_CODEC_PCMA;
                    else if ((pt >= 96) && (pt <= 127))
                        in_codec = MEDIA_CODEC_OPUS;
                }
                (void)session_set_transcode(
                    callee_sess,
                    session_table->default_transcoder,
                    in_codec,
                    session_table->default_transcode_codec);
            }
            if ((call->jitter_buffer_ms > 0) && callee_sess->transcode_enabled) {
                (void)session_set_jitter_buffer(callee_sess, call->jitter_buffer_ms);
            }
        }

        auto const caller_sess = session_find_by_port(session_table, call->caller_port);
        if ((caller_sess != nullptr) && (call->jitter_buffer_ms > 0) &&
            caller_sess->transcode_enabled)
        {
            (void)session_set_jitter_buffer(caller_sess, call->jitter_buffer_ms);
        }

        // Rewrite SDP for caller
        char               sdp_buf[4096] = {};
        size_t             sdp_len       = 0;
        sdp_rewrite_opts_t opts          = {
                     .new_ip                  = call_table->media_ip,
                     .new_port                = call->callee_port,
                     .bundle_into_single_port = call->caller_is_webrtc,
                     .strip_simulcast         = true,
                     .enable_rtcp_mux         = call->callee_rtcp_mux,
        };

        if (has_audio) {
            opts.audio_port = call->streams[audio_idx].callee_port;
        }
        if (has_video) {
            opts.video_port = call->streams[video_idx].callee_port;
        }
        if (opts.audio_port == 0) {
            opts.audio_port = call->callee_port;
        }
        if (opts.video_port == 0) {
            opts.video_port = opts.audio_port;
        }

        if (call->caller_is_webrtc) {
            opts.add_ice          = true;
            opts.ice_ufrag        = call->local_ice_ufrag;
            opts.ice_pwd          = call->local_ice_pwd;
            opts.add_dtls         = true;
            opts.dtls_fingerprint = urtp_dtls_get_fingerprint();
            opts.dtls_setup =
                req->dtls_active ? "active" : (req->dtls_passive ? "passive" : "passive");
            opts.set_transport   = true;
            opts.transport_proto = "UDP/TLS/RTP/SAVPF";
            opts.enable_rtcp_mux = true;
            opts.strip_crypto    = true;
        } else {
            opts.strip_ice  = true;
            opts.strip_dtls = true;
            if (call->caller_use_srtp) {
                opts.add_crypto      = true;
                opts.crypto_tag      = 1;
                opts.crypto_suite    = call->caller_crypto_suite;
                opts.crypto_b64_key  = call->caller_outbound_b64;
                opts.set_transport   = true;
                opts.transport_proto = "RTP/SAVP";
            } else {
                opts.strip_crypto    = true;
                opts.set_transport   = true;
                opts.transport_proto = "RTP/AVP";
            }
        }

        if (!sdp_rewrite_opts(req->sdp, &opts, sdp_buf, sizeof(sdp_buf), &sdp_len)) {
            ng_write_header_cookie(b, req->cookie);
            return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "error") &&
                   bencode_write_kv_str(b, "error-reason", "SDP rewrite buffer overflow") &&
                   bencode_write_dict_end(b);
        }

        ng_write_header_cookie(b, req->cookie);
        return bencode_write_dict_start(b) && bencode_write_kv_str(b, "result", "ok") &&
               bencode_write_kv_sv(b, "sdp", SV_INIT(sdp_buf, sdp_len)) &&
               bencode_write_dict_end(b);
    }
}

bool ng_handle_offer(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b) {
    ng_call_req_t req = {};
    if (!ng_parse_call_req(dict, true, cookie, &req, session_table, b)) {
        return false;
    }
    return ng_execute_negotiation(&req, session_table, call_table, engine, b);
}

bool ng_handle_answer(
    sv_t const cookie,
    sv_t const dict,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    bencode_buf_t *restrict const b) {
    ng_call_req_t req = {};
    if (!ng_parse_call_req(dict, false, cookie, &req, session_table, b)) {
        return false;
    }
    return ng_execute_negotiation(&req, session_table, call_table, engine, b);
}
