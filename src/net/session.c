#include "net/session.h"
#include <stdio.h>
#include <time.h>
#include "core/log.h"
#include "core/macros.h"
#include "net/rtp.h"
#include "net/udp.h"

extern void ng_call_table_remove_by_port(ng_call_table_t *restrict const table, uint16_t const port)
    __attribute__((weak));

void session_table_init(session_table_t *restrict const table) {
    if (unlikely(table == nullptr)) {
        return;
    }
    struct timespec ts = {};
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    *table = (session_table_t){
        .default_transcoder      = TRANSCODER_BACKEND_NONE,
        .default_transcode_codec = MEDIA_CODEC_NONE,
        .default_jitter_delay_ms = 0,
        .jitter_pool             = nullptr,
        .cached_monotonic_sec    = (uint64_t)ts.tv_sec,
        .metrics                 = nullptr,
    };
    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        table->sessions[i].peer_idx   = -1;
        table->sessions[i].record_idx = -1;
        table->sessions[i].table      = table;
    }
    pcap_table_init(&(table->pcap_table));
}

void session_table_destroy(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine) {
    (void)engine;
    if (unlikely(table == nullptr)) {
        return;
    }

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t *const session = &(table->sessions[i]);
        if (session->active) {
            session_clear_transcode(session);
            session_clear_dtls(session);
            session_clear_srtp(session);
            udp_close_socket(session->socket_fd);
            *session = (relay_session_t){.peer_idx = -1, .record_idx = -1, .table = table};
        }
    }
    pcap_table_destroy(&(table->pcap_table));
    if (table->jitter_pool != nullptr) {
        jitter_pool_destroy(table->jitter_pool);
        table->jitter_pool = nullptr;
    }
    table->active_count = 0;
}

relay_session_t *session_create(
    session_table_t *restrict const table,
    char const *const bind_ip,
    uint16_t const    bind_port,
    char const *const dest_ip,
    uint16_t const    dest_port) {
    if (unlikely((table == nullptr) || (table->active_count >= SESSION_TABLE_MAX))) {
        return nullptr;
    }

    // Ensure port is not already bound in session table
    if (unlikely(session_find_by_port(table, bind_port) != nullptr)) {
        return nullptr;
    }

    struct sockaddr_storage dst_addr = {};
    socklen_t               dst_len  = 0;
    bool const              has_dest = (dest_ip != nullptr) && (dest_port > 0);
    if (has_dest) {
        if (unlikely(!udp_parse_endpoint(dest_ip, dest_port, &dst_addr, &dst_len))) {
            return nullptr;
        }
    }

    int const fd = udp_bind_socket(bind_ip, bind_port);
    if (unlikely(fd < 0)) {
        return nullptr;
    }

    // Find free slot
    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t *const session = &(table->sessions[i]);
        if (!(session->active)) {
            *session                    = (relay_session_t){};
            session->socket_fd          = fd;
            session->peer_idx           = -1;
            session->record_idx         = -1;
            session->bind_port          = bind_port;
            session->table              = table;
            session->active             = true;
            session->multishot_armed    = false;
            session->latch_mode         = has_dest ? LATCH_MODE_DISABLED : LATCH_MODE_WAITING;
            session->allow_relatch      = false;
            session->raw_latch          = false;
            session->created_sec        = table->cached_monotonic_sec;
            session->last_activity_sec  = table->cached_monotonic_sec;
            session->inactivity_timeout = 0;

            if (has_dest) {
                session->dest_addr     = dst_addr;
                session->dest_addr_len = dst_len;
                session->dest_port     = dest_port;

                auto const ip_len = __builtin_strlen(dest_ip);
                auto const copy_len =
                    (ip_len < sizeof(session->dest_ip) - 1) ? ip_len : sizeof(session->dest_ip) - 1;
                __builtin_memcpy(session->dest_ip, dest_ip, copy_len);
                session->dest_ip[copy_len] = '\0';

                // Default RTCP destination for non-mux sessions is dest_port + 1
                (void)session_set_rtcp_dest(
                    session,
                    dest_ip,
                    (dest_port < 65535) ? (uint16_t)(dest_port + 1) : dest_port);
            }

            table->active_count++;

            if (table->pcap_table.record_all && table->pcap_table.enabled) {
                session->record_idx =
                    pcap_recorder_start(&(table->pcap_table), nullptr, bind_port, dest_port);
            }

            return session;
        }
    }

    udp_close_socket(fd);
    return nullptr;
}

void session_set_rtcp_mux(relay_session_t *restrict const session, bool const enabled) {
    if (unlikely(session == nullptr)) {
        return;
    }
    session->rtcp_mux = enabled;
    if (enabled) {
        session->rtcp_dest_addr     = session->dest_addr;
        session->rtcp_dest_addr_len = session->dest_addr_len;
        session->rtcp_dest_port     = session->dest_port;
        __builtin_memcpy(session->rtcp_dest_ip, session->dest_ip, sizeof(session->rtcp_dest_ip));
    }
}

bool session_set_rtcp_dest(
    relay_session_t *restrict const session,
    char const *const ip,
    uint16_t const    port) {
    if (unlikely((session == nullptr) || (ip == nullptr) || (port == 0))) {
        return false;
    }
    struct sockaddr_storage addr = {};
    socklen_t               len  = 0;
    if (unlikely(!udp_parse_endpoint(ip, port, &addr, &len))) {
        return false;
    }
    session->rtcp_dest_addr     = addr;
    session->rtcp_dest_addr_len = len;
    session->rtcp_dest_port     = port;
    auto const ip_len           = __builtin_strlen(ip);
    auto const copy_len =
        (ip_len < sizeof(session->rtcp_dest_ip) - 1) ? ip_len : sizeof(session->rtcp_dest_ip) - 1;
    __builtin_memcpy(session->rtcp_dest_ip, ip, copy_len);
    session->rtcp_dest_ip[copy_len] = '\0';
    return true;
}

void session_enable_latching(
    relay_session_t *restrict const session,
    bool const allow_relatch,
    bool const raw_latch) {
    if (unlikely(session == nullptr)) {
        return;
    }
    session->latch_mode    = LATCH_MODE_WAITING;
    session->allow_relatch = allow_relatch;
    session->raw_latch     = raw_latch;
}

void session_latch_endpoint(
    relay_session_t *restrict const session,
    struct sockaddr_storage const *restrict const src_addr,
    socklen_t const src_len) {
    if (unlikely((session == nullptr) || (src_addr == nullptr) || (src_len == 0))) {
        return;
    }

    session->latched_addr     = *src_addr;
    session->latched_addr_len = src_len;
    (void)udp_format_endpoint(
        src_addr,
        session->latched_ip,
        sizeof(session->latched_ip),
        &(session->latched_port));

    // Update forwarding destination to the latched public NAT endpoint
    session->dest_addr     = *src_addr;
    session->dest_addr_len = src_len;
    __builtin_memcpy(session->dest_ip, session->latched_ip, sizeof(session->dest_ip));
    session->dest_port = session->latched_port;

    if (session->rtcp_mux) {
        session->rtcp_dest_addr     = *src_addr;
        session->rtcp_dest_addr_len = src_len;
        session->rtcp_dest_port     = session->latched_port;
        __builtin_memcpy(session->rtcp_dest_ip, session->latched_ip, sizeof(session->rtcp_dest_ip));
    }

    session->latch_mode = LATCH_MODE_LATCHED;
    session->packets_latched++;
}

bool session_bridge_pair(
    session_table_t *restrict const table,
    uint16_t const port_a,
    uint16_t const port_b) {
    if (unlikely((table == nullptr) || (port_a == port_b))) {
        return false;
    }

    auto const session_a = session_find_by_port(table, port_a);
    auto const session_b = session_find_by_port(table, port_b);
    if (unlikely((session_a == nullptr) || (session_b == nullptr))) {
        return false;
    }

    int64_t const idx_a = session_get_index(table, session_a);
    int64_t const idx_b = session_get_index(table, session_b);
    if (unlikely((idx_a < 0) || (idx_b < 0))) {
        return false;
    }

    session_a->peer_idx = (int32_t)idx_b;
    session_b->peer_idx = (int32_t)idx_a;
    if ((session_a->record_idx >= 0) && (session_b->record_idx < 0)) {
        session_b->record_idx = session_a->record_idx;
    } else if ((session_b->record_idx >= 0) && (session_a->record_idx < 0)) {
        session_a->record_idx = session_b->record_idx;
    }
    return true;
}

bool session_unbridge(session_table_t *restrict const table, uint16_t const port) {
    if (unlikely(table == nullptr)) {
        return false;
    }

    auto const session = session_find_by_port(table, port);
    if (unlikely((session == nullptr) || (session->peer_idx < 0))) {
        return false;
    }

    auto const peer = session_find_by_index(table, (size_t)session->peer_idx);
    if (peer != nullptr) {
        peer->peer_idx = -1;
    }
    session->peer_idx = -1;
    return true;
}

relay_session_t *session_find_by_port(session_table_t *restrict const table, uint16_t const port) {
    if (unlikely(table == nullptr)) {
        return nullptr;
    }

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t *const session = &(table->sessions[i]);
        if (session->active && (session->bind_port == port)) {
            return session;
        }
    }
    return nullptr;
}

relay_session_t *session_find_by_index(session_table_t *restrict const table, size_t const index) {
    if (unlikely((table == nullptr) || (index >= SESSION_TABLE_MAX))) {
        return nullptr;
    }
    return &(table->sessions[index]);
}

int64_t session_get_index(
    session_table_t const *restrict const table,
    relay_session_t const *restrict const session) {
    if (unlikely((table == nullptr) || (session == nullptr))) {
        return -1;
    }

    ptrdiff_t const diff = session - table->sessions;
    if ((diff < 0) || ((size_t)diff >= SESSION_TABLE_MAX)) {
        return -1;
    }
    return (int64_t)diff;
}

bool session_delete_by_port(
    session_table_t *restrict const table,
    uint16_t const port,
    ring_engine_t *restrict const engine) {
    (void)engine;
    if (unlikely(table == nullptr)) {
        return false;
    }

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t *const session = &(table->sessions[i]);
        if (session->active && (session->bind_port == port)) {
            if (session->peer_idx >= 0) {
                relay_session_t *const peer = &(table->sessions[session->peer_idx]);
                if (peer->active && (peer->peer_idx == (int32_t)i)) {
                    peer->peer_idx = -1;
                }
            }
            if (session->record_idx >= 0) {
                // If peer is still active and shares record_idx, don't stop yet; otherwise stop
                bool const peer_shares =
                    (session->peer_idx >= 0) && ((size_t)session->peer_idx < SESSION_TABLE_MAX) &&
                    (table->sessions[session->peer_idx].active) &&
                    (table->sessions[session->peer_idx].record_idx == session->record_idx);
                if (!peer_shares) {
                    (void)pcap_recorder_stop_by_index(&(table->pcap_table), session->record_idx);
                }
                session->record_idx = -1;
            }
            session_clear_transcode(session);
            session_clear_dtls(session);
            session_clear_srtp(session);
            udp_close_socket(session->socket_fd);
            *session = (relay_session_t){.peer_idx = -1, .record_idx = -1};
            table->active_count--;
            return true;
        }
    }
    return false;
}

bool session_arm_multishot(
    relay_session_t *restrict const session,
    size_t const session_idx,
    ring_engine_t *restrict const engine) {
    if (unlikely((session == nullptr) || (engine == nullptr) || (session->socket_fd < 0))) {
        return false;
    }

    auto const sqe = ring_engine_get_sqe(engine);
    if (unlikely(sqe == nullptr)) {
        return false;
    }

    session->recv_msghdr = (struct msghdr){
        .msg_namelen = sizeof(struct sockaddr_storage),
    };

    io_uring_prep_recvmsg_multishot(sqe, session->socket_fd, &(session->recv_msghdr), 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = (uint16_t)engine->buf_group_id;

    user_data_tag_t const tag = {
        .fields = {
            .index   = (uint16_t)session_idx,
            .op_type = OP_TYPE_UDP_RECV,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(sqe, tag.raw);
    session->multishot_armed = true;
    return true;
}

typedef struct {
    session_table_t         *table;
    ring_engine_t           *engine;
    relay_session_t         *session;
    relay_session_t         *target_session;
    uint8_t                 *buf;
    uint8_t                 *payload;
    size_t                   payload_len;
    uint64_t                 ingress_bytes;
    uint16_t                 session_idx;
    uint16_t                 target_idx;
    uint16_t                 bid;
    struct sockaddr_storage *src_addr;
    socklen_t                src_addr_len;
    packet_type_t            type;
    sdp_media_type_t         classified_media_type;
    bool                     is_rtp;
    bool                     is_rtcp;
    bool                     is_stun;
    bool                     is_dtls;
    bool                     is_video;
    int                      target_fd;
} rx_packet_flow_t;

static bool flow_init(
    rx_packet_flow_t *restrict const flow,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   session_idx) {
    relay_session_t *const session = &(table->sessions[session_idx]);

    if ((cqe->flags & IORING_CQE_F_MORE) == 0) {
        session->multishot_armed = false;
        (void)session_arm_multishot(session, session_idx, engine);
    }

    if (unlikely(cqe->res <= 0)) {
        session->packets_dropped++;
        if (table->metrics != nullptr) {
            table->metrics->cumulative.packets_dropped++;
        }
        return false;
    }

    if (unlikely((cqe->flags & IORING_CQE_F_BUFFER) == 0)) {
        session->packets_dropped++;
        if (table->metrics != nullptr) {
            table->metrics->cumulative.buffer_ring_exhaustions++;
            table->metrics->cumulative.packets_dropped++;
        }
        return false;
    }

    auto const bid = (uint16_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    if (likely(engine->buf_refcounts != nullptr)) {
        engine->buf_refcounts[bid] = 1;
    }
    uint8_t *const buf = ring_engine_get_buf(engine, bid);
    if (unlikely(buf == nullptr)) {
        session->packets_dropped++;
        if (table->metrics != nullptr) {
            table->metrics->cumulative.packets_dropped++;
        }
        return false;
    }

    struct io_uring_recvmsg_out *const o =
        io_uring_recvmsg_validate(buf, cqe->res, &(session->recv_msghdr));
    if (unlikely(o == nullptr)) {
        ring_engine_recycle_buf(engine, bid);
        session->packets_dropped++;
        if (table->metrics != nullptr) {
            table->metrics->cumulative.packets_dropped++;
        }
        return false;
    }

    void *const        payload = io_uring_recvmsg_payload(o, &(session->recv_msghdr));
    unsigned int const payload_len =
        io_uring_recvmsg_payload_length(o, cqe->res, &(session->recv_msghdr));

    if (unlikely((payload == nullptr) || (payload_len == 0))) {
        ring_engine_recycle_buf(engine, bid);
        return false;
    }

    session->last_activity_sec = table->cached_monotonic_sec;

    packet_type_t const pkt_type = rtp_classify_packet(payload, (size_t)payload_len);
    bool const          is_rtp   = (pkt_type == PACKET_TYPE_RTP);
    bool const          is_rtcp  = (pkt_type == PACKET_TYPE_RTCP);

    if (likely(table->metrics != nullptr)) {
        table->metrics->cumulative.rx_packets++;
        table->metrics->cumulative.rx_bytes += (uint64_t)payload_len;
        if (is_rtp) {
            table->metrics->cumulative.rtp_packets++;
        } else if (is_rtcp) {
            table->metrics->cumulative.rtcp_packets++;
        }
    }

    *flow = (rx_packet_flow_t){
        .table                 = table,
        .engine                = engine,
        .session               = session,
        .target_session        = session,
        .buf                   = buf,
        .payload               = (uint8_t *)payload,
        .payload_len           = (size_t)payload_len,
        .ingress_bytes         = (uint64_t)payload_len,
        .session_idx           = session_idx,
        .target_idx            = session_idx,
        .bid                   = bid,
        .src_addr              = (struct sockaddr_storage *)io_uring_recvmsg_name(o),
        .src_addr_len          = (socklen_t)o->namelen,
        .type                  = pkt_type,
        .classified_media_type = session->media_type,
        .is_rtp                = is_rtp,
        .is_rtcp               = is_rtcp,
        .is_stun               = (pkt_type == PACKET_TYPE_STUN),
        .is_dtls               = (pkt_type == PACKET_TYPE_DTLS),
        .is_video              = false,
        .target_fd             = session->socket_fd,
    };

    return true;
}

static bool flow_handle_control_protocols(rx_packet_flow_t *restrict const flow) {
    if (flow->is_stun) {
        if (stun_is_binding_request(flow->payload, flow->payload_len)) {
            if (likely(
                    (flow->src_addr != nullptr) &&
                    (flow->src_addr_len >= sizeof(struct sockaddr_in))))
            {
                session_latch_endpoint(flow->session, flow->src_addr, flow->src_addr_len);
            }

            stun_request_t req = {};
            (void)stun_parse_request(flow->payload, flow->payload_len, &req);

            char const *const pwd =
                (flow->session->ice_pwd[0] != '\0') ? flow->session->ice_pwd : nullptr;
            uint8_t resp_buf[256] = {};
            size_t  resp_len      = 0;
            if (stun_build_binding_response(
                    req.tx_id,
                    flow->src_addr,
                    flow->src_addr_len,
                    pwd,
                    resp_buf,
                    sizeof(resp_buf),
                    &resp_len))
            {
                auto const send_sqe = ring_engine_get_sqe(flow->engine);
                if (likely(send_sqe != nullptr)) {
                    __builtin_memcpy(flow->buf, resp_buf, resp_len);
                    ring_send_ctx_t *const sctx = ring_engine_get_send_ctx(flow->engine, flow->bid);
                    sctx->iov.iov_base          = flow->buf;
                    sctx->iov.iov_len           = resp_len;
                    sctx->msg                   = (struct msghdr){
                                          .msg_name    = (struct sockaddr *)flow->src_addr,
                                          .msg_namelen = flow->src_addr_len,
                                          .msg_iov     = &(sctx->iov),
                                          .msg_iovlen  = 1,
                    };
                    io_uring_prep_sendmsg(send_sqe, flow->session->socket_fd, &(sctx->msg), 0);

                    user_data_tag_t const send_tag = {
                        .fields = {
                            .index   = flow->session_idx,
                            .op_type = OP_TYPE_UDP_SEND,
                            .bid     = flow->bid,
                            .flags   = 0,
                        }};
                    io_uring_sqe_set_data64(send_sqe, send_tag.raw);
                    return true;
                }
            }
        }
        ring_engine_recycle_buf(flow->engine, flow->bid);
        return true;
    }

    if (flow->is_dtls) {
        if (!(flow->session->dtls_enabled)) {
            if (flow->session->is_webrtc) {
                (void)session_enable_dtls(flow->session, DTLS_ROLE_SERVER);
            } else {
                ring_engine_recycle_buf(flow->engine, flow->bid);
                return true;
            }
        }

        if (likely(
                (flow->src_addr != nullptr) && (flow->src_addr_len >= sizeof(struct sockaddr_in))))
        {
            if ((flow->session->latch_mode == LATCH_MODE_WAITING) ||
                ((flow->session->latch_mode == LATCH_MODE_LATCHED) && flow->session->allow_relatch))
            {
                session_latch_endpoint(flow->session, flow->src_addr, flow->src_addr_len);
            }
        }

        (void)urtp_dtls_feed_packet(&(flow->session->dtls), flow->payload, flow->payload_len);
        (void)urtp_dtls_step(&(flow->session->dtls));

        if ((flow->session->dtls.state == DTLS_STATE_CONNECTED) &&
            !(flow->session->has_inbound_srtp))
        {
            srtp_crypto_suite_t suite       = SRTP_CRYPTO_SUITE_NONE;
            uint8_t             in_key[64]  = {};
            size_t              in_key_len  = 0;
            uint8_t             out_key[64] = {};
            size_t              out_key_len = 0;
            if (urtp_dtls_export_srtp_keys(
                    &(flow->session->dtls),
                    &suite,
                    in_key,
                    sizeof(in_key),
                    &in_key_len,
                    out_key,
                    sizeof(out_key),
                    &out_key_len))
            {
                (void)session_set_inbound_srtp(flow->session, suite, in_key, in_key_len);
                (void)session_set_outbound_srtp(flow->session, suite, out_key, out_key_len);
            }
        }

        size_t const out_bytes =
            urtp_dtls_get_pending_output(&(flow->session->dtls), flow->buf, flow->engine->buf_size);
        if (out_bytes > 0) {
            auto const send_sqe = ring_engine_get_sqe(flow->engine);
            if (likely(send_sqe != nullptr)) {
                ring_send_ctx_t *const sctx = ring_engine_get_send_ctx(flow->engine, flow->bid);
                sctx->iov.iov_base          = flow->buf;
                sctx->iov.iov_len           = out_bytes;
                sctx->msg                   = (struct msghdr){
                                      .msg_name    = (struct sockaddr *)flow->src_addr,
                                      .msg_namelen = flow->src_addr_len,
                                      .msg_iov     = &(sctx->iov),
                                      .msg_iovlen  = 1,
                };
                io_uring_prep_sendmsg(send_sqe, flow->session->socket_fd, &(sctx->msg), 0);

                user_data_tag_t const send_tag = {
                    .fields = {
                        .index   = flow->session_idx,
                        .op_type = OP_TYPE_UDP_SEND,
                        .bid     = flow->bid,
                        .flags   = 0,
                    }};
                io_uring_sqe_set_data64(send_sqe, send_tag.raw);
                return true;
            }
        }

        ring_engine_recycle_buf(flow->engine, flow->bid);
        return true;
    }

    return false;
}

static bool flow_authenticate_and_latch(rx_packet_flow_t *restrict const flow) {
    if (unlikely(flow->session->has_inbound_srtp && !(flow->is_rtp) && !(flow->is_rtcp))) {
        flow->session->packets_dropped++;
        return false;
    }

    // NAT Latching: inspect incoming UDP/RTP/RTCP packet and latch discovered public endpoint
    bool const was_waiting = (flow->session->latch_mode == LATCH_MODE_WAITING);
    if (was_waiting ||
        ((flow->session->latch_mode == LATCH_MODE_LATCHED) && flow->session->allow_relatch))
    {
        if (likely(
                (flow->src_addr != nullptr) && (flow->src_addr_len >= sizeof(struct sockaddr_in))))
        {
            if (flow->is_rtp || (flow->is_rtcp && flow->session->rtcp_mux) ||
                flow->session->raw_latch)
            {
                session_latch_endpoint(flow->session, flow->src_addr, flow->src_addr_len);
                if (was_waiting) {
                    if ((flow->session->media_type == SDP_MEDIA_VIDEO) &&
                        (flow->session->peer_idx >= 0))
                    {
                        relay_session_t *const p =
                            &(flow->table->sessions[flow->session->peer_idx]);
                        if (p->active && (p->latch_mode != LATCH_MODE_WAITING)) {
                            uint32_t const snd_ssrc = (flow->session->last_ssrc != 0)
                                                          ? flow->session->last_ssrc
                                                          : 0x55525450;
                            uint32_t const med_ssrc = (p->last_ssrc != 0) ? p->last_ssrc : 0;
                            (void)session_send_pli(p, snd_ssrc, med_ssrc, flow->engine);
                        }
                    } else if (flow->session->peer_idx >= 0) {
                        relay_session_t *const p =
                            &(flow->table->sessions[flow->session->peer_idx]);
                        if (p->active && (p->media_type == SDP_MEDIA_VIDEO) &&
                            (p->latch_mode != LATCH_MODE_WAITING))
                        {
                            uint32_t const snd_ssrc = (flow->session->last_ssrc != 0)
                                                          ? flow->session->last_ssrc
                                                          : 0x55525450;
                            uint32_t const med_ssrc = (p->last_ssrc != 0) ? p->last_ssrc : 0;
                            (void)session_send_pli(flow->session, snd_ssrc, med_ssrc, flow->engine);
                        }
                    }
                }
            }
        }
    }

    // Inbound SRTP decryption & authentication
    if (flow->session->has_inbound_srtp) {
        size_t dec_len = 0;
        bool   ok      = false;
        if (flow->is_rtp) {
            ok = urtp_srtp_unprotect_rtp(
                &(flow->session->inbound_srtp),
                flow->payload,
                flow->payload_len,
                &dec_len);
        } else if (flow->is_rtcp) {
            ok = urtp_srtp_unprotect_rtcp(
                &(flow->session->inbound_srtp),
                flow->payload,
                flow->payload_len,
                &dec_len);
        }

        if (unlikely(!ok)) {
            flow->session->srtp_auth_failures++;
            flow->session->packets_dropped++;
            if (flow->table->metrics != nullptr) {
                flow->table->metrics->cumulative.srtp_auth_failures++;
                flow->table->metrics->cumulative.packets_dropped++;
            }
            return false;
        }

        flow->payload_len = dec_len;
        flow->session->srtp_packets_decrypted++;
        if (flow->table->metrics != nullptr) {
            flow->table->metrics->cumulative.srtp_decrypted++;
        }
    }

    if (flow->is_rtp && (flow->payload_len >= sizeof(rtp_header_t))) {
        rtp_header_t const *const rtp = (rtp_header_t const *)(void const *)flow->payload;
        flow->session->last_ssrc      = ntohl(rtp->ssrc);
        flow->session->last_ssrc_sec  = flow->table->cached_monotonic_sec;
    }

    // Determine target session and socket for forwarding
    if (flow->session->peer_idx >= 0) {
        if (unlikely((size_t)flow->session->peer_idx >= SESSION_TABLE_MAX)) {
            flow->session->packets_dropped++;
            return false;
        }
        relay_session_t *const peer = &(flow->table->sessions[flow->session->peer_idx]);
        if (unlikely(!(peer->active))) {
            flow->session->packets_dropped++;
            return false;
        }
        flow->target_session = peer;
        flow->target_fd      = peer->socket_fd;
        flow->target_idx     = (uint16_t)flow->session->peer_idx;
    }

    // Demultiplexing via route_table (Option B BUNDLE to unbundled SIP)
    if (flow->session->route_table.count > 0) {
        if (flow->is_rtp && (flow->payload_len >= sizeof(rtp_header_t))) {
            rtp_header_t const *const rtp_hdr = (rtp_header_t const *)(void const *)flow->payload;
            uint8_t const             pt      = rtp_get_payload_type(rtp_hdr);
            uint32_t const            ssrc    = ntohl(rtp_hdr->ssrc);

            for (size_t i = 0; i < flow->session->route_table.count; ++i) {
                ssrc_route_entry_t *const entry = &(flow->session->route_table.entries[i]);
                if (((entry->ssrc != 0) && (entry->ssrc == ssrc)) || (entry->pt == pt)) {
                    if (entry->ssrc == 0) {
                        entry->ssrc = ssrc;
                    }
                    flow->classified_media_type = entry->media_type;
                    int32_t const idx           = entry->target_session_idx;
                    if ((idx >= 0) && ((size_t)idx < SESSION_TABLE_MAX)) {
                        flow->target_session = &(flow->table->sessions[idx]);
                        flow->target_fd      = flow->target_session->socket_fd;
                        flow->target_idx     = (uint16_t)idx;
                    }
                    break;
                }
            }
        } else if (flow->is_rtcp && (flow->payload_len >= 12)) {
            uint32_t media_ssrc = 0;
            __builtin_memcpy(&media_ssrc, (uint8_t const *)flow->payload + 8, sizeof(media_ssrc));
            media_ssrc = ntohl(media_ssrc);

            for (size_t i = 0; i < flow->session->route_table.count; ++i) {
                ssrc_route_entry_t const *const entry = &(flow->session->route_table.entries[i]);
                int32_t const                   idx   = entry->target_session_idx;
                bool match = (entry->ssrc != 0) && (entry->ssrc == media_ssrc);
                if (!match && (idx >= 0) && ((size_t)idx < SESSION_TABLE_MAX)) {
                    match = (flow->table->sessions[idx].last_ssrc != 0) &&
                            (flow->table->sessions[idx].last_ssrc == media_ssrc);
                }
                if (match) {
                    flow->classified_media_type = entry->media_type;
                    if ((idx >= 0) && ((size_t)idx < SESSION_TABLE_MAX)) {
                        flow->target_session = &(flow->table->sessions[idx]);
                        flow->target_fd      = flow->target_session->socket_fd;
                        flow->target_idx     = (uint16_t)idx;
                    }
                    break;
                }
            }
        }
    }

    flow->is_video = (flow->classified_media_type == SDP_MEDIA_VIDEO) ||
                     (flow->session->media_type == SDP_MEDIA_VIDEO) ||
                     (flow->target_session->media_type == SDP_MEDIA_VIDEO);

    if (flow->is_video && flow->is_rtp) {
        if (likely(flow->table->metrics != nullptr)) {
            flow->table->metrics->cumulative.video_rx_packets++;
            flow->table->metrics->cumulative.video_rx_bytes += flow->ingress_bytes;
        }
    }

    if (flow->is_rtcp && (flow->payload_len >= sizeof(rtcp_header_t))) {
        rtcp_header_t const *const rtcp_hdr = (rtcp_header_t const *)(void const *)flow->payload;
        if ((rtcp_hdr->pt == RTCP_PT_PSFB) && ((rtcp_hdr->v_p_rc & 0x1F) == 1)) {
            if (likely(flow->table->metrics != nullptr)) {
                flow->table->metrics->cumulative.rtcp_pli_packets++;
            }
        }
    }

    // Standalone or peer: if target has not latched yet and has no dest, cannot forward media
    if (flow->target_session->latch_mode == LATCH_MODE_WAITING) {
        flow->session->packets_dropped++;
        return false;
    }

    return true;
}

static bool flow_process_transcode(rx_packet_flow_t *restrict const flow) {
    // Audio Transcoding (Video completely bypasses jitter buffer & transcoder!)
    if (flow->is_rtp && (flow->classified_media_type != SDP_MEDIA_VIDEO)) {
        if (!(flow->session->transcode_enabled) &&
            (flow->table->default_transcoder != TRANSCODER_BACKEND_NONE))
        {
            uint8_t const in_pt =
                rtp_get_payload_type((rtp_header_t const *)(void const *)flow->payload);
            media_codec_t const src_c = media_codec_from_pt(in_pt);
            media_codec_t       dst_c = flow->target_session->target_codec;
            if (dst_c == MEDIA_CODEC_NONE) {
                dst_c = flow->table->default_transcode_codec;
            }
            if (dst_c == MEDIA_CODEC_NONE) {
                if (src_c == MEDIA_CODEC_OPUS) {
                    dst_c = MEDIA_CODEC_PCMU;
                } else if ((src_c == MEDIA_CODEC_PCMU) || (src_c == MEDIA_CODEC_PCMA)) {
                    dst_c = MEDIA_CODEC_OPUS;
                }
            }
            if ((src_c != MEDIA_CODEC_NONE) && (dst_c != MEDIA_CODEC_NONE) && (src_c != dst_c)) {
                (void)session_set_transcode(
                    flow->session,
                    flow->table->default_transcoder,
                    src_c,
                    dst_c);
                if (flow->table->default_jitter_delay_ms > 0) {
                    (void)session_set_jitter_buffer(
                        flow->session,
                        flow->table->default_jitter_delay_ms);
                }
            }
        }

        if (flow->session->transcode_enabled) {
            uint8_t trans_buf[2048] = {};
            size_t  trans_len       = 0;
            bool    trans_ok        = false;

            if (flow->session->jitter_enabled && (flow->session->jitter_buf != nullptr)) {
                uint64_t const now_ns   = flow->table->cached_monotonic_sec * 1000000000ULL;
                bool const     inserted = jitter_buffer_insert(
                    flow->session->jitter_buf,
                    flow->payload,
                    flow->payload_len,
                    now_ns);

                if (flow->table->metrics != nullptr) {
                    flow->table->metrics->cumulative.jb_packets_reordered =
                        flow->session->jitter_buf->packets_reordered;
                    flow->table->metrics->cumulative.jb_packets_dropped_late =
                        flow->session->jitter_buf->packets_dropped_late;
                    flow->table->metrics->cumulative.jb_loss_concealments =
                        flow->session->jitter_buf->loss_concealments;
                }

                if (unlikely(!inserted)) {
                    flow->session->packets_dropped++;
                    if (flow->table->metrics != nullptr) {
                        flow->table->metrics->cumulative.packets_dropped++;
                    }
                    return false;
                }

                uint8_t                   out_pkt[JITTER_SLOT_MAX_SIZE] = {};
                size_t                    out_pkt_len                   = 0;
                uint16_t                  out_seq                       = 0;
                uint32_t                  out_ts                        = 0;
                jitter_pop_status_t const pop_st                        = jitter_buffer_pop(
                    flow->session->jitter_buf,
                    out_pkt,
                    sizeof(out_pkt),
                    &out_pkt_len,
                    &out_seq,
                    &out_ts);

                if (pop_st == JB_POP_OK) {
                    trans_ok = transcoder_process_rtp(
                        &(flow->session->transcode_ctx),
                        out_pkt,
                        out_pkt_len,
                        trans_buf,
                        sizeof(trans_buf),
                        &trans_len);
                } else if (pop_st == JB_POP_PLC) {
                    trans_ok = transcoder_process_plc(
                        &(flow->session->transcode_ctx),
                        trans_buf,
                        sizeof(trans_buf),
                        &trans_len);
                } else {
                    // JB_POP_EMPTY: packet held in jitter buffer, waiting for depth or in-order
                    // arrival
                    return false;
                }
            } else {
                trans_ok = transcoder_process_rtp(
                    &(flow->session->transcode_ctx),
                    flow->payload,
                    flow->payload_len,
                    trans_buf,
                    sizeof(trans_buf),
                    &trans_len);
            }

            if (likely(trans_ok)) {
                size_t const payload_offset = (size_t)(flow->payload - flow->buf);
                if ((payload_offset + trans_len) <= flow->engine->buf_size) {
                    __builtin_memcpy(flow->payload, trans_buf, trans_len);
                    flow->payload_len = trans_len;
                    if (flow->table->metrics != nullptr) {
                        flow->table->metrics->cumulative.transcode_decoded++;
                        flow->table->metrics->cumulative.transcode_encoded++;
                    }
                }
            } else {
                flow->session->packets_dropped++;
                if (flow->table->metrics != nullptr) {
                    flow->table->metrics->cumulative.packets_dropped++;
                }
                return false;
            }
        }
    }
    return true;
}

static bool flow_transmit_and_pcap(rx_packet_flow_t *restrict const flow) {
    // Fork media stream for PCAP recording / call tapping before outbound SRTP encryption
    int32_t const rec_idx = (flow->session->record_idx >= 0) ? flow->session->record_idx
                            : (flow->target_session->record_idx >= 0)
                                ? flow->target_session->record_idx
                                : -1;
    if (rec_idx >= 0) {
        struct sockaddr_storage const *src_addr = flow->src_addr;
        if (unlikely(
                (flow->src_addr == nullptr) || (flow->src_addr_len < sizeof(struct sockaddr_in))))
        {
            src_addr = &(flow->session->dest_addr);
        }
        struct sockaddr_storage const *dst_addr = &(flow->target_session->dest_addr);
        if (flow->is_rtcp && !(flow->target_session->rtcp_mux) &&
            (flow->target_session->rtcp_dest_port > 0))
        {
            dst_addr = &(flow->target_session->rtcp_dest_addr);
        }

        urtp_srtp_ctx_t *const out_srtp =
            (flow->target_session->shared_outbound_srtp != nullptr)
                ? flow->target_session->shared_outbound_srtp
                : (flow->target_session->has_outbound_srtp ? &(flow->target_session->outbound_srtp)
                                                           : nullptr);
        bool const can_zero_copy = (out_srtp == nullptr);
        (void)pcap_record_packet(
            &(flow->table->pcap_table),
            flow->engine,
            rec_idx,
            flow->payload,
            flow->payload_len,
            src_addr,
            dst_addr,
            flow->bid,
            can_zero_copy);
    }

    // Outbound SRTP encryption & authentication
    urtp_srtp_ctx_t *const out_srtp =
        (flow->target_session->shared_outbound_srtp != nullptr)
            ? flow->target_session->shared_outbound_srtp
            : (flow->target_session->has_outbound_srtp ? &(flow->target_session->outbound_srtp)
                                                       : nullptr);
    if (out_srtp != nullptr) {
        size_t const payload_offset = (size_t)(flow->payload - flow->buf);
        size_t const max_cap        = (flow->engine->buf_size > payload_offset)
                                          ? (flow->engine->buf_size - payload_offset)
                                          : 0;
        size_t       enc_len        = 0;
        bool         ok             = false;
        if (flow->is_rtp) {
            ok = urtp_srtp_protect_rtp(
                out_srtp,
                flow->payload,
                flow->payload_len,
                max_cap,
                &enc_len);
        } else if (flow->is_rtcp) {
            ok = urtp_srtp_protect_rtcp(
                out_srtp,
                flow->payload,
                flow->payload_len,
                max_cap,
                &enc_len);
        }

        if (unlikely(!ok)) {
            flow->session->packets_dropped++;
            if (flow->table->metrics != nullptr) {
                flow->table->metrics->cumulative.packets_dropped++;
            }
            return false;
        }

        flow->payload_len = enc_len;
        flow->target_session->srtp_packets_encrypted++;
        if (flow->table->metrics != nullptr) {
            flow->table->metrics->cumulative.srtp_encrypted++;
        }
    }

    // Select forwarding destination address based on packet type and RTCP-MUX status
    struct sockaddr_storage *dest_addr_ptr = &(flow->target_session->dest_addr);
    socklen_t                dest_len      = flow->target_session->dest_addr_len;

    if (flow->is_rtcp && !(flow->target_session->rtcp_mux) &&
        (flow->target_session->rtcp_dest_port > 0))
    {
        dest_addr_ptr = &(flow->target_session->rtcp_dest_addr);
        dest_len      = flow->target_session->rtcp_dest_addr_len;
    }

    auto const send_sqe = ring_engine_get_sqe(flow->engine);
    if (unlikely(send_sqe == nullptr)) {
        flow->session->packets_dropped++;
        if (flow->table->metrics != nullptr) {
            flow->table->metrics->cumulative.packets_dropped++;
        }
        return false;
    }

    ring_send_ctx_t *const sctx = ring_engine_get_send_ctx(flow->engine, flow->bid);
    sctx->iov.iov_base          = flow->payload;
    sctx->iov.iov_len           = flow->payload_len;
    sctx->msg                   = (struct msghdr){
                          .msg_name    = (struct sockaddr *)dest_addr_ptr,
                          .msg_namelen = dest_len,
                          .msg_iov     = &(sctx->iov),
                          .msg_iovlen  = 1,
    };

    io_uring_prep_sendmsg(send_sqe, flow->target_fd, &(sctx->msg), 0);

    uint16_t tag_flags = flow->is_rtcp ? TAG_FLAG_PKT_RTCP : TAG_FLAG_PKT_RTP;
    if (flow->is_video && flow->is_rtp) {
        tag_flags |= TAG_FLAG_PKT_VIDEO;
    }
    user_data_tag_t const send_tag = {
        .fields = {
            .index   = flow->target_idx,
            .op_type = OP_TYPE_UDP_SEND,
            .bid     = flow->bid,
            .flags   = tag_flags,
        }};
    io_uring_sqe_set_data64(send_sqe, send_tag.raw);
    return true;
}

void session_handle_rx_cqe(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   session_idx) {
    if (unlikely((table == nullptr) || (engine == nullptr) || (cqe == nullptr))) {
        return;
    }
    if (unlikely(session_idx >= SESSION_TABLE_MAX)) {
        return;
    }

    relay_session_t *const session = &(table->sessions[session_idx]);
    if (unlikely(!(session->active))) {
        if ((cqe->flags & IORING_CQE_F_BUFFER) != 0) {
            auto const bid = (uint16_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
            ring_engine_recycle_buf(engine, bid);
        }
        return;
    }

    rx_packet_flow_t flow = {};
    if (!flow_init(&flow, table, engine, cqe, session_idx)) {
        return;
    }

    if (flow_handle_control_protocols(&flow)) {
        return;
    }

    if (!flow_authenticate_and_latch(&flow)) {
        goto recycle;
    }

    if (!flow_process_transcode(&flow)) {
        goto recycle;
    }

    if (!flow_transmit_and_pcap(&flow)) {
        goto recycle;
    }

    return;

recycle:
    ring_engine_recycle_buf(engine, flow.bid);
}

void session_handle_tx_cqe(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   session_idx,
    uint16_t const                   bid,
    uint16_t const                   flags) {
    if (unlikely((table == nullptr) || (engine == nullptr) || (cqe == nullptr))) {
        return;
    }

    ring_engine_buf_release(engine, bid);

    if (unlikely(session_idx >= SESSION_TABLE_MAX)) {
        return;
    }

    relay_session_t *const session = &(table->sessions[session_idx]);
    if (unlikely(!(session->active))) {
        return;
    }

    session->last_activity_sec = table->cached_monotonic_sec;

    if (likely(cqe->res > 0)) {
        session->packets_relayed++;
        session->bytes_relayed += (uint64_t)cqe->res;
        if ((flags & TAG_FLAG_PKT_RTCP) != 0) {
            session->rtcp_packets_relayed++;
            session->rtcp_bytes_relayed += (uint64_t)cqe->res;
        } else {
            session->rtp_packets_relayed++;
            session->rtp_bytes_relayed += (uint64_t)cqe->res;
        }
        if (likely(table->metrics != nullptr)) {
            table->metrics->cumulative.tx_packets++;
            table->metrics->cumulative.tx_bytes += (uint64_t)cqe->res;
            if ((flags & TAG_FLAG_PKT_VIDEO) != 0) {
                table->metrics->cumulative.video_tx_packets++;
                table->metrics->cumulative.video_tx_bytes += (uint64_t)cqe->res;
            }
        }
    } else {
        session->packets_dropped++;
        if (likely(table->metrics != nullptr)) {
            table->metrics->cumulative.packets_dropped++;
        }
    }
}

bool session_set_inbound_srtp(
    relay_session_t *restrict const session,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len) {
    if (unlikely((session == nullptr) || (key_salt == nullptr))) {
        return false;
    }
    if (session->has_inbound_srtp) {
        urtp_srtp_ctx_destroy(&(session->inbound_srtp));
        session->has_inbound_srtp = false;
    }
    if (suite == SRTP_CRYPTO_SUITE_NONE) {
        return true;
    }
    if (!urtp_srtp_ctx_init(
            &(session->inbound_srtp),
            SRTP_DIR_INBOUND,
            suite,
            key_salt,
            key_salt_len))
    {
        return false;
    }
    session->has_inbound_srtp = true;
    return true;
}

bool session_set_outbound_srtp(
    relay_session_t *restrict const session,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len) {
    if (unlikely((session == nullptr) || (key_salt == nullptr))) {
        return false;
    }
    if (session->has_outbound_srtp) {
        urtp_srtp_ctx_destroy(&(session->outbound_srtp));
        session->has_outbound_srtp = false;
    }
    if (suite == SRTP_CRYPTO_SUITE_NONE) {
        return true;
    }
    if (!urtp_srtp_ctx_init(
            &(session->outbound_srtp),
            SRTP_DIR_OUTBOUND,
            suite,
            key_salt,
            key_salt_len))
    {
        return false;
    }
    session->has_outbound_srtp = true;
    return true;
}

void session_clear_srtp(relay_session_t *restrict const session) {
    if (unlikely(session == nullptr)) {
        return;
    }
    if (session->has_inbound_srtp) {
        urtp_srtp_ctx_destroy(&(session->inbound_srtp));
        session->has_inbound_srtp = false;
    }
    if (session->has_outbound_srtp) {
        urtp_srtp_ctx_destroy(&(session->outbound_srtp));
        session->has_outbound_srtp = false;
    }
}

bool session_enable_dtls(relay_session_t *restrict const session, dtls_role_t const role) {
    if (unlikely(session == nullptr)) {
        return false;
    }
    if (session->dtls_enabled) {
        session_clear_dtls(session);
    }
    if (!urtp_dtls_session_init(&(session->dtls), role)) {
        return false;
    }
    session->dtls_enabled = true;
    session->is_webrtc    = true;
    return true;
}

void session_set_ice_credentials(
    relay_session_t *restrict const session,
    char const *const ufrag,
    char const *const pwd) {
    if (unlikely(session == nullptr)) {
        return;
    }
    if (ufrag != nullptr) {
        size_t const ulen = __builtin_strlen(ufrag);
        size_t const copylen =
            (ulen < (sizeof(session->ice_ufrag) - 1)) ? ulen : (sizeof(session->ice_ufrag) - 1);
        __builtin_memcpy(session->ice_ufrag, ufrag, copylen);
        session->ice_ufrag[copylen] = '\0';
    }
    if (pwd != nullptr) {
        size_t const plen = __builtin_strlen(pwd);
        size_t const copylen =
            (plen < (sizeof(session->ice_pwd) - 1)) ? plen : (sizeof(session->ice_pwd) - 1);
        __builtin_memcpy(session->ice_pwd, pwd, copylen);
        session->ice_pwd[copylen] = '\0';
    }
}

void session_clear_dtls(relay_session_t *restrict const session) {
    if (unlikely(session == nullptr)) {
        return;
    }
    if (session->dtls_enabled) {
        urtp_dtls_session_destroy(&(session->dtls));
        session->dtls_enabled = false;
    }
}

void session_table_set_default_transcoder(
    session_table_t *restrict const table,
    transcoder_backend_t const backend,
    media_codec_t const        codec) {
    if (unlikely(table == nullptr)) {
        return;
    }
    table->default_transcoder      = backend;
    table->default_transcode_codec = codec;
}

void session_table_set_default_jitter(
    session_table_t *restrict const table,
    uint32_t const delay_ms) {
    if (unlikely(table == nullptr)) {
        return;
    }
    table->default_jitter_delay_ms = delay_ms;
    if ((delay_ms > 0) && (table->jitter_pool == nullptr)) {
        table->jitter_pool = jitter_pool_create();
    }
}

bool session_set_transcode(
    relay_session_t *restrict const session,
    transcoder_backend_t const backend,
    media_codec_t const        src_codec,
    media_codec_t const        dst_codec) {
    if (unlikely(session == nullptr)) {
        return false;
    }

    session_clear_transcode(session);

    if (backend == TRANSCODER_BACKEND_NONE) {
        return true;
    }

    if (!transcoder_init(&(session->transcode_ctx), backend, src_codec, dst_codec)) {
        return false;
    }

    session->transcode_enabled = true;
    session->target_codec      = dst_codec;
    return true;
}

bool session_set_jitter_buffer(relay_session_t *restrict const session, uint32_t const delay_ms) {
    if (unlikely(session == nullptr)) {
        return false;
    }

    // Constraint: Jitter buffer only runs if transcoding is also enabled
    if (!session->transcode_enabled) {
        return false;
    }

    auto const table = session->table;

    if (delay_ms == 0) {
        if (session->jitter_buf != nullptr) {
            jitter_buffer_reset(session->jitter_buf);
            if ((table != nullptr) && (table->jitter_pool != nullptr)) {
                jitter_pool_push(table->jitter_pool, session->jitter_buf);
            }
            session->jitter_buf = nullptr;
        }
        session->jitter_enabled  = false;
        session->jitter_delay_ms = 0;
        transcoder_set_jitter_buffer(&(session->transcode_ctx), nullptr);
        return true;
    }

    if (session->jitter_buf == nullptr) {
        if ((table != nullptr) && (table->jitter_pool == nullptr)) {
            table->jitter_pool = jitter_pool_create();
        }
        if ((table != nullptr) && (table->jitter_pool != nullptr)) {
            session->jitter_buf = jitter_pool_pop(table->jitter_pool);
        }
        if (unlikely(session->jitter_buf == nullptr)) {
            return false;
        }
    }

    jitter_buffer_init(session->jitter_buf, delay_ms);
    session->jitter_enabled  = true;
    session->jitter_delay_ms = session->jitter_buf->target_delay_ms;
    transcoder_set_jitter_buffer(&(session->transcode_ctx), session->jitter_buf);
    return true;
}

void session_clear_transcode(relay_session_t *restrict const session) {
    if (unlikely(session == nullptr)) {
        return;
    }
    if (session->jitter_buf != nullptr) {
        jitter_buffer_reset(session->jitter_buf);
        if ((session->table != nullptr) && (session->table->jitter_pool != nullptr)) {
            jitter_pool_push(session->table->jitter_pool, session->jitter_buf);
        }
        session->jitter_buf = nullptr;
    }
    session->jitter_enabled  = false;
    session->jitter_delay_ms = 0;
    transcoder_set_jitter_buffer(&(session->transcode_ctx), nullptr);
    if (session->transcode_enabled) {
        transcoder_destroy(&(session->transcode_ctx));
        session->transcode_enabled = false;
    }
}

void session_table_sweep_inactivity(
    session_table_t *restrict const table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    uint64_t const now_sec,
    uint32_t const default_timeout_sec,
    uint32_t const setup_timeout_sec) {
    if (unlikely(table == nullptr)) {
        return;
    }

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t *const session = &(table->sessions[i]);
        if (!(session->active)) {
            continue;
        }

        uint32_t const timeout =
            (session->inactivity_timeout > 0) ? session->inactivity_timeout : default_timeout_sec;

        bool     timed_out    = false;
        uint64_t inactive_sec = 0;

        if (session->packets_relayed == 0) {
            if ((setup_timeout_sec > 0) && (now_sec >= session->created_sec) &&
                ((now_sec - session->created_sec) >= setup_timeout_sec))
            {
                timed_out    = true;
                inactive_sec = (now_sec - session->created_sec);
            }
        } else {
            if ((timeout > 0) && (now_sec >= session->last_activity_sec) &&
                ((now_sec - session->last_activity_sec) >= timeout))
            {
                timed_out    = true;
                inactive_sec = (now_sec - session->last_activity_sec);
            }
        }

        if (timed_out) {
            uint16_t const port      = session->bind_port;
            int32_t const  peer_idx  = session->peer_idx;
            uint16_t       peer_port = 0;

            if ((peer_idx >= 0) && ((size_t)peer_idx < SESSION_TABLE_MAX)) {
                relay_session_t const *const peer = &(table->sessions[peer_idx]);
                if (peer->active) {
                    peer_port = peer->bind_port;
                }
            }

            LOG_WARN(
                "Session port %u timed out after %llu s of inactivity",
                port,
                (unsigned long long)inactive_sec);

            if ((call_table != nullptr) && (ng_call_table_remove_by_port != nullptr)) {
                ng_call_table_remove_by_port(call_table, port);
                if (peer_port > 0) {
                    ng_call_table_remove_by_port(call_table, peer_port);
                }
            }

            (void)session_delete_by_port(table, port, engine);
            if (likely(table->metrics != nullptr)) {
                table->metrics->cumulative.sessions_reaped++;
            }
            if (peer_port > 0) {
                (void)session_delete_by_port(table, peer_port, engine);
                if (likely(table->metrics != nullptr)) {
                    table->metrics->cumulative.sessions_reaped++;
                }
            }
        }
    }
}

bool session_add_route(
    relay_session_t *restrict const session,
    uint32_t const         ssrc,
    uint8_t const          pt,
    sdp_media_type_t const media_type,
    int32_t const          target_session_idx) {
    if (unlikely(session == nullptr)) {
        return false;
    }
    constexpr size_t max_entries =
        sizeof(session->route_table.entries) / sizeof(session->route_table.entries[0]);
    if (session->route_table.count >= max_entries) {
        return false;
    }
    session->route_table.entries[session->route_table.count++] = (ssrc_route_entry_t){
        .ssrc               = ssrc,
        .pt                 = pt,
        .media_type         = media_type,
        .target_session_idx = target_session_idx,
    };
    return true;
}

void session_clear_routes(relay_session_t *restrict const session) {
    if (unlikely(session == nullptr)) {
        return;
    }
    session->route_table = (ssrc_route_table_t){};
}

bool session_send_pli(
    relay_session_t *restrict const session,
    uint32_t const sender_ssrc,
    uint32_t const media_ssrc,
    ring_engine_t *restrict const engine) {
    if (unlikely((session == nullptr) || (engine == nullptr) || !(session->active))) {
        return false;
    }
    if ((session->dest_port == 0) || (session->latch_mode == LATCH_MODE_WAITING)) {
        return false;
    }

    rtcp_pli_packet_t pli     = {};
    size_t const      pli_len = rtcp_build_pli(sender_ssrc, media_ssrc, &pli);
    if (unlikely(pli_len == 0)) {
        return false;
    }

    __builtin_memcpy(session->pli_tx_buf, &pli, pli_len);
    size_t out_len = pli_len;

    urtp_srtp_ctx_t *const out_srtp =
        (session->shared_outbound_srtp != nullptr)
            ? session->shared_outbound_srtp
            : (session->has_outbound_srtp ? &(session->outbound_srtp) : nullptr);
    if (out_srtp != nullptr) {
        size_t enc_len = 0;
        if (!urtp_srtp_protect_rtcp(
                out_srtp,
                session->pli_tx_buf,
                pli_len,
                sizeof(session->pli_tx_buf),
                &enc_len))
        {
            return false;
        }
        out_len = enc_len;
    }

    auto const sqe = ring_engine_get_sqe(engine);
    if (unlikely(sqe == nullptr)) {
        return false;
    }

    session->pli_tx_iov.iov_base = session->pli_tx_buf;
    session->pli_tx_iov.iov_len  = out_len;
    session->pli_tx_msghdr       = (struct msghdr){
              .msg_name    = (struct sockaddr *)&(session->dest_addr),
              .msg_namelen = session->dest_addr_len,
              .msg_iov     = &(session->pli_tx_iov),
              .msg_iovlen  = 1,
    };

    io_uring_prep_sendmsg(sqe, session->socket_fd, &(session->pli_tx_msghdr), 0);

    int64_t const         sidx     = session_get_index(session->table, session);
    user_data_tag_t const send_tag = {
        .fields = {
            .index   = (sidx >= 0) ? (uint16_t)sidx : 0,
            .op_type = OP_TYPE_UDP_SEND,
            .bid     = 0xFFFF,
            .flags   = TAG_FLAG_PKT_RTCP,
        }};
    io_uring_sqe_set_data64(sqe, send_tag.raw);
    if (likely((session->table != nullptr) && (session->table->metrics != nullptr))) {
        session->table->metrics->cumulative.rtcp_pli_packets++;
    }
    return true;
}

size_t session_table_format_ssrc_metrics(
    session_table_t const *restrict const table,
    char *restrict const buf,
    size_t const max_len) {
    if (unlikely((table == nullptr) || (buf == nullptr) || (max_len == 0))) {
        return 0;
    }

    metric_ssrc_entry_t entries[SESSION_TABLE_MAX];
    size_t              count = 0;

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t const *const s = &(table->sessions[i]);
        if (s->active && (s->last_ssrc != 0)) {
            uint64_t const idle_sec = (table->cached_monotonic_sec >= s->last_ssrc_sec)
                                          ? (table->cached_monotonic_sec - s->last_ssrc_sec)
                                          : 0;
            entries[count++]        = (metric_ssrc_entry_t){
                       .port     = s->bind_port,
                       .ssrc     = s->last_ssrc,
                       .idle_sec = idle_sec,
            };
        }
    }

    if (count == 0) {
        return 0;
    }

    return metrics_format_ssrc(entries, count, buf, max_len);
}
