#include "control/control.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "control/ng.h"
#include "core/macros.h"
#include "core/string_view.h"

static inline void trim_whitespace(char *restrict const str) {
    if (unlikely(str == nullptr)) {
        return;
    }
    size_t len = __builtin_strlen(str);
    while ((len > 0) && ((str[len - 1] == '\r') || (str[len - 1] == '\n') || (str[len - 1] == ' ')))
    {
        str[--len] = '\0';
    }
}

typedef bool (*cmd_handler_t)(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max);

typedef struct {
    sv_t          verb;
    cmd_handler_t handler;
} cmd_entry_t;

static bool handle_ping(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)args;
    (void)table;
    (void)engine;
    (void)snprintf(resp_buf, resp_max, "PONG\n");
    return true;
}

static bool handle_quit(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)args;
    (void)table;
    (void)engine;
    (void)snprintf(resp_buf, resp_max, "BYE\n");
    return true;
}

[[nodiscard]] static inline size_t
count_active_video_sessions(session_table_t const *restrict const table) {
    if (unlikely(table == nullptr)) {
        return 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        if (table->sessions[i].active && (table->sessions[i].media_type == SDP_MEDIA_VIDEO)) {
            count++;
        }
    }
    return count;
}

static bool handle_status(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    if (unlikely((table == nullptr) || (resp_buf == nullptr) || (resp_max == 0))) {
        return false;
    }

    if ((args != nullptr) && (strncasecmp(args, "METRICS", 7) == 0)) {
        if (table->metrics != nullptr) {
            size_t const active_video = count_active_video_sessions(table);
            size_t       len          = metrics_format_prometheus(
                table->metrics,
                table->active_count,
                active_video,
                resp_buf,
                resp_max);
            if ((len > 0) && (len < resp_max)) {
                len += session_table_format_ssrc_metrics(table, resp_buf + len, resp_max - len);
            }
            return (len > 0);
        }
        (void)snprintf(resp_buf, resp_max, "ERROR METRICS_UNAVAILABLE\n");
        return false;
    }

    size_t    off = 0;
    int const written =
        snprintf(resp_buf + off, resp_max - off, "OK SESSIONS active=%zu\n", table->active_count);
    if (written > 0) {
        off += (size_t)written;
    }

    for (size_t i = 0; i < SESSION_TABLE_MAX; ++i) {
        relay_session_t const *const s = &(table->sessions[i]);
        if (s->active && (off < resp_max)) {
            char latch_info[64] = "none";
            if (s->latch_mode == LATCH_MODE_WAITING) {
                (void)snprintf(latch_info, sizeof(latch_info), "waiting");
            } else if (s->latch_mode == LATCH_MODE_LATCHED) {
                (void)snprintf(
                    latch_info,
                    sizeof(latch_info),
                    "latched:%s:%u",
                    s->latched_ip,
                    s->latched_port);
            }

            char const *const mux_str = s->rtcp_mux ? "yes" : "no";
            char const *const rec_str = (s->record_idx >= 0) ? "yes" : "no";

            int item_w = 0;
            if ((s->peer_idx >= 0) && ((size_t)s->peer_idx < SESSION_TABLE_MAX)) {
                relay_session_t const *const peer = &(table->sessions[s->peer_idx]);
                item_w                            = snprintf(
                    resp_buf + off,
                    resp_max - off,
                    "SESSION port=%u -> dest=%s:%u mux=%s latch=%s record=%s peer=%u pkts=%llu "
                                               "bytes=%llu drops=%llu\n",
                    s->bind_port,
                    s->dest_ip,
                    s->dest_port,
                    mux_str,
                    latch_info,
                    rec_str,
                    peer->bind_port,
                    (unsigned long long)s->packets_relayed,
                    (unsigned long long)s->bytes_relayed,
                    (unsigned long long)s->packets_dropped);
            } else {
                item_w = snprintf(
                    resp_buf + off,
                    resp_max - off,
                    "SESSION port=%u -> dest=%s:%u mux=%s latch=%s record=%s pkts=%llu bytes=%llu "
                    "drops=%llu\n",
                    s->bind_port,
                    s->dest_ip,
                    s->dest_port,
                    mux_str,
                    latch_info,
                    rec_str,
                    (unsigned long long)s->packets_relayed,
                    (unsigned long long)s->bytes_relayed,
                    (unsigned long long)s->packets_dropped);
            }
            if (item_w > 0) {
                off += (size_t)item_w;
            }
        }
    }
    return true;
}

static bool handle_delete(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    unsigned int port = 0;
    if ((sscanf(args, "PORT %u", &port) == 1) || (sscanf(args, "%u", &port) == 1)) {
        bool const ok = session_delete_by_port(table, (uint16_t)port, engine);
        if (ok) {
            (void)snprintf(resp_buf, resp_max, "OK DELETED PORT %u\n", port);
            return true;
        } else {
            (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
            return false;
        }
    }
    (void)snprintf(resp_buf, resp_max, "ERROR INVALID_DELETE_SYNTAX\n");
    return false;
}

static bool handle_allocate(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    unsigned int bind_port                 = 0;
    unsigned int dest_port                 = 0;
    char         dest_ip[INET6_ADDRSTRLEN] = {};
    char         extra[16]                 = {};

    bool parsed     = false;
    bool want_latch = false;
    bool has_dest   = false;

    if (sscanf(
            args,
            "PORT %u -> FORWARD TO %45[^:]:%u %15s",
            &bind_port,
            dest_ip,
            &dest_port,
            extra) >= 3)
    {
        parsed   = true;
        has_dest = true;
        if (strcasecmp(extra, "LATCH") == 0) {
            want_latch = true;
        }
    } else if (
        sscanf(
            args,
            "PORT %u FORWARD TO %45[^:]:%u %15s",
            &bind_port,
            dest_ip,
            &dest_port,
            extra) >= 3)
    {
        parsed   = true;
        has_dest = true;
        if (strcasecmp(extra, "LATCH") == 0) {
            want_latch = true;
        }
    } else if (
        sscanf(args, "PORT %u FORWARD %45s %u %15s", &bind_port, dest_ip, &dest_port, extra) >= 3)
    {
        parsed   = true;
        has_dest = true;
        if (strcasecmp(extra, "LATCH") == 0) {
            want_latch = true;
        }
    } else if (sscanf(args, "%u %45[^:]:%u %15s", &bind_port, dest_ip, &dest_port, extra) >= 3) {
        parsed   = true;
        has_dest = true;
        if (strcasecmp(extra, "LATCH") == 0) {
            want_latch = true;
        }
    } else if (sscanf(args, "%u %45s %u %15s", &bind_port, dest_ip, &dest_port, extra) >= 3) {
        parsed   = true;
        has_dest = true;
        if (strcasecmp(extra, "LATCH") == 0) {
            want_latch = true;
        }
    } else if (sscanf(args, "PORT %u LATCH", &bind_port) == 1) {
        parsed     = true;
        want_latch = true;
    } else if (sscanf(args, "%u LATCH", &bind_port) == 1) {
        parsed     = true;
        want_latch = true;
    } else if (sscanf(args, "PORT %u", &bind_port) == 1) {
        parsed     = true;
        want_latch = true;
    } else if (sscanf(args, "%u", &bind_port) == 1) {
        parsed     = true;
        want_latch = true;
    }

    if (!parsed) {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_ALLOCATE_SYNTAX\n");
        return false;
    }

    auto const session = session_create(
        table,
        "0.0.0.0",
        (uint16_t)bind_port,
        has_dest ? dest_ip : nullptr,
        has_dest ? (uint16_t)dest_port : 0);
    if (session == nullptr) {
        (void)snprintf(resp_buf, resp_max, "ERROR ALLOCATION_FAILED\n");
        return false;
    }

    bool const want_mux =
        (strcasestr(args, "RTCP-MUX") != nullptr) || (strcasestr(args, "MUX") != nullptr);
    if (want_mux) {
        session_set_rtcp_mux(session, true);
    }

    if (want_latch) {
        session_enable_latching(session, false, false);
    }

    auto const sidx = session_get_index(table, session);
    if ((sidx >= 0) && (engine != nullptr)) {
        (void)session_arm_multishot(session, (size_t)sidx, engine);
    }

    if (want_latch) {
        if (has_dest) {
            (void)snprintf(
                resp_buf,
                resp_max,
                "OK ALLOCATED PORT %u LATCH WAITING (FORWARD TO %s:%u)\n",
                bind_port,
                dest_ip,
                dest_port);
        } else {
            (void)snprintf(resp_buf, resp_max, "OK ALLOCATED PORT %u LATCH WAITING\n", bind_port);
        }
    } else {
        (void)snprintf(
            resp_buf,
            resp_max,
            "OK ALLOCATED PORT %u FORWARD TO %s:%u\n",
            bind_port,
            dest_ip,
            dest_port);
    }
    return true;
}

static bool handle_latch(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    unsigned int port = 0;
    if ((sscanf(args, "PORT %u", &port) == 1) || (sscanf(args, "%u", &port) == 1)) {
        auto const session = session_find_by_port(table, (uint16_t)port);
        if (session != nullptr) {
            session_enable_latching(session, false, false);
            (void)snprintf(resp_buf, resp_max, "OK LATCH ENABLED PORT %u\n", port);
            return true;
        } else {
            (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
            return false;
        }
    }
    (void)snprintf(resp_buf, resp_max, "ERROR INVALID_LATCH_SYNTAX\n");
    return false;
}

static bool handle_bridge(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    unsigned int port_a = 0;
    unsigned int port_b = 0;

    bool parsed = false;
    if (sscanf(args, "PORT %u <-> PORT %u", &port_a, &port_b) == 2) {
        parsed = true;
    } else if (sscanf(args, "PORT %u PORT %u", &port_a, &port_b) == 2) {
        parsed = true;
    } else if (sscanf(args, "%u %u", &port_a, &port_b) == 2) {
        parsed = true;
    }

    if (!parsed) {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_BRIDGE_SYNTAX\n");
        return false;
    }

    if (session_bridge_pair(table, (uint16_t)port_a, (uint16_t)port_b)) {
        (void)snprintf(resp_buf, resp_max, "OK BRIDGED PORT %u <-> PORT %u\n", port_a, port_b);
        return true;
    }

    (void)snprintf(resp_buf, resp_max, "ERROR BRIDGE_FAILED\n");
    return false;
}

static bool handle_record(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    if (unlikely((table == nullptr) || (resp_buf == nullptr) || (resp_max == 0))) {
        return false;
    }

    if (!(table->pcap_table.enabled)) {
        (void)snprintf(resp_buf, resp_max, "ERROR RECORD_DIR_NOT_CONFIGURED\n");
        return false;
    }

    if ((args == nullptr) || (args[0] == '\0') || (strncasecmp(args, "STATUS", 6) == 0)) {
        size_t off     = 0;
        int    written = snprintf(
            resp_buf + off,
            resp_max - off,
            "OK RECORD dir=%s active=%zu total_packets=%llu total_bytes=%llu errors=%llu\n",
            table->pcap_table.record_dir,
            table->pcap_table.active_recorders,
            (unsigned long long)table->pcap_table.total_packets_recorded,
            (unsigned long long)table->pcap_table.total_bytes_recorded,
            (unsigned long long)table->pcap_table.write_failures);
        if (written > 0) {
            off += (size_t)written;
        }

        for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
            pcap_recorder_t const *const rec = &(table->pcap_table.recorders[i]);
            if (rec->active && (off < resp_max)) {
                int const item_w = snprintf(
                    resp_buf + off,
                    resp_max - off,
                    "RECORDER id=%s file=%s ports=%u,%u pkts=%llu bytes=%llu\n",
                    rec->call_id[0] ? rec->call_id : "-",
                    rec->file_path,
                    rec->session_port_a,
                    rec->session_port_b,
                    (unsigned long long)rec->packets_recorded,
                    (unsigned long long)rec->bytes_recorded);
                if (item_w > 0) {
                    off += (size_t)item_w;
                }
            }
        }
        return true;
    }

    if (strncasecmp(args, "START", 5) == 0) {
        char const *p = args + 5;
        while ((*p == ' ') || (*p == '\t')) {
            p++;
        }

        if (strncasecmp(p, "CALL ", 5) == 0) {
            char const *const call_id = p + 5;
            auto const        rec_idx = pcap_recorder_start(&(table->pcap_table), call_id, 0, 0);
            if (rec_idx < 0) {
                (void)snprintf(resp_buf, resp_max, "ERROR RECORD_START_FAILED\n");
                return false;
            }
            auto const rec = pcap_recorder_get(&(table->pcap_table), rec_idx);
            (void)snprintf(
                resp_buf,
                resp_max,
                "OK RECORDING STARTED CALL %s FILE %s\n",
                call_id,
                (rec != nullptr) ? rec->file_path : "");
            return true;
        }

        unsigned int port = 0;
        if ((sscanf(p, "PORT %u", &port) == 1) || (sscanf(p, "%u", &port) == 1)) {
            auto const session = session_find_by_port(table, (uint16_t)port);
            if (session == nullptr) {
                (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
                return false;
            }
            auto const rec_idx =
                pcap_recorder_start(&(table->pcap_table), nullptr, (uint16_t)port, 0);
            if (rec_idx < 0) {
                (void)snprintf(resp_buf, resp_max, "ERROR RECORD_START_FAILED\n");
                return false;
            }
            session->record_idx = rec_idx;
            if ((session->peer_idx >= 0) && ((size_t)session->peer_idx < SESSION_TABLE_MAX)) {
                table->sessions[session->peer_idx].record_idx = rec_idx;
            }
            auto const rec = pcap_recorder_get(&(table->pcap_table), rec_idx);
            (void)snprintf(
                resp_buf,
                resp_max,
                "OK RECORDING STARTED PORT %u FILE %s\n",
                port,
                (rec != nullptr) ? rec->file_path : "");
            return true;
        }

        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_RECORD_START_SYNTAX\n");
        return false;
    }

    if (strncasecmp(args, "STOP", 4) == 0) {
        char const *p = args + 4;
        while ((*p == ' ') || (*p == '\t')) {
            p++;
        }

        if (strncasecmp(p, "CALL ", 5) == 0) {
            char const *const call_id = p + 5;
            if (pcap_recorder_stop_by_id(&(table->pcap_table), call_id)) {
                (void)snprintf(resp_buf, resp_max, "OK RECORDING STOPPED CALL %s\n", call_id);
                return true;
            }
            (void)snprintf(resp_buf, resp_max, "ERROR RECORDING_NOT_FOUND\n");
            return false;
        }

        unsigned int port = 0;
        if ((sscanf(p, "PORT %u", &port) == 1) || (sscanf(p, "%u", &port) == 1)) {
            auto const session = session_find_by_port(table, (uint16_t)port);
            if (session != nullptr) {
                if (session->record_idx >= 0) {
                    (void)pcap_recorder_stop_by_index(&(table->pcap_table), session->record_idx);
                }
                session->record_idx = -1;
                if ((session->peer_idx >= 0) && ((size_t)session->peer_idx < SESSION_TABLE_MAX)) {
                    table->sessions[session->peer_idx].record_idx = -1;
                }
                (void)snprintf(resp_buf, resp_max, "OK RECORDING STOPPED PORT %u\n", port);
                return true;
            }
            if (pcap_recorder_stop_by_port(&(table->pcap_table), (uint16_t)port)) {
                (void)snprintf(resp_buf, resp_max, "OK RECORDING STOPPED PORT %u\n", port);
                return true;
            }
            (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
            return false;
        }

        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_RECORD_STOP_SYNTAX\n");
        return false;
    }

    (void)snprintf(resp_buf, resp_max, "ERROR UNKNOWN_RECORD_ACTION\n");
    return false;
}

static bool handle_transcode(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    if (unlikely(table == nullptr)) {
        (void)snprintf(resp_buf, resp_max, "ERROR INTERNAL\n");
        return false;
    }

    if ((args == nullptr) || (*args == '\0')) {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_TRANSCODE_SYNTAX\n");
        return false;
    }

    if (strncasecmp(args, "STATUS", 6) == 0) {
        char const *p = args + 6;
        while ((*p == ' ') || (*p == '\t')) {
            p++;
        }
        int const port = atoi(p);
        if ((port <= 0) || (port > 65535)) {
            (void)snprintf(resp_buf, resp_max, "ERROR INVALID_PORT\n");
            return false;
        }
        auto const session = session_find_by_port(table, (uint16_t)port);
        if (session == nullptr) {
            (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
            return false;
        }
        if (!(session->transcode_enabled)) {
            (void)snprintf(resp_buf, resp_max, "OK TRANSCODE DISABLED PORT %u\n", (uint16_t)port);
            return true;
        }
        if (session->jitter_buf != nullptr) {
            (void)snprintf(
                resp_buf,
                resp_max,
                "OK TRANSCODE PORT %u backend=%s src=%s dst=%s in=%lu out=%lu errors=%lu jb=active "
                "depth=%u queued=%u reordered=%lu dropped_late=%lu plc=%lu\n",
                (uint16_t)port,
                transcoder_backend_name(session->transcode_ctx.backend),
                media_codec_name(session->transcode_ctx.src_codec),
                media_codec_name(session->transcode_ctx.dst_codec),
                (unsigned long)session->transcode_ctx.packets_in,
                (unsigned long)session->transcode_ctx.packets_out,
                (unsigned long)session->transcode_ctx.errors,
                (unsigned int)session->jitter_buf->target_depth,
                (unsigned int)session->jitter_buf->occupancy,
                (unsigned long)session->jitter_buf->packets_reordered,
                (unsigned long)session->jitter_buf->packets_dropped_late,
                (unsigned long)session->jitter_buf->loss_concealments);
        } else {
            (void)snprintf(
                resp_buf,
                resp_max,
                "OK TRANSCODE PORT %u backend=%s src=%s dst=%s in=%lu out=%lu errors=%lu "
                "jb=disabled\n",
                (uint16_t)port,
                transcoder_backend_name(session->transcode_ctx.backend),
                media_codec_name(session->transcode_ctx.src_codec),
                media_codec_name(session->transcode_ctx.dst_codec),
                (unsigned long)session->transcode_ctx.packets_in,
                (unsigned long)session->transcode_ctx.packets_out,
                (unsigned long)session->transcode_ctx.errors);
        }
        return true;
    }

    char const *p = args;
    while ((*p == ' ') || (*p == '\t')) {
        p++;
    }
    if (*p == '\0') {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_TRANSCODE_SYNTAX\n");
        return false;
    }

    char   port_buf[32] = {};
    size_t plen         = 0;
    while ((*p != '\0') && (*p != ' ') && (*p != '\t') && (*p != '\r') && (*p != '\n') &&
           (plen < sizeof(port_buf) - 1))
    {
        port_buf[plen++] = *p++;
    }
    port_buf[plen] = '\0';

    int const port = atoi(port_buf);
    if ((port <= 0) || (port > 65535)) {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_PORT\n");
        return false;
    }

    auto const session = session_find_by_port(table, (uint16_t)port);
    if (session == nullptr) {
        (void)snprintf(resp_buf, resp_max, "ERROR PORT_NOT_FOUND\n");
        return false;
    }

    transcoder_backend_t backend    = table->default_transcoder;
    media_codec_t        dst_codec  = MEDIA_CODEC_NONE;
    media_codec_t        src_codec  = MEDIA_CODEC_NONE;
    int                  jitter_ms  = -1;
    bool                 is_disable = false;
    bool                 had_args   = false;
    int                  pos        = 0;

    while (*p != '\0') {
        while ((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n')) {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        had_args         = true;
        char   token[64] = {};
        size_t tlen      = 0;
        while ((*p != '\0') && (*p != ' ') && (*p != '\t') && (*p != '\r') && (*p != '\n') &&
               (tlen < sizeof(token) - 1))
        {
            token[tlen++] = *p++;
        }
        token[tlen] = '\0';

        if ((strcasecmp(token, "OFF") == 0) || (strcasecmp(token, "STOP") == 0) ||
            (strcasecmp(token, "DISABLE") == 0))
        {
            is_disable = true;
            break;
        }

        if (strncasecmp(token, "jitter=", 7) == 0) {
            jitter_ms = atoi(token + 7);
        } else if (strncasecmp(token, "jb=", 3) == 0) {
            jitter_ms = atoi(token + 3);
        } else if (strncasecmp(token, "backend=", 8) == 0) {
            backend = transcoder_backend_from_str(token + 8);
        } else if (strncasecmp(token, "dst=", 4) == 0) {
            dst_codec = media_codec_from_str(token + 4);
        } else if (strncasecmp(token, "src=", 4) == 0) {
            src_codec = media_codec_from_str(token + 4);
        } else {
            if (pos == 0) {
                dst_codec = media_codec_from_str(token);
            } else if (pos == 1) {
                backend = transcoder_backend_from_str(token);
            }
            pos++;
        }
    }

    if (!had_args) {
        (void)snprintf(resp_buf, resp_max, "ERROR INVALID_TRANSCODE_SYNTAX\n");
        return false;
    }

    if (is_disable) {
        session_clear_transcode(session);
        (void)snprintf(resp_buf, resp_max, "OK TRANSCODE DISABLED PORT %u\n", (uint16_t)port);
        return true;
    }

    if (dst_codec == MEDIA_CODEC_NONE) {
        (void)snprintf(resp_buf, resp_max, "ERROR UNKNOWN_CODEC\n");
        return false;
    }

    if (backend == TRANSCODER_BACKEND_NONE) {
        backend = TRANSCODER_BACKEND_OPUS;
    }

    if (src_codec == MEDIA_CODEC_NONE) {
        if (dst_codec == MEDIA_CODEC_OPUS) {
            src_codec = MEDIA_CODEC_PCMU;
        } else {
            src_codec = MEDIA_CODEC_OPUS;
        }
    }

    if (!session_set_transcode(session, backend, src_codec, dst_codec)) {
        (void)snprintf(resp_buf, resp_max, "ERROR TRANSCODE_INIT_FAILED\n");
        return false;
    }

    if (jitter_ms > 0) {
        if (!session_set_jitter_buffer(session, (uint32_t)jitter_ms)) {
            (void)snprintf(resp_buf, resp_max, "ERROR JITTER_BUFFER_INIT_FAILED\n");
            return false;
        }
        (void)snprintf(
            resp_buf,
            resp_max,
            "OK TRANSCODE PORT %u backend=%s src=%s dst=%s jb=%u ms\n",
            (uint16_t)port,
            transcoder_backend_name(backend),
            media_codec_name(src_codec),
            media_codec_name(dst_codec),
            (unsigned int)jitter_ms);
    } else {
        if (jitter_ms == 0) {
            (void)session_set_jitter_buffer(session, 0);
        } else if (table->default_jitter_delay_ms > 0) {
            (void)session_set_jitter_buffer(session, table->default_jitter_delay_ms);
        }
        (void)snprintf(
            resp_buf,
            resp_max,
            "OK TRANSCODE PORT %u backend=%s src=%s dst=%s\n",
            (uint16_t)port,
            transcoder_backend_name(backend),
            media_codec_name(src_codec),
            media_codec_name(dst_codec));
    }
    return true;
}

static bool handle_http_get(
    char const *const args,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    (void)engine;
    if (unlikely((table == nullptr) || (resp_buf == nullptr) || (resp_max == 0))) {
        return false;
    }

    bool const is_metrics =
        (args != nullptr) && ((strncasecmp(args, "/metrics", 8) == 0) &&
                              ((args[8] == ' ') || (args[8] == '\r') || (args[8] == '\n') ||
                               (args[8] == '\0') || (args[8] == '?')));

    bool const is_root = (args != nullptr) && (args[0] == '/') &&
                         ((args[1] == ' ') || (args[1] == '\r') || (args[1] == '\n') ||
                          (args[1] == '\0') || (args[1] == '?'));

    if (is_metrics || is_root) {
        if (table->metrics != nullptr) {
            char         prom_body[CONTROL_BUFFER_SIZE - 256] = {};
            size_t const active_video                         = count_active_video_sessions(table);
            size_t       prom_len                             = metrics_format_prometheus(
                table->metrics,
                table->active_count,
                active_video,
                prom_body,
                sizeof(prom_body));
            if ((prom_len > 0) && (prom_len < sizeof(prom_body))) {
                prom_len += session_table_format_ssrc_metrics(
                    table,
                    prom_body + prom_len,
                    sizeof(prom_body) - prom_len);
            }
            int const written = snprintf(
                resp_buf,
                resp_max,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%.*s",
                prom_len,
                (int)prom_len,
                prom_body);
            return ((written > 0) && ((size_t)written < resp_max));
        }

        int const written = snprintf(
            resp_buf,
            resp_max,
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 26\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ERROR: metrics unavailable\n");
        return ((written > 0) && ((size_t)written < resp_max));
    }

    bool const is_health =
        (args != nullptr) &&
        (((strncasecmp(args, "/health", 7) == 0) &&
          ((args[7] == ' ') || (args[7] == '\r') || (args[7] == '\n') || (args[7] == '\0'))) ||
         ((strncasecmp(args, "/ping", 5) == 0) &&
          ((args[5] == ' ') || (args[5] == '\r') || (args[5] == '\n') || (args[5] == '\0'))));

    if (is_health) {
        int const written = snprintf(
            resp_buf,
            resp_max,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 3\r\n"
            "Connection: close\r\n"
            "\r\n"
            "OK\n");
        return ((written > 0) && ((size_t)written < resp_max));
    }

    int const written = snprintf(
        resp_buf,
        resp_max,
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n");
    (void)written;
    return false;
}

static cmd_entry_t const COMMANDS[] = {
    {.verb = SV_STATIC("PING"), .handler = handle_ping},
    {.verb = SV_STATIC("GET"), .handler = handle_http_get},
    {.verb = SV_STATIC("STATUS"), .handler = handle_status},
    {.verb = SV_STATIC("BRIDGE"), .handler = handle_bridge},
    {.verb = SV_STATIC("ALLOCATE"), .handler = handle_allocate},
    {.verb = SV_STATIC("DELETE"), .handler = handle_delete},
    {.verb = SV_STATIC("LATCH"), .handler = handle_latch},
    {.verb = SV_STATIC("TRANSCODE"), .handler = handle_transcode},
    {.verb = SV_STATIC("RECORD"), .handler = handle_record},
    {.verb = SV_STATIC("QUIT"), .handler = handle_quit},
};

static bool control_process_text(
    char const *const cmd_str,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    char       line[CONTROL_BUFFER_SIZE] = {};
    auto const cmd_len                   = __builtin_strlen(cmd_str);
    auto const copy_len = (cmd_len < sizeof(line) - 1) ? cmd_len : sizeof(line) - 1;
    __builtin_memcpy(line, cmd_str, copy_len);
    line[copy_len] = '\0';
    trim_whitespace(line);

    if (line[0] == '\0') {
        (void)snprintf(resp_buf, resp_max, "ERROR EMPTY_COMMAND\n");
        return false;
    }

    char const *p = line;
    while ((*p != '\0') && (*p != ' ') && (*p != '\t')) {
        p++;
    }

    size_t const verb_len = (size_t)(p - line);
    sv_t const   verb     = SV_INIT(line, verb_len);

    while ((*p == ' ') || (*p == '\t')) {
        p++;
    }
    char const *const args = p;

    for (size_t i = 0; i < (sizeof(COMMANDS) / sizeof(COMMANDS[0])); ++i) {
        cmd_entry_t const *const entry = &COMMANDS[i];
        if ((entry->verb.length == verb.length) &&
            (strncasecmp(entry->verb.data, verb.data, verb.length) == 0))
        {
            return entry->handler(args, table, engine, resp_buf, resp_max);
        }
    }

    (void)snprintf(resp_buf, resp_max, "ERROR UNKNOWN_COMMAND\n");
    return false;
}

bool control_process_command_ex(
    char const *const cmd_str,
    size_t const      cmd_len,
    session_table_t *restrict const table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    if (unlikely(
            (cmd_str == nullptr) || (table == nullptr) || (resp_buf == nullptr) || (resp_max == 0)))
    {
        return false;
    }

    static ng_call_table_t s_fallback_call_table;
    static bool            s_fallback_initialized = false;
    if (!s_fallback_initialized) {
        ng_call_table_init(&s_fallback_call_table, "127.0.0.1");
        s_fallback_initialized = true;
    }

    ng_call_table_t *const target_calls =
        (call_table != nullptr) ? call_table : &s_fallback_call_table;

    if (unlikely(target_calls->draining)) {
        if (!ng_is_message(cmd_str, cmd_len)) {
            char const *p = cmd_str;
            while ((*p == ' ') || (*p == '\t')) {
                p++;
            }
            if ((strncasecmp(p, "ALLOCATE", 8) == 0) || (strncasecmp(p, "BRIDGE", 6) == 0)) {
                (void)snprintf(resp_buf, resp_max, "ERROR server is draining\n");
                return false;
            }
        }
    }

    if (ng_is_message(cmd_str, cmd_len)) {
        return ng_process_message(
            cmd_str,
            cmd_len,
            table,
            target_calls,
            engine,
            resp_buf,
            resp_max,
            nullptr);
    }

    return control_process_text(cmd_str, table, engine, resp_buf, resp_max);
}

bool control_process_command(
    char const *const cmd_str,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max) {
    if (unlikely(cmd_str == nullptr)) {
        return false;
    }
    return control_process_command_ex(
        cmd_str,
        __builtin_strlen(cmd_str),
        table,
        nullptr,
        engine,
        resp_buf,
        resp_max);
}

void control_server_set_media_ip(
    control_server_t *restrict const server,
    char const *const media_ip) {
    if (unlikely(server == nullptr)) {
        return;
    }
    char const *const ip  = (media_ip != nullptr) ? media_ip : "127.0.0.1";
    auto const        len = __builtin_strlen(ip);
    auto const copylen = (len < sizeof(server->media_ip) - 1) ? len : sizeof(server->media_ip) - 1;
    __builtin_memcpy(server->media_ip, ip, copylen);
    server->media_ip[copylen] = '\0';
    __builtin_memcpy(
        server->call_table.media_ip,
        server->media_ip,
        sizeof(server->call_table.media_ip));
}

static bool
control_arm_accept(control_server_t *restrict const server, ring_engine_t *restrict const engine) {
    auto const sqe = ring_engine_get_sqe(engine);
    if (unlikely(sqe == nullptr)) {
        return false;
    }

    io_uring_prep_accept(sqe, server->listen_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    user_data_tag_t const tag = {
        .fields = {
            .index   = 0,
            .op_type = OP_TYPE_CONTROL_ACCEPT,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(sqe, tag.raw);
    return true;
}

static bool control_arm_udp_recv(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine) {
    if (unlikely((server == nullptr) || (engine == nullptr) || (server->udp_fd < 0))) {
        return false;
    }

    auto const sqe = ring_engine_get_sqe(engine);
    if (unlikely(sqe == nullptr)) {
        return false;
    }

    server->udp_rx_iov = (struct iovec){
        .iov_base = server->udp_rx_buffer,
        .iov_len  = sizeof(server->udp_rx_buffer) - 1,
    };
    server->udp_rx_msghdr = (struct msghdr){
        .msg_name       = &(server->udp_peer_addr),
        .msg_namelen    = sizeof(server->udp_peer_addr),
        .msg_iov        = &(server->udp_rx_iov),
        .msg_iovlen     = 1,
        .msg_control    = nullptr,
        .msg_controllen = 0,
        .msg_flags      = 0,
    };

    io_uring_prep_recvmsg(sqe, server->udp_fd, &(server->udp_rx_msghdr), 0);
    user_data_tag_t const tag = {
        .fields = {
            .index   = 0,
            .op_type = OP_TYPE_CONTROL_UDP_RECV,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(sqe, tag.raw);
    return true;
}

bool control_server_init_unix(
    control_server_t *restrict const server,
    char const *const socket_path,
    ring_engine_t *restrict const engine) {
    if (unlikely((server == nullptr) || (socket_path == nullptr) || (engine == nullptr))) {
        return false;
    }

    *server           = (control_server_t){};
    server->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    server->udp_fd    = -1;
    if (unlikely(server->listen_fd < 0)) {
        return false;
    }

    struct sockaddr_un un = {};
    un.sun_family         = AF_UNIX;
    auto const path_len   = __builtin_strlen(socket_path);
    auto const copy_len = (path_len < sizeof(un.sun_path) - 1) ? path_len : sizeof(un.sun_path) - 1;
    __builtin_memcpy(un.sun_path, socket_path, copy_len);
    un.sun_path[copy_len] = '\0';

    (void)unlink(socket_path);

    if (unlikely(bind(server->listen_fd, (struct sockaddr const *)&un, sizeof(un)) < 0)) {
        close(server->listen_fd);
        server->listen_fd = -1;
        return false;
    }

    if (unlikely(listen(server->listen_fd, 16) < 0)) {
        close(server->listen_fd);
        server->listen_fd = -1;
        (void)unlink(socket_path);
        return false;
    }

    server->is_unix = true;
    __builtin_memcpy(server->unix_path, un.sun_path, sizeof(server->unix_path));
    control_server_set_media_ip(server, "127.0.0.1");

    return control_arm_accept(server, engine);
}

bool control_server_init_tcp(
    control_server_t *restrict const server,
    char const *const ip,
    uint16_t const    port,
    ring_engine_t *restrict const engine) {
    if (unlikely((server == nullptr) || (port == 0) || (engine == nullptr))) {
        return false;
    }

    *server           = (control_server_t){};
    server->listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    server->udp_fd    = -1;
    if (unlikely(server->listen_fd < 0)) {
        return false;
    }

    int const opt = 1;
    (void)setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in in       = {};
    in.sin_family               = AF_INET;
    in.sin_port                 = htons(port);
    char const *const target_ip = (ip != nullptr) ? ip : "127.0.0.1";
    (void)inet_pton(AF_INET, target_ip, &(in.sin_addr));

    if (unlikely(bind(server->listen_fd, (struct sockaddr const *)&in, sizeof(in)) < 0)) {
        close(server->listen_fd);
        server->listen_fd = -1;
        return false;
    }

    if (unlikely(listen(server->listen_fd, 16) < 0)) {
        close(server->listen_fd);
        server->listen_fd = -1;
        return false;
    }

    server->is_unix  = false;
    server->tcp_port = port;
    if (server->media_ip[0] == '\0') {
        control_server_set_media_ip(server, target_ip);
    }

    return control_arm_accept(server, engine);
}

bool control_server_init_udp(
    control_server_t *restrict const server,
    char const *const ip,
    uint16_t const    port,
    ring_engine_t *restrict const engine) {
    if (unlikely((server == nullptr) || (port == 0) || (engine == nullptr))) {
        return false;
    }

    server->udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (unlikely(server->udp_fd < 0)) {
        return false;
    }

    int const opt = 1;
    (void)setsockopt(server->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in in       = {};
    in.sin_family               = AF_INET;
    in.sin_port                 = htons(port);
    char const *const target_ip = (ip != nullptr) ? ip : "127.0.0.1";
    (void)inet_pton(AF_INET, target_ip, &(in.sin_addr));

    if (unlikely(bind(server->udp_fd, (struct sockaddr const *)&in, sizeof(in)) < 0)) {
        close(server->udp_fd);
        server->udp_fd = -1;
        return false;
    }

    server->has_udp  = true;
    server->udp_port = port;
    if (server->media_ip[0] == '\0') {
        control_server_set_media_ip(server, target_ip);
    }

    return control_arm_udp_recv(server, engine);
}

void control_server_destroy(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine) {
    if (unlikely(server == nullptr)) {
        return;
    }

    ng_call_table_destroy(&(server->call_table), nullptr, engine);

    for (size_t i = 0; i < MAX_CONTROL_CLIENTS; ++i) {
        if (server->clients[i].active && (server->clients[i].client_fd >= 0)) {
            close(server->clients[i].client_fd);
        }
    }

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
    }

    if (server->udp_fd >= 0) {
        close(server->udp_fd);
    }

    if (server->is_unix && (server->unix_path[0] != '\0')) {
        (void)unlink(server->unix_path);
    }

    *server = (control_server_t){.listen_fd = -1, .udp_fd = -1};
}

void control_server_stop_listen(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine) {
    (void)engine;
    if (unlikely(server == nullptr)) {
        return;
    }
    server->draining            = true;
    server->call_table.draining = true;
    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }
    if (server->is_unix && (server->unix_path[0] != '\0')) {
        (void)unlink(server->unix_path);
        server->unix_path[0] = '\0';
    }
}

void control_server_handle_accept_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe) {
    if (unlikely((server == nullptr) || (engine == nullptr) || (cqe == nullptr))) {
        return;
    }

    int const client_fd = cqe->res;

    if (unlikely(server->draining || (server->listen_fd < 0))) {
        if (client_fd >= 0) {
            close(client_fd);
        }
        return;
    }

    // Immediately re-arm accept listener on ring
    (void)control_arm_accept(server, engine);

    if (unlikely(client_fd < 0)) {
        return;
    }

    // Find free client slot
    for (size_t i = 0; i < MAX_CONTROL_CLIENTS; ++i) {
        control_client_t *const client = &(server->clients[i]);
        if (!(client->active)) {
            *client           = (control_client_t){};
            client->client_fd = client_fd;
            client->active    = true;

            auto const rx_sqe = ring_engine_get_sqe(engine);
            if (unlikely(rx_sqe == nullptr)) {
                close(client_fd);
                *client = (control_client_t){};
                return;
            }

            io_uring_prep_recv(rx_sqe, client_fd, client->rx_buffer, CONTROL_BUFFER_SIZE - 1, 0);
            user_data_tag_t const tag = {
                .fields = {
                    .index   = (uint16_t)i,
                    .op_type = OP_TYPE_CONTROL_RECV,
                    .bid     = 0,
                    .flags   = 0,
                }};
            io_uring_sqe_set_data64(rx_sqe, tag.raw);
            return;
        }
    }

    // No available client slot; reject connection
    close(client_fd);
}

void control_server_handle_rx_cqe(
    control_server_t *restrict const server,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   client_idx) {
    if (unlikely(
            (server == nullptr) || (table == nullptr) || (engine == nullptr) || (cqe == nullptr)))
    {
        return;
    }
    if (unlikely(client_idx >= MAX_CONTROL_CLIENTS)) {
        return;
    }

    control_client_t *const client = &(server->clients[client_idx]);
    if (unlikely(!(client->active))) {
        return;
    }

    if (cqe->res <= 0) {
        // Disconnected or read error
        close(client->client_fd);
        *client = (control_client_t){};
        return;
    }

    client->rx_buffer[cqe->res] = '\0';

    (void)control_process_command_ex(
        client->rx_buffer,
        (size_t)cqe->res,
        table,
        &(server->call_table),
        engine,
        client->tx_buffer,
        CONTROL_BUFFER_SIZE);
    client->tx_len = (uint32_t)__builtin_strlen(client->tx_buffer);

    auto const tx_sqe = ring_engine_get_sqe(engine);
    if (unlikely(tx_sqe == nullptr)) {
        close(client->client_fd);
        *client = (control_client_t){};
        return;
    }

    io_uring_prep_send(tx_sqe, client->client_fd, client->tx_buffer, client->tx_len, 0);
    user_data_tag_t const tag = {
        .fields = {
            .index   = client_idx,
            .op_type = OP_TYPE_CONTROL_SEND,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(tx_sqe, tag.raw);
}

void control_server_handle_tx_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   client_idx) {
    (void)cqe;
    if (unlikely((server == nullptr) || (engine == nullptr) || (client_idx >= MAX_CONTROL_CLIENTS)))
    {
        return;
    }

    control_client_t *const client = &(server->clients[client_idx]);
    if (unlikely(!(client->active))) {
        return;
    }

    // Re-arm receive for subsequent command
    auto const rx_sqe = ring_engine_get_sqe(engine);
    if (unlikely(rx_sqe == nullptr)) {
        close(client->client_fd);
        *client = (control_client_t){};
        return;
    }

    io_uring_prep_recv(rx_sqe, client->client_fd, client->rx_buffer, CONTROL_BUFFER_SIZE - 1, 0);
    user_data_tag_t const tag = {
        .fields = {
            .index   = client_idx,
            .op_type = OP_TYPE_CONTROL_RECV,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(rx_sqe, tag.raw);
}

void control_server_handle_udp_rx_cqe(
    control_server_t *restrict const server,
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe) {
    if (unlikely(
            (server == nullptr) || (table == nullptr) || (engine == nullptr) || (cqe == nullptr)))
    {
        return;
    }

    if (cqe->res <= 0) {
        (void)control_arm_udp_recv(server, engine);
        return;
    }

    server->udp_rx_buffer[cqe->res] = '\0';
    server->udp_peer_len            = server->udp_rx_msghdr.msg_namelen;

    (void)control_process_command_ex(
        server->udp_rx_buffer,
        (size_t)cqe->res,
        table,
        &(server->call_table),
        engine,
        server->udp_tx_buffer,
        CONTROL_BUFFER_SIZE);
    server->udp_tx_len = (uint32_t)__builtin_strlen(server->udp_tx_buffer);

    auto const tx_sqe = ring_engine_get_sqe(engine);
    if (unlikely(tx_sqe == nullptr)) {
        (void)control_arm_udp_recv(server, engine);
        return;
    }

    server->udp_tx_iov = (struct iovec){
        .iov_base = server->udp_tx_buffer,
        .iov_len  = server->udp_tx_len,
    };
    server->udp_tx_msghdr = (struct msghdr){
        .msg_name       = &(server->udp_peer_addr),
        .msg_namelen    = server->udp_peer_len,
        .msg_iov        = &(server->udp_tx_iov),
        .msg_iovlen     = 1,
        .msg_control    = nullptr,
        .msg_controllen = 0,
        .msg_flags      = 0,
    };

    io_uring_prep_sendmsg(tx_sqe, server->udp_fd, &(server->udp_tx_msghdr), 0);
    user_data_tag_t const tag = {
        .fields = {
            .index   = 0,
            .op_type = OP_TYPE_CONTROL_UDP_SEND,
            .bid     = 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(tx_sqe, tag.raw);
}

void control_server_handle_udp_tx_cqe(
    control_server_t *restrict const server,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe) {
    (void)cqe;
    if (unlikely((server == nullptr) || (engine == nullptr))) {
        return;
    }

    // Re-arm receive for subsequent UDP control datagrams
    (void)control_arm_udp_recv(server, engine);
}
