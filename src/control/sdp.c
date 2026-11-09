#include "control/sdp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core/macros.h"

static inline sv_t sdp_next_line(sv_t *restrict const cursor) {
    if (unlikely((cursor == nullptr) || (cursor->data == nullptr) || (cursor->length == 0))) {
        return (sv_t){};
    }

    char const *const start = cursor->data;
    size_t            len   = 0;

    while ((len < cursor->length) && (start[len] != '\r') && (start[len] != '\n')) {
        len++;
    }

    sv_t const res = {.data = start, .length = len};

    size_t adv = len;
    if ((adv < cursor->length) && (start[adv] == '\r')) {
        adv++;
    }
    if ((adv < cursor->length) && (start[adv] == '\n')) {
        adv++;
    }

    cursor->data += adv;
    cursor->length -= adv;
    return res;
}

static inline bool sdp_append_line(
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const off,
    char const *const line,
    size_t const      len) {
    if ((*off + len + 2) >= out_cap) {
        return false;
    }
    __builtin_memcpy(out_buf + *off, line, len);
    *off += len;
    out_buf[(*off)++] = '\r';
    out_buf[(*off)++] = '\n';
    out_buf[*off]     = '\0';
    return true;
}

bool sdp_parse(sv_t const sdp_sv, sdp_session_t *restrict const out) {
    if (unlikely((sdp_sv.data == nullptr) || (sdp_sv.length == 0) || (out == nullptr))) {
        return false;
    }

    *out        = (sdp_session_t){};
    sv_t cursor = sdp_sv;

    char                sess_ice_ufrag[64]  = {};
    char                sess_ice_pwd[128]   = {};
    char                sess_dtls_fp[128]   = {};
    char                sess_dtls_setup[32] = {};
    bool                has_sess_ice        = false;
    bool                has_sess_dtls       = false;
    sdp_media_stream_t *curr                = nullptr;

    while (cursor.length > 0) {
        sv_t const line = sdp_next_line(&cursor);
        if (line.length < 2) {
            continue;
        }

        // Connection line: c=IN IP4 <ip> or c=IN IP6 <ip>
        if ((line.data[0] == 'c') && (line.data[1] == '=')) {
            char net_type[16]         = {};
            char addr_type[16]        = {};
            char ip[INET6_ADDRSTRLEN] = {};
            if (sscanf(line.data, "c=%15s %15s %45s", net_type, addr_type, ip) == 3) {
                auto const iplen   = __builtin_strlen(ip);
                auto const copylen = (iplen < sizeof(out->connection_ip) - 1)
                                         ? iplen
                                         : sizeof(out->connection_ip) - 1;
                __builtin_memcpy(out->connection_ip, ip, copylen);
                out->connection_ip[copylen] = '\0';
                out->has_connection         = true;
            }
            continue;
        }

        // BUNDLE group line: a=group:BUNDLE <mids...>
        if ((line.length >= 14) && (__builtin_memcmp(line.data, "a=group:BUNDLE", 14) == 0)) {
            out->has_bundle = true;
            char const *p   = line.data + 14;
            char const *end = line.data + line.length;
            while (p < end) {
                while ((p < end) && ((*p == ' ') || (*p == '\t'))) {
                    p++;
                }
                if (p >= end) {
                    break;
                }
                char const *tok_start = p;
                while ((p < end) && (*p != ' ') && (*p != '\t') && (*p != '\r') && (*p != '\n')) {
                    p++;
                }
                size_t const tok_len = (size_t)(p - tok_start);
                if ((tok_len > 0) && (out->bundle_mid_count < SDP_MAX_MEDIA_STREAMS)) {
                    size_t const copy_len = (tok_len < (sizeof(out->bundle_mids[0]) - 1))
                                                ? tok_len
                                                : (sizeof(out->bundle_mids[0]) - 1);
                    __builtin_memcpy(out->bundle_mids[out->bundle_mid_count], tok_start, copy_len);
                    out->bundle_mids[out->bundle_mid_count][copy_len] = '\0';
                    out->bundle_mid_count++;
                }
            }
            continue;
        }

        // Media description line: m=<media> <port> <proto> <fmt...>
        if ((line.data[0] == 'm') && (line.data[1] == '=')) {
            if (out->stream_count < SDP_MAX_MEDIA_STREAMS) {
                curr  = &(out->streams[out->stream_count++]);
                *curr = (sdp_media_stream_t){};

                char         media[16] = {};
                unsigned int port      = 0;
                char         proto[32] = {};
                int          n_read    = 0;
                if (sscanf(line.data, "m=%15s %u %31s%n", media, &port, proto, &n_read) >= 3) {
                    curr->port      = (uint16_t)port;
                    auto const mlen = (__builtin_strlen(media) < (sizeof(curr->media_name) - 1))
                                          ? __builtin_strlen(media)
                                          : (sizeof(curr->media_name) - 1);
                    __builtin_memcpy(curr->media_name, media, mlen);
                    curr->media_name[mlen] = '\0';

                    auto const plen = (__builtin_strlen(proto) < (sizeof(curr->transport) - 1))
                                          ? __builtin_strlen(proto)
                                          : (sizeof(curr->transport) - 1);
                    __builtin_memcpy(curr->transport, proto, plen);
                    curr->transport[plen] = '\0';

                    if (strcmp(media, "audio") == 0) {
                        curr->type = SDP_MEDIA_AUDIO;
                    } else if (strcmp(media, "video") == 0) {
                        curr->type = SDP_MEDIA_VIDEO;
                    } else if (strcmp(media, "application") == 0) {
                        curr->type = SDP_MEDIA_APPLICATION;
                    }

                    if ((strstr(proto, "SAVP") != nullptr) || (strstr(proto, "savp") != nullptr)) {
                        curr->is_savp = true;
                    }

                    // Parse payload types
                    char const *p   = line.data + n_read;
                    char const *end = line.data + line.length;
                    while ((p < end) && (curr->payload_type_count < SDP_MAX_PAYLOAD_TYPES)) {
                        while ((p < end) && ((*p == ' ') || (*p == '\t'))) {
                            p++;
                        }
                        if (p >= end) {
                            break;
                        }
                        int pt_val   = 0;
                        int pt_chars = 0;
                        if (sscanf(p, "%d%n", &pt_val, &pt_chars) == 1) {
                            curr->payload_types[curr->payload_type_count++] = (uint8_t)pt_val;
                            p += pt_chars;
                        } else {
                            break;
                        }
                    }

                    // Inherit session-level ICE/DTLS
                    if (has_sess_ice) {
                        __builtin_memcpy(curr->ice_ufrag, sess_ice_ufrag, sizeof(curr->ice_ufrag));
                        __builtin_memcpy(curr->ice_pwd, sess_ice_pwd, sizeof(curr->ice_pwd));
                        curr->has_ice = true;
                    }
                    if (has_sess_dtls) {
                        __builtin_memcpy(
                            curr->dtls_fingerprint,
                            sess_dtls_fp,
                            sizeof(curr->dtls_fingerprint));
                        __builtin_memcpy(
                            curr->dtls_setup,
                            sess_dtls_setup,
                            sizeof(curr->dtls_setup));
                        curr->has_dtls = true;
                    }
                }
            } else {
                curr = nullptr;
            }
            continue;
        }

        // MID line: a=mid:<mid>
        if ((line.length >= 6) && (__builtin_memcmp(line.data, "a=mid:", 6) == 0)) {
            if (curr != nullptr) {
                char mid[16] = {};
                if (sscanf(line.data, "a=mid:%15s", mid) == 1) {
                    auto const mlen = __builtin_strlen(mid);
                    __builtin_memcpy(curr->mid, mid, mlen + 1);
                    curr->has_mid = true;
                }
            }
            continue;
        }

        // RTCP line: a=rtcp:<port>
        if ((line.length >= 7) && (__builtin_memcmp(line.data, "a=rtcp:", 7) == 0)) {
            unsigned int rp = 0;
            if (sscanf(line.data, "a=rtcp:%u", &rp) == 1) {
                if (curr != nullptr) {
                    curr->rtcp_port = (uint16_t)rp;
                    curr->has_rtcp  = true;
                }
            }
            continue;
        }

        // RTCP-MUX line: a=rtcp-mux
        if ((line.length >= 10) && (__builtin_memcmp(line.data, "a=rtcp-mux", 10) == 0) &&
            ((line.length == 10) || (line.data[10] == ' ') || (line.data[10] == '\t')))
        {
            if (curr != nullptr) {
                curr->rtcp_mux = true;
            }
            continue;
        }

        // RTCP feedback lines: a=rtcp-fb:...
        if ((line.length >= 10) && (__builtin_memcmp(line.data, "a=rtcp-fb:", 10) == 0)) {
            if (curr != nullptr) {
                if (strstr(line.data, "pli") != nullptr) {
                    curr->has_pli = true;
                }
                if (strstr(line.data, "fir") != nullptr) {
                    curr->has_fir = true;
                }
                if (strstr(line.data, "nack") != nullptr) {
                    curr->has_nack = true;
                }
                if (strstr(line.data, "goog-remb") != nullptr) {
                    curr->has_remb = true;
                }
                if (strstr(line.data, "transport-cc") != nullptr) {
                    curr->has_twcc = true;
                }
            }
            continue;
        }

        // Extmap line: a=extmap:<id> <uri>
        if ((line.length >= 9) && (__builtin_memcmp(line.data, "a=extmap:", 9) == 0)) {
            if (curr != nullptr) {
                unsigned int ext_id   = 0;
                char         uri[128] = {};
                if (sscanf(line.data, "a=extmap:%u %127s", &ext_id, uri) == 2) {
                    if (curr->extension_count < SDP_MAX_RTP_EXTENSIONS) {
                        auto const idx           = curr->extension_count++;
                        curr->extensions[idx].id = (uint8_t)ext_id;
                        auto const ulen =
                            (__builtin_strlen(uri) < (sizeof(curr->extensions[idx].uri) - 1))
                                ? __builtin_strlen(uri)
                                : (sizeof(curr->extensions[idx].uri) - 1);
                        __builtin_memcpy(curr->extensions[idx].uri, uri, ulen);
                        curr->extensions[idx].uri[ulen] = '\0';
                    }
                }
            }
            continue;
        }

        // Crypto line: a=crypto:<tag> <suite> inline:<key>
        if ((line.length >= 9) && (__builtin_memcmp(line.data, "a=crypto:", 9) == 0)) {
            sdp_media_stream_t *target = curr;
            if ((target == nullptr) && (out->stream_count == 0)) {
                target = &(out->streams[0]);
            }
            if (target != nullptr) {
                sdes_crypto_attr_t attr = {};
                if (sdes_parse_crypto_attr(line.data, line.length, &attr)) {
                    if (target->crypto_count < SDP_MAX_CRYPTO_ATTRS) {
                        target->crypto_attrs[target->crypto_count++] = attr;
                        target->has_crypto                           = true;
                    }
                }
            }
            continue;
        }

        // ICE ufrag line: a=ice-ufrag:<ufrag>
        if ((line.length >= 12) && (__builtin_memcmp(line.data, "a=ice-ufrag:", 12) == 0)) {
            char ufrag[64] = {};
            if (sscanf(line.data, "a=ice-ufrag:%63s", ufrag) == 1) {
                auto const len = __builtin_strlen(ufrag);
                if (curr != nullptr) {
                    auto const copylen =
                        (len < (sizeof(curr->ice_ufrag) - 1)) ? len : (sizeof(curr->ice_ufrag) - 1);
                    __builtin_memcpy(curr->ice_ufrag, ufrag, copylen);
                    curr->ice_ufrag[copylen] = '\0';
                    curr->has_ice            = true;
                } else {
                    auto const copylen =
                        (len < (sizeof(sess_ice_ufrag) - 1)) ? len : (sizeof(sess_ice_ufrag) - 1);
                    __builtin_memcpy(sess_ice_ufrag, ufrag, copylen);
                    sess_ice_ufrag[copylen] = '\0';
                    has_sess_ice            = true;
                }
            }
            continue;
        }

        // ICE pwd line: a=ice-pwd:<pwd>
        if ((line.length >= 10) && (__builtin_memcmp(line.data, "a=ice-pwd:", 10) == 0)) {
            char pwd[128] = {};
            if (sscanf(line.data, "a=ice-pwd:%127s", pwd) == 1) {
                auto const len = __builtin_strlen(pwd);
                if (curr != nullptr) {
                    auto const copylen =
                        (len < (sizeof(curr->ice_pwd) - 1)) ? len : (sizeof(curr->ice_pwd) - 1);
                    __builtin_memcpy(curr->ice_pwd, pwd, copylen);
                    curr->ice_pwd[copylen] = '\0';
                    curr->has_ice          = true;
                } else {
                    auto const copylen =
                        (len < (sizeof(sess_ice_pwd) - 1)) ? len : (sizeof(sess_ice_pwd) - 1);
                    __builtin_memcpy(sess_ice_pwd, pwd, copylen);
                    sess_ice_pwd[copylen] = '\0';
                    has_sess_ice          = true;
                }
            }
            continue;
        }

        // DTLS fingerprint line: a=fingerprint:<hash> <fp>
        if ((line.length >= 14) && (__builtin_memcmp(line.data, "a=fingerprint:", 14) == 0)) {
            char hash[32] = {};
            char fp[128]  = {};
            if (sscanf(line.data, "a=fingerprint:%31s %127s", hash, fp) == 2) {
                auto const fplen = __builtin_strlen(fp);
                if (curr != nullptr) {
                    auto const copylen = (fplen < (sizeof(curr->dtls_fingerprint) - 1))
                                             ? fplen
                                             : (sizeof(curr->dtls_fingerprint) - 1);
                    __builtin_memcpy(curr->dtls_fingerprint, fp, copylen);
                    curr->dtls_fingerprint[copylen] = '\0';
                    curr->has_dtls                  = true;
                } else {
                    auto const copylen =
                        (fplen < (sizeof(sess_dtls_fp) - 1)) ? fplen : (sizeof(sess_dtls_fp) - 1);
                    __builtin_memcpy(sess_dtls_fp, fp, copylen);
                    sess_dtls_fp[copylen] = '\0';
                    has_sess_dtls         = true;
                }
            }
            continue;
        }

        // DTLS setup line: a=setup:<setup>
        if ((line.length >= 8) && (__builtin_memcmp(line.data, "a=setup:", 8) == 0)) {
            char setup[32] = {};
            if (sscanf(line.data, "a=setup:%31s", setup) == 1) {
                auto const slen = __builtin_strlen(setup);
                if (curr != nullptr) {
                    auto const copylen = (slen < (sizeof(curr->dtls_setup) - 1))
                                             ? slen
                                             : (sizeof(curr->dtls_setup) - 1);
                    __builtin_memcpy(curr->dtls_setup, setup, copylen);
                    curr->dtls_setup[copylen] = '\0';
                } else {
                    auto const copylen = (slen < (sizeof(sess_dtls_setup) - 1))
                                             ? slen
                                             : (sizeof(sess_dtls_setup) - 1);
                    __builtin_memcpy(sess_dtls_setup, setup, copylen);
                    sess_dtls_setup[copylen] = '\0';
                }
            }
            continue;
        }
    }

    if (has_sess_ice || has_sess_dtls) {
        out->is_webrtc = true;
    }

    for (size_t i = 0; i < out->stream_count; ++i) {
        sdp_media_stream_t const *const s = &(out->streams[i]);
        if (s->has_ice || s->has_dtls || (strstr(s->transport, "TLS") != nullptr) ||
            (strstr(s->transport, "SAVPF") != nullptr))
        {
            out->is_webrtc = true;
            break;
        }
    }

    // Populate convenience single-stream accessors from primary stream 0
    if (out->stream_count > 0) {
        sdp_media_stream_t const *const s0 = &(out->streams[0]);
        out->media_port                    = s0->port;
        __builtin_memcpy(out->media_type, s0->media_name, sizeof(out->media_type));
        __builtin_memcpy(out->transport_proto, s0->transport, sizeof(out->transport_proto));
        out->rtcp_port    = s0->rtcp_port;
        out->has_media    = true;
        out->has_rtcp     = s0->has_rtcp;
        out->has_rtcp_mux = s0->rtcp_mux;
        out->is_savp      = s0->is_savp;
        out->has_crypto   = s0->has_crypto;
        out->crypto_count = s0->crypto_count;
        __builtin_memcpy(out->crypto_attrs, s0->crypto_attrs, sizeof(out->crypto_attrs));
        __builtin_memcpy(out->ice_ufrag, s0->ice_ufrag, sizeof(out->ice_ufrag));
        __builtin_memcpy(out->ice_pwd, s0->ice_pwd, sizeof(out->ice_pwd));
        __builtin_memcpy(
            out->dtls_fingerprint,
            s0->dtls_fingerprint,
            sizeof(out->dtls_fingerprint));
        __builtin_memcpy(out->dtls_setup, s0->dtls_setup, sizeof(out->dtls_setup));
        out->has_ice  = s0->has_ice;
        out->has_dtls = s0->has_dtls;
    }

    return (out->has_connection && (out->stream_count > 0));
}

static inline bool sdp_append_section_trailer(
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const off,
    sdp_rewrite_opts_t const *restrict const opts,
    char const *const addr_type,
    uint16_t const    media_port,
    bool const        has_rtcp_mux,
    bool const        has_rtcp_line) {
    if (!has_rtcp_line && (opts->enable_rtcp_mux || opts->add_ice)) {
        uint16_t const target_rtcp_port =
            opts->enable_rtcp_mux ? media_port : (uint16_t)(media_port + 1);
        char      rtcp_buf[128] = {};
        int const rw            = snprintf(
            rtcp_buf,
            sizeof(rtcp_buf),
            "a=rtcp:%u IN %s %s",
            (unsigned int)target_rtcp_port,
            addr_type,
            opts->new_ip);
        if ((rw <= 0) || !sdp_append_line(out_buf, out_cap, off, rtcp_buf, (size_t)rw)) {
            return false;
        }
    }

    if (opts->enable_rtcp_mux && !has_rtcp_mux) {
        if (!sdp_append_line(out_buf, out_cap, off, "a=rtcp-mux", 10)) {
            return false;
        }
    }

    if (opts->add_crypto && (opts->crypto_b64_key != nullptr)) {
        char           crypto_line[256] = {};
        size_t         c_len            = 0;
        uint32_t const tag              = (opts->crypto_tag > 0) ? opts->crypto_tag : 1;
        if (sdes_format_crypto_attr(
                tag,
                opts->crypto_suite,
                opts->crypto_b64_key,
                crypto_line,
                sizeof(crypto_line),
                &c_len))
        {
            while ((c_len > 0) &&
                   ((crypto_line[c_len - 1] == '\r') || (crypto_line[c_len - 1] == '\n')))
            {
                c_len--;
            }
            if (!sdp_append_line(out_buf, out_cap, off, crypto_line, c_len)) {
                return false;
            }
        }
    }

    if (opts->add_ice) {
        if (opts->ice_ufrag != nullptr) {
            char      ufrag_buf[128] = {};
            int const w = snprintf(ufrag_buf, sizeof(ufrag_buf), "a=ice-ufrag:%s", opts->ice_ufrag);
            if ((w > 0) && !sdp_append_line(out_buf, out_cap, off, ufrag_buf, (size_t)w)) {
                return false;
            }
        }
        if (opts->ice_pwd != nullptr) {
            char      pwd_buf[256] = {};
            int const w = snprintf(pwd_buf, sizeof(pwd_buf), "a=ice-pwd:%s", opts->ice_pwd);
            if ((w > 0) && !sdp_append_line(out_buf, out_cap, off, pwd_buf, (size_t)w)) {
                return false;
            }
        }
        if (!sdp_append_line(out_buf, out_cap, off, "a=ice-options:trickle", 21)) {
            return false;
        }
        char      cand_buf[256] = {};
        int const cw            = snprintf(
            cand_buf,
            sizeof(cand_buf),
            "a=candidate:1 1 UDP 2130706431 %s %u typ host",
            opts->new_ip,
            (unsigned int)media_port);
        if ((cw > 0) && !sdp_append_line(out_buf, out_cap, off, cand_buf, (size_t)cw)) {
            return false;
        }
    }

    if (opts->add_dtls && (opts->dtls_fingerprint != nullptr)) {
        char      fp_buf[256] = {};
        int const w =
            snprintf(fp_buf, sizeof(fp_buf), "a=fingerprint:sha-256 %s", opts->dtls_fingerprint);
        if ((w > 0) && !sdp_append_line(out_buf, out_cap, off, fp_buf, (size_t)w)) {
            return false;
        }
        char const *const setup_str = (opts->dtls_setup != nullptr) ? opts->dtls_setup : "passive";
        char              setup_buf[64] = {};
        int const         sw = snprintf(setup_buf, sizeof(setup_buf), "a=setup:%s", setup_str);
        if ((sw > 0) && !sdp_append_line(out_buf, out_cap, off, setup_buf, (size_t)sw)) {
            return false;
        }
    }

    return true;
}

bool sdp_rewrite_opts(
    sv_t const sdp_sv,
    sdp_rewrite_opts_t const *restrict const opts,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (sdp_sv.data == nullptr) || (opts == nullptr) || (opts->new_ip == nullptr) ||
            (opts->new_port == 0) || (out_buf == nullptr) || (out_cap == 0)))
    {
        return false;
    }

    size_t off  = 0;
    out_buf[0]  = '\0';
    sv_t cursor = sdp_sv;

    bool const        is_ipv6   = (strchr(opts->new_ip, ':') != nullptr);
    char const *const addr_type = is_ipv6 ? "IP6" : "IP4";

    bool     in_media_section   = false;
    uint16_t current_media_port = 0;
    bool     sec_has_rtcp_mux   = false;
    bool     sec_has_rtcp_line  = false;

    sdp_session_t info = {};
    (void)sdp_parse(sdp_sv, &info);
    bool   bundle_written = false;
    size_t stream_idx     = 0;

    while (cursor.length > 0) {
        sv_t const line = sdp_next_line(&cursor);
        if (line.length == 0) {
            continue;
        }

        // Strip simulcast and rid attributes if requested
        if (opts->strip_simulcast) {
            if ((line.length >= 12) && (__builtin_memcmp(line.data, "a=simulcast:", 12) == 0)) {
                continue;
            }
            if ((line.length >= 6) && (__builtin_memcmp(line.data, "a=rid:", 6) == 0)) {
                continue;
            }
        }

        // BUNDLE group line
        if ((line.length >= 14) && (__builtin_memcmp(line.data, "a=group:BUNDLE", 14) == 0)) {
            if (!(opts->bundle_into_single_port)) {
                // Strip BUNDLE when unbundling into distinct SIP ports
                continue;
            }
            if (!sdp_append_line(out_buf, out_cap, &off, line.data, line.length)) {
                return false;
            }
            bundle_written = true;
            continue;
        }

        // Rewrite c= line
        if ((line.length >= 2) && (line.data[0] == 'c') && (line.data[1] == '=')) {
            char      c_buf[128] = {};
            int const w = snprintf(c_buf, sizeof(c_buf), "c=IN %s %s", addr_type, opts->new_ip);
            if ((w <= 0) || !sdp_append_line(out_buf, out_cap, &off, c_buf, (size_t)w)) {
                return false;
            }
            continue;
        }

        // Rewrite o= line (origin connection IP)
        if ((line.length >= 2) && (line.data[0] == 'o') && (line.data[1] == '=')) {
            char user[64]    = {};
            char sess_id[64] = {};
            char sess_v[64]  = {};
            char net_t[16]   = {};
            char addr_t[16]  = {};
            char old_ip[64]  = {};
            if (sscanf(
                    line.data,
                    "o=%63s %63s %63s %15s %15s %63s",
                    user,
                    sess_id,
                    sess_v,
                    net_t,
                    addr_t,
                    old_ip) == 6)
            {
                char      o_buf[256] = {};
                int const w          = snprintf(
                    o_buf,
                    sizeof(o_buf),
                    "o=%s %s %s IN %s %s",
                    user,
                    sess_id,
                    sess_v,
                    addr_type,
                    opts->new_ip);
                if ((w <= 0) || !sdp_append_line(out_buf, out_cap, &off, o_buf, (size_t)w)) {
                    return false;
                }
                continue;
            }
        }

        // Media description line: m=<media> <port> <proto> ...
        if ((line.length >= 2) && (line.data[0] == 'm') && (line.data[1] == '=')) {
            // If bundling into a single port but incoming SDP lacked a=group:BUNDLE, inject it
            // before first m= line
            if (opts->bundle_into_single_port && !bundle_written && (info.stream_count > 1)) {
                char   bundle_buf[128] = "a=group:BUNDLE";
                size_t b_len           = 14;
                for (size_t i = 0; i < info.stream_count; ++i) {
                    char const *const mid_str =
                        info.streams[i].has_mid ? info.streams[i].mid : (i == 0 ? "0" : "1");
                    int const bw =
                        snprintf(bundle_buf + b_len, sizeof(bundle_buf) - b_len, " %s", mid_str);
                    if (bw > 0) {
                        b_len += (size_t)bw;
                    }
                }
                if (!sdp_append_line(out_buf, out_cap, &off, bundle_buf, b_len)) {
                    return false;
                }
                bundle_written = true;
            }

            // Flush previous section trailer if any
            if (in_media_section) {
                if (!sdp_append_section_trailer(
                        out_buf,
                        out_cap,
                        &off,
                        opts,
                        addr_type,
                        current_media_port,
                        sec_has_rtcp_mux,
                        sec_has_rtcp_line))
                {
                    return false;
                }
            }

            in_media_section  = true;
            sec_has_rtcp_mux  = false;
            sec_has_rtcp_line = false;

            char         media[16] = {};
            unsigned int old_port  = 0;
            char         proto[32] = {};
            int          n_read    = 0;
            if (sscanf(line.data, "m=%15s %u %31s%n", media, &old_port, proto, &n_read) >= 3) {
                size_t const rest_len =
                    (line.length > (size_t)n_read) ? (line.length - (size_t)n_read) : 0;
                char const *const rest = line.data + n_read;
                char const *const target_proto =
                    (opts->set_transport && (opts->transport_proto != nullptr))
                        ? opts->transport_proto
                        : proto;

                uint16_t target_port = opts->audio_port;
                if (!(opts->bundle_into_single_port)) {
                    if ((strcmp(media, "video") == 0) && (opts->video_port > 0)) {
                        target_port = opts->video_port;
                    } else {
                        target_port = opts->audio_port;
                    }
                }
                current_media_port = target_port;

                char      m_buf[256] = {};
                int const w          = snprintf(
                    m_buf,
                    sizeof(m_buf),
                    "m=%s %u %s%.*s",
                    media,
                    target_port,
                    target_proto,
                    (int)rest_len,
                    rest);
                if ((w <= 0) || !sdp_append_line(out_buf, out_cap, &off, m_buf, (size_t)w)) {
                    return false;
                }

                auto const current_stream_idx = stream_idx++;
                if (opts->bundle_into_single_port) {
                    if ((current_stream_idx < info.stream_count) &&
                        !info.streams[current_stream_idx].has_mid)
                    {
                        char      mid_buf[32] = {};
                        int const mw =
                            snprintf(mid_buf, sizeof(mid_buf), "a=mid:%zu", current_stream_idx);
                        if ((mw > 0) &&
                            !sdp_append_line(out_buf, out_cap, &off, mid_buf, (size_t)mw))
                        {
                            return false;
                        }
                    }
                }
                continue;
            }
        }

        // Rewrite a=rtcp: line
        if ((line.length >= 7) && (__builtin_memcmp(line.data, "a=rtcp:", 7) == 0)) {
            uint16_t const target_rtcp_port =
                opts->enable_rtcp_mux ? current_media_port : (uint16_t)(current_media_port + 1);
            char      rtcp_buf[128] = {};
            int const w             = snprintf(
                rtcp_buf,
                sizeof(rtcp_buf),
                "a=rtcp:%u IN %s %s",
                (unsigned int)target_rtcp_port,
                addr_type,
                opts->new_ip);
            if ((w <= 0) || !sdp_append_line(out_buf, out_cap, &off, rtcp_buf, (size_t)w)) {
                return false;
            }
            sec_has_rtcp_line = true;
            continue;
        }

        // Handle a=rtcp-mux line
        if ((line.length >= 10) && (__builtin_memcmp(line.data, "a=rtcp-mux", 10) == 0) &&
            ((line.length == 10) || (line.data[10] == ' ') || (line.data[10] == '\t')))
        {
            if (opts->enable_rtcp_mux) {
                if (!sdp_append_line(out_buf, out_cap, &off, "a=rtcp-mux", 10)) {
                    return false;
                }
                sec_has_rtcp_mux = true;
            }
            continue;
        }

        // Handle a=crypto: lines
        if ((line.length >= 9) && (__builtin_memcmp(line.data, "a=crypto:", 9) == 0)) {
            if (opts->strip_crypto || opts->add_crypto) {
                continue;
            }
        }

        // Handle ICE attributes: a=ice-, a=candidate:
        if ((line.length >= 6) &&
            ((__builtin_memcmp(line.data, "a=ice-", 6) == 0) ||
             ((line.length >= 12) && (__builtin_memcmp(line.data, "a=candidate:", 12) == 0))))
        {
            if (opts->strip_ice || opts->add_ice) {
                continue;
            }
        }

        // Handle DTLS attributes: a=fingerprint:, a=setup:
        if ((line.length >= 8) &&
            ((__builtin_memcmp(line.data, "a=setup:", 8) == 0) ||
             ((line.length >= 14) && (__builtin_memcmp(line.data, "a=fingerprint:", 14) == 0))))
        {
            if (opts->strip_dtls || opts->add_dtls) {
                continue;
            }
        }

        // Keep all other lines intact
        if (!sdp_append_line(out_buf, out_cap, &off, line.data, line.length)) {
            return false;
        }
    }

    if (in_media_section) {
        if (!sdp_append_section_trailer(
                out_buf,
                out_cap,
                &off,
                opts,
                addr_type,
                current_media_port,
                sec_has_rtcp_mux,
                sec_has_rtcp_line))
        {
            return false;
        }
    }

    if (out_len != nullptr) {
        *out_len = off;
    }
    return true;
}

bool sdp_rewrite_ex(
    sv_t const        sdp_sv,
    char const *const new_ip,
    uint16_t const    new_port,
    bool const        enable_rtcp_mux,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    sdp_rewrite_opts_t const opts = {
        .new_ip          = new_ip,
        .new_port        = new_port,
        .enable_rtcp_mux = enable_rtcp_mux,
    };
    return sdp_rewrite_opts(sdp_sv, &opts, out_buf, out_cap, out_len);
}

bool sdp_rewrite(
    sv_t const        sdp_sv,
    char const *const new_ip,
    uint16_t const    new_port,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    sdp_session_t info    = {};
    bool const    has_mux = sdp_parse(sdp_sv, &info) && info.has_rtcp_mux;
    return sdp_rewrite_ex(sdp_sv, new_ip, new_port, has_mux, out_buf, out_cap, out_len);
}
