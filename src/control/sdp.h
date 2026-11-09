#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/string_view.h"
#include "crypto/sdes.h"

/**
 * @file sdp.h
 * @brief RFC 4566 / RFC 8866 Session Description Protocol (SDP) unified parser, mutator, and BUNDLE
 * mediator.
 */

/** @brief Maximum SDES crypto attribute lines parsed per media section. */
constexpr size_t SDP_MAX_CRYPTO_ATTRS = 4;
/** @brief Maximum media stream sections supported in an SDP (Audio, Video, Screen, Application). */
constexpr size_t SDP_MAX_MEDIA_STREAMS = 4;
/** @brief Maximum RTP payload types parsed per media section. */
constexpr size_t SDP_MAX_PAYLOAD_TYPES = 8;
/** @brief Maximum RTP header extension mappings (a=extmap) parsed per media section. */
constexpr size_t SDP_MAX_RTP_EXTENSIONS = 8;

/**
 * @brief SDP media section type discriminator (m= line).
 */
typedef enum : uint8_t {
    SDP_MEDIA_UNKNOWN     = 0, /**< Unrecognized media type. */
    SDP_MEDIA_AUDIO       = 1, /**< Audio media stream ("audio"). */
    SDP_MEDIA_VIDEO       = 2, /**< Video media stream ("video"). */
    SDP_MEDIA_APPLICATION = 3, /**< Application data channel stream ("application"). */
} sdp_media_type_t;

/**
 * @brief Parsed RTP header extension attribute mapping (RFC 8285 'a=extmap:').
 */
typedef struct {
    uint8_t id;       /**< Extension numeric ID (1-14 for one-byte header, 1-255 for two-byte). */
    char    uri[128]; /**< Extension identifier URI (e.g. "urn:ietf:params:rtp-hdrext:sdes:mid"). */
} sdp_extmap_t;

/**
 * @brief Parsed individual media description section (m= block) from an SDP.
 */
typedef struct {
    sdp_media_type_t type;           /**< Stream type (audio, video, etc.). */
    char             media_name[16]; /**< Raw media type name ("audio", "video"). */
    uint16_t         port;           /**< Transport port for the media stream. */
    char             transport[32];  /**< Transport protocol ("RTP/AVP", "UDP/TLS/RTP/SAVPF"). */
    char             mid[16];        /**< Identification tag from 'a=mid:' attribute. */
    bool             has_mid;        /**< True if 'a=mid:' attribute was present. */
    bool             rtcp_mux;       /**< True if 'a=rtcp-mux' attribute was present. */
    uint16_t         rtcp_port;      /**< Separate RTCP port from 'a=rtcp:' attribute. */
    bool             has_rtcp;       /**< True if 'a=rtcp:' port override was specified. */

    // Codecs & Formats
    uint8_t payload_types[SDP_MAX_PAYLOAD_TYPES]; /**< List of declared RTP payload types. */
    size_t  payload_type_count;                   /**< Number of declared payload types. */

    // Feedback & Extensions
    bool         has_nack; /**< True if RTCP NACK feedback is negotiated. */
    bool         has_pli;  /**< True if RTCP PLI keyframe feedback is negotiated. */
    bool         has_fir;  /**< True if RTCP FIR feedback is negotiated. */
    bool         has_remb; /**< True if Google REMB bandwidth estimation is negotiated. */
    bool         has_twcc; /**< True if Transport-wide Congestion Control is negotiated. */
    sdp_extmap_t extensions[SDP_MAX_RTP_EXTENSIONS]; /**< Declared RTP header extension mappings. */
    size_t       extension_count;                    /**< Count of RTP header extension mappings. */

    // Crypto & ICE
    bool               is_savp;      /**< True if secure audio-video profile is specified. */
    bool               has_crypto;   /**< True if 'a=crypto:' attributes are present. */
    size_t             crypto_count; /**< Number of 'a=crypto:' attributes parsed. */
    sdes_crypto_attr_t crypto_attrs[SDP_MAX_CRYPTO_ATTRS]; /**< Parsed SDES crypto attributes. */
    bool               has_ice;               /**< True if ICE credentials are present. */
    char               ice_ufrag[64];         /**< ICE username fragment from 'a=ice-ufrag:'. */
    char               ice_pwd[128];          /**< ICE password from 'a=ice-pwd:'. */
    bool               has_dtls;              /**< True if DTLS fingerprint is present. */
    char               dtls_fingerprint[128]; /**< SHA-256 fingerprint from 'a=fingerprint:'. */
    char               dtls_setup[32]; /**< DTLS setup role ('active', 'passive', 'actpass'). */
} sdp_media_stream_t;

/**
 * @brief Unified SDP session description supporting single and multi-stream (BUNDLE) topologies.
 */
typedef struct sdp_session_s {
    char   connection_ip[INET6_ADDRSTRLEN]; /**< Global connection IP address (c= line). */
    bool   has_connection;                  /**< True if global connection line was parsed. */
    bool   has_bundle;                      /**< True if BUNDLE group is present. */
    char   bundle_mids[SDP_MAX_MEDIA_STREAMS][16]; /**< Media stream IDs in BUNDLE. */
    size_t bundle_mid_count;                       /**< Number of media streams in BUNDLE group. */
    sdp_media_stream_t streams[SDP_MAX_MEDIA_STREAMS]; /**< Array of parsed media sections. */
    size_t             stream_count; /**< Total number of media sections parsed. */
    bool               is_webrtc;    /**< True if session contains WebRTC elements. */

    // Single-stream convenience and backward-compatible accessors (aliasing primary stream 0)
    uint16_t           media_port;          /**< Primary stream port (streams[0].port). */
    char               media_type[16];      /**< Primary stream media type name. */
    char               transport_proto[32]; /**< Primary stream transport protocol. */
    uint16_t           rtcp_port;           /**< Primary stream RTCP port. */
    bool               has_media;           /**< True if stream_count > 0. */
    bool               has_rtcp;            /**< Primary stream RTCP override flag. */
    bool               has_rtcp_mux;        /**< Primary stream RTCP-MUX flag. */
    bool               is_savp;             /**< Primary stream secure SAVP flag. */
    bool               has_crypto;          /**< Primary stream crypto flag. */
    size_t             crypto_count;        /**< Primary stream crypto count. */
    sdes_crypto_attr_t crypto_attrs[SDP_MAX_CRYPTO_ATTRS]; /**< Primary stream crypto attributes. */
    char               ice_ufrag[64];                      /**< Primary stream ICE ufrag. */
    char               ice_pwd[128];                       /**< Primary stream ICE password. */
    char               dtls_fingerprint[128];              /**< Primary stream DTLS fingerprint. */
    char               dtls_setup[32];                     /**< Primary stream DTLS setup role. */
    bool               has_ice;                            /**< Primary stream ICE flag. */
    bool               has_dtls;                           /**< Primary stream DTLS flag. */
} sdp_session_t;

/** @brief Backward compatibility aliases for unified sdp_session_t. */
typedef sdp_session_t sdp_info_t;
typedef sdp_session_t sdp_multi_info_t;

/**
 * @brief Unified configuration parameters for rewriting SDP payloads.
 */
typedef struct sdp_rewrite_opts_s {
    char const *new_ip; /**< Replacement proxy media IP address. */
    union {
        uint16_t new_port;   /**< Replacement proxy media port (single stream). */
        uint16_t audio_port; /**< Bound proxy port for audio stream. */
    };
    uint16_t            video_port;              /**< Bound proxy port for video stream. */
    bool                bundle_into_single_port; /**< Assign audio_port to all bundled sections. */
    bool                strip_simulcast;         /**< Strips a=simulcast and a=rid lines. */
    bool                enable_rtcp_mux;         /**< Injects or forces a=rtcp-mux attribute. */
    bool                set_transport;           /**< Overrides media transport protocol token. */
    char const         *transport_proto;         /**< New transport protocol string. */
    bool                strip_crypto;            /**< Strips all a=crypto: attributes. */
    bool                add_crypto;              /**< Injects SDES a=crypto: attribute. */
    uint32_t            crypto_tag;              /**< Decimal crypto tag identifier. */
    srtp_crypto_suite_t crypto_suite;            /**< SRTP crypto suite to inject. */
    char const         *crypto_b64_key;          /**< Base64 master key string to inject. */
    bool                add_ice;                 /**< Injects local ICE credentials. */
    char const         *ice_ufrag;               /**< Local ICE username fragment. */
    char const         *ice_pwd;                 /**< Local ICE password. */
    bool                strip_ice;        /**< Strips all ICE candidate and credential lines. */
    bool                add_dtls;         /**< Injects DTLS fingerprint attribute. */
    char const         *dtls_fingerprint; /**< DTLS SHA-256 fingerprint string. */
    char const         *dtls_setup;       /**< DTLS setup role string. */
    bool                strip_dtls;       /**< Strips DTLS fingerprint attributes. */
} sdp_rewrite_opts_t;

/** @brief Backward compatibility alias for unified sdp_rewrite_opts_t. */
typedef sdp_rewrite_opts_t sdp_multi_rewrite_opts_t;

/**
 * @brief Unified single-pass parser for all SDP payloads (single-stream, multi-stream, and WebRTC
 * BUNDLE).
 *
 * @param sdp_sv String view containing the SDP text.
 * @param out Pointer to output sdp_session_t structure.
 * @return true if connection address and media port were successfully extracted.
 */
[[nodiscard]] bool sdp_parse(sv_t const sdp_sv, sdp_session_t *restrict const out);

/**
 * @brief Backward compatibility inline wrapper delegating directly to unified sdp_parse.
 */
[[nodiscard]] static inline bool
sdp_parse_multi(sv_t const sdp_sv, sdp_session_t *restrict const out) {
    return sdp_parse(sdp_sv, out);
}

/**
 * @brief Unified single-pass rewriter for all SDP payloads.
 *
 * @param sdp_sv Original SDP text string view.
 * @param opts Pointer to rewrite options.
 * @param out_buf Buffer to receive rewritten SDP.
 * @param out_cap Capacity in bytes of out_buf.
 * @param out_len Pointer to store length of rewritten SDP (can be nullptr).
 * @return true on success, false if output buffer is insufficient.
 */
[[nodiscard]] bool sdp_rewrite_opts(
    sv_t const sdp_sv,
    sdp_rewrite_opts_t const *restrict const opts,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len);

/**
 * @brief Backward compatibility inline wrapper delegating directly to unified sdp_rewrite_opts.
 */
[[nodiscard]] static inline bool sdp_rewrite_multi(
    sv_t const sdp_sv,
    sdp_rewrite_opts_t const *restrict const opts,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    return sdp_rewrite_opts(sdp_sv, opts, out_buf, out_cap, out_len);
}

/**
 * @brief Rewrites an SDP payload with proxy connection IP and media port, with RTCP-MUX control.
 */
[[nodiscard]] bool sdp_rewrite_ex(
    sv_t const        sdp_sv,
    char const *const new_ip,
    uint16_t const    new_port,
    bool const        enable_rtcp_mux,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len);

/**
 * @brief Rewrites an SDP payload with proxy connection IP and media port.
 */
[[nodiscard]] bool sdp_rewrite(
    sv_t const        sdp_sv,
    char const *const new_ip,
    uint16_t const    new_port,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len);
