#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "control/sdp.h"
#include "core/memory.h"
#include "core/metrics.h"
#include "crypto/dtls.h"
#include "crypto/srtp_session.h"
#include "media/jitter.h"
#include "media/transcode.h"
#include "net/pcap.h"
#include "net/rtp.h"
#include "net/stun.h"
#include "ring/ring.h"

/**
 * @file session.h
 * @brief High-throughput zero-copy RTP/RTCP media session relay table and state machine.
 */

typedef struct ng_call_table ng_call_table_t;

/** @brief Maximum number of concurrent media relay sessions in the session table. */
constexpr size_t SESSION_TABLE_MAX = 512;

/**
 * @brief Routing entry mapping SSRC and payload type to a peer session index.
 */
typedef struct {
    uint32_t         ssrc;               /**< SSRC identifier. */
    uint8_t          pt;                 /**< Payload type. */
    sdp_media_type_t media_type;         /**< Audio or video media stream type. */
    int32_t          target_session_idx; /**< Target session table index for relayed packets. */
} ssrc_route_entry_t;

/**
 * @brief Fixed-size SSRC routing table for multi-stream BUNDLE demultiplexing.
 */
typedef struct {
    ssrc_route_entry_t entries[8]; /**< Pre-allocated routing entries array. */
    size_t             count;      /**< Active number of routing entries. */
} ssrc_route_table_t;

/**
 * @brief Symmetric RTP NAT latching mode for dynamic endpoint discovery.
 */
typedef enum : uint8_t {
    LATCH_MODE_DISABLED = 0, /**< NAT latching disabled; uses destination from SDP. */
    LATCH_MODE_WAITING  = 1, /**< Awaiting initial packet to latch remote IP and port. */
    LATCH_MODE_LATCHED  = 2, /**< Successfully latched to remote endpoint. */
} latch_mode_t;

/**
 * @brief Core media relay session state representing a bidirectional RTP/RTCP socket endpoint.
 */
typedef struct {
    alignas(64) int socket_fd;        /**< Bound UDP socket file descriptor. */
    int32_t                 peer_idx; /**< Table index of paired peer session (-1 if unbridged). */
    int32_t                 record_idx;      /**< Attached PCAP recorder index (-1 if disabled). */
    uint16_t                bind_port;       /**< Local UDP port bound for this session. */
    bool                    active;          /**< True if session slot is active. */
    bool                    multishot_armed; /**< True if io_uring multishot recv is active. */
    latch_mode_t            latch_mode;      /**< Current symmetric NAT latching state. */
    bool                    allow_relatch;   /**< Permit re-latching if source address changes. */
    bool                    raw_latch;       /**< Allow latching on non-RTP UDP packets. */
    struct msghdr           recv_msghdr;     /**< io_uring receive message header. */
    struct sockaddr_storage dest_addr;       /**< Configured destination socket address. */
    socklen_t               dest_addr_len;   /**< Length of dest_addr. */
    char                    dest_ip[INET6_ADDRSTRLEN]; /**< Human-readable destination IP. */
    uint16_t                dest_port;                 /**< Destination UDP port. */
    bool                    rtcp_mux; /**< True if RTCP multiplexed on RTP port per RFC 5761. */
    struct sockaddr_storage
              rtcp_dest_addr;     /**< Separate RTCP destination address when not muxed. */
    socklen_t rtcp_dest_addr_len; /**< Length of rtcp_dest_addr. */
    char      rtcp_dest_ip[INET6_ADDRSTRLEN]; /**< Human-readable RTCP destination IP. */
    uint16_t  rtcp_dest_port;                 /**< Destination RTCP port. */
    struct sockaddr_storage latched_addr; /**< Discovered peer socket address from NAT latching. */
    socklen_t               latched_addr_len;             /**< Length of latched_addr. */
    char                    latched_ip[INET6_ADDRSTRLEN]; /**< Human-readable latched IP. */
    uint16_t                latched_port;                 /**< Discovered peer UDP port. */
    uint64_t                packets_relayed;              /**< Total packets forwarded. */
    uint64_t                bytes_relayed;                /**< Total bytes forwarded. */
    uint64_t                rtp_packets_relayed;          /**< RTP media packets forwarded. */
    uint64_t                rtp_bytes_relayed;            /**< RTP bytes forwarded. */
    uint64_t                rtcp_packets_relayed;         /**< RTCP control packets forwarded. */
    uint64_t                rtcp_bytes_relayed;           /**< RTCP bytes forwarded. */
    uint64_t                packets_dropped;              /**< Dropped packets count. */
    uint64_t                packets_latched;   /**< Total packets received from latched endpoint. */
    urtp_srtp_ctx_t         inbound_srtp;      /**< Inbound SRTP decryption context. */
    urtp_srtp_ctx_t         outbound_srtp;     /**< Outbound SRTP encryption context. */
    bool                    has_inbound_srtp;  /**< True if inbound SRTP is active. */
    bool                    has_outbound_srtp; /**< True if outbound SRTP is active. */
    uint64_t                srtp_packets_encrypted; /**< SRTP packets encrypted. */
    uint64_t                srtp_packets_decrypted; /**< SRTP packets decrypted. */
    uint64_t                srtp_auth_failures;     /**< SRTP authentication failures. */
    bool                    dtls_enabled;           /**< True if DTLS key exchange is enabled. */
    urtp_dtls_session_t     dtls;                   /**< DTLS session context. */
    char                    ice_pwd[64];            /**< Remote ICE password for STUN integrity. */
    char                    ice_ufrag[32];          /**< Remote ICE username fragment. */
    bool                    is_webrtc;              /**< True if WebRTC session (ICE/DTLS). */
    transcoder_ctx_t        transcode_ctx;          /**< Media transcoding pipeline context. */
    bool                    transcode_enabled;      /**< True if transcoding is active. */
    media_codec_t           target_codec;           /**< Target transcoding codec. */
    jitter_buffer_t        *jitter_buf;             /**< Attached jitter buffer (from pool). */
    bool                    jitter_enabled;         /**< True if jitter buffering is active. */
    uint32_t                jitter_delay_ms;        /**< Configured jitter delay in ms. */
    struct session_table_s *table;                  /**< Backpointer to parent session table. */
    uint64_t                created_sec;            /**< Creation timestamp in seconds. */
    uint64_t                last_activity_sec;    /**< Last media activity timestamp in seconds. */
    uint32_t                inactivity_timeout;   /**< Inactivity timeout in seconds. */
    uint32_t                last_ssrc;            /**< Last observed SSRC. */
    uint64_t                last_ssrc_sec;        /**< Timestamp of last observed SSRC update. */
    sdp_media_type_t        media_type;           /**< Stream media type (audio/video). */
    ssrc_route_table_t      route_table;          /**< Multi-stream SSRC routing table. */
    urtp_srtp_ctx_t        *shared_outbound_srtp; /**< Shared outbound SRTP context for BUNDLE. */
    uint8_t                 pli_tx_buf[256]; /**< Scratchpad buffer for synthesized PLI packets. */
    struct msghdr           pli_tx_msghdr;   /**< Pre-allocated msghdr for PLI transmission. */
    struct iovec            pli_tx_iov;      /**< Pre-allocated iovec for PLI transmission. */
} relay_session_t;

/**
 * @brief Global session table holding all active media relay sessions and shared resources.
 */
typedef struct session_table_s {
    alignas(64)
        relay_session_t sessions[SESSION_TABLE_MAX]; /**< Contiguous array of relay sessions. */
    size_t               active_count;               /**< Count of currently active sessions. */
    pcap_table_t         pcap_table;                 /**< Integrated PCAP capture table. */
    transcoder_backend_t default_transcoder;         /**< Global default transcoding backend. */
    media_codec_t        default_transcode_codec;    /**< Global default target codec. */
    uint32_t             default_jitter_delay_ms; /**< Global default jitter buffer delay in ms. */
    jitter_pool_t       *jitter_pool; /**< Cache-aligned fixed pool allocator for jitter buffers. */
    uint64_t cached_monotonic_sec;    /**< Cached monotonic timestamp updated per reactor tick. */
    server_metrics_t *metrics;        /**< Pointer to server telemetry metrics instance. */
} session_table_t;

/**
 * @brief Sweeps session table for inactive sessions and unconfirmed setup timeouts.
 *
 * @param table Pointer to session table.
 * @param call_table Pointer to NG call table (can be nullptr).
 * @param engine Pointer to ring engine (can be nullptr).
 * @param now_sec Current monotonic timestamp in seconds.
 * @param default_timeout_sec Default inactivity timeout in seconds for active media.
 * @param setup_timeout_sec Setup timeout in seconds for unconfirmed sessions.
 */
void session_table_sweep_inactivity(
    session_table_t *restrict const table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    uint64_t const now_sec,
    uint32_t const default_timeout_sec,
    uint32_t const setup_timeout_sec);

/**
 * @brief Zero-initializes the session table.
 *
 * @param table Pointer to session table.
 */
void session_table_init(session_table_t *restrict const table);

/**
 * @brief Tears down all active sessions, closing sockets and releasing resources.
 *
 * @param table Pointer to session table.
 * @param engine Pointer to ring engine (can be nullptr).
 */
void session_table_destroy(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine);

/**
 * @brief Allocates and initializes a new relay session.
 *
 * @param table Pointer to session table.
 * @param bind_ip Local IP address to bind to (e.g. "0.0.0.0").
 * @param bind_port Local port to bind to.
 * @param dest_ip Destination IP address.
 * @param dest_port Destination port.
 * @return Pointer to created relay session, or nullptr on failure.
 */
[[nodiscard]] relay_session_t *session_create(
    session_table_t *restrict const table,
    char const *const bind_ip,
    uint16_t const    bind_port,
    char const *const dest_ip,
    uint16_t const    dest_port);

/**
 * @brief Enables NAT latching for a session.
 *
 * @param session Pointer to session.
 * @param allow_relatch If true, permits updating the latched endpoint on address changes.
 * @param raw_latch If true, allows latching on any UDP packet without requiring an RTP header.
 */
void session_enable_latching(
    relay_session_t *restrict const session,
    bool const allow_relatch,
    bool const raw_latch);

/**
 * @brief Latches a session onto a discovered peer public address and port.
 *
 * @param session Pointer to session.
 * @param src_addr Pointer to sockaddr_storage containing discovered peer address.
 * @param src_len Length of sockaddr structure.
 */
void session_latch_endpoint(
    relay_session_t *restrict const session,
    struct sockaddr_storage const *restrict const src_addr,
    socklen_t const src_len);

/**
 * @brief Bridges two sessions together bidirectionally.
 *
 * @param table Pointer to session table.
 * @param port_a Local bind port of first session.
 * @param port_b Local bind port of second session.
 * @return true on success, false if ports not found or identical.
 */
bool session_bridge_pair(
    session_table_t *restrict const table,
    uint16_t const port_a,
    uint16_t const port_b);

/**
 * @brief Removes bridging from a session and its peer.
 *
 * @param table Pointer to session table.
 * @param port Local bind port of the session.
 * @return true if unbridged, false if not found.
 */
bool session_unbridge(session_table_t *restrict const table, uint16_t const port);

/**
 * @brief Finds an active session matching the given local bind port.
 *
 * @param table Pointer to session table.
 * @param port Local bind port.
 * @return Pointer to session if found, nullptr otherwise.
 */
[[nodiscard]] relay_session_t *
session_find_by_port(session_table_t *restrict const table, uint16_t const port);

/**
 * @brief Finds a session by its table slot index.
 *
 * @param table Pointer to session table.
 * @param index Index within table [0..SESSION_TABLE_MAX).
 * @return Pointer to session if in bounds, nullptr otherwise.
 */
[[nodiscard]] relay_session_t *
session_find_by_index(session_table_t *restrict const table, size_t const index);

/**
 * @brief Returns the index of a session within the table.
 *
 * @param table Pointer to session table.
 * @param session Pointer to session.
 * @return Slot index [0..SESSION_TABLE_MAX), or -1 if not found.
 */
[[nodiscard]] int64_t session_get_index(
    session_table_t const *restrict const table,
    relay_session_t const *restrict const session);

/**
 * @brief Deletes a session by its local bind port.
 *
 * @param table Pointer to session table.
 * @param port Local bind port.
 * @param engine Pointer to ring engine (can be nullptr).
 * @return true if deleted, false if not found.
 */
bool session_delete_by_port(
    session_table_t *restrict const table,
    uint16_t const port,
    ring_engine_t *restrict const engine);

/**
 * @brief Arms io_uring multishot receive for a session.
 *
 * @param session Pointer to session.
 * @param session_idx Slot index of the session.
 * @param engine Pointer to ring engine.
 * @return true if armed, false otherwise.
 */
[[nodiscard]] bool session_arm_multishot(
    relay_session_t *restrict const session,
    size_t const session_idx,
    ring_engine_t *restrict const engine);

/**
 * @brief Handles a completion queue entry for a multishot UDP receive event.
 *
 * @param table Pointer to session table.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 * @param session_idx Slot index of receiving session.
 */
void session_handle_rx_cqe(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   session_idx);

/**
 * @brief Enables or disables RTCP-MUX (RTP/RTCP multiplexing on a single port per RFC 5761).
 *
 * @param session Pointer to session.
 * @param enabled true to enable multiplexing, false to disable.
 */
void session_set_rtcp_mux(relay_session_t *restrict const session, bool const enabled);

/**
 * @brief Sets a separate RTCP destination endpoint for non-multiplexed sessions.
 *
 * @param session Pointer to session.
 * @param ip RTCP destination IP address string.
 * @param port RTCP destination port.
 * @return true if endpoint parsed and configured, false otherwise.
 */
bool session_set_rtcp_dest(
    relay_session_t *restrict const session,
    char const *const ip,
    uint16_t const    port);

/**
 * @brief Handles a completion queue entry for an asynchronous UDP send event.
 *
 * @param table Pointer to session table.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to completion entry.
 * @param session_idx Slot index of sending session.
 * @param bid Provided buffer ID used for the send.
 * @param flags Tag flags describing the packet type (TAG_FLAG_PKT_RTP / TAG_FLAG_PKT_RTCP).
 */
void session_handle_tx_cqe(
    session_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   session_idx,
    uint16_t const                   bid,
    uint16_t const                   flags);

/**
 * @brief Configures inbound SRTP decryption context on a session.
 *
 * @param session Pointer to session.
 * @param suite Crypto suite to use.
 * @param key_salt Pointer to binary master key + salt.
 * @param key_salt_len Length in bytes of key_salt.
 * @return true on success, false otherwise.
 */
bool session_set_inbound_srtp(
    relay_session_t *restrict const session,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len);

/**
 * @brief Configures outbound SRTP encryption context on a session.
 *
 * @param session Pointer to session.
 * @param suite Crypto suite to use.
 * @param key_salt Pointer to binary master key + salt.
 * @param key_salt_len Length in bytes of key_salt.
 * @return true on success, false otherwise.
 */
bool session_set_outbound_srtp(
    relay_session_t *restrict const session,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len);

/**
 * @brief Destroys and clears any active SRTP contexts on a session.
 *
 * @param session Pointer to session.
 */
void session_clear_srtp(relay_session_t *restrict const session);

/**
 * @brief Enables DTLS handshake and key derivation on a session.
 *
 * @param session Pointer to session.
 * @param role DTLS_ROLE_SERVER (passive) or DTLS_ROLE_CLIENT (active).
 * @return true on success, false otherwise.
 */
bool session_enable_dtls(relay_session_t *restrict const session, dtls_role_t const role);

/**
 * @brief Configures ICE username fragment and password credentials on a session.
 *
 * @param session Pointer to session.
 * @param ufrag Local ICE user fragment (can be nullptr).
 * @param pwd Local ICE password (can be nullptr).
 */
void session_set_ice_credentials(
    relay_session_t *restrict const session,
    char const *const ufrag,
    char const *const pwd);

/**
 * @brief Destroys and clears active DTLS context on a session.
 *
 * @param session Pointer to session.
 */
void session_clear_dtls(relay_session_t *restrict const session);

/**
 * @brief Configures default transcoding backend and target codec for the session table.
 */
void session_table_set_default_transcoder(
    session_table_t *restrict const table,
    transcoder_backend_t const backend,
    media_codec_t const        codec);

/**
 * @brief Configures transcoding on a relay session.
 *
 * @param session Pointer to session.
 * @param backend Transcode backend (TRANSCODER_BACKEND_OPUS or TRANSCODER_BACKEND_FFMPEG).
 * @param src_codec Source codec.
 * @param dst_codec Target codec.
 * @return true on success, false on failure.
 */
bool session_set_transcode(
    relay_session_t *restrict const session,
    transcoder_backend_t const backend,
    media_codec_t const        src_codec,
    media_codec_t const        dst_codec);

/**
 * @brief Clears and disables transcoding on a relay session.
 *
 * @param session Pointer to session.
 */
void session_clear_transcode(relay_session_t *restrict const session);

/**
 * @brief Configures default jitter buffer delay for transcoding sessions in the table.
 *
 * @param table Pointer to session table.
 * @param delay_ms Target playout delay in ms (0 to disable).
 */
void session_table_set_default_jitter(
    session_table_t *restrict const table,
    uint32_t const delay_ms);

/**
 * @brief Enables or disables jitter buffer on a session.
 *
 * Jitter buffer can only be enabled if transcoding is active on the session.
 *
 * @param session Pointer to relay session.
 * @param delay_ms Target delay in ms (0 to disable).
 * @return true on success, false if transcoding is not enabled.
 */
[[nodiscard]] bool
session_set_jitter_buffer(relay_session_t *restrict const session, uint32_t const delay_ms);

/**
 * @brief Adds an SSRC/PT routing entry to a session.
 *
 * @param session Pointer to session.
 * @param ssrc SSRC identifier.
 * @param pt Payload type.
 * @param media_type Media stream type (audio or video).
 * @param target_session_idx Target session table index to route matching packets to.
 * @return true if added, false if table full.
 */
bool session_add_route(
    relay_session_t *restrict const session,
    uint32_t const         ssrc,
    uint8_t const          pt,
    sdp_media_type_t const media_type,
    int32_t const          target_session_idx);

/**
 * @brief Clears the SSRC/PT routing table for a session.
 *
 * @param session Pointer to session.
 */
void session_clear_routes(relay_session_t *restrict const session);

/**
 * @brief Synthesizes and submits an RTCP PLI keyframe request packet asynchronously via io_uring.
 *
 * @param session Pointer to relay session.
 * @param sender_ssrc SSRC of the feedback sender.
 * @param media_ssrc SSRC of the video source whose keyframe is requested.
 * @param engine Pointer to ring engine.
 * @return true if PLI packet queued to io_uring, false on error.
 */
bool session_send_pli(
    relay_session_t *restrict const session,
    uint32_t const sender_ssrc,
    uint32_t const media_ssrc,
    ring_engine_t *restrict const engine);

/**
 * @brief Formats active SSRC idle duration metrics in Prometheus text exposition format.
 *
 * @param table Pointer to session table.
 * @param buf Output buffer.
 * @param max_len Capacity of output buffer.
 * @return Number of bytes written (excluding null terminator), or 0 on error.
 */
[[nodiscard]] size_t session_table_format_ssrc_metrics(
    session_table_t const *restrict const table,
    char *restrict const buf,
    size_t const max_len);
