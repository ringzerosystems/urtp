#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "control/bencode.h"
#include "control/sdp.h"
#include "core/string_view.h"
#include "net/session.h"
#include "ring/ring.h"

/**
 * @file ng.h
 * @brief Kamailio / OpenSIPS NG control protocol implementation and call session management.
 */

/** @brief Maximum concurrent active SIP calls tracked in the NG call table. */
constexpr size_t NG_MAX_CALLS = 256;
/** @brief Maximum length of SIP Call-ID string. */
constexpr size_t NG_MAX_ID_LEN = 128;
/** @brief Maximum length of SIP from-tag and to-tag strings. */
constexpr size_t NG_MAX_TAG_LEN = 64;
/** @brief Lower bound of dynamic RTP port allocation pool. */
constexpr uint16_t NG_PORT_POOL_MIN = 30000;
/** @brief Upper bound of dynamic RTP port allocation pool. */
constexpr uint16_t NG_PORT_POOL_MAX = 40000;

/**
 * @brief Individual media stream section (m= line) tracked within an NG call.
 */
typedef struct {
    sdp_media_type_t type;              /**< Stream type (audio, video, application). */
    uint16_t         caller_port;       /**< Local proxy port bound for caller. */
    uint16_t         callee_port;       /**< Local proxy port bound for callee. */
    uint16_t         caller_media_port; /**< Discovered or remote caller port. */
    uint16_t         callee_media_port; /**< Discovered or remote callee port. */
    bool             rtcp_mux;          /**< True if RTCP is multiplexed on the RTP port. */
    bool             active;            /**< True if media stream is active. */
    uint8_t payload_types[SDP_MAX_PAYLOAD_TYPES]; /**< Array of supported RTP payload types. */
    size_t  pt_count;                             /**< Number of payload types in stream. */
} ng_media_stream_t;

/**
 * @brief Active SIP call session state tracked across offer/answer transactions.
 */
typedef struct {
    char                call_id[NG_MAX_ID_LEN];      /**< SIP Call-ID string. */
    char                from_tag[NG_MAX_TAG_LEN];    /**< SIP from-tag identifying the caller. */
    char                to_tag[NG_MAX_TAG_LEN];      /**< SIP to-tag identifying the callee. */
    uint16_t            caller_port;                 /**< Primary bound RTP port for caller side. */
    uint16_t            callee_port;                 /**< Primary bound RTP port for callee side. */
    char                caller_ip[INET6_ADDRSTRLEN]; /**< Caller remote IP address. */
    uint16_t            caller_media_port;           /**< Caller remote media port. */
    char                callee_ip[INET6_ADDRSTRLEN]; /**< Callee remote IP address. */
    uint16_t            callee_media_port;           /**< Callee remote media port. */
    bool                active;                      /**< True if call is currently active. */
    int32_t             record_idx; /**< Attached PCAP recorder index (-1 if disabled). */
    bool                has_to_tag; /**< True if to-tag has been received in answer. */
    bool                is_bundled; /**< True if multi-stream call uses BUNDLE on one port. */
    ng_media_stream_t   streams[SDP_MAX_MEDIA_STREAMS]; /**< Array of media stream sections. */
    size_t              stream_count;                   /**< Number of media streams in call. */
    bool                caller_rtcp_mux;                /**< Caller RTCP-MUX preference. */
    bool                callee_rtcp_mux;                /**< Callee RTCP-MUX preference. */
    bool                caller_use_srtp;                /**< True if caller uses SRTP/SDES. */
    srtp_crypto_suite_t caller_crypto_suite;            /**< Caller SRTP crypto suite. */
    uint8_t
        caller_inbound_key[SDES_MAX_KEY_BIN_LEN]; /**< Caller inbound binary master key + salt. */
    size_t caller_inbound_key_len;                /**< Length of caller inbound key. */
    uint8_t
        caller_outbound_key[SDES_MAX_KEY_BIN_LEN]; /**< Caller outbound binary master key + salt. */
    size_t caller_outbound_key_len;                /**< Length of caller outbound key. */
    char   caller_outbound_b64[SDES_MAX_KEY_B64_LEN]; /**< Caller outbound Base64 key string. */
    bool   callee_use_srtp;                           /**< True if callee uses SRTP/SDES. */
    srtp_crypto_suite_t callee_crypto_suite;          /**< Callee SRTP crypto suite. */
    uint8_t
        callee_inbound_key[SDES_MAX_KEY_BIN_LEN]; /**< Callee inbound binary master key + salt. */
    size_t callee_inbound_key_len;                /**< Length of callee inbound key. */
    uint8_t
        callee_outbound_key[SDES_MAX_KEY_BIN_LEN]; /**< Callee outbound binary master key + salt. */
    size_t   callee_outbound_key_len;              /**< Length of callee outbound key. */
    char     callee_outbound_b64[SDES_MAX_KEY_B64_LEN]; /**< Callee outbound Base64 key string. */
    uint64_t created_ts;           /**< Monotonic timestamp of call creation. */
    bool     caller_is_webrtc;     /**< True if caller side is WebRTC (DTLS/ICE). */
    bool     callee_is_webrtc;     /**< True if callee side is WebRTC (DTLS/ICE). */
    char     caller_ice_ufrag[64]; /**< Caller remote ICE username fragment. */
    char     caller_ice_pwd[128];  /**< Caller remote ICE password. */
    char     callee_ice_ufrag[64]; /**< Callee remote ICE username fragment. */
    char     callee_ice_pwd[128];  /**< Callee remote ICE password. */
    char     local_ice_ufrag[32];  /**< Local proxy ICE username fragment. */
    char     local_ice_pwd[64];    /**< Local proxy ICE password. */
    uint32_t jitter_buffer_ms;     /**< Configured jitter buffer delay in ms. */
} ng_call_t;

/**
 * @brief Global call table managing all active NG protocol sessions.
 */
typedef struct ng_call_table {
    alignas(64) ng_call_t calls[NG_MAX_CALLS]; /**< Array of call session slots. */
    size_t   active_count;                     /**< Count of active calls. */
    uint16_t next_port;                        /**< Next port cursor for dynamic allocation. */
    bool     draining; /**< True if server is in graceful shutdown draining mode. */
    char     media_ip[INET6_ADDRSTRLEN]; /**< Advertised media IP address. */
} ng_call_table_t;

/**
 * @brief Removes an active call from the table matching caller or callee port.
 *
 * @param table Pointer to NG call table.
 * @param port Bound port matching call.
 */
void ng_call_table_remove_by_port(ng_call_table_t *restrict const table, uint16_t const port);

/**
 * @brief Initializes the NG call table.
 *
 * @param table Pointer to NG call table.
 * @param media_ip Advertised IP address to embed in rewritten SDPs (default "127.0.0.1" if
 * nullptr).
 */
void ng_call_table_init(ng_call_table_t *restrict const table, char const *const media_ip);

/**
 * @brief Tears down all active calls and deletes their associated media sessions.
 *
 * @param table Pointer to NG call table.
 * @param session_table Pointer to media session table.
 * @param engine Pointer to ring engine.
 */
void ng_call_table_destroy(
    ng_call_table_t *restrict const table,
    session_table_t *restrict const session_table,
    ring_engine_t *restrict const engine);

/**
 * @brief Searches for an active call matching the given Call-ID string view.
 *
 * @param table Pointer to NG call table.
 * @param call_id Call-ID string view.
 * @return Pointer to call if found, nullptr otherwise.
 */
[[nodiscard]] ng_call_t *ng_call_find(ng_call_table_t *restrict const table, sv_t const call_id);

/**
 * @brief Finds an existing call or allocates a new slot for the Call-ID and from-tag.
 *
 * @param table Pointer to NG call table.
 * @param call_id Call-ID string view.
 * @param from_tag From-tag string view.
 * @return Pointer to active or created call, or nullptr if table full.
 */
[[nodiscard]] ng_call_t *ng_call_find_or_create(
    ng_call_table_t *restrict const table,
    sv_t const call_id,
    sv_t const from_tag);

/**
 * @brief Clears an active call from the table.
 *
 * @param table Pointer to NG call table.
 * @param call Pointer to call to clear.
 */
void ng_call_destroy(ng_call_table_t *restrict const table, ng_call_t *restrict const call);

/**
 * @brief Allocates an even RTP port from the dynamic port pool not currently in use.
 *
 * @param table Pointer to NG call table.
 * @param session_table Pointer to session table.
 * @return Allocated even port number, or 0 on exhaustion.
 */
[[nodiscard]] uint16_t ng_call_table_alloc_port(
    ng_call_table_t *restrict const table,
    session_table_t *restrict const session_table);

/**
 * @brief Checks whether an incoming payload is an NG protocol message (cookie + bencode dict or
 * bencode dict).
 *
 * @param msg Pointer to payload string.
 * @param msg_len Length in bytes of payload.
 * @return true if payload format matches NG protocol, false otherwise.
 */
[[nodiscard]] bool ng_is_message(char const *const msg, size_t const msg_len);

/**
 * @brief Processes an incoming Kamailio/OpenSIPS NG protocol message and writes the response.
 *
 * Handles 'ping', 'offer', 'answer', 'delete', 'query', and 'list' commands with cookie echo.
 *
 * @param msg Raw message payload.
 * @param msg_len Length of raw message payload.
 * @param session_table Pointer to RTP relay session table.
 * @param call_table Pointer to NG call table.
 * @param engine Pointer to ring engine.
 * @param resp_buf Output buffer to store response.
 * @param resp_max Capacity of output buffer.
 * @param resp_len Pointer to store length of generated response.
 * @return true if successfully processed and response generated, false otherwise.
 */
bool ng_process_message(
    char const *const msg,
    size_t const      msg_len,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max,
    size_t *restrict const resp_len);
