#pragma once

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/macros.h"
#include "crypto/srtp_session.h"

/**
 * @file dtls.h
 * @brief DTLS-SRTP key negotiation and handshake engine for WebRTC media streams per RFC 5764.
 */

/** @brief Minimum length in bytes of a DTLS record header per RFC 6347. */
constexpr size_t DTLS_RECORD_HEADER_MIN_SIZE = 13;
/** @brief Maximum buffer length for formatted SHA-256 certificate fingerprint string. */
constexpr size_t DTLS_FINGERPRINT_STR_LEN = 128;

/**
 * @brief DTLS endpoint role during handshake negotiation.
 */
typedef enum : uint8_t {
    DTLS_ROLE_SERVER = 0, /**< Passive / actpass role (accepts incoming handshakes). */
    DTLS_ROLE_CLIENT = 1, /**< Active role (initiates DTLS ClientHello handshake). */
} dtls_role_t;

/**
 * @brief State of DTLS handshake state machine.
 */
typedef enum : uint8_t {
    DTLS_STATE_NONE      = 0, /**< Uninitialized or idle. */
    DTLS_STATE_HANDSHAKE = 1, /**< Handshake currently in progress. */
    DTLS_STATE_CONNECTED = 2, /**< Handshake completed; keys exported. */
    DTLS_STATE_FAILED    = 3, /**< Handshake encountered a fatal error. */
} dtls_state_t;

/**
 * @brief Per-session DTLS state machine using memory BIOs with OpenSSL.
 */
typedef struct {
    SSL         *ssl;         /**< OpenSSL SSL connection handle. */
    BIO         *in_bio;      /**< Memory BIO for incoming network datagrams. */
    BIO         *out_bio;     /**< Memory BIO for outgoing handshake datagrams. */
    dtls_role_t  role;        /**< Configured role (client or server). */
    dtls_state_t state;       /**< Current handshake progress state. */
    bool         initialized; /**< True if SSL session is active. */
} urtp_dtls_session_t;

/**
 * @brief Initializes the global DTLS SSL_CTX, generates self-signed certificate,
 * and computes SHA-256 fingerprint.
 *
 * @return true on success, false on OpenSSL failure.
 */
[[nodiscard]] bool urtp_dtls_global_init(void);

/**
 * @brief Releases the global DTLS SSL_CTX and certificate resources.
 */
void urtp_dtls_global_cleanup(void);

/**
 * @brief Returns the cached SHA-256 fingerprint string (e.g. "XX:XX:...").
 *
 * @return Null-terminated SHA-256 certificate fingerprint string.
 */
[[nodiscard]] char const *urtp_dtls_get_fingerprint(void);

/**
 * @brief Checks if a packet is a DTLS record per RFC 7983.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet matches DTLS record demultiplexing range, false otherwise.
 */
[[nodiscard]] static inline bool
urtp_dtls_is_packet(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len < DTLS_RECORD_HEADER_MIN_SIZE))) {
        return false;
    }
    uint8_t const b0 = ((uint8_t const *)data)[0];
    return ((b0 >= 20) && (b0 <= 63));
}

/**
 * @brief Initializes a per-session DTLS state with memory BIOs and configured role.
 *
 * @param ds Pointer to session DTLS context.
 * @param role DTLS_ROLE_SERVER (passive) or DTLS_ROLE_CLIENT (active).
 * @return true on success, false otherwise.
 */
[[nodiscard]] bool
urtp_dtls_session_init(urtp_dtls_session_t *restrict const ds, dtls_role_t const role);

/**
 * @brief Destroys and cleans up a session DTLS context.
 *
 * @param ds Pointer to session DTLS context.
 */
void urtp_dtls_session_destroy(urtp_dtls_session_t *restrict const ds);

/**
 * @brief Feeds incoming DTLS datagram bytes into the session's input memory BIO.
 *
 * @param ds Pointer to session DTLS context.
 * @param data Received packet bytes.
 * @param len Length in bytes.
 * @return true if written to BIO, false on failure.
 */
bool urtp_dtls_feed_packet(
    urtp_dtls_session_t *restrict const ds,
    void const *restrict const data,
    size_t const len);

/**
 * @brief Steps the DTLS handshake state machine.
 *
 * @param ds Pointer to session DTLS context.
 * @return 1 on progress/success, 0 or negative on waiting/error.
 */
int urtp_dtls_step(urtp_dtls_session_t *restrict const ds);

/**
 * @brief Retrieves pending output handshake datagram bytes produced by OpenSSL.
 *
 * @param ds Pointer to session DTLS context.
 * @param out_buf Buffer to receive pending bytes.
 * @param out_cap Capacity in bytes of out_buf.
 * @return Number of bytes read into out_buf.
 */
size_t urtp_dtls_get_pending_output(
    urtp_dtls_session_t *restrict const ds,
    void *restrict const out_buf,
    size_t const out_cap);

/**
 * @brief Exports negotiated SRTP keys from a completed DTLS handshake per RFC 5764.
 *
 * @param ds Pointer to connected DTLS session context.
 * @param suite Output selected SRTP crypto suite.
 * @param in_key_salt Buffer to receive inbound master key + salt.
 * @param in_cap Capacity in bytes of in_key_salt.
 * @param in_len Output length of inbound key + salt.
 * @param out_key_salt Buffer to receive outbound master key + salt.
 * @param out_cap Capacity in bytes of out_key_salt.
 * @param out_len Output length of outbound key + salt.
 * @return true on success, false if handshake not complete or export failed.
 */
[[nodiscard]] bool urtp_dtls_export_srtp_keys(
    urtp_dtls_session_t *restrict const ds,
    srtp_crypto_suite_t *restrict const suite,
    uint8_t *restrict const in_key_salt,
    size_t const in_cap,
    size_t *restrict const in_len,
    uint8_t *restrict const out_key_salt,
    size_t const out_cap,
    size_t *restrict const out_len);
