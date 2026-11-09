#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if __has_include(<srtp2/srtp.h>)
#include <srtp2/srtp.h>
#else
#include <srtp.h>
#endif
#include "core/macros.h"

/**
 * @file srtp_session.h
 * @brief High-performance zero-copy libsrtp2 wrapper for SRTP encryption and decryption.
 */

/**
 * @brief Supported SRTP/SRTCP cryptographic transform suites.
 */
typedef enum : uint8_t {
    SRTP_CRYPTO_SUITE_NONE = 0, /**< No encryption / plain RTP. */
    SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80 =
        1, /**< AES-128 Counter Mode with HMAC-SHA1 80-bit auth tag. */
    SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32 =
        2, /**< AES-128 Counter Mode with HMAC-SHA1 32-bit auth tag. */
    SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM = 3, /**< AEAD AES-128 GCM per RFC 7714. */
    SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM = 4, /**< AEAD AES-256 GCM per RFC 7714. */
} srtp_crypto_suite_t;

/**
 * @brief Direction of SRTP cryptographic stream.
 */
typedef enum : uint8_t {
    SRTP_DIR_INBOUND  = 1, /**< Inbound decryption and authentication check. */
    SRTP_DIR_OUTBOUND = 2, /**< Outbound encryption and authentication generation. */
} srtp_direction_t;

/**
 * @brief libsrtp session context container.
 */
typedef struct {
    srtp_t              session;     /**< libsrtp internal session handle. */
    srtp_crypto_suite_t suite;       /**< Active crypto suite. */
    srtp_direction_t    direction;   /**< Inbound or outbound direction. */
    bool                initialized; /**< True if session is initialized and valid. */
} urtp_srtp_ctx_t;

/**
 * @brief Global SRTP library initialization. Safe to call multiple times.
 *
 * @return true on success, false on libsrtp init failure.
 */
[[nodiscard]] bool urtp_srtp_global_init(void);

/**
 * @brief Global SRTP library deinitialization.
 */
void urtp_srtp_global_cleanup(void);

/**
 * @brief Converts a crypto suite enum value to standard RFC 4568 / RFC 7714 string name.
 *
 * @param suite Crypto suite enum.
 * @return String representation, or "UNKNOWN".
 */
[[nodiscard]] char const *srtp_crypto_suite_to_string(srtp_crypto_suite_t const suite);

/**
 * @brief Parses an RFC 4568 / RFC 7714 crypto suite name string into suite enum.
 *
 * @param name Pointer to name string.
 * @param len Length in bytes of name string.
 * @return Recognized suite enum, or SRTP_CRYPTO_SUITE_NONE.
 */
[[nodiscard]] srtp_crypto_suite_t
srtp_crypto_suite_from_string(char const *const name, size_t const len);

/**
 * @brief Returns master key length in bytes for a given suite.
 *
 * @param suite Crypto suite enum.
 * @return Master key length in bytes (e.g. 16 or 32).
 */
[[nodiscard]] size_t srtp_crypto_suite_key_len(srtp_crypto_suite_t const suite);

/**
 * @brief Returns master salt length in bytes for a given suite.
 *
 * @param suite Crypto suite enum.
 * @return Master salt length in bytes (e.g. 14 or 12).
 */
[[nodiscard]] size_t srtp_crypto_suite_salt_len(srtp_crypto_suite_t const suite);

/**
 * @brief Returns total key + salt length in bytes for a given suite.
 *
 * @param suite Crypto suite enum.
 * @return Sum of key length and salt length in bytes.
 */
[[nodiscard]] static inline size_t
srtp_crypto_suite_total_key_len(srtp_crypto_suite_t const suite) {
    return srtp_crypto_suite_key_len(suite) + srtp_crypto_suite_salt_len(suite);
}

/**
 * @brief Returns authentication tag length in octets added to RTP packets.
 *
 * @param suite Crypto suite enum.
 * @return Authentication tag length in bytes (e.g. 10, 4, or 16).
 */
[[nodiscard]] size_t srtp_crypto_suite_tag_len(srtp_crypto_suite_t const suite);

/**
 * @brief Initializes an SRTP context with given direction, suite, and binary master key + salt.
 *
 * @param ctx Pointer to context structure.
 * @param direction SRTP_DIR_INBOUND (decrypt) or SRTP_DIR_OUTBOUND (encrypt).
 * @param suite Crypto suite to use.
 * @param key_salt Pointer to binary master key and salt concatenated.
 * @param key_salt_len Length of binary key + salt.
 * @return true on success, false on invalid args or libsrtp failure.
 */
[[nodiscard]] bool urtp_srtp_ctx_init(
    urtp_srtp_ctx_t *restrict const ctx,
    srtp_direction_t const    direction,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len);

/**
 * @brief Destroys an SRTP context and releases libsrtp session resources.
 *
 * @param ctx Pointer to context structure.
 */
void urtp_srtp_ctx_destroy(urtp_srtp_ctx_t *restrict const ctx);

/**
 * @brief Protects (encrypts and authenticates) an RTP packet in place.
 *
 * @param ctx Pointer to outbound SRTP context.
 * @param pkt Pointer to RTP packet header and payload.
 * @param in_len Input length in bytes.
 * @param max_cap Maximum capacity of packet buffer.
 * @param out_len Pointer to store resulting SRTP packet length.
 * @return true on success, false on error.
 */
[[nodiscard]] bool urtp_srtp_protect_rtp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t const max_cap,
    size_t *restrict const out_len);

/**
 * @brief Unprotects (authenticates and decrypts) an SRTP packet in place.
 *
 * @param ctx Pointer to inbound SRTP context.
 * @param pkt Pointer to SRTP packet buffer.
 * @param in_len Input length in bytes.
 * @param out_len Pointer to store resulting plain RTP packet length.
 * @return true on success, false on authentication or replay failure.
 */
[[nodiscard]] bool urtp_srtp_unprotect_rtp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t *restrict const out_len);

/**
 * @brief Protects (encrypts and authenticates) an RTCP packet in place.
 *
 * @param ctx Pointer to outbound SRTP context.
 * @param pkt Pointer to RTCP packet buffer.
 * @param in_len Input length in bytes.
 * @param max_cap Maximum capacity of packet buffer.
 * @param out_len Pointer to store resulting SRTCP packet length.
 * @return true on success, false on error.
 */
[[nodiscard]] bool urtp_srtp_protect_rtcp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t const max_cap,
    size_t *restrict const out_len);

/**
 * @brief Unprotects (authenticates and decrypts) an SRTCP packet in place.
 *
 * @param ctx Pointer to inbound SRTP context.
 * @param pkt Pointer to SRTCP packet buffer.
 * @param in_len Input length in bytes.
 * @param out_len Pointer to store resulting plain RTCP packet length.
 * @return true on success, false on authentication or replay failure.
 */
[[nodiscard]] bool urtp_srtp_unprotect_rtcp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t *restrict const out_len);
