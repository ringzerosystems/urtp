#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto/base64.h"
#include "crypto/srtp_session.h"

/**
 * @file sdes.h
 * @brief RFC 4568 Session Description Protocol (SDP) Security Descriptions (SDES) for Media
 * Streams.
 */

/** @brief Maximum binary length in bytes of an SDES master key + salt buffer. */
constexpr size_t SDES_MAX_KEY_BIN_LEN = 64;
/** @brief Maximum Base64-encoded string length for SDES key-params inline parameter. */
constexpr size_t SDES_MAX_KEY_B64_LEN = 128;

/**
 * @brief Parsed RFC 4568 SDES 'a=crypto:' media attribute.
 */
typedef struct {
    uint32_t            tag;   /**< Decimal tag identifier (e.g. 1). */
    srtp_crypto_suite_t suite; /**< Parsed SRTP crypto suite identifier. */
    char suite_str[32]; /**< Raw suite name string from SDP (e.g. "AES_CM_128_HMAC_SHA1_80"). */
    char b64_key[SDES_MAX_KEY_B64_LEN]; /**< Base64 key parameter string from inline parameter. */
    uint8_t
        master_key[SDES_MAX_KEY_BIN_LEN]; /**< Decoded binary master key concatenated with salt. */
    size_t master_key_len;                /**< Byte length of decoded binary master key + salt. */
} sdes_crypto_attr_t;

/**
 * @brief Parses an RFC 4568 'a=crypto:' or 'crypto:' attribute line.
 *
 * Syntax: a=crypto:<tag> <crypto-suite> inline:<key-params> ...
 *
 * @param line Pointer to line text.
 * @param len Length in bytes of line.
 * @param out Pointer to output sdes_crypto_attr_t structure.
 * @return true if successfully parsed and decoded, false on format or decoding error.
 */
[[nodiscard]] bool sdes_parse_crypto_attr(
    char const *const line,
    size_t const      len,
    sdes_crypto_attr_t *restrict const out);

/**
 * @brief Formats an RFC 4568 'a=crypto:' line.
 *
 * @param tag Numeric tag (usually 1).
 * @param suite Crypto suite enum.
 * @param b64_key Base64-encoded master key + salt string.
 * @param out_buf Buffer to store formatted line.
 * @param out_cap Capacity in bytes of out_buf.
 * @param out_len Pointer to store length of formatted line (can be nullptr).
 * @return true on success, false if output buffer too small.
 */
[[nodiscard]] bool sdes_format_crypto_attr(
    uint32_t const            tag,
    srtp_crypto_suite_t const suite,
    char const *const         b64_key,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len);

/**
 * @brief Generates cryptographically secure random master key and salt for the given suite,
 *        and provides both binary and Base64 encoded representations.
 *
 * @param suite Crypto suite to generate keys for.
 * @param out_bin Buffer to store binary key + salt.
 * @param bin_cap Capacity of out_bin.
 * @param out_bin_len Pointer to store binary length.
 * @param out_b64 Buffer to store Base64 string.
 * @param b64_cap Capacity of out_b64.
 * @param out_b64_len Pointer to store Base64 string length (excluding null terminator).
 * @return true on success, false on error.
 */
[[nodiscard]] bool sdes_generate_key(
    srtp_crypto_suite_t const suite,
    uint8_t *restrict const out_bin,
    size_t const bin_cap,
    size_t *restrict const out_bin_len,
    char *restrict const out_b64,
    size_t const b64_cap,
    size_t *restrict const out_b64_len);
