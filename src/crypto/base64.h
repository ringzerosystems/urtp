#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file base64.h
 * @brief Fast RFC 4648 Base64 encoding and decoding for SDES crypto keys.
 */

/**
 * @brief Computes the required Base64 encoded string length (excluding null terminator)
 *        for a given input byte length.
 *
 * @param in_len Input binary byte length.
 * @return Number of characters required for the Base64 encoded string.
 */
[[nodiscard]] static inline size_t base64_encoded_len(size_t const in_len) {
    return ((in_len + 2) / 3) * 4;
}

/**
 * @brief Computes the maximum decoded byte length for a given Base64 string length.
 *
 * @param in_len Length of Base64 string.
 * @return Maximum number of binary bytes after decoding.
 */
[[nodiscard]] static inline size_t base64_max_decoded_len(size_t const in_len) {
    return (in_len / 4) * 3;
}

/**
 * @brief Encodes binary data into standard RFC 4648 Base64 format with null termination.
 *
 * @param src Pointer to binary data to encode.
 * @param src_len Length in bytes of binary data.
 * @param dst Pointer to destination buffer.
 * @param dst_cap Capacity in bytes of destination buffer (must include null terminator).
 * @param out_len Pointer to store length of encoded string (can be nullptr).
 * @return true on success, false if buffer capacity is insufficient.
 */
[[nodiscard]] bool base64_encode(
    uint8_t const *restrict const src,
    size_t const src_len,
    char *restrict const dst,
    size_t const dst_cap,
    size_t *restrict const out_len);

/**
 * @brief Decodes an RFC 4648 Base64 string into binary data.
 *
 * @param src Pointer to Base64 string to decode.
 * @param src_len Length in bytes of Base64 string.
 * @param dst Pointer to destination buffer for binary output.
 * @param dst_cap Capacity in bytes of destination buffer.
 * @param out_len Pointer to store actual decoded byte count.
 * @return true on success, false on invalid character, malformed padding, or buffer overflow.
 */
[[nodiscard]] bool base64_decode(
    char const *restrict const src,
    size_t const src_len,
    uint8_t *restrict const dst,
    size_t const dst_cap,
    size_t *restrict const out_len);
