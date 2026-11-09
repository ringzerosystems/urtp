#pragma once

#include <stdint.h>
#include "core/string_view.h"

/**
 * @file hash.h
 * @brief High-performance non-cryptographic hash functions for data structures.
 */

/**
 * @brief Murmur3's 32-bit avalanche finalizer.
 *
 * Extremely fast, zero-allocation integer hash with excellent distribution.
 *
 * @param x The 32-bit integer to hash.
 * @return The avalanched 32-bit hash value.
 */
[[nodiscard]] static inline uint32_t hash_u32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;
    return x;
}

/**
 * @brief Combines two 32-bit hash values using the Golden Ratio multiplier.
 *
 * @param seed The base hash or accumulator.
 * @param v The hash value to combine.
 * @return Combined 32-bit hash.
 */
[[nodiscard]] static inline uint32_t hash_combine(uint32_t seed, uint32_t v) {
    return seed ^ (v + 0x9e3779b9 + (seed << 6) + (seed >> 2));
}

/** @brief FNV-1a 32-bit offset basis constant per specification. */
static constexpr uint32_t FNV_OFFSET_BASIS = 0x811C9DC5;
/** @brief FNV-1a 32-bit prime multiplier constant per specification. */
static constexpr uint32_t FNV_PRIME = 0x01000193;

/**
 * @brief Case-insensitive FNV-1a hash for ASCII strings.
 * @param str The string view to hash.
 * @return A 32-bit hash value.
 */
[[nodiscard]] static inline uint32_t hash_stringi(sv_t str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < str.length; ++i) {
        hash ^= (uint8_t)ascii_tolower(str.data[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}

/**
 * @brief Case-sensitive FNV-1a hash for ASCII strings.
 * @param str The string view to hash.
 * @return A 32-bit hash value.
 */
[[nodiscard]] static inline uint32_t hash_string(sv_t str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < str.length; ++i) {
        hash ^= (uint8_t)(str.data[i]);
        hash *= FNV_PRIME;
    }
    return hash;
}
