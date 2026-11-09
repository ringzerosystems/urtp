#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * @file string_view.h
 * @brief Non-owning read-only string view primitives and helpers.
 */

/**
 * @brief Non-owning view into a contiguous sequence of characters.
 */
typedef struct {
    char const
          *data;   /**< Pointer to start of character buffer (not necessarily null-terminated). */
    size_t length; /**< Length in bytes of the viewed string slice. */
} sv_t;

/** @brief Initializes a string view with an explicit pointer and byte length. */
#define SV_INIT(psz, len) ((sv_t){.data = (psz), .length = (len)})
/** @brief Initializes a string view from a compile-time static string literal. */
#define SV_STATIC(psz) {.data = (psz), .length = (sizeof(psz) - 1)}
/** @brief Initializes a string view from a null-terminated C string using built-in strlen. */
#define SV_PSZ(psz) SV_INIT(psz, __builtin_strlen(psz))
/** @brief Empty string view constant with null pointer and zero length. */
#define SV_EMPTY SV_INIT(nullptr, 0)
/** @brief Checks if a string view is null or has zero length. */
#define SV_IS_EMPTY(view) (((view).data == nullptr) || ((view).length == 0))

/** @brief Sets the data pointer and length of an existing string view. */
#define SV_SET(view, psz, len)                                                                     \
    do {                                                                                           \
        (view).data   = (psz);                                                                     \
        (view).length = (len);                                                                     \
    } while (0)

/** @brief Clears an existing string view to null and zero length. */
#define SV_CLEAR(view)                                                                             \
    do {                                                                                           \
        (view).data   = nullptr;                                                                   \
        (view).length = 0;                                                                         \
    } while (0)

/**
 * @brief Converts an ASCII character to lowercase.
 * @param c The character to convert.
 * @return The lowercase equivalent if c is uppercase, otherwise c.
 */
[[nodiscard]] static inline char ascii_tolower(char const c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c | 32) : c;
}

/**
 * @brief Converts an ASCII character to uppercase.
 * @param c The character to convert.
 * @return The uppercase equivalent if c is lowercase, otherwise c.
 */
[[nodiscard]] static inline char ascii_toupper(char const c) {
    return (c >= 'a' && c <= 'z') ? (char)(c & ~32) : c;
}

/**
 * @brief Converts all characters in the mutable buffer to uppercase.
 * @param data The character buffer to convert.
 * @param length The number of characters to convert.
 */
static inline void sv_toupper(char *restrict const data, size_t const length) {
    for (size_t i = 0; i < length; ++i) {
        data[i] = ascii_toupper(data[i]);
    }
}

/**
 * @brief Converts all characters in the mutable buffer to lowercase.
 * @param data The character buffer to convert.
 * @param length The number of characters to convert.
 */
static inline void sv_tolower(char *restrict const data, size_t const length) {
    for (size_t i = 0; i < length; ++i) {
        data[i] = ascii_tolower(data[i]);
    }
}

/**
 * @brief Check if two string views are equal.
 * @param a The first string view.
 * @param b The second string view.
 * @return true if the string views are equal, false otherwise.
 */
[[nodiscard]] static inline bool sv_equals(sv_t const a, sv_t const b) {
    if (a.length != b.length) {
        return false;
    }
    return __builtin_memcmp(a.data, b.data, a.length) == 0;
}

/**
 * @brief Compare two string views lexicographically.
 * @param a The first string view.
 * @param b The second string view.
 * @return A negative value if a < b, 0 if a == b, a positive value if a > b.
 */
[[nodiscard]] static inline int sv_cmp(sv_t const a, sv_t const b) {
    size_t const min_length = (a.length < b.length) ? a.length : b.length;
    int const    cmp        = __builtin_memcmp(a.data, b.data, min_length);
    if (cmp != 0) {
        return cmp;
    }
    if (a.length < b.length) {
        return -1;
    } else if (a.length > b.length) {
        return 1;
    }
    return 0;
}
