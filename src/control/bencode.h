#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/string_view.h"

/**
 * @file bencode.h
 * @brief High-performance zero-allocation Bencode parser and serializer for the NG protocol.
 */

/**
 * @brief Bencode value data type discriminator.
 */
typedef enum : uint8_t {
    BENCODE_TYPE_NONE = 0, /**< Uninitialized or invalid type. */
    BENCODE_TYPE_STR  = 1, /**< Bencoded byte string. */
    BENCODE_TYPE_INT  = 2, /**< Bencoded 64-bit signed integer. */
    BENCODE_TYPE_LIST = 3, /**< Bencoded homogeneous or heterogeneous list. */
    BENCODE_TYPE_DICT = 4, /**< Bencoded dictionary mapping strings to values. */
} bencode_type_t;

/**
 * @brief Parsed Bencode token or value node.
 */
typedef struct {
    bencode_type_t type; /**< Bencode data type. */
    sv_t    str; /**< Valid string slice when type == BENCODE_TYPE_STR, or inner container slice. */
    int64_t integer; /**< Valid 64-bit integer when type == BENCODE_TYPE_INT. */
    sv_t raw; /**< Complete raw slice including envelope markers ('d...e', 'l...e', 'i...e', etc.).
               */
} bencode_val_t;

/**
 * @brief Fixed-capacity memory buffer builder for Bencode serialization.
 */
typedef struct {
    char  *buf;      /**< Backing output character buffer. */
    size_t cap;      /**< Capacity in bytes of the buffer. */
    size_t len;      /**< Current number of bytes written. */
    bool   overflow; /**< True if an attempted write exceeded capacity. */
} bencode_buf_t;

/**
 * @brief Parses a single bencoded element from the cursor and advances it.
 *
 * @param cursor Pointer to string view representing remaining input.
 * @param out Pointer to output bencode_val_t structure.
 * @return true if an element was successfully parsed, false on syntax or truncation error.
 */
[[nodiscard]] bool
bencode_parse_element(sv_t *restrict const cursor, bencode_val_t *restrict const out);

/**
 * @brief Searches a bencoded dictionary for a given key.
 *
 * Keys may appear in any order.
 *
 * @param dict String view containing the raw dictionary ('d...e').
 * @param key Key to search for.
 * @param out Pointer to store the value corresponding to the key.
 * @return true if key was found and valid, false otherwise.
 */
[[nodiscard]] bool
bencode_dict_find(sv_t const dict, sv_t const key, bencode_val_t *restrict const out);

/**
 * @brief Convenience function to extract a string value from a bencoded dictionary.
 *
 * @param dict Raw dictionary string view.
 * @param key Key to search for.
 * @param out Pointer to store string view of the value.
 * @return true if key found and is a string, false otherwise.
 */
[[nodiscard]] bool bencode_dict_get_str(sv_t const dict, sv_t const key, sv_t *restrict const out);

/**
 * @brief Convenience function to extract an integer value from a bencoded dictionary.
 *
 * @param dict Raw dictionary string view.
 * @param key Key to search for.
 * @param out Pointer to store integer value.
 * @return true if key found and is an integer, false otherwise.
 */
[[nodiscard]] bool
bencode_dict_get_int(sv_t const dict, sv_t const key, int64_t *restrict const out);

/**
 * @brief Checks if a bencoded list contains a specified string value.
 *
 * @param list Raw list string view ('l...e').
 * @param target String view to search for within the list elements.
 * @return true if target is in the list, false otherwise.
 */
[[nodiscard]] bool bencode_list_contains_str(sv_t const list, sv_t const target);

/**
 * @brief Initializes a bencode serialization buffer.
 *
 * @param b Pointer to buffer builder.
 * @param buf Target character array.
 * @param cap Capacity in bytes of the buffer.
 */
void bencode_buf_init(bencode_buf_t *restrict const b, char *restrict const buf, size_t const cap);

/**
 * @brief Writes dictionary start marker ('d').
 *
 * @param b Pointer to buffer builder.
 * @return true on success, false on overflow.
 */
bool bencode_write_dict_start(bencode_buf_t *restrict const b);

/**
 * @brief Writes dictionary or list end marker ('e').
 *
 * @param b Pointer to buffer builder.
 * @return true on success, false on overflow.
 */
bool bencode_write_dict_end(bencode_buf_t *restrict const b);

/**
 * @brief Writes list start marker ('l').
 *
 * @param b Pointer to buffer builder.
 * @return true on success, false on overflow.
 */
bool bencode_write_list_start(bencode_buf_t *restrict const b);

/**
 * @brief Writes list end marker ('e').
 *
 * @param b Pointer to buffer builder.
 * @return true on success, false on overflow.
 */
bool bencode_write_list_end(bencode_buf_t *restrict const b);

/**
 * @brief Writes a raw bencoded string (<len>:<str>).
 *
 * @param b Pointer to buffer builder.
 * @param str Pointer to string bytes.
 * @param len Length in bytes of string.
 * @return true on success, false on overflow.
 */
bool bencode_write_str_raw(
    bencode_buf_t *restrict const b,
    char const *restrict const str,
    size_t const len);

/**
 * @brief Writes a raw bencoded integer (i<val>e).
 *
 * @param b Pointer to buffer builder.
 * @param val 64-bit integer to write.
 * @return true on success, false on overflow.
 */
bool bencode_write_int_raw(bencode_buf_t *restrict const b, int64_t const val);

/**
 * @brief Writes a key-value pair where the value is a null-terminated string.
 *
 * @param b Pointer to buffer builder.
 * @param key Null-terminated key string.
 * @param val Null-terminated value string.
 * @return true on success, false on overflow.
 */
bool bencode_write_kv_str(
    bencode_buf_t *restrict const b,
    char const *const key,
    char const *const val);

/**
 * @brief Writes a key-value pair where the value is a string view.
 *
 * @param b Pointer to buffer builder.
 * @param key Null-terminated key string.
 * @param val String view value.
 * @return true on success, false on overflow.
 */
bool bencode_write_kv_sv(bencode_buf_t *restrict const b, char const *const key, sv_t const val);

/**
 * @brief Writes a key-value pair where the value is an integer.
 *
 * @param b Pointer to buffer builder.
 * @param key Null-terminated key string.
 * @param val 64-bit integer value.
 * @return true on success, false on overflow.
 */
bool bencode_write_kv_int(
    bencode_buf_t *restrict const b,
    char const *const key,
    int64_t const     val);
