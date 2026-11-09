#include "crypto/base64.h"
#include "core/macros.h"

static char const BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool base64_encode(
    uint8_t const *restrict const src,
    size_t const src_len,
    char *restrict const dst,
    size_t const dst_cap,
    size_t *restrict const out_len) {
    if (unlikely(((src == nullptr) && (src_len > 0)) || (dst == nullptr))) {
        return false;
    }

    size_t const needed = base64_encoded_len(src_len);
    if (unlikely(dst_cap <= needed)) {
        return false;
    }

    size_t di = 0;
    size_t si = 0;

    while ((si + 2) < src_len) {
        uint32_t const triple =
            ((uint32_t)src[si] << 16) | ((uint32_t)src[si + 1] << 8) | (uint32_t)src[si + 2];
        dst[di]     = BASE64_CHARS[(triple >> 18) & 0x3F];
        dst[di + 1] = BASE64_CHARS[(triple >> 12) & 0x3F];
        dst[di + 2] = BASE64_CHARS[(triple >> 6) & 0x3F];
        dst[di + 3] = BASE64_CHARS[triple & 0x3F];
        si += 3;
        di += 4;
    }

    size_t const remain = src_len - si;
    if (remain == 1) {
        uint32_t const triple = (uint32_t)src[si] << 16;
        dst[di]               = BASE64_CHARS[(triple >> 18) & 0x3F];
        dst[di + 1]           = BASE64_CHARS[(triple >> 12) & 0x3F];
        dst[di + 2]           = '=';
        dst[di + 3]           = '=';
        di += 4;
    } else if (remain == 2) {
        uint32_t const triple = ((uint32_t)src[si] << 16) | ((uint32_t)src[si + 1] << 8);
        dst[di]               = BASE64_CHARS[(triple >> 18) & 0x3F];
        dst[di + 1]           = BASE64_CHARS[(triple >> 12) & 0x3F];
        dst[di + 2]           = BASE64_CHARS[(triple >> 6) & 0x3F];
        dst[di + 3]           = '=';
        di += 4;
    }

    dst[di] = '\0';
    if (out_len != nullptr) {
        *out_len = di;
    }
    return true;
}

static inline int8_t base64_char_value(char const c) {
    if ((c >= 'A') && (c <= 'Z')) {
        return (int8_t)(c - 'A');
    }
    if ((c >= 'a') && (c <= 'z')) {
        return (int8_t)(c - 'a' + 26);
    }
    if ((c >= '0') && (c <= '9')) {
        return (int8_t)(c - '0' + 52);
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

bool base64_decode(
    char const *restrict const src,
    size_t const src_len,
    uint8_t *restrict const dst,
    size_t const dst_cap,
    size_t *restrict const out_len) {
    if (unlikely(((src == nullptr) && (src_len > 0)) || (dst == nullptr) || (out_len == nullptr))) {
        return false;
    }

    *out_len = 0;
    if (src_len == 0) {
        return true;
    }

    size_t si = 0;
    size_t di = 0;

    // Filter out trailing whitespace if any
    size_t effective_len = src_len;
    while ((effective_len > 0) &&
           ((src[effective_len - 1] == ' ') || (src[effective_len - 1] == '\r') ||
            (src[effective_len - 1] == '\n') || (src[effective_len - 1] == '\t')))
    {
        effective_len--;
    }

    if (unlikely((effective_len % 4) != 0)) {
        return false;
    }

    while (si < effective_len) {
        char const c0 = src[si];
        char const c1 = src[si + 1];
        char const c2 = src[si + 2];
        char const c3 = src[si + 3];

        int8_t const v0 = base64_char_value(c0);
        int8_t const v1 = base64_char_value(c1);
        if (unlikely((v0 < 0) || (v1 < 0))) {
            return false;
        }

        if (c2 == '=') {
            // Must be the last block and c3 must also be '='
            if (unlikely(((si + 4) != effective_len) || (c3 != '='))) {
                return false;
            }
            if (unlikely(di >= dst_cap)) {
                return false;
            }
            dst[di++] = (uint8_t)(((uint32_t)v0 << 2) | ((uint32_t)v1 >> 4));
            break;
        }

        int8_t const v2 = base64_char_value(c2);
        if (unlikely(v2 < 0)) {
            return false;
        }

        if (c3 == '=') {
            // Must be the last block
            if (unlikely((si + 4) != effective_len)) {
                return false;
            }
            if (unlikely((di + 1) >= dst_cap)) {
                return false;
            }
            dst[di]     = (uint8_t)(((uint32_t)v0 << 2) | ((uint32_t)v1 >> 4));
            dst[di + 1] = (uint8_t)(((uint32_t)(v1 & 0x0F) << 4) | ((uint32_t)v2 >> 2));
            di += 2;
            break;
        }

        int8_t const v3 = base64_char_value(c3);
        if (unlikely(v3 < 0)) {
            return false;
        }

        if (unlikely((di + 2) >= dst_cap)) {
            return false;
        }

        uint32_t const triple =
            ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) | ((uint32_t)v2 << 6) | (uint32_t)v3;

        dst[di]     = (uint8_t)((triple >> 16) & 0xFF);
        dst[di + 1] = (uint8_t)((triple >> 8) & 0xFF);
        dst[di + 2] = (uint8_t)(triple & 0xFF);
        di += 3;
        si += 4;
    }

    *out_len = di;
    return true;
}
