#include "control/bencode.h"
#include <stdio.h>
#include "core/macros.h"

void bencode_buf_init(bencode_buf_t *restrict const b, char *restrict const buf, size_t const cap) {
    if (unlikely((b == nullptr) || (buf == nullptr) || (cap == 0))) {
        if (b != nullptr) {
            *b = (bencode_buf_t){.overflow = true};
        }
        return;
    }
    *b = (bencode_buf_t){
        .buf      = buf,
        .cap      = cap,
        .len      = 0,
        .overflow = false,
    };
    buf[0] = '\0';
}

static inline bool bencode_buf_append(
    bencode_buf_t *restrict const b,
    char const *restrict const src,
    size_t const count) {
    if (unlikely((b == nullptr) || b->overflow || (src == nullptr))) {
        return false;
    }
    if ((b->len + count + 1) > b->cap) {
        b->overflow = true;
        return false;
    }
    __builtin_memcpy(&(b->buf[b->len]), src, count);
    b->len += count;
    b->buf[b->len] = '\0';
    return true;
}

bool bencode_write_dict_start(bencode_buf_t *restrict const b) {
    char const d = 'd';
    return bencode_buf_append(b, &d, 1);
}

bool bencode_write_dict_end(bencode_buf_t *restrict const b) {
    char const e = 'e';
    return bencode_buf_append(b, &e, 1);
}

bool bencode_write_list_start(bencode_buf_t *restrict const b) {
    char const l = 'l';
    return bencode_buf_append(b, &l, 1);
}

bool bencode_write_list_end(bencode_buf_t *restrict const b) {
    char const e = 'e';
    return bencode_buf_append(b, &e, 1);
}

bool bencode_write_str_raw(
    bencode_buf_t *restrict const b,
    char const *restrict const str,
    size_t const len) {
    if (unlikely((b == nullptr) || ((len > 0) && (str == nullptr)))) {
        return false;
    }
    char      prefix[32] = {};
    int const prefix_len = snprintf(prefix, sizeof(prefix), "%zu:", len);
    if (prefix_len <= 0) {
        return false;
    }
    if (!bencode_buf_append(b, prefix, (size_t)prefix_len)) {
        return false;
    }
    if (len > 0) {
        return bencode_buf_append(b, str, len);
    }
    return true;
}

bool bencode_write_int_raw(bencode_buf_t *restrict const b, int64_t const val) {
    if (unlikely(b == nullptr)) {
        return false;
    }
    char      num_buf[32] = {};
    int const num_len     = snprintf(num_buf, sizeof(num_buf), "i%llde", (long long)val);
    if (num_len <= 0) {
        return false;
    }
    return bencode_buf_append(b, num_buf, (size_t)num_len);
}

bool bencode_write_kv_str(
    bencode_buf_t *restrict const b,
    char const *const key,
    char const *const val) {
    if (unlikely((b == nullptr) || (key == nullptr) || (val == nullptr))) {
        return false;
    }
    auto const klen = __builtin_strlen(key);
    auto const vlen = __builtin_strlen(val);
    return bencode_write_str_raw(b, key, klen) && bencode_write_str_raw(b, val, vlen);
}

bool bencode_write_kv_sv(bencode_buf_t *restrict const b, char const *const key, sv_t const val) {
    if (unlikely((b == nullptr) || (key == nullptr))) {
        return false;
    }
    auto const klen = __builtin_strlen(key);
    return bencode_write_str_raw(b, key, klen) && bencode_write_str_raw(b, val.data, val.length);
}

bool bencode_write_kv_int(
    bencode_buf_t *restrict const b,
    char const *const key,
    int64_t const     val) {
    if (unlikely((b == nullptr) || (key == nullptr))) {
        return false;
    }
    auto const klen = __builtin_strlen(key);
    return bencode_write_str_raw(b, key, klen) && bencode_write_int_raw(b, val);
}

[[nodiscard]] bool
bencode_parse_element(sv_t *restrict const cursor, bencode_val_t *restrict const out) {
    if (unlikely(
            (cursor == nullptr) || (cursor->data == nullptr) || (cursor->length == 0) ||
            (out == nullptr)))
    {
        return false;
    }

    char const *const ptr = cursor->data;
    size_t const      len = cursor->length;
    char const        c   = ptr[0];

    // String: <len>:<contents>
    if ((c >= '0') && (c <= '9')) {
        size_t str_len = 0;
        size_t i       = 0;

        if ((c == '0') && (len > 1) && (ptr[1] != ':')) {
            return false; // Leading zeros forbidden
        }

        while ((i < len) && (ptr[i] >= '0') && (ptr[i] <= '9')) {
            auto const digit = (size_t)(ptr[i] - '0');
            str_len          = (str_len * 10) + digit;
            i++;
        }

        if ((i >= len) || (ptr[i] != ':')) {
            return false;
        }

        size_t const prefix_len = i + 1; // digits + ':'
        if ((len - prefix_len) < str_len) {
            return false; // Truncated payload
        }

        size_t const total_len = prefix_len + str_len;
        *out                   = (bencode_val_t){
                              .type    = BENCODE_TYPE_STR,
                              .str     = SV_INIT(ptr + prefix_len, str_len),
                              .integer = 0,
                              .raw     = SV_INIT(ptr, total_len),
        };

        cursor->data += total_len;
        cursor->length -= total_len;
        return true;
    }

    // Integer: i<digits>e
    if (c == 'i') {
        if (len < 3) {
            return false;
        }
        size_t     i      = 1;
        bool const is_neg = (ptr[1] == '-');
        if (is_neg) {
            i++;
            if ((i >= len) || (ptr[i] < '1') || (ptr[i] > '9')) {
                return false; // "-0" or non-digit after '-' forbidden
            }
        } else if ((ptr[1] == '0') && (ptr[2] != 'e')) {
            return false; // Leading zeros forbidden for positive
        }

        int64_t val = 0;
        while ((i < len) && (ptr[i] >= '0') && (ptr[i] <= '9')) {
            auto const digit = (int64_t)(ptr[i] - '0');
            val              = (val * 10) + digit;
            i++;
        }

        if ((i >= len) || (ptr[i] != 'e')) {
            return false;
        }

        if (is_neg) {
            val = -val;
        }

        size_t const total_len = i + 1;
        *out                   = (bencode_val_t){
                              .type    = BENCODE_TYPE_INT,
                              .str     = SV_EMPTY,
                              .integer = val,
                              .raw     = SV_INIT(ptr, total_len),
        };

        cursor->data += total_len;
        cursor->length -= total_len;
        return true;
    }

    // List: l<items>e
    if (c == 'l') {
        sv_t sub = SV_INIT(ptr + 1, len - 1);
        while ((sub.length > 0) && (sub.data[0] != 'e')) {
            bencode_val_t elem = {};
            if (!bencode_parse_element(&sub, &elem)) {
                return false;
            }
        }
        if ((sub.length == 0) || (sub.data[0] != 'e')) {
            return false;
        }

        size_t const inner_len = (size_t)(sub.data - (ptr + 1));
        size_t const total_len = inner_len + 2; // 'l' + inner + 'e'

        *out = (bencode_val_t){
            .type    = BENCODE_TYPE_LIST,
            .str     = SV_INIT(ptr + 1, inner_len),
            .integer = 0,
            .raw     = SV_INIT(ptr, total_len),
        };

        cursor->data += total_len;
        cursor->length -= total_len;
        return true;
    }

    // Dictionary: d<k1><v1>...e
    if (c == 'd') {
        sv_t sub = SV_INIT(ptr + 1, len - 1);
        while ((sub.length > 0) && (sub.data[0] != 'e')) {
            bencode_val_t k = {};
            if (!bencode_parse_element(&sub, &k) || (k.type != BENCODE_TYPE_STR)) {
                return false; // Keys must be strings
            }
            bencode_val_t v = {};
            if (!bencode_parse_element(&sub, &v)) {
                return false;
            }
        }
        if ((sub.length == 0) || (sub.data[0] != 'e')) {
            return false;
        }

        size_t const inner_len = (size_t)(sub.data - (ptr + 1));
        size_t const total_len = inner_len + 2; // 'd' + inner + 'e'

        *out = (bencode_val_t){
            .type    = BENCODE_TYPE_DICT,
            .str     = SV_INIT(ptr + 1, inner_len),
            .integer = 0,
            .raw     = SV_INIT(ptr, total_len),
        };

        cursor->data += total_len;
        cursor->length -= total_len;
        return true;
    }

    return false;
}

bool bencode_dict_find(sv_t const dict, sv_t const key, bencode_val_t *restrict const out) {
    if (unlikely((dict.data == nullptr) || (dict.length < 2) || (out == nullptr))) {
        return false;
    }
    if ((dict.data[0] != 'd') || (dict.data[dict.length - 1] != 'e')) {
        return false;
    }

    sv_t cur = SV_INIT(dict.data + 1, dict.length - 2);
    while ((cur.length > 0) && (cur.data[0] != 'e')) {
        bencode_val_t k = {};
        if (!bencode_parse_element(&cur, &k) || (k.type != BENCODE_TYPE_STR)) {
            return false;
        }
        bencode_val_t v = {};
        if (!bencode_parse_element(&cur, &v)) {
            return false;
        }
        if (sv_equals(k.str, key)) {
            *out = v;
            return true;
        }
    }
    return false;
}

bool bencode_dict_get_str(sv_t const dict, sv_t const key, sv_t *restrict const out) {
    if (unlikely(out == nullptr)) {
        return false;
    }
    bencode_val_t val = {};
    if (bencode_dict_find(dict, key, &val) && (val.type == BENCODE_TYPE_STR)) {
        *out = val.str;
        return true;
    }
    return false;
}

bool bencode_dict_get_int(sv_t const dict, sv_t const key, int64_t *restrict const out) {
    if (unlikely(out == nullptr)) {
        return false;
    }
    bencode_val_t val = {};
    if (bencode_dict_find(dict, key, &val) && (val.type == BENCODE_TYPE_INT)) {
        *out = val.integer;
        return true;
    }
    return false;
}

bool bencode_list_contains_str(sv_t const list, sv_t const target) {
    if (unlikely((list.data == nullptr) || (list.length < 2))) {
        return false;
    }
    if ((list.data[0] != 'l') || (list.data[list.length - 1] != 'e')) {
        return false;
    }

    sv_t cur = SV_INIT(list.data + 1, list.length - 2);
    while ((cur.length > 0) && (cur.data[0] != 'e')) {
        bencode_val_t elem = {};
        if (!bencode_parse_element(&cur, &elem)) {
            return false;
        }
        if ((elem.type == BENCODE_TYPE_STR) && sv_equals(elem.str, target)) {
            return true;
        }
    }
    return false;
}
