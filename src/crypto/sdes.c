#include "crypto/sdes.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>
#include "core/macros.h"

bool sdes_parse_crypto_attr(
    char const *const line,
    size_t const      len,
    sdes_crypto_attr_t *restrict const out) {
    if (unlikely((line == nullptr) || (len < 10) || (out == nullptr))) {
        return false;
    }

    *out = (sdes_crypto_attr_t){};

    size_t i = 0;
    while ((i < len) && ((line[i] == ' ') || (line[i] == '\t'))) {
        i++;
    }

    // Skip optional "a="
    if (((i + 2) <= len) && (line[i] == 'a') && (line[i + 1] == '=')) {
        i += 2;
    }

    // Must start with "crypto:"
    if (((i + 7) > len) || (__builtin_memcmp(&line[i], "crypto:", 7) != 0)) {
        return false;
    }
    i += 7;

    while ((i < len) && ((line[i] == ' ') || (line[i] == '\t'))) {
        i++;
    }

    // Parse tag (1 to 9 digits)
    size_t const tag_start = i;
    while ((i < len) && (line[i] >= '0') && (line[i] <= '9')) {
        i++;
    }
    if (i == tag_start) {
        return false;
    }

    uint32_t tag = 0;
    for (size_t t = tag_start; t < i; ++t) {
        tag = (tag * 10) + (uint32_t)(line[t] - '0');
    }
    out->tag = tag;

    while ((i < len) && ((line[i] == ' ') || (line[i] == '\t'))) {
        i++;
    }

    // Parse suite
    size_t const suite_start = i;
    while ((i < len) && (line[i] != ' ') && (line[i] != '\t') && (line[i] != '\r') &&
           (line[i] != '\n'))
    {
        i++;
    }
    size_t const suite_len = i - suite_start;
    if (suite_len == 0) {
        return false;
    }

    auto const suite = srtp_crypto_suite_from_string(&line[suite_start], suite_len);
    if (suite == SRTP_CRYPTO_SUITE_NONE) {
        return false;
    }
    out->suite = suite;

    auto const copylen =
        (suite_len < sizeof(out->suite_str) - 1) ? suite_len : sizeof(out->suite_str) - 1;
    __builtin_memcpy(out->suite_str, &line[suite_start], copylen);
    out->suite_str[copylen] = '\0';

    while ((i < len) && ((line[i] == ' ') || (line[i] == '\t'))) {
        i++;
    }

    // Parse key-params: must start with "inline:"
    if (((i + 7) > len) || (__builtin_memcmp(&line[i], "inline:", 7) != 0)) {
        return false;
    }
    i += 7;

    size_t const key_start = i;
    while ((i < len) && (line[i] != '|') && (line[i] != ';') && (line[i] != ' ') &&
           (line[i] != '\t') && (line[i] != '\r') && (line[i] != '\n'))
    {
        i++;
    }
    size_t const key_len = i - key_start;
    if ((key_len == 0) || (key_len >= sizeof(out->b64_key))) {
        return false;
    }

    __builtin_memcpy(out->b64_key, &line[key_start], key_len);
    out->b64_key[key_len] = '\0';

    // Decode Base64 key to binary
    size_t decoded_len = 0;
    if (!base64_decode(
            out->b64_key,
            key_len,
            out->master_key,
            sizeof(out->master_key),
            &decoded_len))
    {
        return false;
    }

    size_t const expected_len = srtp_crypto_suite_total_key_len(suite);
    if (decoded_len != expected_len) {
        return false;
    }

    out->master_key_len = decoded_len;
    return true;
}

bool sdes_format_crypto_attr(
    uint32_t const            tag,
    srtp_crypto_suite_t const suite,
    char const *const         b64_key,
    char *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely((b64_key == nullptr) || (out_buf == nullptr) || (out_cap == 0))) {
        return false;
    }

    char const *const suite_name = srtp_crypto_suite_to_string(suite);
    if (suite == SRTP_CRYPTO_SUITE_NONE) {
        return false;
    }

    int const written =
        snprintf(out_buf, out_cap, "a=crypto:%u %s inline:%s\r\n", tag, suite_name, b64_key);
    if ((written <= 0) || ((size_t)written >= out_cap)) {
        return false;
    }

    if (out_len != nullptr) {
        *out_len = (size_t)written;
    }
    return true;
}

bool sdes_generate_key(
    srtp_crypto_suite_t const suite,
    uint8_t *restrict const out_bin,
    size_t const bin_cap,
    size_t *restrict const out_bin_len,
    char *restrict const out_b64,
    size_t const b64_cap,
    size_t *restrict const out_b64_len) {
    if (unlikely(
            (out_bin == nullptr) || (out_bin_len == nullptr) || (out_b64 == nullptr) ||
            (out_b64_len == nullptr)))
    {
        return false;
    }

    size_t const needed_len = srtp_crypto_suite_total_key_len(suite);
    if (unlikely((needed_len == 0) || (bin_cap < needed_len))) {
        return false;
    }

    // Fill buffer using Linux getrandom(2)
    ssize_t const ret = getrandom(out_bin, needed_len, 0);
    if (ret != (ssize_t)needed_len) {
        // Fallback to /dev/urandom if getrandom was interrupted or unavailable
        int const fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return false;
        }
        ssize_t const r = read(fd, out_bin, needed_len);
        close(fd);
        if (r != (ssize_t)needed_len) {
            return false;
        }
    }

    *out_bin_len = needed_len;

    // Encode to Base64
    size_t b64_written = 0;
    if (!base64_encode(out_bin, needed_len, out_b64, b64_cap, &b64_written)) {
        return false;
    }

    *out_b64_len = b64_written;
    return true;
}
