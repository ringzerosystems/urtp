#include "crypto/srtp_session.h"
#include <stdatomic.h>
#include <string.h>

static atomic_bool s_srtp_initialized = false;

bool urtp_srtp_global_init(void) {
    bool expected = false;
    if (atomic_compare_exchange_strong(&s_srtp_initialized, &expected, true)) {
        srtp_err_status_t const status = srtp_init();
        if (unlikely(status != srtp_err_status_ok)) {
            atomic_store(&s_srtp_initialized, false);
            return false;
        }
    }
    return true;
}

void urtp_srtp_global_cleanup(void) {
    bool expected = true;
    if (atomic_compare_exchange_strong(&s_srtp_initialized, &expected, false)) {
        (void)srtp_shutdown();
    }
}

char const *srtp_crypto_suite_to_string(srtp_crypto_suite_t const suite) {
    switch (suite) {
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80:
        return "AES_CM_128_HMAC_SHA1_80";
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32:
        return "AES_CM_128_HMAC_SHA1_32";
    case SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM:
        return "AEAD_AES_128_GCM";
    case SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM:
        return "AEAD_AES_256_GCM";
    case SRTP_CRYPTO_SUITE_NONE:
    default:
        return "UNKNOWN";
    }
}

srtp_crypto_suite_t srtp_crypto_suite_from_string(char const *const name, size_t const len) {
    if (unlikely((name == nullptr) || (len == 0))) {
        return SRTP_CRYPTO_SUITE_NONE;
    }

    if ((len == 23) && (__builtin_memcmp(name, "AES_CM_128_HMAC_SHA1_80", 23) == 0)) {
        return SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80;
    }
    if ((len == 23) && (__builtin_memcmp(name, "AES_CM_128_HMAC_SHA1_32", 23) == 0)) {
        return SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32;
    }
    if ((len == 16) && (__builtin_memcmp(name, "AEAD_AES_128_GCM", 16) == 0)) {
        return SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM;
    }
    if ((len == 16) && (__builtin_memcmp(name, "AEAD_AES_256_GCM", 16) == 0)) {
        return SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM;
    }

    return SRTP_CRYPTO_SUITE_NONE;
}

size_t srtp_crypto_suite_key_len(srtp_crypto_suite_t const suite) {
    switch (suite) {
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80:
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32:
    case SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM:
        return 16;
    case SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM:
        return 32;
    case SRTP_CRYPTO_SUITE_NONE:
    default:
        return 0;
    }
}

size_t srtp_crypto_suite_salt_len(srtp_crypto_suite_t const suite) {
    switch (suite) {
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80:
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32:
        return 14;
    case SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM:
    case SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM:
        return 12;
    case SRTP_CRYPTO_SUITE_NONE:
    default:
        return 0;
    }
}

size_t srtp_crypto_suite_tag_len(srtp_crypto_suite_t const suite) {
    switch (suite) {
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80:
        return 10;
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32:
        return 4;
    case SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM:
    case SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM:
        return 16;
    case SRTP_CRYPTO_SUITE_NONE:
    default:
        return 0;
    }
}

bool urtp_srtp_ctx_init(
    urtp_srtp_ctx_t *restrict const ctx,
    srtp_direction_t const    direction,
    srtp_crypto_suite_t const suite,
    uint8_t const *restrict const key_salt,
    size_t const key_salt_len) {
    if (unlikely((ctx == nullptr) || (key_salt == nullptr))) {
        return false;
    }

    if (!urtp_srtp_global_init()) {
        return false;
    }

    size_t const expected_len = srtp_crypto_suite_total_key_len(suite);
    if (unlikely((expected_len == 0) || (key_salt_len < expected_len))) {
        return false;
    }

    srtp_policy_t policy = {};
    policy.ssrc.type     = (direction == SRTP_DIR_INBOUND) ? ssrc_any_inbound : ssrc_any_outbound;
    policy.ssrc.value    = 0;

    switch (suite) {
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy.rtp));
        srtp_crypto_policy_set_rtcp_default(&(policy.rtcp));
        break;
    case SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy.rtp));
        srtp_crypto_policy_set_rtcp_default(&(policy.rtcp));
        break;
    case SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM:
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy.rtp));
        srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy.rtcp));
        break;
    case SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM:
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy.rtp));
        srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy.rtcp));
        break;
    case SRTP_CRYPTO_SUITE_NONE:
    default:
        return false;
    }

    // Cast away const for libsrtp policy interface; libsrtp copies the key internally into its
    // cipher context
    policy.key             = (unsigned char *)(uintptr_t)key_salt;
    policy.window_size     = 1024;
    policy.allow_repeat_tx = 1;
    policy.next            = nullptr;

    srtp_t                  session = nullptr;
    srtp_err_status_t const status  = srtp_create(&session, &policy);
    if (unlikely(status != srtp_err_status_ok)) {
        return false;
    }

    *ctx = (urtp_srtp_ctx_t){
        .session     = session,
        .suite       = suite,
        .direction   = direction,
        .initialized = true,
    };
    return true;
}

void urtp_srtp_ctx_destroy(urtp_srtp_ctx_t *restrict const ctx) {
    if (unlikely(ctx == nullptr)) {
        return;
    }
    if (ctx->initialized && (ctx->session != nullptr)) {
        (void)srtp_dealloc(ctx->session);
    }
    *ctx = (urtp_srtp_ctx_t){};
}

bool urtp_srtp_protect_rtp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t const max_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->initialized) || (pkt == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    size_t const tag_len = srtp_crypto_suite_tag_len(ctx->suite);
    if (unlikely((in_len + tag_len) > max_cap)) {
        return false;
    }

    int                     len    = (int)in_len;
    srtp_err_status_t const status = srtp_protect(ctx->session, pkt, &len);
    if (unlikely(status != srtp_err_status_ok)) {
        return false;
    }

    *out_len = (size_t)len;
    return true;
}

bool urtp_srtp_unprotect_rtp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->initialized) || (pkt == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    int                     len    = (int)in_len;
    srtp_err_status_t const status = srtp_unprotect(ctx->session, pkt, &len);
    if (unlikely(status != srtp_err_status_ok)) {
        return false;
    }

    *out_len = (size_t)len;
    return true;
}

bool urtp_srtp_protect_rtcp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t const max_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->initialized) || (pkt == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    // SRTCP appends 4 bytes index + auth tag
    size_t const tag_len = srtp_crypto_suite_tag_len(ctx->suite);
    if (unlikely((in_len + 4 + tag_len) > max_cap)) {
        return false;
    }

    int                     len    = (int)in_len;
    srtp_err_status_t const status = srtp_protect_rtcp(ctx->session, pkt, &len);
    if (unlikely(status != srtp_err_status_ok)) {
        return false;
    }

    *out_len = (size_t)len;
    return true;
}

bool urtp_srtp_unprotect_rtcp(
    urtp_srtp_ctx_t *restrict const ctx,
    void *restrict const pkt,
    size_t const in_len,
    size_t *restrict const out_len) {
    if (unlikely(
            (ctx == nullptr) || !(ctx->initialized) || (pkt == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    int                     len    = (int)in_len;
    srtp_err_status_t const status = srtp_unprotect_rtcp(ctx->session, pkt, &len);
    if (unlikely(status != srtp_err_status_ok)) {
        return false;
    }

    *out_len = (size_t)len;
    return true;
}
