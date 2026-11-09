#include "crypto/dtls.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static SSL_CTX    *s_dtls_ctx                              = nullptr;
static char        s_fingerprint[DTLS_FINGERPRINT_STR_LEN] = {};
static atomic_bool s_dtls_initialized                      = false;

static int dtls_verify_callback(int const ok, X509_STORE_CTX *const ctx) {
    (void)ok;
    (void)ctx;
    // Self-signed certificates in WebRTC are verified by fingerprint matching in SDP
    return 1;
}

bool urtp_dtls_global_init(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&s_dtls_initialized, &expected, true)) {
        return true;
    }

    auto const method = DTLS_method();
    if (unlikely(method == nullptr)) {
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    s_dtls_ctx = SSL_CTX_new(method);
    if (unlikely(s_dtls_ctx == nullptr)) {
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    (void)SSL_CTX_set_min_proto_version(s_dtls_ctx, DTLS1_2_VERSION);
    SSL_CTX_set_read_ahead(s_dtls_ctx, 1);

    // Generate EC P-256 key pair for WebRTC DTLS
    EVP_PKEY *const pkey = EVP_EC_gen("prime256v1");
    if (unlikely(pkey == nullptr)) {
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    // Generate self-signed X.509 certificate
    X509 *const x509 = X509_new();
    if (unlikely(x509 == nullptr)) {
        EVP_PKEY_free(pkey);
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    (void)ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    (void)X509_gmtime_adj(X509_getm_notBefore(x509), -3600);
    (void)X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L); // 1 year validity
    (void)X509_set_pubkey(x509, pkey);

    X509_NAME *const name = X509_get_subject_name(x509);
    (void)X509_NAME_add_entry_by_txt(
        name,
        "CN",
        MBSTRING_ASC,
        (unsigned char const *)"urtp",
        -1,
        -1,
        0);
    (void)X509_set_issuer_name(x509, name);
    (void)X509_sign(x509, pkey, EVP_sha256());

    if (SSL_CTX_use_certificate(s_dtls_ctx, x509) != 1) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    if (SSL_CTX_use_PrivateKey(s_dtls_ctx, pkey) != 1) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    if (SSL_CTX_check_private_key(s_dtls_ctx) != 1) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    // Compute SHA-256 fingerprint for SDP
    unsigned char md[EVP_MAX_MD_SIZE] = {};
    unsigned int  md_len              = 0;
    if (X509_digest(x509, EVP_sha256(), md, &md_len) == 1) {
        size_t off = 0;
        for (unsigned int i = 0; i < md_len; ++i) {
            int const n = snprintf(
                s_fingerprint + off,
                sizeof(s_fingerprint) - off,
                (i == (md_len - 1)) ? "%02X" : "%02X:",
                md[i]);
            if (n > 0) {
                off += (size_t)n;
            }
        }
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    // Configure RFC 5764 SRTP protection profiles
    static char const *const srtp_profiles =
        "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM:SRTP_AES128_CM_SHA1_32";
    if (SSL_CTX_set_tlsext_use_srtp(s_dtls_ctx, srtp_profiles) != 0) {
        SSL_CTX_free(s_dtls_ctx);
        s_dtls_ctx = nullptr;
        atomic_store(&s_dtls_initialized, false);
        return false;
    }

    SSL_CTX_set_verify(
        s_dtls_ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        dtls_verify_callback);

    return true;
}

void urtp_dtls_global_cleanup(void) {
    bool expected = true;
    if (atomic_compare_exchange_strong(&s_dtls_initialized, &expected, false)) {
        if (s_dtls_ctx != nullptr) {
            SSL_CTX_free(s_dtls_ctx);
            s_dtls_ctx = nullptr;
        }
        s_fingerprint[0] = '\0';
    }
}

char const *urtp_dtls_get_fingerprint(void) { return s_fingerprint; }

bool urtp_dtls_session_init(urtp_dtls_session_t *restrict const ds, dtls_role_t const role) {
    if (unlikely(ds == nullptr)) {
        return false;
    }

    if (!urtp_dtls_global_init()) {
        return false;
    }

    SSL *const ssl = SSL_new(s_dtls_ctx);
    if (unlikely(ssl == nullptr)) {
        return false;
    }

    BIO *const in_bio  = BIO_new(BIO_s_mem());
    BIO *const out_bio = BIO_new(BIO_s_mem());
    if (unlikely((in_bio == nullptr) || (out_bio == nullptr))) {
        if (in_bio != nullptr) {
            BIO_free(in_bio);
        }
        if (out_bio != nullptr) {
            BIO_free(out_bio);
        }
        SSL_free(ssl);
        return false;
    }

    (void)BIO_set_mem_eof_return(in_bio, -1);
    (void)BIO_set_mem_eof_return(out_bio, -1);
    SSL_set_bio(ssl, in_bio, out_bio);

    SSL_set_mtu(ssl, 1200);
    (void)DTLS_set_link_mtu(ssl, 1200);

    if (role == DTLS_ROLE_SERVER) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }

    *ds = (urtp_dtls_session_t){
        .ssl         = ssl,
        .in_bio      = in_bio,
        .out_bio     = out_bio,
        .role        = role,
        .state       = DTLS_STATE_HANDSHAKE,
        .initialized = true,
    };
    return true;
}

void urtp_dtls_session_destroy(urtp_dtls_session_t *restrict const ds) {
    if (unlikely(ds == nullptr)) {
        return;
    }
    if (ds->initialized && (ds->ssl != nullptr)) {
        SSL_free(ds->ssl); // Also frees in_bio and out_bio
    }
    *ds = (urtp_dtls_session_t){};
}

bool urtp_dtls_feed_packet(
    urtp_dtls_session_t *restrict const ds,
    void const *restrict const data,
    size_t const len) {
    if (unlikely(
            (ds == nullptr) || !(ds->initialized) || (ds->in_bio == nullptr) || (data == nullptr)))
    {
        return false;
    }
    int const written = BIO_write(ds->in_bio, data, (int)len);
    return (written > 0) && ((size_t)written == len);
}

int urtp_dtls_step(urtp_dtls_session_t *restrict const ds) {
    if (unlikely((ds == nullptr) || !(ds->initialized) || (ds->ssl == nullptr))) {
        return -1;
    }

    if (ds->state == DTLS_STATE_CONNECTED) {
        return 1;
    }

    int const ret = SSL_do_handshake(ds->ssl);
    if (SSL_is_init_finished(ds->ssl)) {
        ds->state = DTLS_STATE_CONNECTED;
        return 1;
    }

    int const err = SSL_get_error(ds->ssl, ret);
    if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE)) {
        return 0;
    }

    ds->state = DTLS_STATE_FAILED;
    return -1;
}

size_t urtp_dtls_get_pending_output(
    urtp_dtls_session_t *restrict const ds,
    void *restrict const out_buf,
    size_t const out_cap) {
    if (unlikely(
            (ds == nullptr) || !(ds->initialized) || (ds->out_bio == nullptr) ||
            (out_buf == nullptr)))
    {
        return 0;
    }

    size_t const pending = (size_t)BIO_ctrl_pending(ds->out_bio);
    if (pending == 0) {
        return 0;
    }

    int const n = BIO_read(ds->out_bio, out_buf, (int)out_cap);
    return (n > 0) ? (size_t)n : 0;
}

bool urtp_dtls_export_srtp_keys(
    urtp_dtls_session_t *restrict const ds,
    srtp_crypto_suite_t *restrict const suite,
    uint8_t *restrict const in_key_salt,
    size_t const in_cap,
    size_t *restrict const in_len,
    uint8_t *restrict const out_key_salt,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (ds == nullptr) || !(ds->initialized) || (ds->state != DTLS_STATE_CONNECTED) ||
            (suite == nullptr) || (in_key_salt == nullptr) || (out_key_salt == nullptr) ||
            (in_len == nullptr) || (out_len == nullptr)))
    {
        return false;
    }

    auto const profile = SSL_get_selected_srtp_profile(ds->ssl);
    if (unlikely(profile == nullptr)) {
        return false;
    }

    srtp_crypto_suite_t s = SRTP_CRYPTO_SUITE_NONE;
    switch (profile->id) {
    case 0x0001: // SRTP_AES128_CM_SHA1_80
        s = SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_80;
        break;
    case 0x0002: // SRTP_AES128_CM_SHA1_32
        s = SRTP_CRYPTO_SUITE_AES_CM_128_HMAC_SHA1_32;
        break;
    case 0x0007: // SRTP_AEAD_AES_128_GCM
        s = SRTP_CRYPTO_SUITE_AEAD_AES_128_GCM;
        break;
    case 0x0008: // SRTP_AEAD_AES_256_GCM
        s = SRTP_CRYPTO_SUITE_AEAD_AES_256_GCM;
        break;
    default:
        return false;
    }

    size_t const k_len     = srtp_crypto_suite_key_len(s);
    size_t const s_len     = srtp_crypto_suite_salt_len(s);
    size_t const total_len = (2 * k_len) + (2 * s_len);

    if (unlikely(((k_len + s_len) > in_cap) || ((k_len + s_len) > out_cap))) {
        return false;
    }

    uint8_t material[128] = {};
    if (SSL_export_keying_material(
            ds->ssl,
            material,
            total_len,
            "EXTRACTOR-dtls_srtp",
            19,
            nullptr,
            0,
            0) != 1)
    {
        return false;
    }

    // RFC 5764 Section 4.2 layout:
    // client_write_key  [k_len]
    // server_write_key  [k_len]
    // client_write_salt [s_len]
    // server_write_salt [s_len]
    uint8_t const *const client_key  = material;
    uint8_t const *const server_key  = material + k_len;
    uint8_t const *const client_salt = material + (2 * k_len);
    uint8_t const *const server_salt = material + (2 * k_len) + s_len;

    if (ds->role == DTLS_ROLE_SERVER) {
        // Proxy is server: inbound from client, outbound to client
        __builtin_memcpy(in_key_salt, client_key, k_len);
        __builtin_memcpy(in_key_salt + k_len, client_salt, s_len);
        *in_len = k_len + s_len;

        __builtin_memcpy(out_key_salt, server_key, k_len);
        __builtin_memcpy(out_key_salt + k_len, server_salt, s_len);
        *out_len = k_len + s_len;
    } else {
        // Proxy is client: inbound from server, outbound to server
        __builtin_memcpy(in_key_salt, server_key, k_len);
        __builtin_memcpy(in_key_salt + k_len, server_salt, s_len);
        *in_len = k_len + s_len;

        __builtin_memcpy(out_key_salt, client_key, k_len);
        __builtin_memcpy(out_key_salt + k_len, client_salt, s_len);
        *out_len = k_len + s_len;
    }

    *suite = s;
    return true;
}
