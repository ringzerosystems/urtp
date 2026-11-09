#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "core/macros.h"

/**
 * @file stun.h
 * @brief Lightweight RFC 5389 / RFC 8445 STUN binding request parsing and response generation for
 * WebRTC ICE.
 */

/** @brief Fixed STUN message header size in bytes per RFC 5389 (20). */
constexpr uint16_t STUN_HEADER_SIZE = 20;
/** @brief Standard STUN magic cookie value per RFC 5389 (0x2112A442). */
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;
/** @brief STUN Binding Request message type code (0x0001). */
constexpr uint16_t STUN_MSG_BINDING_REQUEST = 0x0001;
/** @brief STUN Binding Response message type code (0x0101). */
constexpr uint16_t STUN_MSG_BINDING_RESPONSE = 0x0101;
/** @brief STUN Binding Error Response message type code (0x0111). */
constexpr uint16_t STUN_MSG_BINDING_ERROR_RESPONSE = 0x0111;
/** @brief STUN Binding Indication message type code (0x0011). */
constexpr uint16_t STUN_MSG_BINDING_INDICATION = 0x0011;

/** @brief STUN MAPPED-ADDRESS attribute type (0x0001). */
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
/** @brief STUN USERNAME attribute type (0x0006). */
constexpr uint16_t STUN_ATTR_USERNAME = 0x0006;
/** @brief STUN MESSAGE-INTEGRITY attribute type (0x0008). */
constexpr uint16_t STUN_ATTR_MESSAGE_INTEGRITY = 0x0008;
/** @brief STUN ERROR-CODE attribute type (0x0009). */
constexpr uint16_t STUN_ATTR_ERROR_CODE = 0x0009;
/** @brief STUN UNKNOWN-ATTRIBUTES attribute type (0x000A). */
constexpr uint16_t STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
/** @brief STUN XOR-MAPPED-ADDRESS attribute type (0x0020). */
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
/** @brief STUN PRIORITY attribute type (0x0024). */
constexpr uint16_t STUN_ATTR_PRIORITY = 0x0024;
/** @brief STUN USE-CANDIDATE attribute type (0x0025). */
constexpr uint16_t STUN_ATTR_USE_CANDIDATE = 0x0025;
/** @brief STUN FINGERPRINT attribute type (0x8028). */
constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;
/** @brief STUN ICE-CONTROLLED attribute type (0x8029). */
constexpr uint16_t STUN_ATTR_ICE_CONTROLLED = 0x8029;
/** @brief STUN ICE-CONTROLLING attribute type (0x802A). */
constexpr uint16_t STUN_ATTR_ICE_CONTROLLING = 0x802A;

/** @brief XOR mask applied to CRC-32 in STUN FINGERPRINT attribute. */
constexpr uint32_t STUN_FINGERPRINT_XOR = 0x5354554E;
/** @brief STUN transaction ID length in bytes (12). */
constexpr size_t STUN_TX_ID_LEN = 12;
/** @brief Maximum STUN username attribute length in bytes. */
constexpr size_t STUN_MAX_USERNAME_LEN = 128;

/**
 * @brief Fixed 20-byte STUN message header per RFC 5389 Section 6.
 */
typedef struct {
    uint16_t msg_type;     /**< Message type (network byte order). */
    uint16_t msg_len;      /**< Message length excluding 20-byte header (network byte order). */
    uint32_t magic_cookie; /**< Magic cookie 0x2112A442 (network byte order). */
    uint8_t  tx_id[STUN_TX_ID_LEN]; /**< 96-bit transaction identifier. */
} stun_header_t;

static_assert(sizeof(stun_header_t) == 20, "stun_header_t must be exactly 20 bytes");

/**
 * @brief STUN TLV attribute header per RFC 5389 Section 15.
 */
typedef struct {
    uint16_t type;   /**< Attribute type code (network byte order). */
    uint16_t length; /**< Attribute value length in bytes (network byte order). */
} stun_attr_header_t;

static_assert(sizeof(stun_attr_header_t) == 4, "stun_attr_header_t must be exactly 4 bytes");

/**
 * @brief Parsed attributes extracted from an incoming STUN Binding Request.
 */
typedef struct {
    uint8_t  tx_id[STUN_TX_ID_LEN];           /**< Extracted 12-byte transaction identifier. */
    char     username[STUN_MAX_USERNAME_LEN]; /**< USERNAME attribute string value. */
    uint32_t priority;                        /**< PRIORITY attribute integer value. */
    bool     has_username;                    /**< True if USERNAME attribute was present. */
    bool     has_priority;                    /**< True if PRIORITY attribute was present. */
    bool     has_use_candidate;               /**< True if USE-CANDIDATE attribute was present. */
    bool     has_message_integrity;           /**< True if MESSAGE-INTEGRITY was validated. */
    bool     has_fingerprint;                 /**< True if FINGERPRINT was validated. */
} stun_request_t;

/**
 * @brief Checks if a buffer contains a well-formed STUN Binding Request per RFC 5389.
 *
 * @param data Pointer to received datagram.
 * @param len Length in bytes of the datagram.
 * @return true if valid STUN Binding Request, false otherwise.
 */
[[nodiscard]] bool stun_is_binding_request(void const *restrict const data, size_t const len);

/**
 * @brief Parses attributes from a STUN Binding Request message.
 *
 * @param data Pointer to received datagram.
 * @param len Length in bytes of the datagram.
 * @param req Output parsed request info.
 * @return true if parsed successfully, false on malformed data.
 */
[[nodiscard]] bool stun_parse_request(
    void const *restrict const data,
    size_t const len,
    stun_request_t *restrict const req);

/**
 * @brief Constructs an RFC 5389 / RFC 8445 STUN Binding Success Response.
 *
 * @param tx_id Pointer to 12-byte transaction ID from the request.
 * @param src_addr Source address of the request (to encode into XOR-MAPPED-ADDRESS).
 * @param src_len Length of sockaddr structure.
 * @param ice_pwd Optional ICE password for computing MESSAGE-INTEGRITY (can be nullptr).
 * @param out_buf Destination buffer for the response.
 * @param out_cap Capacity in bytes of destination buffer.
 * @param out_len Output length in bytes of the constructed response.
 * @return true on success, false on buffer overflow or error.
 */
[[nodiscard]] bool stun_build_binding_response(
    uint8_t const *restrict const tx_id,
    struct sockaddr_storage const *restrict const src_addr,
    socklen_t const   src_len,
    char const *const ice_pwd,
    void *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len);

/**
 * @brief Computes standard IEEE 802.3 CRC-32 over data buffer.
 *
 * @param data Pointer to data buffer.
 * @param len Length in bytes of data buffer.
 * @return Computed CRC-32 value.
 */
[[nodiscard]] uint32_t stun_crc32(void const *restrict const data, size_t const len);
