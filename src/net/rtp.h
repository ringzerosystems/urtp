#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "core/macros.h"

/**
 * @file rtp.h
 * @brief Zero-overhead RFC 3550 RTP/RTCP packet parsing, header manipulation, and classification.
 */

/** @brief Minimum size in bytes of a standard RFC 3550 RTP fixed header. */
constexpr size_t RTP_HEADER_MIN_SIZE = 12;
/** @brief Minimum size in bytes of a standard RFC 3550 RTCP header. */
constexpr size_t RTCP_HEADER_MIN_SIZE = 8;
/** @brief Standard RTP and RTCP protocol version (2). */
constexpr uint8_t RTP_VERSION_2 = 2;

// Standard RTCP packet types per RFC 3550, RFC 4585, RFC 3611
/** @brief RTCP Sender Report packet type (200). */
constexpr uint8_t RTCP_PT_SR = 200; // Sender Report
/** @brief RTCP Receiver Report packet type (201). */
constexpr uint8_t RTCP_PT_RR = 201; // Receiver Report
/** @brief RTCP Source Description packet type (202). */
constexpr uint8_t RTCP_PT_SDES = 202; // Source Description
/** @brief RTCP Goodbye packet type (203). */
constexpr uint8_t RTCP_PT_BYE = 203; // Goodbye
/** @brief RTCP Application-defined packet type (204). */
constexpr uint8_t RTCP_PT_APP = 204; // Application-defined
/** @brief RTCP Transport-layer feedback packet type (205, e.g. NACK). */
constexpr uint8_t RTCP_PT_RTPFB = 205; // Transport-layer feedback (e.g. NACK)
/** @brief RTCP Payload-specific feedback packet type (206, e.g. PLI). */
constexpr uint8_t RTCP_PT_PSFB = 206; // Payload-specific feedback (e.g. PLI)
/** @brief RTCP Extended Report packet type (207). */
constexpr uint8_t RTCP_PT_XR = 207; // Extended Report
/** @brief RTCP Audio-video bridging packet type (208). */
constexpr uint8_t RTCP_PT_AVB = 208; // Audio-video bridging RTCP

// RFC 5761 Section 4 reserved range for RTCP packet types when multiplexing
/** @brief Minimum packet type byte reserved for RTCP when multiplexing (200). */
constexpr uint8_t RTCP_PT_MIN = 200;
/** @brief Maximum packet type byte reserved for RTCP when multiplexing (223). */
constexpr uint8_t RTCP_PT_MAX = 223;

/**
 * @brief Classified transport payload types.
 */
typedef enum : uint8_t {
    PACKET_TYPE_UNKNOWN = 0, /**< Unrecognized packet format. */
    PACKET_TYPE_RTP     = 1, /**< RFC 3550 RTP media packet. */
    PACKET_TYPE_RTCP    = 2, /**< RFC 3550 RTCP control packet. */
    PACKET_TYPE_STUN    = 3, /**< RFC 5389 / RFC 8445 STUN packet. */
    PACKET_TYPE_DTLS    = 4, /**< RFC 7983 DTLS record. */
} packet_type_t;

/**
 * @brief Fixed RTP header structure according to RFC 3550 Section 5.1.
 */
typedef struct {
    uint8_t  v_p_x_cc;  /**< Version (2), Padding (1), Extension (1), CSRC count (4). */
    uint8_t  m_pt;      /**< Marker bit (1), Payload type (7). */
    uint16_t seq;       /**< Sequence number (network byte order). */
    uint32_t timestamp; /**< Timestamp (network byte order). */
    uint32_t ssrc;      /**< SSRC identifier (network byte order). */
} rtp_header_t;

static_assert(sizeof(rtp_header_t) == 12, "rtp_header_t must be exactly 12 bytes");

/**
 * @brief Fixed RTCP common header structure according to RFC 3550 Section 6.1.
 */
typedef struct {
    uint8_t  v_p_rc; /**< Version (2), Padding (1), Reception report count / subtype (5). */
    uint8_t  pt;     /**< Packet type (8) [200-223]. */
    uint16_t length; /**< Length in 32-bit words minus one (network byte order). */
    uint32_t ssrc;   /**< SSRC of sender (network byte order). */
} rtcp_header_t;

static_assert(sizeof(rtcp_header_t) == 8, "rtcp_header_t must be exactly 8 bytes");

/**
 * @brief RTCP Picture Loss Indication (PLI) packet structure per RFC 4585 Section 6.3.1.
 */
typedef struct {
    rtcp_header_t hdr;   /**< Standard RTCP common header with PT=PSFB and FMT=1. */
    uint32_t media_ssrc; /**< SSRC of sender whose keyframe is requested (network byte order). */
} rtcp_pli_packet_t;

static_assert(sizeof(rtcp_pli_packet_t) == 12, "RTCP PLI packet must be exactly 12 bytes");

/**
 * @brief Synthesizes an RTCP Picture Loss Indication (PLI) packet.
 *
 * @param sender_ssrc SSRC of the feedback sender.
 * @param media_ssrc SSRC of the video source whose keyframe is requested.
 * @param out_pkt Pointer to output rtcp_pli_packet_t buffer.
 * @return Size of the packet in bytes (12), or 0 on error.
 */
[[nodiscard]] static inline size_t rtcp_build_pli(
    uint32_t const sender_ssrc,
    uint32_t const media_ssrc,
    rtcp_pli_packet_t *restrict const out_pkt) {
    if (unlikely(out_pkt == nullptr)) {
        return 0;
    }

    *out_pkt = (rtcp_pli_packet_t){
        .hdr =
            {
                .v_p_rc = (RTP_VERSION_2 << 6) | (1 & 0x1F), // V=2, P=0, FMT=1 (PLI)
                .pt     = RTCP_PT_PSFB,                      // PT=206 (Payload-Specific Feedback)
                .length = htons(2),                          // (12 / 4) - 1 = 2 words
                .ssrc   = htonl(sender_ssrc),
            },
        .media_ssrc = htonl(media_ssrc),
    };

    return sizeof(rtcp_pli_packet_t);
}

/**
 * @brief Extracts the RTP version from an RTP packet header.
 *
 * @param hdr Pointer to RTP header.
 * @return RTP version (0-3).
 */
[[nodiscard]] static inline uint8_t rtp_get_version(rtp_header_t const *restrict const hdr) {
    if (unlikely(hdr == nullptr)) {
        return 0;
    }
    return (uint8_t)((hdr->v_p_x_cc >> 6) & 0x03);
}

/**
 * @brief Extracts the RTP payload type from an RTP packet header.
 *
 * @param hdr Pointer to RTP header.
 * @return Payload type (0-127).
 */
[[nodiscard]] static inline uint8_t rtp_get_payload_type(rtp_header_t const *restrict const hdr) {
    if (unlikely(hdr == nullptr)) {
        return 0;
    }
    return (uint8_t)(hdr->m_pt & 0x7F);
}

/**
 * @brief Extracts the RTCP version from an RTCP packet header.
 *
 * @param hdr Pointer to RTCP header.
 * @return RTCP version (0-3).
 */
[[nodiscard]] static inline uint8_t rtcp_get_version(rtcp_header_t const *restrict const hdr) {
    if (unlikely(hdr == nullptr)) {
        return 0;
    }
    return (uint8_t)((hdr->v_p_rc >> 6) & 0x03);
}

/**
 * @brief Extracts the RTCP packet type from an RTCP packet header.
 *
 * @param hdr Pointer to RTCP header.
 * @return Packet type (0-255).
 */
[[nodiscard]] static inline uint8_t rtcp_get_packet_type(rtcp_header_t const *restrict const hdr) {
    if (unlikely(hdr == nullptr)) {
        return 0;
    }
    return hdr->pt;
}

/**
 * @brief Calculates the length in bytes of the RTCP packet from its header.
 *
 * @param hdr Pointer to RTCP header.
 * @return Total length in bytes of the RTCP packet (including header).
 */
[[nodiscard]] static inline size_t rtcp_get_length_bytes(rtcp_header_t const *restrict const hdr) {
    if (unlikely(hdr == nullptr)) {
        return 0;
    }
    return ((size_t)ntohs(hdr->length) + 1) * 4;
}

/**
 * @brief Validates whether a buffer contains a well-formed RFC 3550 RTCP packet.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is at least 8 bytes, has version 2, and valid packet type in range.
 */
[[nodiscard]] static inline bool
rtcp_is_valid_packet(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len < RTCP_HEADER_MIN_SIZE))) {
        return false;
    }
    auto const hdr = (rtcp_header_t const *)data;
    if (unlikely(rtcp_get_version(hdr) != RTP_VERSION_2)) {
        return false;
    }
    if (unlikely((hdr->pt < RTCP_PT_MIN) || (hdr->pt > RTCP_PT_MAX))) {
        return false;
    }
    size_t const expected_len = rtcp_get_length_bytes(hdr);
    return (len >= expected_len);
}

/**
 * @brief Validates whether a buffer contains a well-formed RFC 3550 RTP packet.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is at least 12 bytes and has RTP version 2.
 */
[[nodiscard]] static inline bool
rtp_is_valid_packet(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len < RTP_HEADER_MIN_SIZE))) {
        return false;
    }
    auto const hdr = (rtp_header_t const *)data;
    return (rtp_get_version(hdr) == RTP_VERSION_2);
}

/**
 * @brief Classifies an incoming UDP payload as RTP, RTCP, or unknown per RFC 5761 Section 4.
 *
 * When multiplexing RTP and RTCP on the same port:
 * - Version must be 2.
 * - If the second byte (PT) is in [200, 223], it is RTCP.
 * - Otherwise, if size >= 12 and version is 2, it is RTP.
 *
 * @param data Pointer to received packet buffer.
 * @param len Length in bytes of the packet.
 * @return PACKET_TYPE_RTP, PACKET_TYPE_RTCP, or PACKET_TYPE_UNKNOWN.
 */
[[nodiscard]] static inline packet_type_t
rtp_classify_packet(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len < 4))) {
        return PACKET_TYPE_UNKNOWN;
    }

    auto const    bytes = (uint8_t const *)data;
    uint8_t const b0    = bytes[0];

    // RFC 7983 / RFC 5389: STUN (first two bits 00, magic cookie 0x2112A442 at offset 4)
    if ((b0 & 0xC0) == 0) {
        if (len >= 20) {
            uint32_t cookie = 0;
            __builtin_memcpy(&cookie, bytes + 4, sizeof(cookie));
            if (ntohl(cookie) == 0x2112A442) {
                return PACKET_TYPE_STUN;
            }
        }
        return PACKET_TYPE_UNKNOWN;
    }

    // RFC 7983 / RFC 5764: DTLS (first byte in [20, 63])
    if ((b0 >= 20) && (b0 <= 63)) {
        if (len >= 13) {
            return PACKET_TYPE_DTLS;
        }
        return PACKET_TYPE_UNKNOWN;
    }

    // RFC 3550 / RFC 5761: RTP / RTCP (first byte has version 2, b0 >> 6 == 2)
    if (likely(((b0 >> 6) & 0x03) == RTP_VERSION_2)) {
        if (unlikely(len < RTCP_HEADER_MIN_SIZE)) {
            return PACKET_TYPE_UNKNOWN;
        }

        uint8_t const pt_byte = bytes[1];
        if ((pt_byte >= RTCP_PT_MIN) && (pt_byte <= RTCP_PT_MAX)) {
            if (likely(rtcp_is_valid_packet(data, len))) {
                return PACKET_TYPE_RTCP;
            }
            return PACKET_TYPE_UNKNOWN;
        }

        if (likely(len >= RTP_HEADER_MIN_SIZE)) {
            return PACKET_TYPE_RTP;
        }
    }

    return PACKET_TYPE_UNKNOWN;
}

/**
 * @brief Checks whether a packet is an RTCP packet according to RFC 5761.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is RTCP, false otherwise.
 */
[[nodiscard]] static inline bool
rtp_is_rtcp_packet(void const *restrict const data, size_t const len) {
    return (rtp_classify_packet(data, len) == PACKET_TYPE_RTCP);
}

/**
 * @brief Checks whether a packet is an RTP data packet according to RFC 5761.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is RTP, false otherwise.
 */
[[nodiscard]] static inline bool
rtp_is_rtp_packet(void const *restrict const data, size_t const len) {
    return (rtp_classify_packet(data, len) == PACKET_TYPE_RTP);
}

/**
 * @brief Checks whether a packet is a STUN packet according to RFC 7983 / RFC 5389.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is STUN, false otherwise.
 */
[[nodiscard]] static inline bool
rtp_is_stun_packet(void const *restrict const data, size_t const len) {
    return (rtp_classify_packet(data, len) == PACKET_TYPE_STUN);
}

/**
 * @brief Checks whether a packet is a DTLS record according to RFC 7983.
 *
 * @param data Pointer to received packet data.
 * @param len Length in bytes of the packet.
 * @return true if packet is DTLS, false otherwise.
 */
[[nodiscard]] static inline bool
rtp_is_dtls_packet(void const *restrict const data, size_t const len) {
    return (rtp_classify_packet(data, len) == PACKET_TYPE_DTLS);
}
