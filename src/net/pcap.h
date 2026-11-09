#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "core/macros.h"
#include "core/string_view.h"
#include "ring/ring.h"

/**
 * @file pcap.h
 * @brief Zero-overhead asynchronous PCAP packet capture and forensic recording via io_uring.
 */

/** @brief Microsecond timestamp format PCAP magic number (0xa1b2c3d4). */
constexpr uint32_t PCAP_MAGIC_USEC = 0xa1b2c3d4;
/** @brief PCAP file major version number (2). */
constexpr uint16_t PCAP_VERSION_MAJOR = 2;
/** @brief PCAP file minor version number (4). */
constexpr uint16_t PCAP_VERSION_MINOR = 4;
/** @brief Maximum packet snapshot length in bytes for captures (65535). */
constexpr uint32_t PCAP_SNAPLEN = 65535;
/** @brief Standard Ethernet data link type code (1). */
constexpr uint32_t PCAP_LINKTYPE_ETHERNET = 1;

/** @brief Maximum number of concurrent active PCAP file recorders. */
constexpr size_t PCAP_MAX_RECORDERS = 64;
/** @brief Maximum number of in-flight asynchronous write contexts on io_uring. */
constexpr size_t PCAP_MAX_PENDING_WRITES = 64;
/** @brief Maximum file system path length for PCAP capture files. */
constexpr size_t PCAP_PATH_MAX = 256;
/** @brief Maximum Call-ID identifier length for indexed recording. */
constexpr size_t PCAP_ID_MAX = 128;
/** @brief Maximum payload copy buffer size in bytes for non-zero-copy captures. */
constexpr size_t PCAP_MAX_PAYLOAD_COPY = 2048;

/**
 * @brief Standard 24-byte PCAP file header per libpcap specification.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic_number;  /**< Magic number indicating endianness and timestamp resolution. */
    uint16_t version_major; /**< Major version number (2). */
    uint16_t version_minor; /**< Minor version number (4). */
    int32_t  thiszone;      /**< GMT to local correction in seconds. */
    uint32_t sigfigs;       /**< Accuracy of timestamps. */
    uint32_t snaplen;       /**< Max snapshot length per packet in bytes. */
    uint32_t network;       /**< Data link layer type (e.g. PCAP_LINKTYPE_ETHERNET). */
} pcap_file_hdr_t;

static_assert(sizeof(pcap_file_hdr_t) == 24, "pcap_file_hdr_t must be 24 bytes");

/**
 * @brief Standard 16-byte PCAP packet record header per libpcap specification.
 */
typedef struct __attribute__((packed)) {
    uint32_t ts_sec;   /**< Timestamp seconds since UNIX epoch. */
    uint32_t ts_usec;  /**< Timestamp microseconds. */
    uint32_t incl_len; /**< Number of bytes of packet captured in file. */
    uint32_t orig_len; /**< Actual length of packet off wire in bytes. */
} pcap_packet_hdr_t;

static_assert(sizeof(pcap_packet_hdr_t) == 16, "pcap_packet_hdr_t must be 16 bytes");

/**
 * @brief Synthesized 14-byte Ethernet header for synthetic PCAP frames.
 */
typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[6]; /**< Destination MAC address. */
    uint8_t  src_mac[6]; /**< Source MAC address. */
    uint16_t ethertype;  /**< EtherType protocol (IPv4 or IPv6 in network byte order). */
} pcap_eth_hdr_t;

static_assert(sizeof(pcap_eth_hdr_t) == 14, "pcap_eth_hdr_t must be 14 bytes");

/**
 * @brief Synthesized 20-byte IPv4 packet header for synthetic PCAP frames.
 */
typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;  /**< Version (4 bits) and Internet Header Length (4 bits). */
    uint8_t  tos;      /**< Type of Service / DSCP. */
    uint16_t tot_len;  /**< Total length of IP packet in bytes. */
    uint16_t id;       /**< Identification. */
    uint16_t frag_off; /**< Flags and fragment offset. */
    uint8_t  ttl;      /**< Time to live. */
    uint8_t  proto;    /**< Protocol (UDP = 17). */
    uint16_t check;    /**< Header checksum. */
    uint32_t saddr;    /**< Source IPv4 address in network byte order. */
    uint32_t daddr;    /**< Destination IPv4 address in network byte order. */
} pcap_ipv4_hdr_t;

static_assert(sizeof(pcap_ipv4_hdr_t) == 20, "pcap_ipv4_hdr_t must be 20 bytes");

/**
 * @brief Synthesized 40-byte IPv6 packet header for synthetic PCAP frames.
 */
typedef struct __attribute__((packed)) {
    uint32_t ver_tc_fl;   /**< Version, Traffic Class, and Flow Label. */
    uint16_t payload_len; /**< Length of payload following IPv6 header in bytes. */
    uint8_t  next_header; /**< Next header protocol (UDP = 17). */
    uint8_t  hop_limit;   /**< Hop limit. */
    uint8_t  saddr[16];   /**< Source IPv6 address. */
    uint8_t  daddr[16];   /**< Destination IPv6 address. */
} pcap_ipv6_hdr_t;

static_assert(sizeof(pcap_ipv6_hdr_t) == 40, "pcap_ipv6_hdr_t must be 40 bytes");

/**
 * @brief Synthesized 8-byte UDP packet header for synthetic PCAP frames.
 */
typedef struct __attribute__((packed)) {
    uint16_t source; /**< Source UDP port in network byte order. */
    uint16_t dest;   /**< Destination UDP port in network byte order. */
    uint16_t len;    /**< UDP length including header and payload in bytes. */
    uint16_t check;  /**< UDP checksum. */
} pcap_udp_hdr_t;

static_assert(sizeof(pcap_udp_hdr_t) == 8, "pcap_udp_hdr_t must be 8 bytes");

/**
 * @brief Composite encapsulation header for PCAP record, Ethernet, IP, and UDP headers.
 */
typedef struct __attribute__((packed)) {
    pcap_packet_hdr_t pcap_hdr; /**< PCAP per-packet record header. */
    pcap_eth_hdr_t    eth_hdr;  /**< Synthetic Ethernet header. */
    union {
        struct __attribute__((packed)) {
            pcap_ipv4_hdr_t ip4; /**< Synthetic IPv4 header. */
            pcap_udp_hdr_t  udp; /**< Synthetic UDP header. */
        } v4;                    /**< IPv4 UDP header block. */
        struct __attribute__((packed)) {
            pcap_ipv6_hdr_t ip6; /**< Synthetic IPv6 header. */
            pcap_udp_hdr_t  udp; /**< Synthetic UDP header. */
        } v6;                    /**< IPv6 UDP header block. */
    } net;                       /**< Network layer variant union. */
} pcap_frame_hdr_t;

/**
 * @brief Context structure for an in-flight asynchronous PCAP write on io_uring.
 */
typedef struct {
    alignas(64) struct iovec iov[2]; /**< Scatter-gather vector: [0]=frame header, [1]=payload. */
    pcap_frame_hdr_t hdr;            /**< Synthesized frame header. */
    uint8_t payload_copy[PCAP_MAX_PAYLOAD_COPY]; /**< Local copy of payload when zero-copy is
                                                    disabled. */
    uint16_t bid;          /**< Provided buffer ID retained for zero-copy write. */
    uint16_t recorder_idx; /**< Index of target recorder. */
    bool     in_use;       /**< True if write context slot is actively queued. */
    bool     bid_retained; /**< True if buffer ID was retained for zero-copy. */
} pcap_write_ctx_t;

/**
 * @brief Active PCAP file recorder state for an individual media call or session port.
 */
typedef struct {
    alignas(64) int fd;                /**< Open file descriptor for the PCAP capture file. */
    char     call_id[PCAP_ID_MAX];     /**< Call-ID string associated with this recording. */
    char     file_path[PCAP_PATH_MAX]; /**< Full filesystem path to the PCAP file. */
    uint64_t file_offset;              /**< Current write offset in bytes within the file. */
    uint64_t packets_recorded;         /**< Total number of packets written to this file. */
    uint64_t bytes_recorded;           /**< Total payload and header bytes written. */
    uint16_t session_port_a;           /**< First session port (e.g. caller). */
    uint16_t session_port_b;           /**< Second session port (e.g. callee). */
    bool     active;                   /**< True if recorder slot is active. */
} pcap_recorder_t;

/**
 * @brief Global PCAP capture manager with recorder table and write context pool.
 */
typedef struct {
    alignas(64)
        pcap_recorder_t recorders[PCAP_MAX_RECORDERS]; /**< Array of active call recorders. */
    pcap_write_ctx_t
        write_ctxs[PCAP_MAX_PENDING_WRITES]; /**< Pool of pre-allocated io_uring write contexts. */
    size_t   active_recorders;               /**< Current count of active recorders. */
    char     record_dir[PCAP_PATH_MAX];      /**< Destination directory for capture files. */
    bool     enabled;                        /**< True if PCAP recording subsystem is enabled. */
    bool     record_all;             /**< True if all sessions should automatically record. */
    uint64_t total_packets_recorded; /**< Global count of packets captured. */
    uint64_t total_bytes_recorded;   /**< Global count of bytes captured. */
    uint64_t write_failures;         /**< Global count of write or buffer errors. */
} pcap_table_t;

/**
 * @brief Initializes the PCAP recorder table and pre-allocated write context pool.
 *
 * @param table Pointer to PCAP table.
 */
void pcap_table_init(pcap_table_t *restrict const table);

/**
 * @brief Destroys the PCAP table, closing all open capture files.
 *
 * @param table Pointer to PCAP table.
 */
void pcap_table_destroy(pcap_table_t *restrict const table);

/**
 * @brief Sets the storage directory/volume for PCAP captures and creates it if missing.
 *
 * @param table Pointer to PCAP table.
 * @param dir_path Filesystem directory path.
 * @return true if valid and accessible/created, false on error.
 */
[[nodiscard]] bool
pcap_table_set_record_dir(pcap_table_t *restrict const table, char const *const dir_path);

/**
 * @brief Starts or retrieves a PCAP recording for a given Call-ID or session ports.
 *
 * @param table Pointer to PCAP table.
 * @param call_id Call identifier string (can be nullptr).
 * @param port_a First session port (e.g. caller).
 * @param port_b Second session port (e.g. callee, or 0).
 * @return Recorder index [0..PCAP_MAX_RECORDERS) on success, or -1 on error.
 */
[[nodiscard]] int32_t pcap_recorder_start(
    pcap_table_t *restrict const table,
    char const *const call_id,
    uint16_t const    port_a,
    uint16_t const    port_b);

/**
 * @brief Stops an active PCAP recording matching the given Call-ID.
 *
 * @param table Pointer to PCAP table.
 * @param call_id Call-ID to stop.
 * @return true if found and closed, false otherwise.
 */
bool pcap_recorder_stop_by_id(pcap_table_t *restrict const table, char const *const call_id);

/**
 * @brief Stops an active PCAP recording matching a session port.
 *
 * @param table Pointer to PCAP table.
 * @param port Session port to stop.
 * @return true if found and closed, false otherwise.
 */
bool pcap_recorder_stop_by_port(pcap_table_t *restrict const table, uint16_t const port);

/**
 * @brief Stops an active PCAP recording by its table slot index.
 *
 * @param table Pointer to PCAP table.
 * @param recorder_idx Recorder index [0..PCAP_MAX_RECORDERS).
 * @return true if valid and stopped, false otherwise.
 */
bool pcap_recorder_stop_by_index(pcap_table_t *restrict const table, int32_t const recorder_idx);

/**
 * @brief Finds an active recorder index matching a Call-ID or port.
 *
 * @param table Pointer to PCAP table.
 * @param call_id Call-ID string (can be nullptr).
 * @param port Session port (or 0).
 * @return Slot index or -1 if not found.
 */
[[nodiscard]] int32_t pcap_recorder_find(
    pcap_table_t const *restrict const table,
    char const *const call_id,
    uint16_t const    port);

/**
 * @brief Retrieves a pointer to a recorder by index.
 *
 * @param table Pointer to PCAP table.
 * @param recorder_idx Recorder index.
 * @return Pointer to recorder or nullptr if out of range/inactive.
 */
[[nodiscard]] pcap_recorder_t *
pcap_recorder_get(pcap_table_t *restrict const table, int32_t const recorder_idx);

/**
 * @brief Submits an asynchronous PCAP file write on the io_uring reactor ring for a media packet.
 *
 * @param table Pointer to PCAP table.
 * @param engine Pointer to ring engine.
 * @param recorder_idx Target recorder index.
 * @param payload Pointer to decrypted/plain RTP payload.
 * @param payload_len Length in bytes of payload.
 * @param src_addr Discovered or latched source socket address.
 * @param dst_addr Destination socket address.
 * @param bid Provided buffer ID holding payload.
 * @param can_zero_copy true to retain bid and scatter-gather, false to copy payload.
 * @return true if write was queued to io_uring, false otherwise.
 */
bool pcap_record_packet(
    pcap_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    int32_t const     recorder_idx,
    void const *const payload,
    size_t const      payload_len,
    struct sockaddr_storage const *restrict const src_addr,
    struct sockaddr_storage const *restrict const dst_addr,
    uint16_t const bid,
    bool const     can_zero_copy);

/**
 * @brief Handles completion of an asynchronous PCAP write on io_uring.
 *
 * @param table Pointer to PCAP table.
 * @param engine Pointer to ring engine.
 * @param cqe Pointer to io_uring completion queue entry.
 * @param ctx_idx Write context pool index.
 * @param bid Buffer ID used for zero-copy write (if retained).
 */
void pcap_handle_write_cqe(
    pcap_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   ctx_idx,
    uint16_t const                   bid);
