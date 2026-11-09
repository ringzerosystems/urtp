#include "net/pcap.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "core/macros.h"

static inline uint16_t ip_checksum(void const *const buf, size_t const len) {
    uint16_t const *ptr = (uint16_t const *)buf;
    uint32_t        sum = 0;
    for (size_t i = 0; i < (len / 2); ++i) {
        sum += ptr[i];
    }
    if ((len & 1) != 0) {
        sum += (uint32_t)((uint8_t const *)buf)[len - 1];
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static bool pcap_ensure_dir(char const *const path) {
    if (unlikely((path == nullptr) || (path[0] == '\0'))) {
        return false;
    }
    char       tmp[PCAP_PATH_MAX] = {};
    auto const len                = __builtin_strlen(path);
    if (len >= sizeof(tmp)) {
        return false;
    }
    __builtin_memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if ((mkdir(tmp, 0755) != 0) && (errno != EEXIST)) {
                return false;
            }
            *p = '/';
        }
    }
    if ((mkdir(tmp, 0755) != 0) && (errno != EEXIST)) {
        return false;
    }
    return true;
}

static void
pcap_sanitize_filename(char *restrict const dest, size_t const dest_max, char const *const src) {
    if (unlikely((dest == nullptr) || (dest_max == 0))) {
        return;
    }
    if (unlikely((src == nullptr) || (src[0] == '\0'))) {
        dest[0] = '\0';
        return;
    }

    size_t j = 0;
    for (size_t i = 0; (src[i] != '\0') && ((j + 1) < dest_max); ++i) {
        char const c = src[i];
        if ((c == '/') || (c == '\\') || (c == ':') || (c == ' ') || (c == '\t') || (c == '\r') ||
            (c == '\n'))
        {
            dest[j++] = '_';
        } else if ((c == '.') && (i > 0) && (src[i - 1] == '.')) {
            dest[j++] = '_';
        } else {
            dest[j++] = c;
        }
    }
    dest[j] = '\0';
}

void pcap_table_init(pcap_table_t *restrict const table) {
    if (unlikely(table == nullptr)) {
        return;
    }
    __builtin_memset(table, 0, sizeof(*table));
    for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
        table->recorders[i].fd = -1;
    }
}

void pcap_table_destroy(pcap_table_t *restrict const table) {
    if (unlikely(table == nullptr)) {
        return;
    }

    for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
        pcap_recorder_t *const rec = &(table->recorders[i]);
        if (rec->active && (rec->fd >= 0)) {
            close(rec->fd);
            rec->fd     = -1;
            rec->active = false;
        }
    }
    __builtin_memset(table, 0, sizeof(*table));
    for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
        table->recorders[i].fd = -1;
    }
}

bool pcap_table_set_record_dir(pcap_table_t *restrict const table, char const *const dir_path) {
    if (unlikely((table == nullptr) || (dir_path == nullptr) || (dir_path[0] == '\0'))) {
        return false;
    }

    auto const len = __builtin_strlen(dir_path);
    if (len >= sizeof(table->record_dir)) {
        return false;
    }

    if (!pcap_ensure_dir(dir_path)) {
        return false;
    }

    __builtin_memcpy(table->record_dir, dir_path, len + 1);
    table->enabled = true;
    return true;
}

int32_t pcap_recorder_start(
    pcap_table_t *restrict const table,
    char const *const call_id,
    uint16_t const    port_a,
    uint16_t const    port_b) {
    if (unlikely(table == nullptr)) {
        return -1;
    }

    if (table->record_dir[0] == '\0') {
        return -1;
    }

    // Check if a recorder is already active for this Call-ID or port
    auto const existing = pcap_recorder_find(table, call_id, port_a);
    if (existing >= 0) {
        pcap_recorder_t *const rec = &(table->recorders[existing]);
        if ((port_b > 0) && (rec->session_port_b == 0)) {
            rec->session_port_b = port_b;
        }
        return existing;
    }

    // Find free recorder slot
    int32_t slot = -1;
    for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
        if (!(table->recorders[i].active)) {
            slot = (int32_t)i;
            break;
        }
    }
    if (slot < 0) {
        return -1;
    }

    pcap_recorder_t *const rec = &(table->recorders[slot]);
    *rec                       = (pcap_recorder_t){.fd = -1};

    char sanitized_id[PCAP_ID_MAX] = {};
    if (call_id != nullptr) {
        pcap_sanitize_filename(sanitized_id, sizeof(sanitized_id), call_id);
    }

    if (sanitized_id[0] != '\0') {
        (void)snprintf(
            rec->file_path,
            sizeof(rec->file_path),
            "%s/%s.pcap",
            table->record_dir,
            sanitized_id);
        auto const cid_len = __builtin_strlen(call_id);
        auto const copy_len =
            (cid_len < sizeof(rec->call_id) - 1) ? cid_len : sizeof(rec->call_id) - 1;
        __builtin_memcpy(rec->call_id, call_id, copy_len);
        rec->call_id[copy_len] = '\0';
    } else {
        (void)snprintf(
            rec->file_path,
            sizeof(rec->file_path),
            "%s/session_%u.pcap",
            table->record_dir,
            port_a);
    }

    int const fd = open(rec->file_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }

    pcap_file_hdr_t const file_hdr = {
        .magic_number  = PCAP_MAGIC_USEC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = PCAP_SNAPLEN,
        .network       = PCAP_LINKTYPE_ETHERNET,
    };

    auto const written = write(fd, &file_hdr, sizeof(file_hdr));
    if (written != (ssize_t)sizeof(file_hdr)) {
        close(fd);
        (void)unlink(rec->file_path);
        return -1;
    }

    rec->fd             = fd;
    rec->file_offset    = sizeof(pcap_file_hdr_t);
    rec->session_port_a = port_a;
    rec->session_port_b = port_b;
    rec->active         = true;
    table->active_recorders++;

    return slot;
}

bool pcap_recorder_stop_by_index(pcap_table_t *restrict const table, int32_t const recorder_idx) {
    if (unlikely(
            (table == nullptr) || (recorder_idx < 0) ||
            ((size_t)recorder_idx >= PCAP_MAX_RECORDERS)))
    {
        return false;
    }

    pcap_recorder_t *const rec = &(table->recorders[recorder_idx]);
    if (!(rec->active)) {
        return false;
    }

    if (rec->fd >= 0) {
        close(rec->fd);
        rec->fd = -1;
    }
    rec->active = false;
    if (table->active_recorders > 0) {
        table->active_recorders--;
    }
    return true;
}

bool pcap_recorder_stop_by_id(pcap_table_t *restrict const table, char const *const call_id) {
    if (unlikely((table == nullptr) || (call_id == nullptr) || (call_id[0] == '\0'))) {
        return false;
    }

    auto const idx = pcap_recorder_find(table, call_id, 0);
    if (idx < 0) {
        return false;
    }
    return pcap_recorder_stop_by_index(table, idx);
}

bool pcap_recorder_stop_by_port(pcap_table_t *restrict const table, uint16_t const port) {
    if (unlikely((table == nullptr) || (port == 0))) {
        return false;
    }

    auto const idx = pcap_recorder_find(table, nullptr, port);
    if (idx < 0) {
        return false;
    }
    return pcap_recorder_stop_by_index(table, idx);
}

int32_t pcap_recorder_find(
    pcap_table_t const *restrict const table,
    char const *const call_id,
    uint16_t const    port) {
    if (unlikely(table == nullptr)) {
        return -1;
    }

    bool const check_id   = (call_id != nullptr) && (call_id[0] != '\0');
    bool const check_port = (port > 0);

    for (size_t i = 0; i < PCAP_MAX_RECORDERS; ++i) {
        pcap_recorder_t const *const rec = &(table->recorders[i]);
        if (!rec->active) {
            continue;
        }

        if (check_id && (strcmp(rec->call_id, call_id) == 0)) {
            return (int32_t)i;
        }

        if (check_port && ((rec->session_port_a == port) || (rec->session_port_b == port))) {
            return (int32_t)i;
        }
    }

    return -1;
}

pcap_recorder_t *pcap_recorder_get(pcap_table_t *restrict const table, int32_t const recorder_idx) {
    if (unlikely(
            (table == nullptr) || (recorder_idx < 0) ||
            ((size_t)recorder_idx >= PCAP_MAX_RECORDERS)))
    {
        return nullptr;
    }
    pcap_recorder_t *const rec = &(table->recorders[recorder_idx]);
    return rec->active ? rec : nullptr;
}

bool pcap_record_packet(
    pcap_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    int32_t const     recorder_idx,
    void const *const payload,
    size_t const      payload_len,
    struct sockaddr_storage const *restrict const src_addr,
    struct sockaddr_storage const *restrict const dst_addr,
    uint16_t const bid,
    bool const     can_zero_copy) {
    if (unlikely(
            (table == nullptr) || (engine == nullptr) || (payload == nullptr) ||
            (payload_len == 0) || (recorder_idx < 0) ||
            ((size_t)recorder_idx >= PCAP_MAX_RECORDERS)))
    {
        return false;
    }

    pcap_recorder_t *const rec = &(table->recorders[recorder_idx]);
    if (unlikely(!(rec->active) || (rec->fd < 0))) {
        return false;
    }

    // Allocate a free write context from the pre-allocated pool
    pcap_write_ctx_t *ctx     = nullptr;
    uint16_t          ctx_idx = 0;
    for (size_t i = 0; i < PCAP_MAX_PENDING_WRITES; ++i) {
        if (!(table->write_ctxs[i].in_use)) {
            ctx     = &(table->write_ctxs[i]);
            ctx_idx = (uint16_t)i;
            break;
        }
    }
    if (unlikely(ctx == nullptr)) {
        table->write_failures++;
        return false;
    }

    *ctx              = (pcap_write_ctx_t){};
    ctx->in_use       = true;
    ctx->recorder_idx = (uint16_t)recorder_idx;

    struct timespec ts = {};
    (void)clock_gettime(CLOCK_REALTIME, &ts);

    bool const is_v6    = (src_addr != nullptr) && (src_addr->ss_family == AF_INET6);
    size_t     hdr_size = 0;

    static uint16_t s_ip_id = 0;

    if (!is_v6) {
        hdr_size = sizeof(pcap_packet_hdr_t) + sizeof(pcap_eth_hdr_t) + sizeof(pcap_ipv4_hdr_t) +
                   sizeof(pcap_udp_hdr_t);

        uint32_t const frame_len = (uint32_t)(sizeof(pcap_eth_hdr_t) + sizeof(pcap_ipv4_hdr_t) +
                                              sizeof(pcap_udp_hdr_t) + payload_len);

        ctx->hdr.pcap_hdr = (pcap_packet_hdr_t){
            .ts_sec   = (uint32_t)ts.tv_sec,
            .ts_usec  = (uint32_t)(ts.tv_nsec / 1000),
            .incl_len = frame_len,
            .orig_len = frame_len,
        };

        ctx->hdr.eth_hdr = (pcap_eth_hdr_t){
            .dst_mac   = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
            .src_mac   = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
            .ethertype = htons(0x0800),
        };

        uint32_t saddr = htonl(INADDR_LOOPBACK);
        uint16_t sport = htons(10000);
        if (src_addr != nullptr) {
            struct sockaddr_in const *const sin = (struct sockaddr_in const *)src_addr;
            saddr                               = sin->sin_addr.s_addr;
            sport                               = sin->sin_port;
        }

        uint32_t daddr = htonl(INADDR_LOOPBACK);
        uint16_t dport = htons(10002);
        if (dst_addr != nullptr) {
            struct sockaddr_in const *const din = (struct sockaddr_in const *)dst_addr;
            daddr                               = din->sin_addr.s_addr;
            dport                               = din->sin_port;
        }

        ctx->hdr.net.v4.ip4 = (pcap_ipv4_hdr_t){
            .ver_ihl = 0x45,
            .tos     = 0,
            .tot_len =
                htons((uint16_t)(sizeof(pcap_ipv4_hdr_t) + sizeof(pcap_udp_hdr_t) + payload_len)),
            .id       = htons(++s_ip_id),
            .frag_off = htons(0x4000),
            .ttl      = 64,
            .proto    = 17,
            .check    = 0,
            .saddr    = saddr,
            .daddr    = daddr,
        };
        ctx->hdr.net.v4.ip4.check = ip_checksum(&(ctx->hdr.net.v4.ip4), sizeof(pcap_ipv4_hdr_t));

        ctx->hdr.net.v4.udp = (pcap_udp_hdr_t){
            .source = sport,
            .dest   = dport,
            .len    = htons((uint16_t)(sizeof(pcap_udp_hdr_t) + payload_len)),
            .check  = 0,
        };
    } else {
        hdr_size = sizeof(pcap_packet_hdr_t) + sizeof(pcap_eth_hdr_t) + sizeof(pcap_ipv6_hdr_t) +
                   sizeof(pcap_udp_hdr_t);

        uint32_t const frame_len = (uint32_t)(sizeof(pcap_eth_hdr_t) + sizeof(pcap_ipv6_hdr_t) +
                                              sizeof(pcap_udp_hdr_t) + payload_len);

        ctx->hdr.pcap_hdr = (pcap_packet_hdr_t){
            .ts_sec   = (uint32_t)ts.tv_sec,
            .ts_usec  = (uint32_t)(ts.tv_nsec / 1000),
            .incl_len = frame_len,
            .orig_len = frame_len,
        };

        ctx->hdr.eth_hdr = (pcap_eth_hdr_t){
            .dst_mac   = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
            .src_mac   = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
            .ethertype = htons(0x86dd),
        };

        uint16_t sport = htons(10000);
        uint16_t dport = htons(10002);

        ctx->hdr.net.v6.ip6 = (pcap_ipv6_hdr_t){
            .ver_tc_fl   = htonl(0x60000000),
            .payload_len = htons((uint16_t)(sizeof(pcap_udp_hdr_t) + payload_len)),
            .next_header = 17,
            .hop_limit   = 64,
        };

        if (src_addr != nullptr) {
            struct sockaddr_in6 const *const sin6 = (struct sockaddr_in6 const *)src_addr;
            __builtin_memcpy(ctx->hdr.net.v6.ip6.saddr, &(sin6->sin6_addr), 16);
            sport = sin6->sin6_port;
        }
        if (dst_addr != nullptr) {
            struct sockaddr_in6 const *const din6 = (struct sockaddr_in6 const *)dst_addr;
            __builtin_memcpy(ctx->hdr.net.v6.ip6.daddr, &(din6->sin6_addr), 16);
            dport = din6->sin6_port;
        }

        ctx->hdr.net.v6.udp = (pcap_udp_hdr_t){
            .source = sport,
            .dest   = dport,
            .len    = htons((uint16_t)(sizeof(pcap_udp_hdr_t) + payload_len)),
            .check  = 0,
        };
    }

    ctx->iov[0].iov_base = &(ctx->hdr);
    ctx->iov[0].iov_len  = hdr_size;

    if (can_zero_copy) {
        ring_engine_buf_retain(engine, bid);
        ctx->bid_retained    = true;
        ctx->bid             = bid;
        ctx->iov[1].iov_base = (void *)(uintptr_t)payload;
        ctx->iov[1].iov_len  = payload_len;
    } else {
        ctx->bid_retained = false;
        ctx->bid          = 0;
        auto const copy_sz =
            (payload_len <= PCAP_MAX_PAYLOAD_COPY) ? payload_len : PCAP_MAX_PAYLOAD_COPY;
        __builtin_memcpy(ctx->payload_copy, payload, copy_sz);
        ctx->iov[1].iov_base = ctx->payload_copy;
        ctx->iov[1].iov_len  = copy_sz;
    }

    auto const sqe = ring_engine_get_sqe(engine);
    if (unlikely(sqe == nullptr)) {
        if (ctx->bid_retained) {
            ring_engine_buf_release(engine, bid);
        }
        ctx->in_use = false;
        table->write_failures++;
        return false;
    }

    io_uring_prep_writev(sqe, rec->fd, ctx->iov, 2, rec->file_offset);

    user_data_tag_t const tag = {
        .fields = {
            .index   = ctx_idx,
            .op_type = OP_TYPE_PCAP_WRITE,
            .bid     = ctx->bid_retained ? bid : 0,
            .flags   = 0,
        }};
    io_uring_sqe_set_data64(sqe, tag.raw);

    size_t const total_bytes = (hdr_size + payload_len);
    rec->file_offset += total_bytes;
    rec->packets_recorded++;
    rec->bytes_recorded += total_bytes;
    table->total_packets_recorded++;
    table->total_bytes_recorded += total_bytes;

    return true;
}

void pcap_handle_write_cqe(
    pcap_table_t *restrict const table,
    ring_engine_t *restrict const engine,
    struct io_uring_cqe const *const cqe,
    uint16_t const                   ctx_idx,
    uint16_t const                   bid) {
    if (unlikely((table == nullptr) || (engine == nullptr) || (cqe == nullptr))) {
        return;
    }
    if (unlikely(ctx_idx >= PCAP_MAX_PENDING_WRITES)) {
        return;
    }

    pcap_write_ctx_t *const ctx = &(table->write_ctxs[ctx_idx]);
    if (unlikely(!(ctx->in_use))) {
        return;
    }

    if (unlikely(cqe->res < 0)) {
        table->write_failures++;
    }

    if (ctx->bid_retained) {
        ring_engine_buf_release(engine, bid);
    }

    ctx->in_use       = false;
    ctx->bid_retained = false;
}
