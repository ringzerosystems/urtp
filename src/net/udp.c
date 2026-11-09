#include "net/udp.h"
#include <unistd.h>
#include "core/macros.h"

bool udp_parse_endpoint(
    char const *const ip_str,
    uint16_t const    port,
    struct sockaddr_storage *restrict const out_addr,
    socklen_t *restrict const out_len) {
    if (unlikely((ip_str == nullptr) || (out_addr == nullptr) || (out_len == nullptr))) {
        return false;
    }

    *out_addr = (struct sockaddr_storage){};

    // Attempt IPv4 parsing
    struct sockaddr_in *const in4 = (struct sockaddr_in *)out_addr;
    if (inet_pton(AF_INET, ip_str, &(in4->sin_addr)) == 1) {
        in4->sin_family = AF_INET;
        in4->sin_port   = htons(port);
        *out_len        = sizeof(struct sockaddr_in);
        return true;
    }

    // Attempt IPv6 parsing
    struct sockaddr_in6 *const in6 = (struct sockaddr_in6 *)out_addr;
    if (inet_pton(AF_INET6, ip_str, &(in6->sin6_addr)) == 1) {
        in6->sin6_family = AF_INET6;
        in6->sin6_port   = htons(port);
        *out_len         = sizeof(struct sockaddr_in6);
        return true;
    }

    return false;
}

bool udp_format_endpoint(
    struct sockaddr_storage const *restrict const addr,
    char *restrict const buf,
    size_t const buf_size,
    uint16_t *restrict const out_port) {
    if (unlikely((addr == nullptr) || (buf == nullptr) || (buf_size == 0))) {
        return false;
    }

    if (addr->ss_family == AF_INET) {
        auto const in4 = (struct sockaddr_in const *)addr;
        if (inet_ntop(AF_INET, &(in4->sin_addr), buf, (socklen_t)buf_size) == nullptr) {
            return false;
        }
        if (out_port != nullptr) {
            *out_port = ntohs(in4->sin_port);
        }
        return true;
    }

    if (addr->ss_family == AF_INET6) {
        auto const in6 = (struct sockaddr_in6 const *)addr;
        if (inet_ntop(AF_INET6, &(in6->sin6_addr), buf, (socklen_t)buf_size) == nullptr) {
            return false;
        }
        if (out_port != nullptr) {
            *out_port = ntohs(in6->sin6_port);
        }
        return true;
    }

    return false;
}

int udp_bind_socket(char const *const ip, uint16_t const port) {
    struct sockaddr_storage addr     = {};
    socklen_t               addr_len = 0;

    char const *const target_ip = (ip != nullptr) ? ip : "0.0.0.0";
    if (unlikely(!udp_parse_endpoint(target_ip, port, &addr, &addr_len))) {
        return -1;
    }

    int const fd = socket(addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (unlikely(fd < 0)) {
        return -1;
    }

    int const opt_val = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val));

    int const buf_size = 4 * 1024 * 1024; // 4 MB socket buffers
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    if (unlikely(bind(fd, (struct sockaddr const *)&addr, addr_len) < 0)) {
        close(fd);
        return -1;
    }

    return fd;
}

void udp_close_socket(int const fd) {
    if (fd >= 0) {
        close(fd);
    }
}
