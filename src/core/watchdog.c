#include "core/watchdog.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "core/macros.h"

bool watchdog_init(systemd_watchdog_t *restrict const watchdog) {
    if (unlikely(watchdog == nullptr)) {
        return false;
    }

    *watchdog = (systemd_watchdog_t){.notify_fd = -1};

    char const *const sock = getenv("NOTIFY_SOCKET");
    if ((sock == nullptr) || (sock[0] == '\0')) {
        return false;
    }

    char const *const usec_str = getenv("WATCHDOG_USEC");
    uint64_t          interval = 0;
    if (usec_str != nullptr) {
        uint64_t const usec = (uint64_t)strtoull(usec_str, nullptr, 10);
        interval            = usec / 2000000ULL;
        if (interval == 0) {
            interval = 1;
        }
    }

    int const fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (unlikely(fd < 0)) {
        return false;
    }

    watchdog->notify_addr.sun_family = AF_UNIX;
    size_t const path_len            = __builtin_strlen(sock);
    if (unlikely(path_len >= sizeof(watchdog->notify_addr.sun_path))) {
        (void)close(fd);
        return false;
    }

    if (sock[0] == '@') {
        watchdog->notify_addr.sun_path[0] = '\0';
        __builtin_memcpy(&(watchdog->notify_addr.sun_path[1]), &(sock[1]), path_len - 1);
    } else {
        __builtin_memcpy(watchdog->notify_addr.sun_path, sock, path_len);
        watchdog->notify_addr.sun_path[path_len] = '\0';
    }

    watchdog->notify_addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len);
    watchdog->notify_fd       = fd;
    watchdog->watchdog_interval_sec = interval;
    watchdog->last_ping_sec         = 0;
    watchdog->enabled               = true;

    return true;
}

void watchdog_destroy(systemd_watchdog_t *restrict const watchdog) {
    if (unlikely(watchdog == nullptr)) {
        return;
    }

    if (watchdog->notify_fd >= 0) {
        (void)close(watchdog->notify_fd);
    }
    *watchdog = (systemd_watchdog_t){.notify_fd = -1};
}

static void
watchdog_send(systemd_watchdog_t const *restrict const watchdog, char const *const msg) {
    if (unlikely(
            (watchdog == nullptr) || !(watchdog->enabled) || (watchdog->notify_fd < 0) ||
            (msg == nullptr)))
    {
        return;
    }

    size_t const len = __builtin_strlen(msg);
    (void)sendto(
        watchdog->notify_fd,
        msg,
        len,
        MSG_NOSIGNAL,
        (struct sockaddr const *)&(watchdog->notify_addr),
        watchdog->notify_addr_len);
}

void watchdog_notify_ready(systemd_watchdog_t *restrict const watchdog) {
    watchdog_send(watchdog, "READY=1\n");
}

void watchdog_notify_stopping(systemd_watchdog_t *restrict const watchdog) {
    watchdog_send(watchdog, "STOPPING=1\n");
}

void watchdog_ping(systemd_watchdog_t *restrict const watchdog, uint64_t const now_sec) {
    if (unlikely(
            (watchdog == nullptr) || !(watchdog->enabled) ||
            (watchdog->watchdog_interval_sec == 0)))
    {
        return;
    }

    if ((now_sec - watchdog->last_ping_sec) >= watchdog->watchdog_interval_sec) {
        watchdog_send(watchdog, "WATCHDOG=1\n");
        watchdog->last_ping_sec = now_sec;
    }
}
