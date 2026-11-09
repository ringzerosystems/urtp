#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include "core/log.h"
#include "unity.h"

#define LOG_DEBUG(fmt, ...) LOG_DEBUG_PRIMITIVE("LOCAL: " fmt __VA_OPT__(, ) __VA_ARGS__)

void setUp(void) {}
void tearDown(void) {}

static void test_log_erro_to_stderr(void) {
    int pipefd[2] = {};
    TEST_ASSERT_EQUAL_INT(0, pipe(pipefd));

    int const saved_stderr = dup(STDERR_FILENO);
    TEST_ASSERT_TRUE(saved_stderr >= 0);
    (void)dup2(pipefd[1], STDERR_FILENO);
    (void)close(pipefd[1]);

    LOG_ERRO("error code=%d", 503);
    (void)fflush(stderr);

    char          buf[256] = {};
    ssize_t const n        = read(pipefd[0], buf, sizeof(buf) - 1);
    (void)n;
    (void)close(pipefd[0]);
    (void)dup2(saved_stderr, STDERR_FILENO);
    (void)close(saved_stderr);

    TEST_ASSERT_NOT_NULL(strstr(buf, "[ERRO]"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "test_log.c:"));
    TEST_ASSERT_NOT_NULL(strstr(buf, ": error code=503\n"));
}

static void test_log_info_and_warn_to_stdout(void) {
    int pipefd[2] = {};
    TEST_ASSERT_EQUAL_INT(0, pipe(pipefd));

    int const saved_stdout = dup(STDOUT_FILENO);
    TEST_ASSERT_TRUE(saved_stdout >= 0);
    (void)dup2(pipefd[1], STDOUT_FILENO);
    (void)close(pipefd[1]);

    LOG_INFO("server ready on port %u", 8080U);
    LOG_WARN("high water mark %zu", (size_t)1024);
    (void)fflush(stdout);

    char          buf[512] = {};
    ssize_t const n        = read(pipefd[0], buf, sizeof(buf) - 1);
    (void)n;
    (void)close(pipefd[0]);
    (void)dup2(saved_stdout, STDOUT_FILENO);
    (void)close(saved_stdout);

    TEST_ASSERT_NOT_NULL(strstr(buf, "[INFO]"));
    TEST_ASSERT_NOT_NULL(strstr(buf, ": server ready on port 8080\n"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "[WARN]"));
    TEST_ASSERT_NOT_NULL(strstr(buf, ": high water mark 1024\n"));
}

static void test_localized_log_debug(void) {
    int pipefd[2] = {};
    TEST_ASSERT_EQUAL_INT(0, pipe(pipefd));

    int const saved_stdout = dup(STDOUT_FILENO);
    TEST_ASSERT_TRUE(saved_stdout >= 0);
    (void)dup2(pipefd[1], STDOUT_FILENO);
    (void)close(pipefd[1]);

    LOG_DEBUG("localized tracing active val=%d", 42);
    (void)fflush(stdout);

    char          buf[256] = {};
    ssize_t const n        = read(pipefd[0], buf, sizeof(buf) - 1);
    (void)n;
    (void)close(pipefd[0]);
    (void)dup2(saved_stdout, STDOUT_FILENO);
    (void)close(saved_stdout);

    TEST_ASSERT_NOT_NULL(strstr(buf, "[DEBUG]"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "test_log.c:"));
    TEST_ASSERT_NOT_NULL(strstr(buf, ": LOCAL: localized tracing active val=42\n"));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_log_erro_to_stderr);
    RUN_TEST(test_log_info_and_warn_to_stdout);
    RUN_TEST(test_localized_log_debug);
    return UNITY_END();
}
