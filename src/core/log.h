#pragma once

#include <stdio.h>

/**
 * @file log.h
 * @brief Zero-overhead structured logging primitives and levels.
 */

/** @brief Formats a log line prefix with tag, filename, and line number. */
#define LOG_FMT(tag, fmt) "[" tag "] %s:%d: " fmt "\n"

/** @brief Primitive log emitter to an arbitrary output stream. */
#define LOG_PRIMITIVE(stream, tag, fmt, ...)                                                       \
    ((void)fprintf((stream), LOG_FMT(tag, fmt), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__))

/** @brief Logs an informational message to standard output. */
#define LOG_INFO(fmt, ...) LOG_PRIMITIVE(stdout, "INFO", fmt __VA_OPT__(, ) __VA_ARGS__)
/** @brief Logs a warning message to standard output. */
#define LOG_WARN(fmt, ...) LOG_PRIMITIVE(stdout, "WARN", fmt __VA_OPT__(, ) __VA_ARGS__)
/** @brief Logs an error message to standard error. */
#define LOG_ERRO(fmt, ...) LOG_PRIMITIVE(stderr, "ERRO", fmt __VA_OPT__(, ) __VA_ARGS__)

#ifndef LOG_ERROR
/** @brief Alias for LOG_ERRO. */
#define LOG_ERROR(fmt, ...) LOG_ERRO(fmt __VA_OPT__(, ) __VA_ARGS__)
#endif

// Primitive for localized debug logging in .c translation units
/** @brief Primitive for localized debug logging to standard output. */
#define LOG_DEBUG_PRIMITIVE(fmt, ...) LOG_PRIMITIVE(stdout, "DEBUG", fmt __VA_OPT__(, ) __VA_ARGS__)
/** @brief Implementation alias for debug logging. */
#define LOG_DEBUG_IMPL(fmt, ...) LOG_DEBUG_PRIMITIVE(fmt __VA_OPT__(, ) __VA_ARGS__)
/** @brief Raw debug logger alias. */
#define LOG_DEBUG_RAW(fmt, ...) LOG_DEBUG_PRIMITIVE(fmt __VA_OPT__(, ) __VA_ARGS__)
/** @brief No-operation debug logger when debugging is disabled. */
#define LOG_DEBUG_NOOP(fmt, ...) ((void)0)

// Auto-wire LOG_DEBUG if localized debug macro is defined in .c file
#if defined(DEBUG) || defined(LOCAL_DEBUG)
#ifndef LOG_DEBUG
#define LOG_DEBUG(fmt, ...) LOG_DEBUG_PRIMITIVE(fmt __VA_OPT__(, ) __VA_ARGS__)
#endif
#endif
