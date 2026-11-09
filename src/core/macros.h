#pragma once

/**
 * @file macros.h
 * @brief Performance and branch prediction compiler macros.
 */

#ifndef likely
/** @brief Hints to the compiler that the condition is likely to be true. */
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
/** @brief Hints to the compiler that the condition is likely to be false. */
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/** @brief Atomic boolean typedef convenience macro. */
#define ATOMIC_BOOL _Atomic bool
