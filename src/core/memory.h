#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file memory.h
 * @brief Memory utilities and cacheline-aligned allocation helpers.
 */

/**
 * @brief Allocates cacheline-aligned memory and tracks allocated bytes.
 *
 * @param alignment Alignment boundary in bytes (e.g. 64).
 * @param size Number of bytes to allocate.
 * @return Pointer to allocated memory, or nullptr on failure.
 */
[[nodiscard]] void *mem_alloc_aligned(size_t const alignment, size_t const size);

/**
 * @brief Frees memory allocated by mem_alloc_aligned and updates memory tracking.
 *
 * @param ptr Pointer to free.
 * @param size Size in bytes previously allocated (for metric accounting).
 */
void mem_free_aligned(void *const ptr, size_t const size);

/**
 * @brief Helper function to cleanly convert megabytes to bytes.
 *
 * @param mb Value in megabytes.
 * @return Equivalent size in bytes.
 */
static inline size_t mb_to_bytes(size_t const mb) { return mb * 1024 * 1024; }

/**
 * @brief Helper function to cleanly convert bytes to megabytes as a double.
 *
 * @param bytes Value in bytes.
 * @return Equivalent size in megabytes as a double.
 */
static inline double bytes_to_mb(size_t const bytes) { return (double)bytes / (1024ULL * 1024ULL); }

/**
 * @brief Retrieves the total number of bytes allocated by all allocators.
 *
 * @return Total allocated bytes.
 */
[[nodiscard]] size_t memory_total_allocated(void);
