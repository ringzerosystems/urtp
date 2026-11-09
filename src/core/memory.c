#include "memory.h"
#include <stdatomic.h>
#include <stdlib.h>
#include "macros.h"

static _Atomic uint64_t _total_bytes_allocated = 0;

size_t memory_total_allocated(void) { return (size_t)atomic_load(&_total_bytes_allocated); }

void *mem_alloc_aligned(size_t const alignment, size_t const size) {
    if (unlikely((alignment == 0) || (size == 0))) {
        return nullptr;
    }
    void *ptr = nullptr;
    if (unlikely(posix_memalign(&ptr, alignment, size) != 0)) {
        return nullptr;
    }
    atomic_fetch_add(&_total_bytes_allocated, size);
    return ptr;
}

void mem_free_aligned(void *const ptr, size_t const size) {
    if (ptr != nullptr) {
        atomic_fetch_sub(&_total_bytes_allocated, size);
        free(ptr);
    }
}
