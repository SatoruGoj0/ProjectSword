#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <mach/mach.h>

// Convert virtual address to physical via kernel page tables
uint64_t translate_virt_to_phys(uint64_t virt);

// Write to PPL-protected memory by translating virt→phys and writing directly
bool kwrite_ppl(uint64_t virt_addr, void *buf, size_t len);

// Platformize current process (set TF_PLATFORM, clear csflags restrictions)
bool platformize_proc(void);

// Load a trust cache from file
bool tcload_file(const char *path);

// Find kernel proc (pid=0)
uint64_t find_kernel_proc(void);

// Find our own proc
uint64_t find_our_proc(void);

// Map physical memory to user space at a fixed address
void *map_physical_page(uint64_t phys_addr);

#endif
