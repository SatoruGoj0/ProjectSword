#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdbool.h>

// Find our proc in kernel via allproc walk
uint64_t find_our_proc(void);

// Platformize: set TF_PLATFORM + uid 0 via kernel R/W
bool platformize_proc(void);

#endif
