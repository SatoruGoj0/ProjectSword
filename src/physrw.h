#ifndef PHYSrw_H
#define PHYSrw_H

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>

bool buildPhysPrimitive(void);

bool physread(uint64_t addr, size_t len, void *buffer);
bool physwrite(uint64_t addr, void *buffer, size_t len);

uint64_t translateAddr_inTTEP(uint64_t ttep, uint64_t virt);
uint64_t translateAddr(uint64_t virt);

uint64_t physrw_map_once(uint64_t addr);

#endif
