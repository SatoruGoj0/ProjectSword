#!/usr/bin/env python3
"""
Scan the kext __TEXT_EXEC for ADRP+ADD references into __DATA_CONST that
could point at the AppleJPEGDriver dispatch table (vm 0xfffffff007bbfb70).

References may use any ADRP page whose ADD offset reaches the table, so we
scan ALL ADRP instructions, compute the effective address, and flag any
that land in the kext __DATA_CONST window.

Usage: python3 find_adrp_refs.py <kernelcache_macho>
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TABLE_VA = 0xfffffff007bbfb70
WINDOW_LO = 0xfffffff007b00000
WINDOW_HI = 0xfffffff007c00000

LC_SEGMENT_64 = 0x19

def parse_macho(path):
    data = open(path, 'rb').read()
    ncmds, = struct.unpack_from('<I', data, 16)
    cmds = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        cmds.append((cmd, cmdsize, data[off:off+cmdsize]))
        off += cmdsize
    return data, cmds

def seg_ranges(cmds):
    out = []
    for cmd, cmdsize, payload in cmds:
        if cmd == LC_SEGMENT_64:
            name = payload[8:24].rstrip(b'\x00').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', payload, 0x18)
            out.append((name, vmaddr, vmsize, fileoff, filesize))
    return out

def off_to_vm(segments, off):
    for name, vmaddr, vmsize, fileoff, filesize in segments:
        if fileoff <= off < fileoff + filesize:
            return vmaddr + (off - fileoff)
    return None

def vm_to_off(segments, va):
    for name, vmaddr, vmsize, fileoff, filesize in segments:
        if vmaddr <= va < vmaddr + vmsize:
            delta = va - vmaddr
            if delta < filesize:
                return fileoff + delta
    return None

def disasm(data, segments, va, count=30, stop_at_ret=True):
    off = vm_to_off(segments, va)
    if off is None:
        return f"  (no file image at vm 0x{va:x})"
    code = data[off:off + 4 * (count + 32)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for ins in md.disasm(code, va):
        out.append(f"  0x{ins.address:016x}: {ins.mnemonic:<8} {ins.op_str}")
        if stop_at_ret and ins.mnemonic == 'ret':
            break
        if len(out) >= count:
            break
    return "\n".join(out)

if __name__ == '__main__':
    path = sys.argv[1]
    data, cmds = parse_macho(path)
    segments = seg_ranges(cmds)

    # find outer __TEXT_EXEC
    tx = None
    for s in segments:
        if s[0] == '__TEXT_EXEC':
            tx = s
            break
    if tx is None:
        print("[-] no __TEXT_EXEC")
        sys.exit(1)
    name, txva, txvs, txfo, txfs = tx
    print(f"[*] __TEXT_EXEC: vm 0x{txva:x}-0x{txva+txvs:x} file 0x{txfo:x}+0x{txfs:x}")

    code = data[txfo:txfo + txfs]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    hits = []
    insns = list(md.disasm(code, txva))
    print(f"[*] {len(insns)} instructions")

    # First pass: find all adrp and their targets
    adrp_map = {}  # addr -> (reg, page)
    for ins in insns:
        if ins.mnemonic == 'adrp':
            # op_str like "x0, #0xfffffff007bbf000"
            try:
                reg = ins.op_str.split(',')[0].strip()
                target = int(ins.op_str.split('#')[1], 16)
                adrp_map[ins.address] = (reg, target)
            except Exception:
                pass

    # Second pass: find add right after adrp using same reg
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'add':
            continue
        # add reg_dst, reg_src, #imm
        parts = ins.op_str.replace(',', ' ').split()
        if len(parts) < 3:
            continue
        dst, src = parts[0], parts[1]
        if src.startswith('[') or not src.startswith('x'):
            continue
        imm = parts[-1].lstrip('#')
        if not imm.startswith('0x'):
            continue
        try:
            imm = int(imm, 16)
        except Exception:
            continue
        # find a preceding adrp within ~10 instructions that set src
        for back in range(i - 1, max(i - 12, 0), -1):
            prev = insns[back]
            if prev.mnemonic == 'adrp' and prev.address in adrp_map:
                preg, page = adrp_map[prev.address]
                if preg == src:
                    eff = (page & 0xfffffffffffff000) + imm
                    if WINDOW_LO <= eff < WINDOW_HI:
                        hits.append((prev.address, page, ins.address, eff))
                    break
                # also handle ldr from page with imm -> maybe loads a pointer
            if prev.address < ins.address - 32:
                break

    print(f"[*] {len(hits)} ADRP+ADD references into __DATA_CONST window:")
    hits.sort()
    for hadrp, page, hadd, eff in hits:
        print(f"  adrp@{hadrp:016x} page=0x{page:x} + add@{hadd:016x} -> 0x{eff:x}" +
              ("   <== TABLE!!!" if abs(eff - TABLE_VA) < 0x100 else ""))

    # Disassemble functions around the closest hits
    print("\n[*] Function disassembly for hits near the table:")
    seen = set()
    for hadrp, page, hadd, eff in sorted(hits, key=lambda h: abs(h[3] - TABLE_VA)):
        if abs(eff - TABLE_VA) > 0x100:
            continue
        # function start: scan back for a pacibsp/bti or ret
        func_start = hadrp - 0x80
        if any(abs(func_start - s) < 0x40 for s in seen):
            continue
        seen.add(func_start)
        print(f"\n===== hit at 0x{hadd:016x} -> 0x{eff:x} =====")
        print(disasm(data, segments, func_start, count=80))
