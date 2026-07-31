#!/usr/bin/env python3
"""
Robust linear-sweep scan for ADRP+ADD references into __DATA_CONST within
the AppleJPEGDriver kext code ranges (its __TEXT and __TEXT_EXEC).

Scan every 4-byte offset, decode up to 8 instructions, look for
adrp -> (add|ldr|ldrh|ldrb) pairs targeting the __DATA_CONST window that
contains the dispatch table (0xfffffff007bbfb70).

Usage: python3 find_adrp_refs2.py <kernelcache_macho>
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TABLE_VA = 0xfffffff007bbfb70
KEXT_TEXT_VA   = 0xfffffff007409420   # kext __TEXT
KEXT_TEXT_SIZE = 0x147d4
KEXT_TE_VA     = 0xfffffff008f2ca50   # kext __TEXT_EXEC
KEXT_TE_SIZE   = 0x3470c
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

def vm_to_off(segments, va):
    for name, vmaddr, vmsize, fileoff, filesize in segments:
        if vmaddr <= va < vmaddr + vmsize:
            delta = va - vmaddr
            if delta < filesize:
                return fileoff + delta
    return None

def disasm(data, segments, va, count=60, stop_at_ret=True):
    off = vm_to_off(segments, va)
    if off is None:
        return f"  (no file image at vm 0x{va:x})"
    code = data[off:off + 4 * (count + 64)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for ins in md.disasm(code, va):
        out.append(f"  0x{ins.address:016x}: {ins.mnemonic:<8} {ins.op_str}")
        if stop_at_ret and ins.mnemonic in ('ret', 'retab'):
            break
        if len(out) >= count:
            break
    return "\n".join(out)

if __name__ == '__main__':
    path = sys.argv[1]
    data, cmds = parse_macho(path)
    segments = seg_ranges(cmds)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    all_hits = []
    for seg_va, seg_size, segname in ((KEXT_TEXT_VA, KEXT_TEXT_SIZE, '__TEXT'),
                                      (KEXT_TE_VA, KEXT_TE_SIZE, '__TEXT_EXEC')):
        base_off = vm_to_off(segments, seg_va)
        if base_off is None:
            print(f"[-] cannot map {segname} 0x{seg_va:x}")
            continue
        code = data[base_off:base_off + seg_size]
        print(f"[*] scanning {segname} 0x{seg_va:x}-0x{seg_va+seg_size:x} ({seg_size:#x} bytes)")

        # linear sweep: at each offset decode 8 insns, look for adrp pairs
        for off in range(0, len(code) - 8, 4):
            va = seg_va + off
            insns = list(md.disasm(code[off:off + 32], va))
            if len(insns) < 2:
                continue
            adrp_seen = {}
            for k, ins in enumerate(insns):
                if ins.mnemonic == 'adrp':
                    try:
                        reg = ins.op_str.split(',')[0].strip()
                        page = int(ins.op_str.split('#')[1], 16)
                        adrp_seen[reg] = (page, k, ins.address)
                    except Exception:
                        pass
                elif ins.mnemonic in ('add', 'ldr', 'ldrh', 'ldrb', 'ldrsb', 'ldur') and adrp_seen:
                    parts = ins.op_str.replace(',', ' ').split()
                    if len(parts) < 3:
                        continue
                    src = parts[1]
                    if not src.startswith('x') or src not in adrp_seen:
                        continue
                    page, k_adrp, a_addr = adrp_seen[src]
                    # immediate from last part
                    imm = parts[-1].lstrip('#')
                    if not imm.startswith('0x'):
                        continue
                    try:
                        imm = int(imm, 16)
                    except Exception:
                        continue
                    eff = (page & 0xfffffffffffff000) + imm
                    if WINDOW_LO <= eff < WINDOW_HI:
                        tag = "  <== TABLE region" if abs(eff - TABLE_VA) < 0x200 else ""
                        print(f"  {ins.mnemonic}@{ins.address:016x} (adrp@{a_addr:016x}) -> 0x{eff:016x}{tag}")
                        all_hits.append((a_addr, ins.address, eff, page, segname))
            if len(all_hits) > 200:
                break

    print(f"\n[*] total hits: {len(all_hits)}")
    # disassemble around nearest hits
    for a_addr, i_addr, eff, page, segname in sorted(all_hits, key=lambda h: abs(h[2] - TABLE_VA)):
        if abs(eff - TABLE_VA) > 0x200:
            continue
        print(f"\n===== {segname} ref @0x{i_addr:016x} -> 0x{eff:016x} (adrp page 0x{page:x}) =====")
        print(disasm(data, segments, i_addr - 0x40, count=70))
