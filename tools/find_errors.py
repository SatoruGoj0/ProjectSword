#!/usr/bin/env python3
"""
Fast scan for IOKit error-constant construction across the kernelcache.

Finds `mov wX, #lo16; movk wX, #0xe000, lsl #16` byte patterns
(which produce 0xe000xxxx IOReturns) using raw-byte search.

Usage: python3 find_errors.py <kernelcache_macho>
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

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

    # movk wX, #0xe000, lsl#16 = 0x72BC0000 | X ; LE bytes: [X] 00 BC 72
    needle = b'\x00\xbc\x72'
    hits = {}
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        # register byte is at idx-1
        if idx >= 1:
            reg = data[idx - 1]
            # look backwards up to 6 insns for movz w<same reg>, #imm
            lo = None
            for back in range(4, 4 + 6 * 4, 4):
                cand = idx - 1 - back
                if cand < 0:
                    break
                ins = struct.unpack_from('<I', data, cand)[0]
                # MOVZ Wd,#imm16 (sf=0): (ins & 0xFF800000) == 0x52800000
                if (ins & 0xFF800000) == 0x52800000:
                    imm = (ins >> 5) & 0xFFFF
                    rd = ins & 0x1F
                    if rd == reg:
                        lo = imm
                        break
            if lo is not None:
                err = (0xe000 << 16) | lo
                if err not in hits:
                    hits[err] = idx - 1  # va of the movk
        start = idx + 1

    print(f"[*] IOKit error constants constructed via movz/movk (0xe000xxxx):")
    for err, off in sorted(hits.items()):
        va = off_to_vm(segments, off)
        print(f"    0xe000{err & 0xFFFF:04x}  at file 0x{off:x}" + (f" vm 0x{va:016x}" if va else ""))

    want = [0xe00002c2, 0xe00002c1, 0xe00002c0, 0xe00002bc, 0xe00002bd, 0xe00002d1, 0xe00002c7]
    print("\n[*] Disassembling functions containing the wanted errors:")
    for err in want:
        off = hits.get(err)
        if off is None:
            print(f"    (0xe000{err & 0xFFFF:04x}: not constructed via movz/movk pattern)")
            continue
        va = off_to_vm(segments, off)
        if not va:
            continue
        print(f"\n===== 0xe000{err & 0xFFFF:04x} at vm 0x{va:016x} =====")
        print(disasm(data, segments, va - 0x60, count=80))
