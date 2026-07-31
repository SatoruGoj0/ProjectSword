#!/usr/bin/env python3
"""
Locate getExternalMethodForIndex-style references to the AppleJPEGDriver
dispatch table in an iOS 18 kernelcache, and map userland method indices
to table entries.

The dispatch table was previously located at vm 0xffffffff007bbfb70
(kext __DATA_CONST + 0x1af0), 10 entries x 0x28 bytes.

Methods:
  1. Raw byte searches: 8-byte and 4-byte LE values for the table base in
     both raw (0xffffffff007bbfb70) and encoded (0x8050bcad00bbfb70 /
     0x8030bcad00bbfb70) forms across the whole file.
  2. For each hit, disassemble the surrounding function to identify the
     referencing routine (getExternalMethodForIndex).
  3. Disassemble the region around a table entry base + index computation
     (x0 + idx*0x28) if findable.

Usage: python3 find_gemfi.py <kernelcache_macho>
"""
import struct, sys, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TABLE_VA = 0xfffffff007bbfb70
PTR_BASE = 0xfffffff007004000
TABLE_LOW = TABLE_VA - PTR_BASE  # 0xbbfb70

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

segments = []

def find_all(data, needle, label):
    hits = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    if hits:
        print(f"[+] {label} ({needle.hex()}): {len(hits)} hit(s) at file offsets:")
        for h in hits:
            vm = off_to_vm(segments, h)
            print(f"     0x{h:x}" + (f" (vm 0x{vm:x})" if vm else ""))
    else:
        print(f"[-] {label}: no hits")
    return hits

def disasm_at(data, segments, va, count=24, stop_at_ret=True):
    off = vm_to_off(segments, va)
    if off is None:
        return f"  (no file image at vm 0x{va:x})"
    code = data[off:off + 4 * (count + 64)]
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
    print(f"[*] File size: {len(data):#x} bytes")

    # --- Raw byte searches ---
    raw8 = struct.pack('<Q', TABLE_VA)
    enc8050 = struct.pack('<Q', (0x8050bcad << 32) | TABLE_LOW)
    enc8030 = struct.pack('<Q', (0x8030bcad << 32) | TABLE_LOW)
    low32 = struct.pack('<I', TABLE_LOW)

    h_raw = find_all(data, raw8, "raw 8-byte table ptr")
    h_8050 = find_all(data, enc8050, "encoded 0x8050bcad table ptr")
    h_8030 = find_all(data, enc8030, "encoded 0x8030bcad table ptr")

    print("\n[*] All 8-byte values with low32 == TABLE_LOW (any prefix):")
    anylow = []
    start = 0
    while True:
        idx = data.find(low32, start)
        if idx < 0:
            break
        if idx >= 4:
            pref = struct.unpack_from('<I', data, idx - 4)[0]
            print(f"     file 0x{idx-4:x} vm 0x{off_to_vm(segments, idx-4):x}: 0x{pref:08x}{struct.unpack('<I', data, idx)[0]:08x}")
            anylow.append(idx - 4)
        start = idx + 1

    # --- Disassemble around hits ---
    for label, hits in (("raw", h_raw), ("8050", h_8050), ("8030", h_8030)):
        for h in hits:
            va = off_to_vm(segments, h)
            if not va:
                continue
            print(f"\n===== {label} hit at file 0x{h:x} vm 0x{va:x} =====")
            # back up ~40 instructions and disassemble
            start_va = va - 32 * 4
            so = vm_to_off(segments, start_va)
            if so is not None and start_va > 0xfffffff007000000:
                print(disasm_at(data, segments, start_va, count=96))
            else:
                print(disasm_at(data, segments, va, count=24))

    # --- Fully disassemble startDecoder impl ---
    print("\n\n========== startDecoder impl 0xfffffff008f33680 ==========")
    print(disasm_at(data, segments, 0xfffffff008f33680, count=400))
