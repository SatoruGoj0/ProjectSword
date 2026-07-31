#!/usr/bin/env python3
"""
Focused analysis: locate the AppleJPEGDriverUserClient IOExternalMethodDispatch
table in an iOS 18 kernelcache and disassemble its methods.

Usage: python3 find_jpeg_dispatch.py <kernelcache_macho>

Strategy:
1. Parse Mach-O segments -> build (vmaddr, filesize, fileoff) ranges.
2. Locate 'AppleJPEGDriver' / 'AppleJPEGDriverUserClient' strings -> VM addr.
3. Scan __DATA_CONST / __DATA for 24-byte IOExternalMethodDispatch tables whose
   8-byte 'action' fields are all readable kernel pointers into __TEXT_EXEC.
4. Score tables against the classic AppleJPEGDriver layout:
     m0 = initializeDecoder (no I/O)
     m1 = startDecoder     (struct in)
     m2 = initializeEncoder (no I/O)
     m3 = startEncoder     (struct in)
5. Disassemble the action of each method to extract field usage.
"""
import struct, sys, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OPT_SYNTAX

MACHO_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2

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
    """Return list of (segname, vmaddr, vmsize, fileoff, filesize)."""
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

def off_to_vm(segments, off):
    for name, vmaddr, vmsize, fileoff, filesize in segments:
        if fileoff <= off < fileoff + filesize:
            return vmaddr + (off - fileoff)
    return None

def find_str(data, s):
    if isinstance(s, str):
        s = s.encode()
    return data.find(s)

def is_text_ptr(segments, val, text_seg):
    """True if val points inside __TEXT_EXEC (or __TEXT) vm range."""
    name, vmaddr, vmsize, fileoff, filesize = text_seg
    return vmaddr <= val < vmaddr + vmsize

def scan_tables(data, segments, text_seg):
    """Scan for 24-byte dispatch tables whose action fields are text pointers."""
    text_name, text_va, text_vs, text_fo, text_fs = text_seg
    # iterate all file offsets where a 24-byte entry could start
    # Build candidate entries: action ptr in text, 4 uint32 checks
    entries = []
    N = len(data) - 24
    step = 8  # tables are 8-aligned
    for off in range(0, N, step):
        action, = struct.unpack_from('<Q', data, off)
        if not is_text_ptr(segments, action, text_seg):
            continue
        sc_in, st_in, sc_out, st_out = struct.unpack_from('<IIII', data, off + 8)
        # sanity: size checks small
        if st_in > 0x4000 or st_out > 0x4000:
            continue
        if sc_in > 2 and sc_in != 0xFFFFFFFF:
            continue
        if sc_out > 2 and sc_out != 0xFFFFFFFF:
            continue
        entries.append((off, action, sc_in, st_in, sc_out, st_out))
    print(f"[*] {len(entries)} single-entry candidates with text action ptr")

    # group into tables (consecutive 24-byte entries, all actions in text)
    tables = []
    i = 0
    eoff = [e[0] for e in entries]
    used = set()
    for idx, off in enumerate(eoff):
        if off in used:
            continue
        run = [entries[idx]]
        used.add(off)
        cur = off + 24
        while True:
            # next entry must be in set
            found = None
            for j, o2 in enumerate(eoff):
                if o2 == cur and o2 not in used:
                    found = j
                    break
            if found is None:
                break
            # validate spacing & action
            action, = struct.unpack_from('<Q', data, cur)
            if not is_text_ptr(segments, action, text_seg):
                break
            used.add(cur)
            run.append(entries[found])
            cur += 24
        if len(run) >= 4:
            tables.append(run)
    print(f"[*] {len(tables)} tables with >=4 consecutive entries")
    return tables

def score_table(run):
    entries = [(e[2], e[3], e[4], e[5]) for e in run]
    score = 0
    # classic AppleJPEGDriver: m0/m2 no-I/O, m1/m3 struct in (same size)
    if len(entries) >= 4:
        e0, e1, e2, e3 = entries[0], entries[1], entries[2], entries[3]
        if e0 == (0, 0, 0, 0): score += 3
        if e2 == (0, 0, 0, 0): score += 3
        if e1[1] > 0 and e1[1] == e3[1] and e1[1] in (40, 60, 76, 80, 88, 96, 104, 112, 120):
            score += 4
        elif e1[1] > 0 and e1[1] == e3[1]:
            score += 2
    return score

def disasm(data, segments, text_seg, va, count=30):
    """Disassemble count instructions at va."""
    off = vm_to_off(segments, va)
    if off is None:
        return "  (no file image)"
    code = data[off:off + 8 * count]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    out = []
    for ins in md.disasm(code, va):
        out.append(f"    0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str}")
        if len(out) >= count:
            break
    return "\n".join(out)

def main():
    path = sys.argv[1]
    data, cmds = parse_macho(path)
    segments = seg_ranges(cmds)
    print(f"[*] Segments:")
    for name, va, vs, fo, fs in segments:
        print(f"    {name}: vm=0x{va:x}-0x{va+vs:x} file=0x{fo:x}+0x{fs:x}")

    text_seg = None
    for s in segments:
        if s[0] in ('__TEXT_EXEC', '__TEXT'):
            text_seg = s
            break
    if text_seg is None:
        print("[-] no __TEXT_EXEC/__TEXT")
        sys.exit(1)
    print(f"[*] Using text segment {text_seg[0]}")

    for s, label in [(b"AppleJPEGDriver", "service"), (b"AppleJPEGDriverUserClient", "userclient")]:
        idx = find_str(data, s)
        if idx >= 0:
            va = off_to_vm(segments, idx)
            print(f"[+] '{s.decode()}' file=0x{idx:x} vm=0x{va:x}" if va else f"[+] '{s.decode()}' file=0x{idx:x} (not mapped)")
        else:
            print(f"[-] '{s.decode()}' not found")

    tables = scan_tables(data, segments, text_seg)
    scored = [(score_table(r), r) for r in tables]
    scored.sort(key=lambda x: -x[0])

    print(f"\n[*] Top tables by score:")
    for score, run in scored[:12]:
        off = run[0][0]
        va = off_to_vm(segments, off)
        print(f"\n  table file=0x{off:x} vm=0x{va:x} score={score} ({len(run)} entries)")
        for i, (eoff, action, sc_in, st_in, sc_out, st_out) in enumerate(run):
            aoff = vm_to_off(segments, action)
            print(f"    m[{i}]: action=0x{action:016x} (file 0x{aoff:x}) scIn={sc_in:#x} stIn={st_in:#x} scOut={sc_out:#x} stOut={st_out:#x}")

    best = scored[0][1] if scored else None
    if best:
        off = best[0][0]
        va = off_to_vm(segments, off)
        print(f"\n[!!!] BEST MATCH: file=0x{off:x} vm=0x{va:x} ({len(best)} entries)")
        for i, (eoff, action, sc_in, st_in, sc_out, st_out) in enumerate(best):
            print(f"\n  === m[{i}] action=0x{action:x} scIn={sc_in:#x} stIn={st_in:#x} scOut={sc_out:#x} stOut={st_out:#x} ===")
            print(disasm(data, segments, text_seg, action, 40))
    else:
        print("\n[-] No table found")

if __name__ == '__main__':
    main()
