#!/usr/bin/env python3
"""
Analyze AppleJPEGDriver IOExternalMethodDispatch from a kernelcache.

Usage: python3 analyze_jpeg_dispatch.py <kernelcache_macho>

Strategy:
1. Locate 'AppleJPEGDriver' string (service name used by IOServiceNameMatching).
2. Find the AppleJPEGDriverUserClient meta-class and its vtable via the
   AppleJPEGDriver string xref (class name table in __DATA_CONST).
3. Search for IOExternalMethodDispatch tables:
   struct IOExternalMethodDispatch {
       IOExternalMethodAction action;   // 8 bytes on arm64 (PAC-signed pointer)
       uint32_t checkScalarInputCount;
       uint32_t checkStructureInputSize;
       uint32_t checkScalarOutputCount;
       uint32_t checkStructureOutputSize;
   };  // total 24 bytes per entry on arm64/arm64e
4. AppleJPEGDriver method table (from Apple Wiki / gist):
   method 0 = initializeDecoder  (no I/O)
   method 1 = startDecoder      (40B struct in)
   method 2 = initializeEncoder (no I/O)
   method 3 = startEncoder      (40B struct in)
"""
import struct, sys, os, re

MACHO_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
CPU_ARM64 = 0x0100000C
CPU_ARM64E = 0x0100000C | 0x100

def parse_macho(path):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 8:
        print(f"[-] File too small ({len(data)} bytes)")
        return None
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic == MACHO_MAGIC_64:
        pass
    elif struct.unpack_from('>I', data, 0)[0] == MACHO_MAGIC_64:
        print("[-] Big-endian Mach-O? unexpected for arm64")
        return None
    else:
        print(f"[-] Not a 64-bit Mach-O (magic=0x{magic:08x})")
        return None

    ncmds, cpu = struct.unpack_from('<II', data, 16)[0], struct.unpack_from('<I', data, 4)[0]
    print(f"[*] Mach-O: {ncmds} load commands, cpu=0x{cpu:08x}")
    if cpu == CPU_ARM64E:
        print("[*] Architecture: arm64e (PAC) - dispatch 'action' is 8-byte PAC pointer")
    elif cpu == CPU_ARM64:
        print("[*] Architecture: arm64 - dispatch 'action' is 8-byte pointer")

    cmds = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        cmds.append((cmd, cmdsize, data[off:off+cmdsize]))
        off += cmdsize
    return data, cmds

def find_string(data, s):
    return data.find(s.encode())

def find_section(cmds, segname, sectname):
    for cmd, cmdsize, payload in cmds:
        if cmd == LC_SEGMENT_64:
            name = payload[8:24].rstrip(b'\x00').decode()
            if name == segname:
                nsects = struct.unpack_from('<I', payload, 0x44)[0]
                sect_off = 0x48
                for _ in range(nsects):
                    sname = payload[sect_off:sect_off+16].rstrip(b'\x00').decode()
                    if sname == sectname:
                        addr = struct.unpack_from('<Q', payload, sect_off+0x20)[0]
                        size = struct.unpack_from('<Q', payload, sect_off+0x28)[0]
                        fileoff = struct.unpack_from('<Q', payload, sect_off+0x30)[0]
                        return fileoff, size, addr
                    sect_off += 0x50
    return None

def find_dispatch_tables(data, min_entries=4):
    """Find arrays of IOExternalMethodDispatch (24B stride) in the binary.

    A valid entry: action != 0 (8 bytes), then 4 uint32 fields. For
    AppleJPEGDriver we expect entries 0 and 2 to be no-I/O (all zero fields),
    and 1 and 3 to have a small non-zero checkStructureInputSize.
    Returns list of (file_offset, [entry dicts]).
    """
    results = []
    # Regex for 24-byte entry: 8 bytes (func) + 4 bytes count + 4 bytes size + 4 count + 4 size
    # We search for candidate struct-size fields (0x00000000..0x00000200) in LE.
    # To limit noise, require the scalar counts (offset +8 and +16) to be 0 or 0xFFFFFFFF.
    entry_re = re.compile(
        b'(?s)'
        b'(.){8}'                      # action (8 bytes)
        b'(\x00\x00\x00\x00|\xff\xff\xff\xff)'  # checkScalarInputCount
        b'(.{4})'                      # checkStructureInputSize
        b'(\x00\x00\x00\x00|\xff\xff\xff\xff)'  # checkScalarOutputCount
        b'(.{4})'                      # checkStructureOutputSize
    )

    # Iterate over all 24-byte windows is too slow in Python on 500MB.
    # Instead use finditer but only scan the __DATA_CONST / __DATA / __TEXT_EXEC ranges if possible.
    # Fall back to chunked search over whole file.

    # Fast path: use regex on the whole buffer but it's anchored per position...
    # Better: scan with find over a packed 4-byte size pattern then check context.
    # A plausible struct size (0 < size <= 0x200) followed 8 bytes later by count 0/0xFFFFFFFF.
    found_offsets = set()
    # Search for size bytes: little-endian 4 bytes where value in [1, 512]
    for size_val in range(4, 257, 4):
        size_bytes = struct.pack('<I', size_val)
        start = 0
        while True:
            idx = data.find(size_bytes, start)
            if idx < 0:
                break
            # candidate: this size is at entry offset +8 (after 8-byte action + 4-byte scalarInCnt)
            # So entry start = idx - 12
            entry_start = idx - 12
            if entry_start >= 0:
                # validate the 8-byte action is non-zero
                action = struct.unpack_from('<Q', data, entry_start)[0]
                if action != 0:
                    # validate scalarInCnt
                    sc_in = struct.unpack_from('<I', data, entry_start + 8)[0]
                    sc_out = struct.unpack_from('<I', data, entry_start + 16)[0]
                    if sc_in in (0, 0xFFFFFFFF) and sc_out in (0, 0xFFFFFFFF):
                        found_offsets.add(entry_start)
            start = idx + 1

    print(f"[*] Found {len(found_offsets)} candidate dispatch entries (24B stride)")

    # Now group consecutive entries
    for off in sorted(found_offsets):
        # Try to build a run starting at off
        run = []
        for i in range(8):
            e = off + i * 24
            if e + 24 > len(data):
                break
            action = struct.unpack_from('<Q', data, e)[0]
            if action == 0:
                break
            sc_in = struct.unpack_from('<I', data, e + 8)[0]
            st_in = struct.unpack_from('<I', data, e + 12)[0]
            sc_out = struct.unpack_from('<I', data, e + 16)[0]
            st_out = struct.unpack_from('<I', data, e + 20)[0]
            if sc_in not in (0, 0xFFFFFFFF) or sc_out not in (0, 0xFFFFFFFF):
                break
            if st_in > 0x1000 or st_out > 0x1000:
                break
            run.append((e, action, sc_in, st_in, sc_out, st_out))
        if len(run) >= min_entries:
            # Dedup: keep the longest run starting at each offset
            key = run[0][0]
            results.append(run)

    # Dedup overlapping
    dedup = []
    seen = set()
    for run in sorted(results, key=lambda r: -len(r)):
        if run[0][0] in seen:
            continue
        seen.add(run[0][0])
        dedup.append(run)
    return dedup

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <kernelcache_macho>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"[-] {path} not found")
        sys.exit(1)

    print(f"[*] Analyzing {path} ({os.path.getsize(path) / 1e6:.1f} MB)")

    parsed = parse_macho(path)
    if parsed is None:
        sys.exit(1)
    data, cmds = parsed

    # 1. Find service name strings
    svc = b"AppleJPEGDriver"
    idx = find_string(data, svc)
    if idx >= 0:
        print(f"[+] 'AppleJPEGDriver' at file offset 0x{idx:x}")
        # If inside __TEXT_EXEC, also give VM address
        for seg in ['__TEXT_EXEC', '__TEXT', '__DATA', '__DATA_CONST']:
            sect = find_section(cmds, seg, '__cstring')
            if sect:
                if sect[0] <= idx < sect[0] + sect[1]:
                    va = sect[2] + (idx - sect[0])
                    print(f"    -> in {seg}.__cstring, VA=0x{va:x}")
                    break
    else:
        print("[-] 'AppleJPEGDriver' not found")

    cls = b"AppleJPEGDriverUserClient"
    idx2 = find_string(data, cls)
    if idx2 >= 0:
        print(f"[+] '{cls.decode()}' at file offset 0x{idx2:x}")
    else:
        print("[-] 'AppleJPEGDriverUserClient' not found")

    # 2. Find dispatch tables
    print("\n[*] Searching for IOExternalMethodDispatch tables (24B stride)...")
    tables = find_dispatch_tables(data)
    print(f"[+] Found {len(tables)} candidate tables")

    best = None
    for run in tables:
        entries = []
        for (e, action, sc_in, st_in, sc_out, st_out) in run:
            entries.append((sc_in, st_in, sc_out, st_out))
        # Score: AppleJPEGDriver has entries 0 and 2 = no-I/O
        score = 0
        for i, ent in enumerate(entries):
            if i in (0, 2) and ent == (0, 0, 0, 0):
                score += 2
            if i in (1, 3) and ent[1] in (40, 60, 76, 80, 88, 96):
                score += 2
        print(f"\n  --- table at file offset 0x{run[0][0]:x} ({len(entries)} entries, score={score}) ---")
        for i, (e, action, sc_in, st_in, sc_out, st_out) in enumerate(run):
            flag = ""
            if i in (0, 2) and (sc_in, st_in, sc_out, st_out) == (0, 0, 0, 0):
                flag = "  <-- initialize* no-I/O"
            elif i in (1, 3) and st_in > 0:
                flag = "  <-- start* struct input size"
            print(f"    m[{i}]: action=0x{action:016x} scIn={sc_in:#x} stIn={st_in:#x} scOut={sc_out:#x} stOut={st_out:#x}{flag}")
        if score >= 4:
            best = run

    if best:
        print("\n[!!!] BEST MATCH - likely AppleJPEGDriver dispatch table:")
        for i, (e, action, sc_in, st_in, sc_out, st_out) in enumerate(best):
            print(f"  method {i}: struct_input_size = {st_in:#x} ({st_in}), struct_output_size = {st_out:#x} ({st_out})")
    else:
        print("\n[*] No strong AppleJPEGDriver match found - will need cross-referencing")

    # 3. Print useful sections
    print("\n[*] Sections:")
    for seg in ['__TEXT_EXEC', '__DATA', '__DATA_CONST', '__LINKEDIT']:
        for sname in ['__cstring', '__const', '__data', '__objc_data']:
            sect = find_section(cmds, seg, sname)
            if sect:
                print(f"    {seg}.{sname}: file=0x{sect[0]:x} size=0x{sect[1]:x} va=0x{sect[2]:x}")

if __name__ == '__main__':
    main()
