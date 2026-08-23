#!/usr/bin/env python3
"""
mk_tc.py -- build a v1 trust cache from the CodeDirectory of Mach-O slices.

Usage:
  mk_tc.py --out TrustCache <file or tar>...

For each input:
  - regular file: parse FAT/arm64 slices, find LC_CODE_SIGNATURE, pick the
    best CodeDirectory (highest version), compute its cdhash (SHA-1/SHA-256
    truncated to 20 bytes, per the CD's own hashSize), emit a 22-byte
    entry (20B hash + hash_type + flags).
  - tar archive (bootstrap.tar / sileo.tar): stream entries matching
    --filter suffixes (default: /uicache, /dpkg, Sileo.app/Sileo) and hash
    just those executables.

The output is a Fugu15-format v1 trust cache:
  u32 version=1 | 16B uuid | u32 length | entries (22B each, sorted)

No external deps (pure stdlib). Matches what phase6.m parses on-device.
"""
import hashlib
import os
import struct
import sys
import tarfile
import uuid

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
LC_CODE_SIGNATURE = 0x1D
CPU_TYPE_ARM64 = 0x0100000C

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0C02
CSMAGIC_CODEDIRECTORY = 0xFADE0B01


def be32(b):
    return struct.unpack(">I", b)[0]


def pick_cd(blob: bytes, off: int, size: int):
    """Return (cd_bytes, hashSize) or None."""
    if size < 8:
        return None
    magic = be32(blob[off:off + 4])
    best = None
    if magic == CSMAGIC_CODEDIRECTORY:
        ln = be32(blob[off + 4:off + 8])
        if ln >= 0x28 and ln <= size:
            best = (blob[off:off + ln], ln)
    elif magic == CSMAGIC_EMBEDDED_SIGNATURE:
        cnt = be32(blob[off + 8:off + 12])
        base = off + 12
        for i in range(cnt):
            btype, boff = struct.unpack(">II", blob[base + i * 8:base + i * 8 + 8])
            if btype != CSMAGIC_CODEDIRECTORY:
                continue
            pos = off + boff
            if pos + 8 > off + size:
                continue
            if be32(blob[pos:pos + 4]) != CSMAGIC_CODEDIRECTORY:
                continue
            ln = be32(blob[pos + 4:pos + 8])
            if ln < 0x28 or pos + ln > off + size:
                continue
            if best is None or ln > best[1]:
                best = (blob[pos:pos + ln], ln)
    return best


def cdhash_of_macho(data: bytes):
    """Yield (hash20, hash_type) per slice with an LC_CODE_SIGNATURE."""
    out = []
    first4 = struct.unpack(">I", data[:4])[0] if len(data) >= 4 else 0
    regions = []
    if first4 in (FAT_MAGIC, FAT_CIGAM):
        n = be32(data[4:8])
        for i in range(n):
            foff = data[8 + i * 20:8 + i * 20 + 20]
            cpu, _sub, off, sz = struct.unpack(">IIII", foff[:16])
            if cpu == CPU_TYPE_ARM64 and off + sz <= len(data):
                regions.append((off, sz))
        if not regions:
            for i in range(n):
                foff = data[8 + i * 20:8 + i * 20 + 20]
                off, sz = struct.unpack(">II", foff[8:16])
                if off + sz <= len(data):
                    regions.append((off, sz))
    else:
        regions = [(0, len(data))]

    for (roff, rsz) in regions:
        if rsz < 32:
            continue
        if struct.unpack("<I", data[roff:roff + 4])[0] != MH_MAGIC_64:
            continue
        ncmds = struct.unpack("<I", data[roff + 16:roff + 20])[0]
        lcp = roff + 32
        for _ in range(ncmds):
            if lcp + 24 > roff + rsz:
                break
            cmd, cmdsize = struct.unpack("<II", data[lcp:lcp + 8])
            if cmdsize < 8:
                break
            if cmd == LC_CODE_SIGNATURE:
                csoff, cssz = struct.unpack("<II", data[lcp + 8:lcp + 16])
                p = roff + csoff
                if p + cssz <= len(data):
                    cd = pick_cd(data, p, cssz)
                    if cd:
                        cdb, _ = cd
                        hs = cdb[0x24]
                        if hs == 20:
                            out.append((hashlib.sha1(cdb).digest()[:20], 1))
                        else:
                            out.append((hashlib.sha256(cdb).digest()[:20], 2))
            lcp += cmdsize
    return out


def entry_files(inputs, filters):
    """Resolve input paths to (filename, bytes) pairs to hash."""
    pairs = []
    for path in inputs:
        if not os.path.isfile(path):
            continue
        suffix_ok = any(path.endswith(f) for f in filters)
        try:
            with tarfile.open(path, "r:*") as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    if not any(m.name.endswith(f) for f in filters):
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    pairs.append((m.name, f.read()))
                continue
        except tarfile.ReadError:
            pass
        with open(path, "rb") as f:
            pairs.append((path, f.read()))
    return pairs


def build(files_with_data):
    entries = set()
    for (name, data) in files_with_data:
        res = cdhash_of_macho(data)
        if res:
            entries.update(res)
        else:
            print(f"  [!] no cdhash from {name}", file=sys.stderr)
    keys = sorted(entries)
    blob = bytearray()
    blob += struct.pack("<I", 1)                    # version
    blob += uuid.uuid4().bytes                      # uuid
    blob += struct.pack("<I", len(keys))            # length
    for h, t in keys:
        blob += h + bytes([t, 0])                   # 22B entry
    return bytes(blob)


def main():
    args = sys.argv[1:]
    out = "TrustCache"
    filters = ["/uicache", "Sileo.app/Sileo", "/dpkg", "/apt", "/ldid"]
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        del args[i:i + 2]
    while "--filter" in args:
        i = args.index("--filter")
        filters.append(args[i + 1])
        del args[i:i + 2]
    files = entry_files(args, filters)
    if not files:
        print("[-] mk_tc: nothing matched — writing empty TrustCache", file=sys.stderr)
    blob = build(files)
    with open(out, "wb") as f:
        f.write(blob)
    n = len(blob)
    cnt = struct.unpack("<I", blob[20:24])[0]
    print(f"[+] {out}: {cnt} cdhashes, {n} bytes")


if __name__ == "__main__":
    main()
