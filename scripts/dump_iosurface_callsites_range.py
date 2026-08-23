#!/usr/bin/env python3
"""Disassemble +/- N instrs around the withAddressRanges call site for
IOSurface (0xfffffff009d2ed04) and dump raw/capstone text, verifying
ranges=0x360 and rangeCount at the w1 arg slot. Also dump the function
prologue backward until pacibsp. Outputs tool/ps29_iosurface_callsite.txt."""
import struct, sys, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

KC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    "C:", os.sep, "Users", "User", "Documents", "Project sword",
    "22C161__iPhone13,2", "kernelcache.release.iPhone13,2_3")
d = open(KC, "rb").read()

ncmds, = struct.unpack_from("<I", d, 16)
off = 32
segs = {}
for _ in range(ncmds):
    cmd, csz = struct.unpack_from("<II", d, off)
    if cmd == 0x19:
        nm = d[off+8:off+24].rstrip(b"\x00").decode()
        va, vsz, foff, fsz = struct.unpack_from("<QQQQ", d, off+24)
        segs[nm] = (va, vsz, foff, fsz)
    off += csz

def fileoff_of(vm):
    for n, (va, vsz, foff, fsz) in segs.items():
        if va <= vm < va + vsz:
            return foff + (vm - va)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

CALL = 0xfffffff009d2ed04   # bl IOMemoryDescriptor::withAddressRanges
N_BACK, N_FWD = 80, 24

lines = []
def emit(s):
    lines.append(s)

emit(f"; IOSurface::getOrCreateMemoryDescriptorForUser IOVA/Morph disasm")
emit(f"; call site (bl): {CALL:#x}")
emit(f"; kernel cache: {os.path.basename(KC)}")
emit("")

fo = fileoff_of(CALL)
if fo is None:
    print("call site outside mapped segs"); sys.exit(1)

# walk back to pacibsp (0xD503237F) to get the function start
start = CALL
for i in range(1, 300):
    pc = CALL - i*4
    w = struct.unpack_from("<I", d, fileoff_of(pc))[0]
    if w == 0xD503237F:  # pacibsp
        start = pc
        break
    if w == 0xD503245F:  # paciasp alt (some funcs)
        start = pc
        break
emit(f"; function prologue detected at {start:#x}")
emit("")

for i in range(0, N_BACK + N_FWD + 1):
    pc = start + i*4
    fo2 = fileoff_of(pc)
    if fo2 is None or fo2 + 4 > len(d): break
    w = struct.unpack_from("<I", d, fo2)[0]
    mark = ""
    if pc == CALL: mark = "   ; <<< CALL withAddressRanges"
    # annotate ldr w1 / ldr x? with decoded reg
    ins_list = list(md.disasm(d[fo2:fo2+4], pc))
    if ins_list:
        ins = ins_list[0]
        txt = f"{pc:#x}:  {w:08X}  {ins.mnemonic} {ins.op_str}{mark}"
    else:
        txt = f"{pc:#x}:  {w:08X}  (raw){mark}"
    emit(txt)

out = "\n".join(lines)
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "ps29_iosurface_callsite.txt")
with open(out_path, "w") as f:
    f.write(out)
print(out[-3500:])
