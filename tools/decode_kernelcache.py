#!/usr/bin/env python3
"""
Decode a kernelcache IMG4 from an IPSW into a raw Mach-O.

Usage: python3 decode_kernelcache.py <input_kernelcache> <output_path>
"""
import sys, os, struct

def is_img4(data):
    return data[:4] == b'IM4P'

def try_pyimg4(data, out_path):
    try:
        import pyimg4
    except ImportError:
        print("[-] pyimg4 not installed")
        return False

    try:
        im4p = pyimg4.IM4P(data)
        print(f"[*] IM4P type={im4p.type.decode(errors='replace')}")
        print(f"[*] description={im4p.description}")
        print(f"[*] payload size={len(im4p.payload)}")

        # Try decompress
        try:
            payload = im4p.payload.decompress()
            print(f"[+] Decompressed to {len(payload)} bytes")
            with open(out_path, 'wb') as f:
                f.write(payload)
            return True
        except Exception as e:
            print(f"[-] Decompress failed: {e}")
            print("    (payload may be encrypted - need img4 keys)")

            # Try writing the raw payload anyway
            with open(out_path + '.raw', 'wb') as f:
                f.write(im4p.payload)
            print(f"[*] Wrote raw payload to {out_path}.raw")
            return False
    except Exception as e:
        print(f"[-] pyimg4 parse failed: {e}")
        return False

def manual_decode(data, out_path):
    """Manual IM4P parser fallback."""
    if data[:4] != b'IM4P':
        print("[-] Not an IM4P file")
        return False

    # IM4P format: 'IM4P' + type(4) + description(len:1 + bytes) + data(len:4 BE) + ... + 'IM4P' + data
    # Actually format: IM4P [type:4] [description_len:1] [description] [len:4 BE] [data]
    print("[*] Manual IM4P parse...")
    type = data[4:8]
    desc_len = data[8]
    desc = data[9:9+desc_len]
    dlen = struct.unpack('>I', data[9+desc_len:13+desc_len])[0]
    payload = data[13+desc_len:13+desc_len+dlen]
    print(f"[*] type={type} desc={desc} payload={len(payload)} bytes")

    # Check for compression: LZFSE, ZLIB, or raw
    # Look for common compression magic
    if payload[:4] == b'bv44':  # LZFSE magic (bv44)
        print("[*] LZFSE compressed - need lzfse library")
        try:
            import lzfse
            decompressed = lzfse.decompress(payload)
            with open(out_path, 'wb') as f:
                f.write(decompressed)
            print(f"[+] LZFSE decompressed to {len(decompressed)} bytes")
            return True
        except ImportError:
            print("[-] lzfse not installed (pip3 install lzfse)")
        except Exception as e:
            print(f"[-] LZFSE decompress failed: {e}")
    elif payload[:2] == b'\x78\x9c' or payload[:2] == b'\x78\xda':
        print("[*] ZLIB compressed")
        import zlib
        try:
            decompressed = zlib.decompress(payload)
            with open(out_path, 'wb') as f:
                f.write(decompressed)
            print(f"[+] ZLIB decompressed to {len(decompressed)} bytes")
            return True
        except Exception as e:
            print(f"[-] ZLIB decompress failed: {e}")
    else:
        print(f"[*] No known compression magic ({payload[:8].hex()})")
        print("[*] Writing raw payload")
        with open(out_path, 'wb') as f:
            f.write(payload)
        return True

    return False

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input> <output>")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]
    if not os.path.exists(in_path):
        print(f"[-] {in_path} not found")
        sys.exit(1)

    with open(in_path, 'rb') as f:
        data = f.read()

    print(f"[*] Input: {in_path} ({len(data)} bytes)")
    print(f"[*] Magic: {data[:4]}")

    if is_img4(data):
        print("[*] IMG4 (IM4P) container detected")
        if not try_pyimg4(data, out_path):
            print("[*] pyimg4 failed, trying manual parse")
            manual_decode(data, out_path)
    else:
        # Might already be a raw Mach-O or compressed
        if data[:4] == b'\xfe\xed\xfa\xcf' or data[:4] == b'\xcf\xfa\xed\xfe':
            print("[*] Already a Mach-O, copying")
            with open(out_path, 'wb') as f:
                f.write(data)
            print(f"[+] Copied to {out_path}")
        else:
            print("[*] Unknown format, trying manual decode")
            manual_decode(data, out_path)

if __name__ == '__main__':
    main()
