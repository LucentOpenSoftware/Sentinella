#!/usr/bin/env python3
"""Generate the deterministic fuzz seed corpus for the framework / ETW /
cmdline targets (workstreams X+Y).

WHY a generator: the seeds are binary PE fixtures with internal offsets
(NSIS CRC trailers, Inno offset tables pointing into the overlay, Burn
stub-size self-references). Hand-editing them is error-prone; this script
is the single source of truth. It is fully deterministic (fixed PRNG
seeds, no timestamps) so the committed corpus is reproducible byte-for-byte:

    python fuzz/tools/gen_framework_corpus.py

Layout produced (relative to this file):
    fuzz/corpus/framework_detect/    PE files driven through framework::detect
    fuzz/corpus/framework_pe_parse/  same PE files (driven through pe::parse)
    fuzz/corpus/etw_props_layout/    32-byte param blobs for compute_layout
    fuzz/corpus/cmdline_decode/      UNICODE_STRING buffers (relative-pointer
                                     convention: the 8-byte pointer field holds
                                     a RELATIVE offset; the harness rebases it
                                     to buf.as_ptr() + (rel % buf.len()))

The same conventions are implemented by the cargo-fuzz targets and by the
no-cargo-fuzz replay tests (argus tests/installer_spoofing.rs,
sentinella-common etw_props.rs tests, sentinelld plm/cmdline.rs tests).
"""

import os
import random
import shutil
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.normpath(os.path.join(HERE, "..", "corpus"))


# ── minimal PE builder (mirrors crates/argus/tests/installer_spoofing.rs) ──

class Section:
    def __init__(self, name, vsize, raw_size, body_len=None, fill=0x41,
                 characteristics=0x60000020, raw_ptr=None):
        self.name = name
        self.vsize = vsize
        self.raw_size = raw_size
        self.body_len = raw_size if body_len is None else body_len
        self.fill = fill
        self.characteristics = characteristics
        self.raw_ptr = raw_ptr


def build_pe(sections, overlay=b"", count_override=None):
    """Returns (bytearray, raw_ptrs, overlay_start)."""
    e_lfanew = 0x80
    size_opt = 224
    buf = bytearray(e_lfanew)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    count = count_override if count_override is not None else len(sections)
    buf += b"PE\0\0"
    buf += struct.pack("<HHIIIHH", 0x14C, count, 0, 0, 0, size_opt, 0x0102)
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 56, 0x4000)
    struct.pack_into("<I", opt, 92, 16)
    buf += opt

    raw_cursor = len(buf) + len(sections) * 40
    vaddr = 0x1000
    raw_ptrs = []
    for s in sections:
        rp = s.raw_ptr if s.raw_ptr is not None else raw_cursor
        raw_ptrs.append(rp)
        raw_cursor = max(raw_cursor, rp + s.body_len)
        entry = bytearray(40)
        nb = s.name.encode()[:8]
        entry[: len(nb)] = nb
        struct.pack_into("<IIII", entry, 8, s.vsize, vaddr, s.raw_size, rp)
        struct.pack_into("<I", entry, 36, s.characteristics)
        vaddr = (vaddr + s.vsize + 0xFFF) & ~0xFFF
        buf += entry

    for s, rp in zip(sections, raw_ptrs):
        end = rp + s.body_len
        if len(buf) < end:
            buf += b"\x00" * (end - len(buf))
        for i in range(rp, end):
            buf[i] = s.fill

    overlay_start = len(buf)
    buf += overlay
    return buf, raw_ptrs, overlay_start


# ── NSIS ──

NSIS_SIG = b"\xef\xbe\xad\xdeNullsoftInst"


def nsis_firstheader(flags, header_len, arc_size):
    return struct.pack("<II", flags, 0xDEADBEEF) + b"NullsoftInst" + struct.pack(
        "<II", header_len, arc_size
    )


def nsis_pe_crc(payload_len):
    arc_size = 28 + payload_len + 4
    overlay = nsis_firstheader(0, 0x100, arc_size) + b"\xcc" * payload_len + b"\x00" * 4
    buf, _, overlay_start = build_pe(
        [Section(".text", 0x200, 0x200, raw_ptr=0x200)], overlay
    )
    assert overlay_start == 0x400
    crc_end = overlay_start + arc_size - 4
    crc = zlib.crc32(bytes(buf[0x200:crc_end]))
    struct.pack_into("<I", buf, crc_end, crc)
    return bytes(buf)


# ── Inno ──

INNO_TABLE_ID = b"rDlPtS" + bytes([0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A])


def inno_table_v2(total, offset_exe, offset0, offset1):
    rec = bytearray(64)
    rec[:12] = INNO_TABLE_ID
    struct.pack_into("<I", rec, 12, 2)
    struct.pack_into("<Q", rec, 16, total)
    struct.pack_into("<Q", rec, 24, offset_exe)
    struct.pack_into("<Q", rec, 40, offset0)
    struct.pack_into("<Q", rec, 48, offset1)
    struct.pack_into("<I", rec, 60, zlib.crc32(bytes(rec[:60])))
    return rec


def inno_pe():
    setup_id = b"Inno Setup Setup Data (6.5.0)".ljust(64, b"\x00")
    overlay = b"\x61" * 32
    off0 = len(overlay)
    overlay += setup_id + b"\x62" * 100
    offexe = len(overlay)
    overlay += b"\x63" * 50
    buf, raw_ptrs, overlay_start = build_pe(
        [
            Section(".text", 0x200, 0x200),
            Section(".rsrc", 0x200, 0x200, fill=0),
        ],
        overlay,
    )
    table_off = raw_ptrs[1] + 0x20
    total = len(buf)
    buf[table_off : table_off + 64] = inno_table_v2(
        total, overlay_start + offexe, overlay_start + off0, overlay_start
    )
    return bytes(buf)


# ── WiX Burn ──

def burn_pe():
    overlay = b"MSCF" + b"\x00" * 0x7C
    buf, raw_ptrs, overlay_start = build_pe(
        [Section(".text", 0x100, 0x100), Section(".wixburn", 0x200, 0x200)],
        overlay,
    )
    base = raw_ptrs[1]
    struct.pack_into("<I", buf, base + 0x00, 0x00F14300)  # magic
    struct.pack_into("<I", buf, base + 0x04, 2)           # version
    struct.pack_into("<I", buf, base + 0x18, overlay_start)  # dwStubSize
    struct.pack_into("<I", buf, base + 0x28, 1)           # CABINET
    struct.pack_into("<I", buf, base + 0x2C, 1)           # cContainers
    struct.pack_into("<I", buf, base + 0x30, len(overlay))   # UX size
    return bytes(buf)


# ── seeds ──

def write(rel, data):
    path = os.path.join(CORPUS, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {rel} ({len(data)} bytes)")


def main():
    rng = random.Random(0xC0FFEE)

    # framework_detect / framework_pe_parse — PE fixtures.
    minimal, _, _ = build_pe([Section(".text", 0x200, 0x200)], b"overlay-bytes")

    spoof_overlay = (
        b"Nullsoft Inst" + NSIS_SIG + b"Inno Setup" + b"Windows Installer" + b"\x99" * 64
    )
    spoofed, _, _ = build_pe(
        [Section(".text", 0x200, 0x200, raw_ptr=0x200)], spoof_overlay
    )

    malformed, _, _ = build_pe(
        [Section(".text", 0x200, 0x200, raw_ptr=0x200)],
        nsis_firstheader(4, 0x100, 28 + 128) + b"\xcc" * 128,
    )
    struct.pack_into("<I", malformed, 0x3C, len(malformed) + 0x1000)  # e_lfanew past EOF

    polyglot_overlay = b"PK\x03\x04" + b"\x00" * 60 + NSIS_SIG + b"\x00" * 64
    polyglot, _, _ = build_pe(
        [Section(".text", 0x200, 0x200, raw_ptr=0x200)], polyglot_overlay
    )

    rand = rng.randbytes(1337)

    fw = {
        "seed00-minimal-pe.bin": bytes(minimal),
        "seed01-structural-nsis.bin": nsis_pe_crc(200),
        "seed02-structural-inno.bin": inno_pe(),
        "seed03-structural-burn.bin": burn_pe(),
        "seed04-spoofed-markers.bin": bytes(spoofed),
        "seed05-malformed-all-markers.bin": bytes(malformed),
        "seed06-polyglot-mz-zip.bin": bytes(polyglot),
        "seed07-random.bin": rand,
    }
    for name, data in fw.items():
        write(f"framework_detect/{name}", data)
        write(f"framework_pe_parse/{name}", data)

    # etw_props_layout — 32-byte param blobs:
    #   [0:8] struct_size, [8:16] logger_units, [16:24] logfile_units
    #   (u64::MAX = None), [24:32] extra_bytes — all u64 LE.
    def layout_blob(struct_size, logger, logfile, extra):
        return struct.pack("<QQQQ", struct_size, logger, logfile, extra)

    U64_MAX = 0xFFFFFFFFFFFFFFFF
    write("etw_props_layout/seed00-typical.bin",
          layout_blob(120, 13, U64_MAX, 256))
    write("etw_props_layout/seed01-empty-names.bin",
          layout_blob(120, 0, 0, 0))
    write("etw_props_layout/seed02-u32-boundary.bin",
          layout_blob(120, (0xFFFFFFFF - 124) // 2, U64_MAX, 0))
    write("etw_props_layout/seed03-overflow.bin",
          layout_blob(U64_MAX, U64_MAX, U64_MAX - 1, U64_MAX))

    # cmdline_decode — UNICODE_STRING buffers, RELATIVE-pointer convention.
    def cmdline_seed(units, length_override=None, rel_ptr=16, terminate=True):
        payload = b"".join(struct.pack("<H", u) for u in units)
        if terminate:
            payload += b"\x00\x00"
        length = length_override if length_override is not None else len(units) * 2
        hdr = struct.pack("<HHIQ", length, len(payload), 0, rel_ptr)
        return hdr + payload

    wide = lambda s: [ord(c) for c in s]
    write("cmdline_decode/seed00-valid-terminated.bin",
          cmdline_seed(wide("javaw.exe -jar Component.jar")))
    write("cmdline_decode/seed01-embedded-nul.bin",
          cmdline_seed(wide("benign.exe\x00evil -DisableRealtimeMonitoring")))
    write("cmdline_decode/seed02-odd-length.bin",
          cmdline_seed(wide("ab"), length_override=3))
    write("cmdline_decode/seed03-extent-past-buffer.bin",
          cmdline_seed(wide("ab"), length_override=0xFFFE))
    write("cmdline_decode/seed04-random.bin",
          rng.randbytes(96))

    print("done — corpus is deterministic; commit the regenerated files.")


if __name__ == "__main__":
    main()
