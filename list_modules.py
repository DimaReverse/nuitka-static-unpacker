#!/usr/bin/env python3
"""
list_modules.py - List modules inside an authorized Nuitka-compiled binary.

Does ONLY:
  1. PE analysis (Python version, edition)
  2. Blob extraction
  3. Protected module-name normalization when present
  4. Module name parsing from blob headers

Does NOT:
  - Reconstruct or decompile application source
  - Extract .pyc files
  - Run the disassembler
  - Write any output files

Usage:
    python list_modules.py authorized_app.exe
    python list_modules.py authorized_app.exe --json
    python list_modules.py authorized_app.exe --filter mypackage
    python list_modules.py authorized_app.exe --filter mypackage --copy-cmd
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zlib
from pathlib import Path
from random import Random

# ---------------------------------------------------------------------------
# Minimal standalone implementations — no dependency on nuitka_decompiler.py
# (so this script works even if you haven't set up the full tool)
# ---------------------------------------------------------------------------

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ---- Protected module-name decoding ----------------------------------------

def _build_mapping2() -> list[int]:
    """Build a module-name decoding table for supported protected layouts."""
    r = Random(27)
    fwd = list(range(1, 256))
    r.shuffle(fwd)
    fwd.insert(0, 0)
    return fwd


_MAPPING2 = _build_mapping2()


def decode_module_name(raw: bytes) -> str:
    """Decode a module name from a supported protected layout."""
    return bytes(_MAPPING2[b] for b in raw).decode("utf-8", errors="replace")


# ── Blob extraction (minimal PE walk) ───────────────────────────────────────

def _find_blob_in_pe(path: str) -> tuple[bytes | None, str]:
    """
    Return (blob_bytes, source_description).
    Tries pefile first for reliability; falls back to a raw scan.
    """
    data = Path(path).read_bytes()

    if HAS_PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            pe.parse_data_directories()

            # Try PE resources first
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for res_id in res_type.directory.entries:
                        for res_lang in res_id.directory.entries:
                            rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            try:
                                chunk = pe.get_data(rva, size)
                                if len(chunk) >= 8:
                                    return chunk, "PE resource"
                            except Exception:
                                pass

            # Try sections: look for one that starts with CRC+size pattern
            for section in pe.sections:
                raw = data[section.PointerToRawData:
                           section.PointerToRawData + section.SizeOfRawData]
                if len(raw) >= 8:
                    declared = struct.unpack_from("<I", raw, 4)[0]
                    if 8 + declared <= len(raw) <= 8 + declared + 4096:
                        actual_crc = zlib.crc32(raw[8:8 + declared]) & 0xFFFFFFFF
                        stored_crc = struct.unpack_from("<I", raw, 0)[0]
                        if actual_crc == stored_crc:
                            sec_name = section.Name.rstrip(b'\x00').decode('ascii', 'replace')
                            return raw, f"section {sec_name}"

        except Exception:
            pass

    # Raw scan fallback: find first occurrence of a plausible blob header
    # (4-byte CRC, 4-byte size, then data matches CRC)
    for off in range(0, len(data) - 8, 4):
        stored_crc = struct.unpack_from("<I", data, off)[0]
        declared   = struct.unpack_from("<I", data, off + 4)[0]
        if declared < 1024 or declared > 64 * 1024 * 1024:
            continue
        if off + 8 + declared > len(data):
            continue
        actual_crc = zlib.crc32(data[off + 8: off + 8 + declared]) & 0xFFFFFFFF
        if actual_crc == stored_crc:
            return data[off: off + 8 + declared], "raw scan"

    return None, "not found"


# ── Blob module-name parser ──────────────────────────────────────────────────

def _is_likely_encrypted(blob: bytes) -> bool:
    """Quick check: if CRC doesn't match, blob is encrypted."""
    if len(blob) < 8:
        return False
    stored = struct.unpack_from("<I", blob, 0)[0]
    declared = struct.unpack_from("<I", blob, 4)[0]
    if 8 + declared > len(blob):
        return True
    actual = zlib.crc32(blob[8:8 + declared]) & 0xFFFFFFFF
    return actual != stored


def _parse_module_names(blob: bytes, is_commercial: bool) -> list[dict]:
    """
    Parse only the module names from the blob (no constant decoding).
    Returns list of dicts: {name, size, is_main, is_bytecode}.
    """
    data = blob[8:]  # skip CRC + declared_size
    offset = 0
    modules = []

    while offset < len(data) - 5:
        name_end = data.find(b"\x00", offset, min(offset + 512, len(data)))
        if name_end == -1:
            break

        raw_name = data[offset:name_end]
        offset = name_end + 1

        if offset + 4 > len(data):
            break
        chunk_size = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        if chunk_size > 128 * 1024 * 1024 or offset + chunk_size > len(data):
            break

        # Decode name
        try:
            name = raw_name.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            if is_commercial:
                name = decode_module_name(raw_name)
            else:
                name = raw_name.decode("utf-8", errors="replace")

        modules.append({
            "name": name,
            "size": chunk_size,
            "is_main": (name in ("__main__", "") or
                        (not name.startswith("_") and "." not in name and
                         not name.startswith("nuitka"))),
            "is_bytecode": name == ".bytecode",
        })

        offset += chunk_size

    return modules


# ── Main ─────────────────────────────────────────────────────────────────────

def list_modules(target: str,
                 as_json: bool = False,
                 filter_str: str | None = None,
                 copy_cmd: bool = False) -> int:

    if not os.path.isfile(target):
        print(f"[ERROR] File not found: {target}", file=sys.stderr)
        return 1

    if not HAS_PEFILE:
        print("[WARN] pefile not installed — using raw scan fallback (less reliable)")
        print("       Install with: pip install pefile\n")

    blob, source = _find_blob_in_pe(target)
    if blob is None:
        print(f"[ERROR] Could not find Nuitka constants blob in {target}", file=sys.stderr)
        print("        Is this a Nuitka-compiled binary?", file=sys.stderr)
        return 1

    is_enc = _is_likely_encrypted(blob)
    is_commercial = is_enc  # encrypted → commercial build

    modules = _parse_module_names(blob, is_commercial)

    if not modules:
        print("[ERROR] Blob found but no modules parsed — format may be unsupported.",
              file=sys.stderr)
        return 1

    # Apply filter
    if filter_str:
        f = filter_str.lower()
        modules = [m for m in modules if f in m["name"].lower()]

    # ── Output ──────────────────────────────────────────────────────────────

    if as_json:
        print(json.dumps(modules, indent=2))
        return 0

    total = len(modules)
    enc_label = "protected metadata" if is_enc else "plain metadata"
    print(f"\n  Target  : {os.path.basename(target)}")
    print(f"  Blob    : {source}")
    print(f"  Edition : {enc_label}")
    print(f"  Modules : {total}")
    if filter_str:
        print(f"  Filter  : '{filter_str}'")
    print()
    print(f"  {'#':<5}  {'MODULE NAME':<55}  {'SIZE':>9}  {'NOTE'}")
    print("  " + "─" * 80)

    for i, m in enumerate(modules, 1):
        note = ""
        if m["is_bytecode"]:
            note = "← .pyc bytecode chunk"
        elif m["is_main"]:
            note = "← likely main module"
        size_kb = m["size"] / 1024
        print(f"  {i:<5}  {m['name']:<55}  {size_kb:>7.1f} KB  {note}")

    print()

    if copy_cmd:
        names = ",".join(m["name"] for m in modules if not m["is_bytecode"])
        print("  ── Ready to use with --only: ──────────────────────────────────")
        print(f"  python nuitka_decompiler.py --source {os.path.basename(target)} --only {names}")
        print()

    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="list_modules",
        description="List modules inside an authorized Nuitka binary. Fast; no source reconstruction.",
    )
    ap.add_argument("target", help="Authorized Nuitka-compiled .exe or .dll")
    ap.add_argument("--json", action="store_true",
                    help="Output as JSON (for scripting)")
    ap.add_argument("--filter", metavar="STR", default=None,
                    help="Only show modules whose name contains STR (case-insensitive)")
    ap.add_argument("--copy-cmd", action="store_true",
                    help="Print a ready-to-run --only command at the end")
    args = ap.parse_args(argv)
    return list_modules(args.target, args.json, args.filter, args.copy_cmd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
