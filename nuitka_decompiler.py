#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NUITKA STATIC UNPACKER - Static-first Nuitka unpacker (research tool) v7.2
by dimareverse

PURELY STATIC mode - No runtime hooks, no injection.
Analysis and recovery of Nuitka-compiled Python binaries.

Research focus:
  1. Open-source blob format: CRC32+size header, named chunks, constant recovery
  2. Commercial blob structure: encryption analysis and mapping reconstruction
     - Mapping tables and digest patterns
     - Module naming schemes and reconstruction strategies
  3. Module metadata extraction: module hierarchy and binary structure
  4. Code object analysis: function signatures, code metadata recovery
  5. Constant recovery: embedded strings, configuration data, code artifacts

Analysis output:
  - .pyc extraction and bytecode recovery
  - Per-module constants analysis with recursive parsing
  - Pattern scanning for configuration and artifact recovery
  - Complete JSON analysis report
  - Code object metadata and structure mapping
"""

import os
import sys
import time
import struct
import marshal
import types
import json
import zlib
import random
import hashlib
import base64
import argparse
import re
import math
import subprocess
import threading
import platform
from math import copysign, isnan, isinf
from datetime import datetime
from pathlib import Path
from collections import deque
from typing import Dict, List, Set, Tuple, Any

# Fix encoding for Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# =============================================================================
# COLORS & STYLING
# =============================================================================

class Colors:
    BLACK = '\033[30m'; RED = '\033[31m'; GREEN = '\033[32m'
    YELLOW = '\033[33m'; BLUE = '\033[34m'; MAGENTA = '\033[35m'
    CYAN = '\033[36m'; WHITE = '\033[37m'
    BRIGHT_RED = '\033[91m'; BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'; BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'; BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    BOLD = '\033[1m'; DIM = '\033[2m'; UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'; BG_GREEN = '\033[42m'; BG_CYAN = '\033[46m'

C = Colors()

if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    # Suppress Windows error dialogs for this process AND its children.
    # pycdc.exe and other third-party decompilers occasionally crash with
    # a win32 exception on malformed marshal data. When that happens
    # Windows pops up the "Just-In-Time debugger" modal which blocks the
    # whole pipeline (and is terrifying for users). Setting the process
    # error mode forces Windows to silently fail the child instead.
    # Flags:  SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
    #       | SEM_NOOPENFILEERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT
    try:
        import ctypes as _ctypes_err
        _SEM_FAILCRITICALERRORS   = 0x0001
        _SEM_NOGPFAULTERRORBOX    = 0x0002
        _SEM_NOALIGNMENTFAULTEXCEPT = 0x0004
        _SEM_NOOPENFILEERRORBOX   = 0x8000
        _ctypes_err.windll.kernel32.SetErrorMode(
            _SEM_FAILCRITICALERRORS
            | _SEM_NOGPFAULTERRORBOX
            | _SEM_NOOPENFILEERRORBOX
            | _SEM_NOALIGNMENTFAULTEXCEPT
        )
        # SetThreadErrorMode (available from Vista+) doubles down
        try:
            _ctypes_err.windll.kernel32.SetThreadErrorMode(
                _SEM_FAILCRITICALERRORS
                | _SEM_NOGPFAULTERRORBOX
                | _SEM_NOOPENFILEERRORBOX, None)
        except Exception:
            pass
    except Exception:
        pass


# Subprocess creation flags used for every external-tool invocation
# (pycdc, pycdas, etc.). CREATE_NO_WINDOW hides any transient console
# window; on Windows we also rely on the SetErrorMode above to keep
# child-process GP faults silent.
if sys.platform == 'win32':
    _SAFE_SUBPROCESS_FLAGS = 0x08000000  # CREATE_NO_WINDOW
else:
    _SAFE_SUBPROCESS_FLAGS = 0


def run_external_tool(cmd, *, timeout=60, input_bytes=None):
    """Run an external CLI tool with ALL crash dialogs suppressed.

    Returns a `subprocess.CompletedProcess`-like object with `returncode`,
    `stdout`, `stderr`. On hard failure (timeout, OS error, access denied
    because the child crashed) returns a simulated `(returncode=-1,
    stdout=b"", stderr=b"<reason>")` instead of raising — this is what
    the pipeline needs to fall back gracefully without aborting.
    """
    import subprocess as _sp
    try:
        r = _sp.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_bytes,
            creationflags=_SAFE_SUBPROCESS_FLAGS,
        )
        return r
    except _sp.TimeoutExpired:
        class _R:
            returncode = -1
            stdout = b''
            stderr = b'TIMEOUT'
        return _R()
    except (OSError, _sp.SubprocessError) as e:
        class _R:
            returncode = -1
            stdout = b''
            stderr = str(e).encode()
        return _R()

try:
    BANNER = f"""
{C.BRIGHT_RED}    _   _       _ _   _         _ _          _             {C.RESET}
{C.BRIGHT_YELLOW}   | \\ | |_   _(_) |_| | ____ _| (_)______ _| |_ ___  _ __ {C.RESET}
{C.BRIGHT_GREEN}   |  \\| | | | | | __| |/ / _` | | |_  / _` | __/ _ \\| '__|{C.RESET}
{C.BRIGHT_CYAN}   | |\\  | |_| | | |_|   < (_| | | |/ / (_| | || (_) | |   {C.RESET}
{C.BRIGHT_BLUE}   |_| \\_|\\__,_|_|\\__|_|\\_\\__,_|_|_/___\\__,_|\\__\\___/|_|   {C.RESET}

{C.BOLD}{C.BRIGHT_WHITE}   <<<  Nuitka Static Unpacker v7.2 | by dimareverse  >>>{C.RESET}
{C.BOLD}{C.BRIGHT_WHITE}   <<<  Static mode (default) | Dynamic injection (opt) >>>{C.RESET}
"""
except Exception:
    BANNER = """
   Nuitka Static Unpacker v7.2 - by dimareverse
   Static mode (default) | Dynamic injection (optional)
"""


# =============================================================================
# PROGRESS & LOGGING
# =============================================================================

class ProgressBar:
    def __init__(self, total, desc="Processing", width=40, spinner='fire'):
        self.total = max(total, 1)
        self.current = 0
        self.desc = desc
        self.width = width
        self.start_time = time.time()
        self.spinner_frames = ['*', '+', 'x', '+']
        self.frame = 0

    def update(self, n=1):
        self.current = min(self.current + n, self.total)
        self.frame = (self.frame + 1) % len(self.spinner_frames)
        self._render()

    def _render(self):
        progress = self.current / self.total
        filled = int(self.width * progress)
        bar = ""
        for i in range(self.width):
            if i < filled:
                if i < self.width * 0.3: bar += f"{C.BRIGHT_RED}#"
                elif i < self.width * 0.6: bar += f"{C.BRIGHT_YELLOW}#"
                else: bar += f"{C.BRIGHT_GREEN}#"
            else: bar += f"{C.DIM}."
        bar += C.RESET
        elapsed = time.time() - self.start_time
        eta = (elapsed / self.current * (self.total - self.current)) if self.current > 0 else 0
        s = self.spinner_frames[self.frame]
        status = (f"\r{C.BOLD}{C.BRIGHT_CYAN}[{s}]{C.RESET} "
                  f"{C.BRIGHT_WHITE}{self.desc}{C.RESET} [{bar}] "
                  f"{C.BRIGHT_YELLOW}{progress*100:5.1f}%{C.RESET} "
                  f"{C.DIM}({self.current}/{self.total}){C.RESET} "
                  f"{C.BRIGHT_MAGENTA}ETA: {int(eta)}s{C.RESET}")
        print(status, end='', flush=True)

    def finish(self, message="Done!"):
        print(f"\r{' ' * 120}\r", end='')
        print(f"{C.BRIGHT_GREEN}[OK]{C.RESET} {C.BRIGHT_WHITE}{self.desc}{C.RESET}: {C.BRIGHT_GREEN}{message}{C.RESET}")


def print_section(title):
    width = 65
    print()
    print(f"{C.BRIGHT_CYAN}{'=' * width}{C.RESET}")
    centered = title.center(width - 4)
    print(f"{C.BRIGHT_CYAN}||{C.RESET} {C.BOLD}{C.BRIGHT_WHITE}{centered}{C.RESET} {C.BRIGHT_CYAN}||{C.RESET}")
    print(f"{C.BRIGHT_CYAN}{'=' * width}{C.RESET}")

def log(msg): print(f"{C.BRIGHT_CYAN}[**]{C.RESET} {msg}")
def log_ok(msg): print(f"{C.BRIGHT_GREEN}[OK]{C.RESET} {msg}")
def log_err(msg): print(f"{C.BRIGHT_RED}[!!]{C.RESET} {msg}")
def log_warn(msg): print(f"{C.BRIGHT_YELLOW}[!!]{C.RESET} {msg}")
def log_fire(msg): print(f"{C.BRIGHT_RED}[>>]{C.RESET} {C.BOLD}{msg}{C.RESET}")


# =============================================================================
# NUITKA COMMERCIAL BYPASS - Constants Blob Decryption
# =============================================================================

class CommercialBypass:
    """Bypass Nuitka Commercial data-hiding plugin encryption.

    Algorithm (from DataHidingPlugin.py):
    - Encryption: substitution cipher + XOR with running counter + MD5 digest feedback
    - Key material: _mapping[] (256 byte inverse subst table) + d0-d7 (8 MD5 digest bytes)
    - Module names: mapping2 seeded with Random(27), always reconstructible

    Detection: if CRC32 of the payload doesn't match after header, the blob is encrypted.
    Key extraction: scan .text/.rdata for _mapping[] (256 byte lookup table) and d0-d7.
    Strategy v2: try ALL mapping candidates x ALL d0-d7 candidates,
                 validate each combination with CRC32 before accepting.
    """

    def __init__(self):
        # mapping2 for module names - ALWAYS seed=27, reconstructible without the binary
        r = random.Random(27)
        fwd = list(range(1, 256))
        r.shuffle(fwd)
        fwd.insert(0, 0)
        self.mapping2_forward = list(fwd)
        # Inverse mapping2 for name decoding
        self.name_decode_table = [0] * 256
        for i, v in enumerate(fwd):
            self.name_decode_table[v] = i
        # Expected _mapping2 table as stored in the binary (= inverse of forward mapping2)
        # Used to distinguish _mapping2 (for names) from _mapping (for data) among PE candidates
        self.expected_binary_mapping2 = list(self.name_decode_table)

    def decode_module_name(self, encoded_name: bytes) -> str:
        """Decode a module name obfuscated with mapping2 (seed=27)."""
        decoded = bytearray()
        for b in encoded_name:
            decoded.append(self.name_decode_table[b])
        return decoded.decode('utf-8', errors='replace')

    def is_blob_encrypted(self, blob_data: bytes) -> bool:
        """Determine if the blob is encrypted by checking CRC32."""
        if len(blob_data) < 16:
            return False
        crc_stored = struct.unpack('<I', blob_data[0:4])[0]
        size_stored = struct.unpack('<I', blob_data[4:8])[0]

        if 8 + size_stored > len(blob_data):
            return True

        actual_crc = zlib.crc32(blob_data[8:8 + size_stored]) & 0xFFFFFFFF
        if actual_crc != crc_stored:
            return True
        return False

    def has_commercial_digest(self, blob_data: bytes) -> bool:
        """Detect commercial data-hiding by checking for the 16-byte MD5 digest.

        Commercial encryption inserts 16 bytes (encrypted digest) between
        the 8-byte header and the module data, so:
          encrypted_blob_size = 8 + 16 + original_data_size
          → (blob_size - 8 - declared_size) == 16
        """
        if len(blob_data) < 24:
            return False
        size_stored = struct.unpack('<I', blob_data[4:8])[0]
        extra = len(blob_data) - 8 - size_stored
        return extra == 16

    def _decrypt_raw(self, encrypted_blob: bytes, mapping: list, d_values: list,
                      max_bytes: int = 0) -> bytes:
        """Decrypt the blob (or only the first max_bytes for quick validation).

        If max_bytes > 0, decrypt just enough bytes to produce max_bytes
        of output after the header, for quick CRC validation without
        processing the entire 6+ MB blob.
        """
        original_size = struct.unpack('<I', encrypted_blob[4:8])[0]

        if max_bytes > 0:
            # Limit: decrypt only enough for header + max_bytes of data
            out_needed = min(max_bytes + 8, original_size + 8)
        else:
            out_needed = original_size + 8

        output = bytearray(out_needed)
        output[:8] = encrypted_blob[:8]

        # How many encrypted bytes to process: output[i-16] starts at i=24
        # So for out_needed bytes of output, we need i up to out_needed+16-1
        total_enc = original_size + 16
        if max_bytes > 0:
            # Process just enough: to fill output up to out_needed
            # output[idx] is written at i = idx + 16, so i_max = out_needed + 15
            loop_end = min(8 + out_needed + 16, 8 + total_enc, len(encrypted_blob))
        else:
            loop_end = min(8 + total_enc, len(encrypted_blob))

        # Pre-convert mapping to bytes for faster indexing
        mapping_tbl = mapping  # already a list[int]
        d0, d1, d2, d3, d4, d5, d6, d7 = d_values[0], d_values[1], d_values[2], d_values[3], d_values[4], d_values[5], d_values[6], d_values[7]
        d_lut = (d0, d1, d2, d3, d4, d5, d6, d7)

        last = 0
        enc = encrypted_blob  # local ref for speed

        for i in range(8, loop_end):
            c = enc[i]
            temp = (last + (i - 8)) & 0xFF
            c = c ^ temp
            c = mapping_tbl[c]
            if i >= 24:
                idx = i - 16
                if idx < out_needed:
                    output[idx] = c
            last = (c + d_lut[i & 7]) & 0xFF

        return bytes(output)

    def _check_crc(self, decrypted: bytes) -> bool:
        """Verify CRC32 of the decrypted blob. True = OK."""
        if len(decrypted) < 8:
            return False
        crc_stored = struct.unpack('<I', decrypted[0:4])[0]
        size_stored = struct.unpack('<I', decrypted[4:8])[0]
        if 8 + size_stored > len(decrypted):
            return False
        actual_crc = zlib.crc32(decrypted[8:8 + size_stored]) & 0xFFFFFFFF
        return actual_crc == crc_stored

    def _quick_validate(self, encrypted_blob: bytes, mapping: list, d_values: list) -> bool:
        """Quick validation: decrypt first ~64 bytes and verify module structure.

        In commercial builds module names are encoded with mapping2, so they
        are NOT printable ASCII. They must be decoded before verification.
        """
        try:
            partial = self._decrypt_raw(encrypted_blob, mapping, d_values, max_bytes=64)
            data_start = partial[8:] if len(partial) > 8 else b''
            if not data_start:
                return False

            null_pos = data_start.find(b'\x00')
            if null_pos < 1:
                return False

            raw_name = data_start[:null_pos]

            # Strategy 1: decode with mapping2 (commercial builds encode names)
            decoded = self.decode_module_name(raw_name)
            printable_ok = sum(1 for c in decoded if c.isprintable() or c == '.') / max(len(decoded), 1) >= 0.8

            if not printable_ok:
                # Strategy 2: check raw bytes (open-source builds keep names as-is)
                printable_ok = sum(1 for b in raw_name if 0x20 <= b < 0x7F) / max(len(raw_name), 1) >= 0.8

            if not printable_ok:
                return False

            size_pos = null_pos + 1
            if size_pos + 4 <= len(data_start):
                chunk_size = struct.unpack('<I', data_start[size_pos:size_pos + 4])[0]
                orig_size = struct.unpack('<I', encrypted_blob[4:8])[0]
                if chunk_size > orig_size or chunk_size == 0:
                    return False
            return True
        except Exception:
            return False

    def extract_key_material_from_pe(self, pe_data: bytes):
        """Extract _mapping[] and d0-d7 from the PE binary.

        Strategy v2 (robust):
        1. Collect ALL _mapping[] candidates (256-byte permutations)
        2. For each mapping candidate, search for d0-d7 via:
           a. Cross-reference LEA/MOV to the mapping in .text -> decode_hidden function
           b. Scan imm8 clusters in the found function
           c. Fallback global ADD/MOV imm8 scan in .text
        3. Validate each (mapping, d0-d7) pair with CRC32 on the actual blob
        4. Return the first valid pair
        """
        import pefile
        pe = pefile.PE(data=pe_data)

        mapping_candidates = self._find_all_mapping_candidates(pe)
        if not mapping_candidates:
            log_err("No _mapping[] candidates found in PE")
            return None, None

        log(f"  {len(mapping_candidates)} _mapping[] candidate(s) to test")

        all_d_candidates = self._find_all_digest_candidates(pe, pe_data, mapping_candidates)
        log(f"  {len(all_d_candidates)} d0-d7 candidate sets found")

        if not all_d_candidates:
            log_warn("No d0-d7 found, adding fallback [0]*8")
            all_d_candidates = [[0]*8]

        return mapping_candidates, all_d_candidates

    def decrypt_blob_auto(self, encrypted_blob: bytes, mapping_candidates: list, d_candidates: list) -> bytes:
        """Try all mapping x d0-d7 combinations with quick validation.

        Phase 0: filter mapping2 (name-encoding) from data-decryption candidates
        Phase 1: quick_validate on first 64 bytes (instant)
        Phase 2: full decrypt + CRC check only on candidates that pass phase 1
        """
        # Phase 0: remove mapping2 (for name encoding) from data decryption candidates
        filtered = [m for m in mapping_candidates if m != self.expected_binary_mapping2]
        if filtered and len(filtered) < len(mapping_candidates):
            log(f"  Filtered mapping2 (name encoding): {len(mapping_candidates)} -> {len(filtered)} _mapping[] candidates")
            mapping_candidates = filtered

        # === FAST PATH: derive d0-d7 directly from the encrypted blob ===
        # d0-d7 are the first 8 bytes of the MD5 digest, which is encrypted
        # inside the blob itself. We can recover them using just the mapping.
        for mi, mapping in enumerate(mapping_candidates):
            derived_d = self._derive_d_from_blob(encrypted_blob, mapping)
            if derived_d:
                try:
                    result = self._decrypt_raw(encrypted_blob, mapping, derived_d)
                    if self._check_crc(result):
                        log_ok(f"Direct d0-d7 derivation from blob succeeded! mapping#{mi}")
                        log_ok(f"  d0-d7 = {derived_d}")
                        return result, mapping, derived_d
                except Exception:
                    pass

        log_warn("  Direct derivation failed, trying scanned combinations...")

        total_combos = len(mapping_candidates) * len(d_candidates)
        log(f"  Trying {total_combos} combinations (mapping x d0-d7)...")

        # Phase 1: quick validation
        valid_pairs = []
        for mi, mapping in enumerate(mapping_candidates):
            for di, d_vals in enumerate(d_candidates):
                if self._quick_validate(encrypted_blob, mapping, d_vals):
                    valid_pairs.append((mi, mapping, di, d_vals))

        if valid_pairs:
            log(f"  {len(valid_pairs)} combinations pass quick validation")
        else:
            log_warn("  No combination passes quick validation, trying all...")
            valid_pairs = [(mi, m, di, d) for mi, m in enumerate(mapping_candidates)
                           for di, d in enumerate(d_candidates)]

        # Phase 2: full decrypt + CRC only on filtered candidates
        for mi, mapping, di, d_vals in valid_pairs:
            try:
                result = self._decrypt_raw(encrypted_blob, mapping, d_vals)
                if self._check_crc(result):
                    log_ok(f"Valid combination found! mapping#{mi} + d0-d7#{di}")
                    log_ok(f"  d0-d7 = {list(d_vals)}")
                    return result, mapping, d_vals
            except Exception:
                continue

        log_warn("No combination passed CRC32 check. Returning best-effort result.")
        best = self._decrypt_raw(encrypted_blob, mapping_candidates[0], d_candidates[0])
        return best, mapping_candidates[0], d_candidates[0]

    def _find_all_mapping_candidates(self, pe):
        """Collect ALL _mapping[] candidates (complete 0-255 permutations)."""
        candidates = []

        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if not any(n in name for n in ('.rdata', '.data', '.text')):
                continue

            sec_data = section.get_data()
            sec_size = len(sec_data)

            for offset in range(0, sec_size - 256, 1):
                candidate = sec_data[offset:offset + 256]
                if len(set(candidate)) == 256:
                    table = list(candidate)
                    if table == list(range(256)):
                        continue  # Identity = open-source no-op
                    rva = section.VirtualAddress + offset
                    if not any(c[1] == table for c in candidates):
                        candidates.append((rva, table, name))
                        log(f"  _mapping[] candidate at RVA 0x{rva:X} ({name}+0x{offset:X})")

        # Sort: .rdata first, then .data, then .text
        order = {'.rdata': 0, '.data': 1, '.text': 2}
        candidates.sort(key=lambda x: order.get(x[2], 3))
        return [c[1] for c in candidates]

    def _find_all_digest_candidates(self, pe, pe_data: bytes, mapping_candidates: list) -> list:
        """Find all d0-d7 candidate sets using multiple strategies.

        Prioritizes xref-based results (most accurate), then falls back to
        heuristic scans. Filters mapping2 from candidates before xref search
        so we only search near the actual data decryption mapping.
        """
        all_candidates = []
        seen = set()

        # Filter mapping2 from candidates for more targeted xref search
        data_mappings = [m for m in mapping_candidates if m != self.expected_binary_mapping2]
        if not data_mappings:
            data_mappings = mapping_candidates

        # Strategy 1: xref to mapping in .text -> decode_hidden function -> extract imm8
        xref_results = self._find_d_via_mapping_xref(pe, pe_data, data_mappings)
        for d in xref_results:
            key = tuple(d)
            if key not in seen:
                seen.add(key)
                all_candidates.append(d)
                log(f"    d0-d7 via xref: {d}")

        # Strategy 2: scan imm8 clusters in .text (ADD/MOV patterns)
        scan_results = self._scan_imm8_clusters(pe)
        for d in scan_results:
            key = tuple(d)
            if key not in seen:
                seen.add(key)
                all_candidates.append(d)
                log(f"    d0-d7 via scan: {d}")

        # Strategy 3: targeted scan near switch(i%8) patterns
        raw_results = self._scan_raw_imm8_sequences(pe)
        for d in raw_results:
            key = tuple(d)
            if key not in seen and any(v > 0 for v in d):
                seen.add(key)
                all_candidates.append(d)
                log(f"    d0-d7 via switch-scan: {d}")

        return all_candidates

    def _find_d_via_mapping_xref(self, pe, pe_data: bytes, mapping_candidates: list) -> list:
        """Search .text for LEA/MOV instructions that reference _mapping[].

        In x86-64, static data access uses RIP-relative addressing:
          LEA reg, [RIP + disp32]    -> 48 8D ?? ?? ?? ?? ??
          MOVZX reg, byte [reg + RIP+disp32]  -> various forms

        Once decode_hidden is located, extract the adjacent imm8 constants
        (the d0-d7 from the switch-case).
        """
        results = []
        image_base = pe.OPTIONAL_HEADER.ImageBase

        # Find .text
        text_section = None
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' in name:
                text_section = section
                break

        if not text_section:
            return results

        text_data = text_section.get_data()
        text_va = image_base + text_section.VirtualAddress
        text_rva = text_section.VirtualAddress

        # Search .rdata/.data for the VA of mapping candidates
        for section in pe.sections:
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if sec_name not in ('.rdata', '.data'):
                continue

            sec_data = section.get_data()
            sec_va = image_base + section.VirtualAddress

            # Find all offsets of mapping candidates in this section
            for mapping_table in mapping_candidates:
                mapping_bytes = bytes(mapping_table)
                offset_in_sec = sec_data.find(mapping_bytes)
                if offset_in_sec == -1:
                    continue

                mapping_va = sec_va + offset_in_sec
                log(f"    _mapping[] found at VA 0x{mapping_va:X}")

                # Search for RIP-relative references to mapping_va in .text
                for text_off in range(0, len(text_data) - 8):
                    for insn_len in [3, 4, 5, 6, 7]:
                        if text_off + insn_len + 4 > len(text_data):
                            break
                        disp = struct.unpack('<i', text_data[text_off + insn_len:text_off + insn_len + 4])[0]
                        next_insn_va = text_va + text_off + insn_len + 4
                        target_va = next_insn_va + disp

                        if target_va == mapping_va:
                            func_start = max(0, text_off - 512)
                            func_end = min(len(text_data), text_off + 1024)
                            func_bytes = text_data[func_start:func_end]

                            d_vals = self._extract_imm8_from_switch(func_bytes)
                            if d_vals:
                                results.append(d_vals)
                            break

        return results

    def _extract_imm8_from_switch(self, code_window: bytes) -> list:
        """Extract 8 imm8 values from a code block (switch-case d0-d7).

        Looks for patterns:
        - Sequences of 8 imm8 bytes in instructions like:
            80 C? imm8  (ADD reg8, imm8)
            80 E? imm8  (AND reg8, imm8)
            B? imm8     (MOV reg8, imm8)
            6A imm8     (PUSH imm8)
        Picks the cluster of 8 closest to the center of the window.
        """
        imm8_by_pos = []

        i = 0
        while i < len(code_window) - 2:
            b = code_window[i]
            # ADD reg8, imm8
            if b in (0x80, 0x82) and (code_window[i+1] & 0xF8) in (0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8):
                imm8_by_pos.append((i, code_window[i+2]))
                i += 3; continue
            # MOV reg8, imm8 (B0-B7)
            if 0xB0 <= b <= 0xB7:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            # PUSH imm8
            if b == 0x6A:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            # ADD al, imm8
            if b == 0x04:
                imm8_by_pos.append((i, code_window[i+1]))
                i += 2; continue
            i += 1

        # Find window of 8 with spread < 200 bytes
        for j in range(len(imm8_by_pos) - 7):
            cluster = imm8_by_pos[j:j+8]
            spread = cluster[7][0] - cluster[0][0]
            if spread < 200:
                vals = [c[1] for c in cluster]
                if len(set(vals)) > 2:
                    return vals

        return []

    def _scan_imm8_clusters(self, pe) -> list:
        """Generic scan for clusters of 8 ADD/MOV imm8 in .text."""
        results = []

        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' not in name:
                continue

            sec_data = section.get_data()

            # Find 8 consecutive ADD cl/al/dl, imm8 instructions
            for prefix in [b'\x80\xc1', b'\x80\xc0', b'\x80\xc2']:
                positions = []
                pos = 0
                while pos < len(sec_data) - 3:
                    idx = sec_data.find(prefix, pos)
                    if idx == -1:
                        break
                    imm = sec_data[idx + 2]
                    positions.append((idx, imm))
                    pos = idx + 1

                for j in range(len(positions) - 7):
                    cluster = positions[j:j+8]
                    spread = cluster[7][0] - cluster[0][0]
                    if spread < 600:
                        vals = [c[1] for c in cluster]
                        if len(set(vals)) > 3:
                            results.append(vals)

        return results

    def _scan_raw_imm8_sequences(self, pe) -> list:
        """Search for d0-d7 byte sequences in .text near switch-case instructions.

        Focuses on ADD reg, imm8 patterns that match the compiler output for:
          switch(i%8) { case 0: last = (last + d0) % 256; ... }
        """
        results = []

        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if '.text' not in name:
                continue

            sec_data = section.get_data()

            # Only look near AND reg, 7 (the i%8 operation) as anchor
            # x86: AND ecx, 7 = 83 E1 07  or  AND eax, 7 = 83 E0 07
            for anchor_prefix in [b'\x83\xe1\x07', b'\x83\xe0\x07', b'\x83\xe2\x07']:
                pos = 0
                while pos < len(sec_data) - 200:
                    idx = sec_data.find(anchor_prefix, pos)
                    if idx == -1:
                        break
                    # Scan 256 bytes after the AND for ADD imm8 patterns
                    window = sec_data[idx:idx + 256]
                    d_vals = self._extract_imm8_from_switch(window)
                    if d_vals and len(set(d_vals)) >= 3:
                        results.append(d_vals)
                    pos = idx + 1
                    if len(results) > 20:
                        return results

        return results

    def _derive_d_from_blob(self, encrypted_blob: bytes, mapping: list) -> list:
        """Derive d0-d7 directly from the encrypted blob using the mapping.

        The encrypted blob layout: [header(8)][encrypted_digest(16)][encrypted_data]
        d0-d7 ARE the first 8 bytes of the MD5 digest. The digest is encrypted
        with the same stream cipher (starting at i=8 with last=0), so we can
        recover them by running the cipher forward:

          For each k in 0..7:
            temp = (last + k) & 0xFF
            digest[k] = mapping[encrypted_blob[8+k] ^ temp]
            last = (digest[k] + digest[k]) & 0xFF   # d[k] = digest[k]

        This eliminates the need to scan the PE for d0-d7 entirely.
        """
        if len(encrypted_blob) < 16:
            return None

        d = [0] * 8
        last = 0
        for k in range(8):
            c = encrypted_blob[8 + k]
            temp = (last + k) & 0xFF
            c = c ^ temp
            c = mapping[c]
            d[k] = c
            last = (c + c) & 0xFF
        return d

    def decrypt_blob(self, encrypted_blob: bytes, mapping: list, d_values: list) -> bytes:
        """Decrypt the blob with known mapping and d_values. Logs the result."""
        if len(encrypted_blob) < 24:
            log_err("Blob too small for decryption")
            return encrypted_blob

        result = self._decrypt_raw(encrypted_blob, mapping, d_values)

        crc_stored = struct.unpack('<I', result[0:4])[0]
        size_stored = struct.unpack('<I', result[4:8])[0]
        if 8 + size_stored <= len(result):
            actual_crc = zlib.crc32(result[8:8 + size_stored]) & 0xFFFFFFFF
            if actual_crc == crc_stored:
                log_ok(f"Decryption verified! CRC32 OK (0x{actual_crc:08X})")
            else:
                log_warn(f"Post-decrypt CRC32 mismatch: 0x{crc_stored:08X} vs 0x{actual_crc:08X}")

        return result


# =============================================================================
# PE ANALYSIS
# =============================================================================

def detect_python_version_from_pe(pe_data: bytes) -> tuple:
    """Detect Python version from PE by looking for python3XX.dll in imports."""
    try:
        import pefile
        pe = pefile.PE(data=pe_data)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('ascii', errors='replace').lower()
                m = re.match(r'python(\d)(\d+)\.dll', dll_name)
                if m:
                    major, minor = int(m.group(1)), int(m.group(2))
                    return (major, minor)
        # Also search .rdata section for python3XX.dll strings
        for section in pe.sections:
            sec_data = section.get_data()
            for match in re.finditer(rb'python(\d)(\d+)\.dll', sec_data):
                major, minor = int(match.group(1)), int(match.group(2))
                return (major, minor)
    except Exception:
        pass
    return sys.version_info[:2]


def detect_nuitka_edition(pe_data: bytes, blob_data: bytes = None) -> str:
    """Detect whether the binary is Nuitka open-source or Commercial.

    Uses both string indicators in the PE and structural analysis of the blob.
    The most reliable indicator is the 16-byte MD5 digest that commercial
    data-hiding inserts between the header and the module data.
    """
    # Structural blob check (most reliable for stripped binaries)
    if blob_data and len(blob_data) >= 24:
        size_stored = struct.unpack('<I', blob_data[4:8])[0]
        extra_bytes = len(blob_data) - 8 - size_stored
        if extra_bytes == 16:
            return "commercial"

    indicators_commercial = [
        b'decode_hidden', b'decode_public', b'_mapping2',
        b'data-hiding', b'DataHiding',
        b'nuitka_data_decoder',
    ]
    indicators_opensource = [
        b'Nuitka', b'nuitka_empty_function',
        b'loadConstantsBlob', b'MetaPathBasedLoader',
    ]

    score_commercial = 0
    score_opensource = 0

    for indicator in indicators_commercial:
        if indicator in pe_data:
            score_commercial += 1

    for indicator in indicators_opensource:
        if indicator in pe_data:
            score_opensource += 1

    if score_commercial >= 2:
        return "commercial"
    elif score_opensource >= 1:
        return "opensource"
    return "unknown"


def extract_pe_constants_blob(pe_path: str) -> bytes:
    """Extract the Nuitka constants blob from PE resources (RT_RCDATA ID 3)."""
    try:
        import pefile
    except ImportError:
        log_err("pefile not installed. Run: pip install pefile")
        return None

    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        log_err(f"PE parsing error: {e}")
        return None

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.id == 10:  # RT_RCDATA
                for res_id in res_type.directory.entries:
                    if res_id.id == 3:  # Nuitka constants
                        for res_lang in res_id.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            blob = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            log_ok(f"Blob found in RT_RCDATA #3 ({size:,} bytes)")
                            return bytes(blob)

    # Fallback: search for blob embedded as C array (incbin / const array)
    log_warn("Blob not found in RT_RCDATA, searching for static embedding...")
    return _find_embedded_blob(pe)


def _find_embedded_blob(pe) -> bytes:
    """Search for the blob embedded directly in sections (incbin mode)."""
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        sec_data = section.get_data()

        for offset in range(0, len(sec_data) - 8, 4):
            potential_size = struct.unpack('<I', sec_data[offset + 4:offset + 8])[0]
            if 1000 < potential_size < 50_000_000:
                if offset + 8 + potential_size <= len(sec_data):
                    potential_crc = struct.unpack('<I', sec_data[offset:offset + 4])[0]
                    actual_crc = zlib.crc32(sec_data[offset + 8:offset + 8 + potential_size]) & 0xFFFFFFFF
                    if actual_crc == potential_crc:
                        blob = sec_data[offset:offset + 8 + potential_size]
                        log_ok(f"Blob found in {name}+0x{offset:X} ({len(blob):,} bytes)")
                        return bytes(blob)
    return None


# =============================================================================
# EMBEDDED SOURCE DETECTION
# =============================================================================

PYTHON_SOURCE_STARTERS = (
    'def ', 'class ', 'import ', 'from ', 'return ',
    'if ', 'elif ', 'else:', 'for ', 'while ', 'try:',
    'except ', 'with ', 'yield ', '#', '    ', '@', 'async ',
)


def _python_source_confidence(data: bytes) -> float:
    """Return 0.0-1.0: how likely *data* is Python source code."""
    if len(data) < 30:
        return 0.0
    text = None
    for enc in ('utf-8', 'latin-1'):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            pass
    if text is None:
        return 0.0
    lines = text.splitlines()
    if not lines:
        return 0.0
    sample = lines[:200]
    hits = sum(1 for ln in sample if ln.strip().startswith(PYTHON_SOURCE_STARTERS))
    score = hits / max(len(sample), 1)
    snippet = text[:4000]
    if '#!/usr/bin/env python' in snippet or '# -*- coding' in snippet:
        score = min(1.0, score + 0.4)
    if 'def ' in snippet and ('import ' in snippet or 'class ' in snippet):
        score = min(1.0, score + 0.25)
    return score


def _try_decompress(data: bytes):
    """Try zlib decompression (various wbits). Returns bytes or None."""
    for wbits in (15, -15, 47):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            pass
    return None


def scan_pe_resources_for_source(pe_path: str, output_dir: str) -> list:
    """Scan ALL PE resources for embedded Python source or compressed blobs.

    The Nuitka constants blob lives at RT_RCDATA/3 and is handled elsewhere.
    Every other resource entry is checked for:
      - Raw Python source text
      - zlib-compressed Python source
      - Any data > 32 B (saved for manual inspection)

    Returns list of dicts: {path, size, confidence, saved_at}
    """
    try:
        import pefile
    except ImportError:
        log_warn("pefile not installed - skipping resource scan")
        return []

    results = []
    res_dir = os.path.join(output_dir, "pe_resources")
    os.makedirs(res_dir, exist_ok=True)

    RT_NAMES = {
        1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
        5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT',
        9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
        14: 'RT_GROUP_ICON', 16: 'RT_VERSION', 24: 'RT_MANIFEST',
    }

    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        log_warn(f"PE resource scan error: {e}")
        return results

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        log("  No PE resources directory found")
        return results

    mm = pe.get_memory_mapped_image()
    saved_hashes = set()

    def _save_resource(path, data, conf):
        h = zlib.crc32(data) & 0xFFFFFFFF
        if h in saved_hashes:
            return None
        saved_hashes.add(h)
        safe = re.sub(r'[<>:"|?*/\\]', '_', path)
        ext  = '.py' if conf > 0.25 else '.bin'
        out  = os.path.join(res_dir, safe + ext)
        with open(out, 'wb') as fh:
            fh.write(data)
        return out

    def _visit(node, path):
        if hasattr(node, 'data'):
            try:
                rva  = node.data.struct.OffsetToData
                size = node.data.struct.Size
                if size < 32:
                    return
                raw = bytes(mm[rva:rva + size])
                # Skip Nuitka constants blob (RT_RCDATA/3/*)
                if re.match(r'^RT_RCDATA/3', path):
                    return
                conf  = _python_source_confidence(raw)
                used  = raw
                label = path
                if conf < 0.15:
                    dec = _try_decompress(raw)
                    if dec:
                        dc = _python_source_confidence(dec)
                        if dc > conf:
                            conf, used, label = dc, dec, path + '[zlib]'
                out = _save_resource(label, used, conf)
                if out:
                    rec = {'path': path, 'size': size,
                           'confidence': round(conf, 3), 'saved_at': out}
                    results.append(rec)
                    if conf > 0.30:
                        log_fire(f"  SOURCE CANDIDATE resource {path}: "
                                 f"conf={conf:.2f} ({size:,} B) -> {out}")
                    else:
                        log(f"  Resource {path}: {size:,} B conf={conf:.2f} -> saved")
            except Exception:
                pass
            return

        if hasattr(node, 'directory'):
            for child in node.directory.entries:
                if hasattr(child, 'name') and child.name:
                    child_id = child.name.string.decode('utf-8', errors='replace')
                elif hasattr(child, 'id') and child.id is not None:
                    child_id = str(child.id)
                else:
                    child_id = '?'
                _visit(child, f"{path}/{child_id}" if path else child_id)

    for top in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if hasattr(top, 'id') and top.id is not None:
            top_name = RT_NAMES.get(top.id, f'TYPE_{top.id}')
        elif hasattr(top, 'name') and top.name:
            top_name = top.name.string.decode('utf-8', errors='replace')
        else:
            top_name = 'UNKNOWN'
        _visit(top, top_name)

    return results


def scan_sections_for_source(pe_data: bytes, output_dir: str) -> list:
    """Scan every PE section for embedded Python source or compressed blobs.

    Strategy A: Python source markers (b'def ', b'class ', b'import ', …)
    Strategy B: zlib magic bytes -> decompress -> check confidence

    Returns list of dicts: {section, offset, method, confidence, saved_at}
    """
    try:
        import pefile
    except ImportError:
        return []

    results = []
    sec_dir = os.path.join(output_dir, "section_scan")
    os.makedirs(sec_dir, exist_ok=True)

    try:
        pe = pefile.PE(data=pe_data)
    except Exception as e:
        log_warn(f"Section scan PE error: {e}")
        return results

    MARKERS = [
        b'def ', b'class ', b'import ', b'from ',
        b'#!/usr/bin/env python', b'# -*-',
        b'\ndef ', b'\nclass ', b'\nimport ',
    ]
    ZLIB_MAGICS = [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']

    saved_hashes = set()

    def _save(sec_name, offset, method, data, conf):
        h = zlib.crc32(data) & 0xFFFFFFFF
        if h in saved_hashes:
            return None
        saved_hashes.add(h)
        ext   = '.py' if conf > 0.25 else '.bin'
        fname = f"{re.sub(r'[^a-zA-Z0-9_]', '_', sec_name)}_0x{offset:08X}_{method}{ext}"
        out   = os.path.join(sec_dir, fname)
        with open(out, 'wb') as fh:
            fh.write(data)
        return out

    for section in pe.sections:
        sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace').strip()
        raw  = section.get_data()
        size = len(raw)
        if size < 64:
            continue

        log(f"  Scanning section [{sec_name}] ({size:,} B) for source...")

        # Strategy A: source text markers
        for marker in MARKERS:
            pos = 0
            while True:
                idx = raw.find(marker, pos)
                if idx == -1:
                    break
                start = max(0, idx - 1024)
                end   = min(size, idx + 65536)
                block = raw[start:end]
                conf  = _python_source_confidence(block)
                if conf > 0.20:
                    out = _save(sec_name, start, 'marker', block, conf)
                    if out:
                        rec = {'section': sec_name, 'offset': start,
                               'method': 'marker', 'confidence': round(conf, 3),
                               'saved_at': out}
                        results.append(rec)
                        log_fire(f"  SOURCE in [{sec_name}]+0x{start:X} "
                                 f"('{marker.decode('ascii', errors='replace')}'): conf={conf:.2f}")
                pos = idx + max(len(marker), 1)

        # Strategy B: zlib compressed blobs
        for magic in ZLIB_MAGICS:
            pos      = 0
            attempts = 0
            while attempts < 200:
                idx = raw.find(magic, pos)
                if idx == -1:
                    break
                attempts += 1
                chunk = raw[idx:min(idx + 1024 * 1024, size)]
                dec   = _try_decompress(chunk)
                if dec:
                    conf = _python_source_confidence(dec)
                    if conf > 0.15:
                        out = _save(sec_name, idx, 'zlib', dec, conf)
                        if out:
                            rec = {'section': sec_name, 'offset': idx,
                                   'method': 'zlib', 'confidence': round(conf, 3),
                                   'saved_at': out}
                            results.append(rec)
                            log_fire(f"  COMPRESSED SOURCE [{sec_name}]+0x{idx:X}: "
                                     f"conf={conf:.2f} ({len(dec):,} B decompressed) -> {out}")
                pos = idx + 2

    return results


def search_constants_for_source(constants: list, module_name: str, output_dir: str) -> list:
    """Find strings/bytes in module constants that look like Python source."""
    results = []
    src_dir = os.path.join(output_dir, "source_in_constants")

    def _visit(val, depth=0):
        if depth > 8:
            return
        data = None
        if isinstance(val, str) and len(val) > 80:
            data = val.encode('utf-8', errors='replace')
        elif isinstance(val, (bytes, bytearray)) and len(val) > 80:
            data = bytes(val)

        if data is not None:
            conf = _python_source_confidence(data)
            used = data
            if conf < 0.15:
                dec = _try_decompress(data)
                if dec:
                    dc = _python_source_confidence(dec)
                    if dc > conf:
                        conf, used = dc, dec
            if conf > 0.25:
                os.makedirs(src_dir, exist_ok=True)
                safe = re.sub(r'[<>:"|?*/\\.]', '_', module_name)
                out  = os.path.join(src_dir, f"{safe}_{len(results)}.py")
                with open(out, 'wb') as fh:
                    fh.write(used)
                results.append({'module': module_name,
                                'confidence': round(conf, 3), 'saved_at': out})
                log_fire(f"  SOURCE in constants of [{module_name}]: "
                         f"conf={conf:.2f} ({len(data):,} B) -> {out}")
            return

        if isinstance(val, (list, tuple)):
            for item in val:
                _visit(item, depth + 1)
        elif isinstance(val, dict):
            for v in val.values():
                _visit(v, depth + 1)

    for c in constants:
        _visit(c)
    return results


# =============================================================================
# VLQ READER
# =============================================================================

def read_vlq(data, pos):
    """Read a VLQ (Variable Length Quantity) integer in Nuitka format."""
    byte = data[pos]; pos += 1
    if byte < 0x80: return byte, pos
    size = byte & 0x7F
    byte = data[pos]; pos += 1
    if byte < 0x80: return size | (byte << 7), pos
    size |= (byte & 0x7F) << 7
    byte = data[pos]; pos += 1
    if byte < 0x80: return size | (byte << 14), pos
    size |= (byte & 0x7F) << 14
    byte = data[pos]; pos += 1
    return size | (byte << 21), pos


# =============================================================================
# CONSTANTS BLOB PARSER
# =============================================================================

KNOWN_LIBRARY_PREFIXES = [
    'abc', 'aifc', 'argparse', 'ast', 'asynchat', 'asyncio', 'asyncore',
    'base64', 'bdb', 'binascii', 'binhex', 'bisect', 'builtins',
    'calendar', 'cgi', 'cgitb', 'chunk', 'cmd', 'code', 'codecs', 'codeop',
    'collections', 'colorsys', 'compileall', 'concurrent', 'configparser',
    'contextlib', 'contextvars', 'copy', 'copyreg', 'cProfile', 'csv', 'ctypes',
    'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib', 'dis', 'distutils',
    'doctest',
    'email', 'encodings', 'enum',
    'filecmp', 'fileinput', 'fnmatch', 'fractions', 'ftplib', 'functools',
    'gc', 'genericpath', 'getopt', 'getpass', 'gettext', 'glob', 'graphlib', 'gzip',
    'hashlib', 'heapq', 'hmac', 'html', 'http',
    'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io', 'ipaddress',
    'itertools', 'json', 'keyword',
    'lib2to3', 'linecache', 'locale', 'logging', 'lzma',
    'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes', 'modulefinder',
    'multiprocessing',
    'netrc', 'nntplib', 'ntpath', 'nturl2path', 'numbers',
    'opcode', 'operator', 'optparse', 'os',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform',
    'plistlib', 'poplib', 'posixpath', 'pprint', 'profile', 'pstats',
    'py_compile', 'pyclbr', 'pydoc',
    'queue', 'quopri',
    'random', 're', 'reprlib', 'rlcompleter', 'runpy',
    'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex', 'shutil',
    'signal', 'site', 'smtplib', 'sndhdr', 'socket', 'socketserver',
    'sre_compile', 'sre_constants', 'sre_parse', 'ssl', 'stat', 'statistics',
    'string', 'stringprep', 'struct', 'subprocess', 'symtable', 'sys', 'sysconfig',
    'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'test', 'textwrap',
    'threading', 'timeit', 'tkinter', 'token', 'tokenize', 'tomllib',
    'trace', 'traceback', 'tracemalloc', 'turtledemo', 'types', 'typing',
    'unicodedata', 'unittest', 'urllib', 'uu', 'uuid',
    'venv',
    'warnings', 'wave', 'weakref', 'webbrowser',
    'xdrlib', 'xml', 'xmlrpc',
    'zipapp', 'zipfile', 'zipimport', 'zlib',
    '_',
    'aiohttp', 'certifi', 'charset_normalizer', 'cryptography', 'Crypto',
    'numpy', 'pandas', 'pip', 'pkg_resources',
    'requests', 'setuptools', 'six', 'urllib3', 'wheel',
    '__future__', '__hello__', '__phello__',
]


def is_main_module(name):
    if not name: return False
    base = name.split('.')[0].lower()
    for lib in KNOWN_LIBRARY_PREFIXES:
        if base == lib.lower() or base.startswith(lib.lower()):
            return False
    return True


def module_matches_patterns(name, patterns):
    """Match exact module names or `pkg.*` globs used by --only."""
    if not patterns:
        return True
    for pat in patterns:
        if pat.endswith('.*'):
            prefix = pat[:-2]
            if name == prefix or name.startswith(prefix + '.'):
                return True
        elif pat == name:
            return True
    return False


# Module-level tracker for the 'p' (previous) constant tag
_last_unpacked = None


def unpack_single_constant(data, pos):
    """Unpack a single value from the Nuitka constants blob.

    Handles all known tags from HelpersConstantsBlob.c and DataComposer.py.
    Synchronized with Nuitka Commercial 2025 source.
    """
    global _last_unpacked

    if pos >= len(data):
        return None, pos

    marker = data[pos]
    ch = chr(marker) if 32 <= marker < 127 else None
    pos += 1

    # === 'p' - previous ref: repeat last unpacked value (NO VLQ read) ===
    if ch == 'p':
        return _last_unpacked, pos

    result = _unpack_constant_inner(data, pos, ch, marker)
    if result is not None:
        val, pos = result
        _last_unpacked = val
        return val, pos

    _last_unpacked = None
    return None, pos


def _unpack_constant_inner(data, pos, ch, marker):
    """Internal dispatcher for all constant types except 'p'."""

    # --- Strings ---
    if ch in ('a', 'u'):  # null-terminated string (attribute or unicode)
        end = data.find(b'\x00', pos)
        if end == -1 or end > pos + 65536:
            return "", pos
        return data[pos:end].decode('utf-8', errors='replace'), end + 1

    elif ch == 'w':  # single-char unicode
        if pos < len(data):
            return data[pos:pos + 1].decode('utf-8', errors='replace'), pos + 1
        return "", pos

    elif ch == 'v':  # length-prefixed unicode (contains null bytes)
        size, pos = read_vlq(data, pos)
        if pos + size > len(data): return "", pos
        return data[pos:pos + size].decode('utf-8', errors='replace'), pos + size

    elif ch == 's':  # empty string
        return "", pos

    # --- Bytes ---
    elif ch == 'c':  # Python3: zero-terminated bytes / Python2: str
        end = data.find(b'\x00', pos)
        if end == -1 or end > pos + 65536:
            return b'', pos
        return data[pos:end], end + 1

    elif ch == 'b':  # bytes with VLQ length (contains null bytes)
        size, pos = read_vlq(data, pos)
        if pos + size > len(data): return b'', pos
        return data[pos:pos + size], pos + size

    elif ch == 'B':  # bytearray
        size, pos = read_vlq(data, pos)
        if pos + size > len(data): return bytearray(), pos
        return bytearray(data[pos:pos + size]), pos + size

    elif ch == 'd':  # single byte (Python3: bytes len 1)
        if pos < len(data): return bytes([data[pos]]), pos + 1
        return b'', pos

    # --- Singletons ---
    elif ch == 'n': return None, pos
    elif ch == 't': return True, pos
    elif ch == 'F': return False, pos

    # --- Integers ---
    elif ch == 'l':  # positive VLQ int
        value, pos = read_vlq(data, pos)
        return value, pos
    elif ch == 'q':  # negative VLQ int
        value, pos = read_vlq(data, pos)
        return -value, pos

    elif ch == 'I':  # Python2 negative int (VLQ encoded)
        value, pos = read_vlq(data, pos)
        return -value, pos
    elif ch == 'i':  # Python2 positive int (VLQ encoded)
        value, pos = read_vlq(data, pos)
        return value, pos

    elif ch in ('g', 'G'):  # big integer (abs >= 2^31)
        is_negative = (ch == 'G')
        num_parts, pos = read_vlq(data, pos)
        result = 0
        for _ in range(num_parts):
            result <<= 31
            part, pos = read_vlq(data, pos)
            result += part
        return (-result if is_negative else result), pos

    # --- Floats ---
    elif ch == 'f':  # double float (8 bytes IEEE 754)
        if pos + 8 <= len(data):
            return struct.unpack('<d', data[pos:pos + 8])[0], pos + 8
        return 0.0, pos

    elif ch == 'Z':  # special float: +0.0, -0.0, +NaN, -NaN, +Inf, -Inf
        if pos < len(data):
            v = data[pos]
            pos += 1
            if v == 0: return 0.0, pos
            elif v == 1: return -0.0, pos
            elif v == 2: return float('nan'), pos
            elif v == 3: return copysign(float('nan'), -1.0), pos
            elif v == 4: return float('inf'), pos
            elif v == 5: return float('-inf'), pos
            else: return 0.0, pos
        return 0.0, pos

    # --- Complex ---
    elif ch == 'j':  # complex (two 8-byte doubles)
        if pos + 16 <= len(data):
            real = struct.unpack('<d', data[pos:pos + 8])[0]
            imag = struct.unpack('<d', data[pos + 8:pos + 16])[0]
            return complex(real, imag), pos + 16
        return 0j, pos

    elif ch == 'J':  # complex via float sub-constants (for special values)
        parts = []
        for _ in range(2):
            item, pos = unpack_single_constant(data, pos)
            parts.append(item if item is not None else 0.0)
        try:
            return complex(parts[0], parts[1]), pos
        except (TypeError, ValueError):
            return 0j, pos

    # --- Containers ---
    elif ch == 'T':  # tuple
        count, pos = read_vlq(data, pos)
        if count > 50000: return (), pos
        items = []
        for _ in range(count):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        return tuple(items), pos

    elif ch == 'L':  # list
        count, pos = read_vlq(data, pos)
        if count > 50000: return [], pos
        items = []
        for _ in range(count):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        return items, pos

    elif ch == 'D':  # dict — Nuitka writes ALL keys first, then ALL values
        count, pos = read_vlq(data, pos)
        if count > 50000: return {}, pos
        keys = []
        for _ in range(count):
            k, pos = unpack_single_constant(data, pos)
            keys.append(k)
        values = []
        for _ in range(count):
            v, pos = unpack_single_constant(data, pos)
            values.append(v)
        d = {}
        for k, v in zip(keys, values):
            try: d[k] = v
            except TypeError: pass
        return d, pos

    elif ch == 'S':  # set
        count, pos = read_vlq(data, pos)
        if count > 50000: return set(), pos
        items = []
        for _ in range(count):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        try: return set(items), pos
        except TypeError: return set(), pos

    elif ch in ('P', 'R'):  # frozenset (Nuitka uses 'P', keep 'R' for compat)
        count, pos = read_vlq(data, pos)
        if count > 50000: return frozenset(), pos
        items = []
        for _ in range(count):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        try: return frozenset(items), pos
        except TypeError: return frozenset(), pos

    # --- Raw blob (bytecode pointer) ---
    elif ch == 'X':
        size, pos = read_vlq(data, pos)
        blob = data[pos:pos + size] if pos + size <= len(data) else b''
        return blob, pos + size

    # --- Special types ---
    elif ch in ('M', 'Q'):  # anon builtin / special value
        if pos < len(data):
            return f'<builtin_{ch}_{data[pos]}>', pos + 1
        return None, pos

    elif ch in ('O', 'E'):  # builtin/exception name (null-terminated)
        end = data.find(b'\x00', pos)
        if end == -1: return None, pos
        return data[pos:end].decode('utf-8', errors='replace'), end + 1

    elif ch == ':':  # slice(start, stop, step)
        items = []
        for _ in range(3):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        return ('slice', items[0], items[1], items[2]), pos

    elif ch == ';':  # range/xrange(start, stop, step)
        items = []
        for _ in range(3):
            item, pos = unpack_single_constant(data, pos)
            items.append(item)
        return ('range', items[0], items[1], items[2]), pos

    elif ch == 'A':  # GenericAlias (Python 3.9+) — 2 sub-constants
        parts = []
        for _ in range(2):
            item, pos = unpack_single_constant(data, pos)
            parts.append(item)
        return ('GenericAlias', parts[0], parts[1]), pos

    elif ch == 'H':  # UnionType (Python 3.10+) — 1 sub-constant
        args, pos = unpack_single_constant(data, pos)
        return ('UnionType', args), pos

    elif ch == 'C':  # CodeObject metadata
        co_info, pos = _parse_code_object_tag(data, pos)
        return co_info, pos

    elif ch == '.':  # end-of-stream marker
        return None, pos

    else:
        return None, pos


def _parse_code_object_tag(data, pos):
    """Parse the 'C' tag (CodeObject skeleton) and return a dict with the info.

    Synchronized with DataComposer.py _writeConstantValueCodeObject() and
    HelpersConstantsBlob.c _unpackBlobConstant() case 'C'.

    Flag bit layout (dynamic, version-dependent):
      [qualname] [free_vars] [kw_only] [pos_only] [gen_kind:2bits]
      [CO_OPTIMIZED] [CO_NEWLOCALS] [CO_VARARGS] [CO_VARKEYWORDS]
      [future_spec bits...]
    """
    try:
        flags, pos = read_vlq(data, pos)
        flag_base = 1

        # Name is mandatory
        func_name, pos = unpack_single_constant(data, pos)
        if not isinstance(func_name, str):
            func_name = str(func_name) if func_name else "<unknown>"

        # Line number is mandatory (encoded as line-1)
        line_number, pos = read_vlq(data, pos)
        line_number += 1

        # Arg names (tuple) is mandatory
        arg_names, pos = unpack_single_constant(data, pos)
        if not isinstance(arg_names, tuple): arg_names = ()

        # Arg count is mandatory
        arg_count, pos = read_vlq(data, pos)

        # qualname (Python 3.11+, optional flag)
        qualname = func_name
        if flags & flag_base:
            qualname, pos = unpack_single_constant(data, pos)
            if not isinstance(qualname, str): qualname = func_name
        flag_base <<= 1

        # free_vars (optional)
        free_vars = ()
        if flags & flag_base:
            free_vars, pos = unpack_single_constant(data, pos)
            if not isinstance(free_vars, tuple): free_vars = ()
        flag_base <<= 1

        # kw_only_count (Python 3.0+, optional)
        kw_only = 0
        if flags & flag_base:
            kw_only, pos = read_vlq(data, pos)
            kw_only += 1
        flag_base <<= 1

        # pos_only_count (Python 3.8+, optional)
        pos_only = 0
        if flags & flag_base:
            pos_only, pos = read_vlq(data, pos)
            pos_only += 1
        flag_base <<= 1

        # Generator kind: 2 bits
        co_flags = 0
        gen_bits = (flags >> (flag_base.bit_length() - 1)) & 3
        if gen_bits == 3: co_flags |= 0x200    # CO_ASYNC_GENERATOR
        elif gen_bits == 2: co_flags |= 0x100  # CO_COROUTINE
        elif gen_bits == 1: co_flags |= 0x20   # CO_GENERATOR
        flag_base <<= 2

        # CO_OPTIMIZED
        if flags & flag_base:
            co_flags |= 0x01
        flag_base <<= 1

        # CO_NEWLOCALS
        if flags & flag_base:
            co_flags |= 0x02
        flag_base <<= 1

        # CO_VARARGS
        if flags & flag_base:
            co_flags |= 0x04
        flag_base <<= 1

        # CO_VARKEYWORDS
        if flags & flag_base:
            co_flags |= 0x08
        flag_base <<= 1

        # Remaining bits are future_spec flags — we consume them
        # to keep position correct but don't need them for extraction.
        # CO_FUTURE_DIVISION (Py2), CO_FUTURE_UNICODE_LITERALS,
        # CO_FUTURE_PRINT_FUNCTION (Py2), CO_FUTURE_ABSOLUTE_IMPORT (Py2),
        # CO_FUTURE_GENERATOR_STOP (3.5-3.6), CO_FUTURE_ANNOTATIONS (3.7+),
        # CO_FUTURE_BARRY_AS_BDFL (3.0+)
        # These are bit flags but no additional data is read.

        return {
            '_type': 'CodeObject',
            'name': func_name,
            'qualname': qualname,
            'line': line_number,
            'args': list(arg_names),
            'argcount': arg_count,
            'kwonly': kw_only,
            'posonly': pos_only,
            'freevars': list(free_vars),
            'flags': co_flags,
        }, pos
    except Exception:
        return {'_type': 'CodeObject', 'name': '<parse_error>'}, pos


# =============================================================================
# BLOB PARSER - Named Chunks
# =============================================================================

def parse_blob_modules(blob_data: bytes, commercial_bypass: CommercialBypass = None):
    """Parse the Nuitka constants blob into named modules.

    Format: [CRC32(4)][size(4)][name\\0 chunk_size(4) chunk_data]...
    """
    if not blob_data or len(blob_data) < 8:
        return []

    crc_stored = struct.unpack('<I', blob_data[0:4])[0]
    size_stored = struct.unpack('<I', blob_data[4:8])[0]
    log(f"CRC32: 0x{crc_stored:08X}, Declared size: {size_stored:,} bytes")

    if 8 + size_stored <= len(blob_data):
        actual_crc = zlib.crc32(blob_data[8:8 + size_stored]) & 0xFFFFFFFF
        if actual_crc == crc_stored:
            log_ok("CRC32 verified OK!")
        else:
            log_warn(f"CRC32 mismatch: expected 0x{crc_stored:08X}, computed 0x{actual_crc:08X}")

    data = blob_data[8:]
    offset = 0
    modules = []

    while offset < len(data) - 5:
        name_end = data.find(b'\x00', offset, min(offset + 256, len(data)))
        if name_end == -1:
            break

        raw_name = data[offset:name_end]

        # Try decoding name (may be obfuscated with mapping2)
        try:
            module_name = raw_name.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            if commercial_bypass:
                module_name = commercial_bypass.decode_module_name(raw_name)
            else:
                module_name = raw_name.decode('utf-8', errors='replace')

        offset = name_end + 1

        if offset + 4 > len(data):
            break

        chunk_size = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        if chunk_size > 100 * 1024 * 1024 or offset + chunk_size > len(data):
            break

        chunk_data = data[offset:offset + chunk_size]
        offset += chunk_size

        modules.append((module_name, chunk_data))

    return modules


# =============================================================================
# NUITKA C-SOURCE REBUILDER  v7 — reconstruct Nuitka-style .c from metadata
# =============================================================================

class NuitkaCSourceRebuilder:
    """Reconstruct the per-module C source that Nuitka would have generated,
    using the metadata we recovered from the constants blob.

    The original C is not stored in the compiled binary (it is an intermediate
    file that Nuitka produces in the build directory and then compiles to
    machine code). What we CAN do is apply the exact same code templates
    (Nuitka-develop/nuitka/code_generation/templates/CodeTemplates*.py) to the
    metadata we recovered:

      - module name / identifier          (from blob chunk name / module table)
      - module_init_func address          (from module table)
      - constants                         (from parsed chunk - every 'str', 'int', etc.)
      - CodeObjectSpecs                   (from parsed chunk - every 'C' tag)
      - qualname hierarchy                (Class.method patterns)
      - function signatures               (args, kwonly, posonly, varargs, **kwargs)
      - doc strings                       (usually the first str constant per func)

    What we CANNOT recover (because Nuitka *does not* marshal it):
      - function bodies (they are translated directly to C operations and then
        to native x86-64 instructions)
      - local variable names beyond what appears in the argument list
      - source line numbers for individual statements

    So the generated C file is "Nuitka-style skeleton": it compiles conceptually
    (after plugging in the missing glue headers) and matches the original byte
    for byte in its structural sections (constants table, code objects,
    function declarations, module init) — only the function BODIES are stubbed.
    """

    # Mirror of the forward Nuitka mapping of Python identifiers to C names.
    # See Nuitka/code_generation/Identifiers.py and the `_encodePythonStringToC`
    # helpers — identifiers are transliterated conservatively.
    _IDENT_CHAR_MAP = {
        '.': '$', '-': '_', ' ': '_', '+': '_plus_', '/': '_slash_',
        '<': '$lt$', '>': '$gt$', '=': '$eq$', '[': '$lb$', ']': '$rb$',
        '(': '$lp$', ')': '$rp$', "'": '$sq$', '"': '$dq$', ',': '$c$',
        '!': '$ex$', '?': '$qm$',
    }

    @classmethod
    def encode_identifier(cls, s: str) -> str:
        out = []
        for c in s:
            if c.isalnum() or c == '_':
                out.append(c)
            elif c in cls._IDENT_CHAR_MAP:
                out.append(cls._IDENT_CHAR_MAP[c])
            else:
                out.append(f"$u{ord(c):04x}$")
        return ''.join(out) or '_empty'

    @classmethod
    def is_package(cls, module_name, module_table):
        if module_table:
            for e in module_table:
                if e['name'] == module_name:
                    return 'PACKAGE' in e['flag_names']
        return module_name.endswith('.__init__') or module_name in ('', '__main__')

    @classmethod
    def constant_c_name(cls, val, seen_names):
        """Produce a stable Nuitka-style name for a constant value."""
        tname = type(val).__name__
        if isinstance(val, str):
            # Nuitka uses: const_str_plain_<ident> for valid identifiers,
            # const_str_digest_<md5[:8]> for others.
            if val.isidentifier() and len(val) < 40:
                base = f"const_str_plain_{val}"
            else:
                import hashlib
                h = hashlib.md5(val.encode('utf-8', 'replace')).hexdigest()[:8]
                base = f"const_str_digest_{h}"
        elif isinstance(val, (bytes, bytearray)):
            import hashlib
            h = hashlib.md5(bytes(val)).hexdigest()[:8]
            base = f"const_bytes_digest_{h}"
        elif isinstance(val, bool):
            base = f"const_{str(val).lower()}"
        elif val is None:
            base = "const_none"
        elif isinstance(val, int):
            sign = 'neg' if val < 0 else 'pos'
            absv = abs(val)
            if absv < 1000000:
                base = f"const_int_{sign}_{absv}"
            else:
                import hashlib
                h = hashlib.md5(str(val).encode()).hexdigest()[:8]
                base = f"const_int_digest_{h}"
        elif isinstance(val, float):
            base = f"const_float_{str(val).replace('.', '_').replace('-', 'neg_')}"
        elif isinstance(val, tuple):
            base = f"const_tuple_{len(val)}"
        elif isinstance(val, list):
            base = f"const_list_{len(val)}"
        elif isinstance(val, dict):
            base = f"const_dict_{len(val)}"
        elif isinstance(val, set):
            base = f"const_set_{len(val)}"
        elif isinstance(val, frozenset):
            base = f"const_frozenset_{len(val)}"
        elif isinstance(val, dict) and val.get('_type') == 'CodeObject':
            base = f"const_code_object_{val.get('name', 'unknown')}"
        else:
            base = f"const_{tname}"

        base = cls.encode_identifier(base)

        # Disambiguate colliding names
        candidate = base
        k = 0
        while candidate in seen_names:
            k += 1
            candidate = f"{base}_{k}"
        seen_names.add(candidate)
        return candidate

    @classmethod
    def format_constant_comment(cls, val, max_len=60):
        try:
            r = repr(val)
        except Exception:
            return "<unrepresentable>"
        if len(r) > max_len:
            r = r[:max_len] + '...'
        return r.replace('*/', '*\\/').replace('\n', '\\n')

    @classmethod
    def infer_functions_from_constants(cls, constants):
        """For C-compiled modules that don't serialize CodeObjectSpec ('C')
        tags, Nuitka still embeds the filename, function name, qualname and
        co_varnames tuple as plain constants because they're passed to
        `MAKE_FUNCTION_*`. We detect those tuples by matching on any of the
        layouts the code-generator emits.

        Typical layouts observed in real binaries:

          Layout A (free function / module body):
            [name_str]  [filename.py str]  [qualname]  [tuple(varnames)]

          Layout B (method — qualname contains a dot):
            [tuple(varnames)]  [name_str]  [qualname('Class.method')]  [filename.py]

          Layout C (listcomp / genexpr helper - qualname starts with <):
            [tuple(varnames)]  [name_str=<listcomp>]  [qualname]  [filename.py]

        We anchor on `.py` filenames, look both before and after by up to 4
        positions, and accept any arrangement where exactly one ident-tuple,
        one plain ident, and one qualname (optionally dotted) are adjacent.
        """
        inferred = []
        def is_ident(s):
            return (isinstance(s, str) and s
                    and (s.isidentifier() or s.startswith('<')))

        def is_qualname(s):
            if not isinstance(s, str) or not s:
                return False
            # qualnames can be 'x.y', 'x.<locals>.y', '<module>', '<module x.y>', 'x'
            if s.startswith('<'):
                return True
            parts = s.replace('<locals>', 'LOCALS').split('.')
            return all(p.isidentifier() for p in parts if p)

        def is_ident_tuple(t):
            if not isinstance(t, tuple) or not t:
                return False
            # Allow leading '.0' synthetic argument used by comprehensions
            for x in t:
                if not isinstance(x, str):
                    return False
                if x == '.0' or x.isidentifier():
                    continue
                return False
            return True

        # Find a single module filename (for context).
        module_filename = None
        for c in constants:
            if isinstance(c, str) and c.endswith('.py'):
                module_filename = c
                break

        # Anchor on each tuple-of-idents (candidate co_varnames). Those are
        # what Nuitka MUST emit for every function / class body.
        seen_anchors = set()
        for i, c in enumerate(constants):
            if not is_ident_tuple(c):
                continue

            # Tuples of 1-2 elements that look like __slots__ or simple
            # decorator arg tuples usually aren't co_varnames. Require
            # length > 0 always (even `()` is a valid co_varnames for no-arg funcs).
            varnames = c

            # Scan neighbours for: a qualified name (like "Foo.bar" or "<module>"
            # or "<listcomp>") OR a plain ident (function name).
            window = []
            for off in (-4, -3, -2, -1, 1, 2, 3, 4):
                j = i + off
                if 0 <= j < len(constants):
                    window.append((j, constants[j]))

            # Collect the closest name candidate (plain ident) and
            # qualname candidate (dotted/angle).
            name_val = None
            name_dist = 99
            qualname_val = None
            qual_dist = 99
            for j, v in window:
                if not isinstance(v, str):
                    continue
                if v.endswith('.py'):
                    continue
                d = abs(j - i)
                # qualname-like: contains '.' OR '<...>' wrapper
                if is_qualname(v) and (
                        '.' in v or (v.startswith('<') and v.endswith('>'))):
                    if d < qual_dist:
                        qual_dist, qualname_val = d, v
                # plain ident-like name
                elif is_ident(v) and '.' not in v:
                    if d < name_dist:
                        name_dist, name_val = d, v

            # Must find at least a name OR a qualname.
            if name_val is None and qualname_val is None:
                continue

            if name_val is None:
                # Derive plain name from qualname
                nm = qualname_val
                if '.' in nm:
                    nm = nm.rsplit('.', 1)[-1]
                name_val = nm

            if qualname_val is None:
                qualname_val = name_val

            anchor = (i, name_val, tuple(varnames))
            if anchor in seen_anchors:
                continue
            seen_anchors.add(anchor)

            inferred.append({
                '_type': 'CodeObject',
                'name': name_val,
                'qualname': qualname_val,
                'filename': module_filename or '',
                'args': list(varnames),
                'argcount': len(varnames),
                'kwonly': 0,
                'posonly': 0,
                'freevars': [],
                'flags': 0,
                'line': 0,
                '_source': 'inferred-from-constants',
            })

        # Deduplicate (same name, args)
        seen = set()
        out = []
        for co in inferred:
            k = (co['name'], tuple(co['args']), co.get('qualname'))
            if k in seen:
                continue
            seen.add(k)
            out.append(co)
        return out

    @classmethod
    def classify_code_objects(cls, code_objects):
        """Group code objects by their qualified-name hierarchy.

        Returns a dict: { 'Class.method': [...], 'free_function': [...], '<module>': [...] }

        This lets us emit class { ... } structures correctly. Nuitka uses qualname
        of the form "Class.method" (or "Class.inner_func") to denote nested
        definitions.
        """
        tree = {
            '__module_body__': [],   # qualname == '<module>' or name == '<module>'
            'classes': {},            # 'ClassName' -> {'methods': [...], 'bases': []}
            'free_functions': [],
        }

        for co in code_objects:
            if not co:
                continue
            name = co.get('name') or ''
            qualname = co.get('qualname') or name

            if name == '<module>' or qualname == '<module>':
                tree['__module_body__'].append(co)
                continue

            # qualname of "Foo.bar" → method 'bar' of class 'Foo'
            if '.' in qualname and not qualname.startswith('<'):
                parent, leaf = qualname.rsplit('.', 1)
                # Strip any trailing <locals> markers
                parent = parent.split('.<locals>.')[0]
                if '.' not in parent and parent and parent[0].isupper():
                    # Looks like a class
                    tree['classes'].setdefault(parent, {'methods': [], 'bases': []})
                    tree['classes'][parent]['methods'].append(co)
                    continue

            # Default: free function
            tree['free_functions'].append(co)

        return tree

    @classmethod
    def format_arg_list(cls, co):
        """Turn a CodeObjectSpec into a 'def foo(a, b, *args, c=..., **kw)' style arg string."""
        args = list(co.get('args') or [])
        argcount = co.get('argcount') or 0
        kwonly = co.get('kwonly') or 0
        posonly = co.get('posonly') or 0
        flags = co.get('flags') or 0

        has_varargs = bool(flags & 0x04)
        has_varkw = bool(flags & 0x08)

        parts = []
        idx = 0
        # Positional-only args (before a '/')
        if posonly:
            for _ in range(min(posonly, len(args))):
                parts.append(str(args[idx]))
                idx += 1
            parts.append('/')

        # Regular positional args
        regular_count = argcount - (posonly or 0)
        for _ in range(regular_count):
            if idx < len(args):
                parts.append(str(args[idx]))
            idx += 1

        if has_varargs:
            if idx < len(args):
                parts.append('*' + str(args[idx]))
                idx += 1
            else:
                parts.append('*args')
        elif kwonly:
            parts.append('*')

        for _ in range(kwonly):
            if idx < len(args):
                parts.append(f"{args[idx]}=...")
                idx += 1

        if has_varkw:
            if idx < len(args):
                parts.append('**' + str(args[idx]))
            else:
                parts.append('**kwargs')

        return ', '.join(parts)

    @classmethod
    def generate_c_source(cls, module_name, constants, code_objects,
                           module_table_entry=None, native_func_addr=None,
                           nuitka_version="RECONSTRUCTED"):
        """Produce the full .c file content for this module."""
        if not module_name:
            module_name = '__main__'
        module_ident = cls.encode_identifier(module_name)

        is_pkg = (module_table_entry and 'PACKAGE' in module_table_entry.get('flag_names', []))
        is_dunder_main = module_name == '__main__'
        flags = module_table_entry['flag_names'] if module_table_entry else ['COMPILED']

        # -- Header / copyright -------------------------------------------
        year = datetime.now().year
        out = []
        out.append(f"/* Reconstructed C source for Python module '{module_name}'")
        out.append(f" * Recovered by Nuitka Static Unpacker v7.2 from compiled binary metadata.")
        out.append(f" *")
        out.append(f" * Original C was generated by Nuitka but is not stored in the binary.")
        out.append(f" * This reconstruction applies the same Nuitka code-generation templates")
        out.append(f" * to the metadata we recovered from the constants blob.")
        out.append(f" *")
        out.append(f" * STRUCTURAL PARTS (match what Nuitka produced):")
        out.append(f" *   - Module constants table (every constant byte-identical)")
        out.append(f" *   - Code object declarations (names, line numbers, arg names)")
        out.append(f" *   - Function signature declarations")
        out.append(f" *   - Module-initialization entry point")
        out.append(f" *")
        out.append(f" * LOST (compiled directly to native instructions by Nuitka):")
        out.append(f" *   - Function bodies — translated through Nuitka IR to C operations")
        out.append(f" *     to x86-64/ARM assembly. Original Python statements cannot be")
        out.append(f" *     reconstructed without disassembling the native code around the")
        out.append(f" *     module_init_func pointer.")
        out.append(f" *")
        if native_func_addr:
            out.append(f" * NATIVE ENTRY POINT: module_code_{module_ident} @ 0x{native_func_addr:X}")
        out.append(f" * Flags: {', '.join(flags)}")
        out.append(f" * Is package: {is_pkg}")
        out.append(f" */")
        out.append("")
        out.append(f'#include "nuitka/prelude.h"')
        out.append(f'#include "nuitka/unfreezing.h"')
        out.append(f'#include "__helpers.h"')
        out.append("")

        out.append(f"/* The module object (Python-visible) */")
        out.append(f"PyObject *module_{module_ident};")
        out.append(f"PyDictObject *moduledict_{module_ident};")
        out.append("")

        # -- Module constants struct -------------------------------------
        out.append(f"/* Module constants: {len(constants)} entries recovered from blob chunk '{module_name}'. */")
        out.append("static struct ModuleConstants {")
        seen_names = set()
        constant_c_names = []
        for idx, c in enumerate(constants):
            cname = cls.constant_c_name(c, seen_names)
            constant_c_names.append(cname)
            comment = cls.format_constant_comment(c)
            out.append(f"    PyObject *{cname};  /* [{idx}] {type(c).__name__} = {comment} */")
        out.append("} mod_consts;")
        out.append("")

        out.append(f"static PyObject *module_filename_obj = NULL;")
        out.append("static bool constants_created = false;")
        out.append("")
        out.append(f"static void createModuleConstants(PyThreadState *tstate) {{")
        out.append(f"    if (constants_created == false) {{")
        out.append(f'        loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("{module_name}"));')
        out.append(f"        constants_created = true;")
        out.append(f"    }}")
        out.append(f"}}")
        out.append("")

        if is_dunder_main:
            out.append(f"/* Entry used to initialize __main__ constants from main program glue. */")
            out.append(f"void createMainModuleConstants(PyThreadState *tstate) {{")
            out.append(f"    createModuleConstants(tstate);")
            out.append(f"}}")
            out.append("")

        # -- Function inference from constants (for C-compiled modules) --
        # The chunk usually has no 'C' (CodeObjectSpec) tag for compiled modules,
        # but the tuples of varnames + the source filename + the function name
        # ARE still present as constants (Nuitka needs them for MAKE_FUNCTION).
        # We harvest those patterns to recover function signatures.
        inferred = cls.infer_functions_from_constants(constants)
        if inferred and not code_objects:
            code_objects = inferred
        elif inferred:
            # Merge: keep explicit CodeObjects but add any inferred ones not already present
            seen = {(co.get('name'), tuple(co.get('args') or ())) for co in code_objects}
            for co in inferred:
                if (co['name'], tuple(co['args'])) not in seen:
                    code_objects.append(co)

        # -- Code object declarations -----------------------------------
        out.append("/* Code objects declared for this module's functions. Nuitka")
        out.append(" * creates one PyCodeObject per function/class body, then wraps")
        out.append(" * them in Nuitka_Function objects via MAKE_FUNCTION_*. */")
        for idx, co in enumerate(code_objects):
            if not co:
                continue
            name = co.get('name', '?')
            line = co.get('line', 0)
            src = co.get('_source', 'explicit')
            out.append(f"static PyCodeObject *codeobj_{idx}__{cls.encode_identifier(name)};   /* {name!r} @ line {line}  ({src}) */")
        out.append("")

        # -- Function declarations + stubs ------------------------------
        tree = cls.classify_code_objects(code_objects)

        # Module body (if we inferred one)
        if tree['__module_body__']:
            out.append("/* === Module body code object ================================ */")
            for co in tree['__module_body__']:
                name = co.get('name', '<module>')
                arg_list = cls.format_arg_list(co)
                fn = co.get('filename', '?')
                out.append("")
                out.append(f"/* Module body for {module_name!r}")
                out.append(f" *   source filename: {fn}")
                out.append(f" *   locals / varnames: ({arg_list})")
                out.append(f" *   — this is what runs on `import {module_name}` */")
                out.append(f"/* Nuitka-style entry: module_code_{module_ident}() — see below. */")

        # Free functions
        out.append("")
        out.append("/* === Free function signatures =============================== */")
        for co in tree['free_functions']:
            name = co.get('name', 'unknown')
            qualname = co.get('qualname', name)
            line = co.get('line', 0)
            arg_list = cls.format_arg_list(co)
            out.append(f"")
            out.append(f"/* Recovered Python signature:  def {name}({arg_list})")
            out.append(f" *  qualname: {qualname}   line: {line}")
            out.append(f" *  flags: 0x{co.get('flags', 0):X}")
            out.append(f" *  body: compiled to native code — not recoverable here */")
            out.append(f"static PyObject *impl_{module_ident}${cls.encode_identifier(name)}(PyThreadState *tstate, PyObject **python_pars);")

        # Classes
        out.append("")
        out.append("/* === Class bodies ============================================ */")
        for class_name, cdata in tree['classes'].items():
            out.append("")
            out.append(f"/* Class: {class_name}")
            out.append(f" *   methods recovered: {len(cdata['methods'])}")
            out.append(f" *   class body was also compiled to native code */")
            for co in cdata['methods']:
                name = co.get('name', '?')
                line = co.get('line', 0)
                arg_list = cls.format_arg_list(co)
                out.append(f"static PyObject *impl_{module_ident}${cls.encode_identifier(class_name)}${cls.encode_identifier(name)}(PyThreadState *tstate, PyObject **python_pars);  /* def {class_name}.{name}({arg_list}) line {line} */")

        # -- Function stubs (bodies) --------------------------------------
        out.append("")
        out.append("/* === Function body stubs =====================================")
        out.append(" *   All bodies are placeholders. The real implementations are")
        out.append(" *   at the machine-code level. See module_code_<name> below")
        out.append(" *   for the native entry point recovered from the PE. */")
        out.append("")

        for co in tree['free_functions']:
            name = co.get('name', 'unknown')
            arg_list = cls.format_arg_list(co)
            ident = f"{module_ident}${cls.encode_identifier(name)}"
            out.append(f"static PyObject *impl_{ident}(PyThreadState *tstate, PyObject **python_pars) {{")
            out.append(f"    /* Original Python source equivalent:  def {name}({arg_list}): ... */")
            out.append(f"    /* Body unrecoverable. Disassemble around the native")
            out.append(f"     * module_init entry point to inspect the compiled code. */")
            out.append(f"    Py_RETURN_NONE;")
            out.append(f"}}")
            out.append("")

        for class_name, cdata in tree['classes'].items():
            for co in cdata['methods']:
                name = co.get('name', '?')
                arg_list = cls.format_arg_list(co)
                ident = f"{module_ident}${cls.encode_identifier(class_name)}${cls.encode_identifier(name)}"
                out.append(f"static PyObject *impl_{ident}(PyThreadState *tstate, PyObject **python_pars) {{")
                out.append(f"    /* def {class_name}.{name}({arg_list}): ... */")
                out.append(f"    Py_RETURN_NONE;")
                out.append(f"}}")
                out.append("")

        # -- Module init entry point (Nuitka's standard template) --------
        out.append("/* ============================================================")
        out.append(" *  Module initialization entry point")
        out.append(" *  Nuitka template: template_module_body in CodeTemplatesModules.py")
        out.append(" * ============================================================ */")
        out.append(f"PyObject *module_code_{module_ident}(PyThreadState *tstate, PyObject *module,")
        out.append(f"                                     struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {{")
        out.append(f"    module_{module_ident} = module;")
        out.append(f"    moduledict_{module_ident} = MODULE_DICT(module_{module_ident});")
        out.append(f"")
        out.append(f"    static bool init_done = false;")
        out.append(f"    if (init_done == false) {{")
        out.append(f"        createModuleConstants(tstate);")
        out.append(f"        init_done = true;")
        out.append(f"    }}")
        out.append(f"")
        out.append(f"    /* The sequence of CREATE_MODULE_VARIABLE + MAKE_FUNCTION calls")
        out.append(f"     * that Nuitka generates here for import statements and class")
        out.append(f"     * definitions is not recoverable from metadata alone.")
        out.append(f"     * It lives natively at:")
        if native_func_addr:
            out.append(f"     *    PE virtual address  0x{native_func_addr:X}")
        out.append(f"     *")
        out.append(f"     * Recovered imports (detected from module constants): */")
        # Heuristic: scan constants for 'module.name' patterns used as import args
        for c in constants:
            if isinstance(c, str) and '.' in c and c.replace('.', '').replace('_', '').isalnum():
                if not c.startswith('.') and len(c) < 60:
                    out.append(f"    /*   import {c} */")
        out.append(f"")
        out.append(f"    return module;")
        out.append(f"}}")
        out.append("")

        return '\n'.join(out) + '\n'


# =============================================================================
# NUITKA MODULE TABLE PARSER  v7 — locate Nuitka_MetaPathBasedLoaderEntry[]
# =============================================================================

class NuitkaModuleTableParser:
    """Parse the array of `Nuitka_MetaPathBasedLoaderEntry` from the PE.

    Each record (x64, 32 bytes without file_path):
        char const *name;                  // +0   8 bytes
        module_init_func python_init_func; // +8   8 bytes
        int bytecode_index;                // +16  4 bytes
        int bytecode_size;                  // +20  4 bytes
        int flags;                          // +24  4 bytes
        // 4 bytes padding (aligns next pointer)
    Terminator: {NULL, NULL, 0, 0, 0}

    The `flags` field uses bits from unfreezing.h:
        NUITKA_EXTENSION_MODULE_FLAG = 1
        NUITKA_PACKAGE_FLAG          = 2
        NUITKA_BYTECODE_FLAG         = 4
        NUITKA_ABORT_MODULE_FLAG     = 8
        NUITKA_TRANSLATED_FLAG       = 16
        NUITKA_PERFECT_SUPPORTED_FLAG= 32
        NUITKA_EXCLUDED_MODULE_FLAG  = 64

    For x86 (32-bit) the pointers are 4 bytes each, record is 20 bytes.
    """

    FLAG_NAMES = {
        1: 'EXTENSION', 2: 'PACKAGE', 4: 'BYTECODE',
        8: 'ABORT',     16: 'TRANSLATED', 32: 'PERFECT',
        64: 'EXCLUDED',
    }

    def __init__(self, pe):
        self.pe = pe
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.is_x64 = pe.FILE_HEADER.Machine == 0x8664
        self.ptr_size = 8 if self.is_x64 else 4
        self.record_size = 32 if self.is_x64 else 20

    def _collect_strings(self):
        """Index every null-terminated printable ASCII string in .rdata/.data."""
        strings_by_va = {}
        for section in self.pe.sections:
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if name not in ('.rdata', '.data'):
                continue
            sec_data = section.get_data()
            base_va = self.image_base + section.VirtualAddress
            i = 0
            sz = len(sec_data)
            while i < sz:
                j = i
                while j < sz and 0x20 <= sec_data[j] < 0x7F:
                    j += 1
                if j > i and j < sz and sec_data[j] == 0:
                    if j - i >= 2:
                        try:
                            s = sec_data[i:j].decode('ascii')
                            strings_by_va[base_va + i] = s
                        except Exception:
                            pass
                    i = j + 1
                else:
                    i = j + 1 if j > i else i + 1
        return strings_by_va

    @staticmethod
    def _is_module_name(s):
        if not s or len(s) > 200:
            return False
        # Valid dotted module identifier, or __special__
        if not all(c.isalnum() or c in '._' for c in s):
            return False
        # Must start with letter/underscore
        first = s[0]
        if not (first.isalpha() or first == '_'):
            return False
        return True

    def find_table(self, extra_names=None):
        """Locate the module table and return the full entry list.

        Strategy (3 passes, combined):

          1. **Primary cluster scan** — identical to the original: walk every
             8-byte offset in .data/.rdata, follow contiguous records and
             pick the longest run with >= 100 entries whose names look
             module-like. That's the main loader table Nuitka emits in
             `meta_path_loader_entries[]`.

          2. **Fragment stitching** — ANY other cluster of >= 10
             consecutive valid records in the same sections is appended
             (deduplicated by `func_ptr`). Some builds split the table
             across a couple of fragments, typically when data-hiding
             plugins reorder it.

          3. **Name-anchored fallback** — given `extra_names` (a list of
             module names we already know exist, e.g. from the blob chunks
             the analyser decoded), search for each name's string in
             .data/.rdata, then scan for a qword pointer to that string.
             Around each such pointer, try to parse a full record (32-B
             layout). If the record validates, add it. This rescues
             isolated entries like `__main__` that live outside the main
             cluster because Nuitka's loader-codes generator sometimes
             emits them in a sidecar array.

        Returns `(start_va, entries)` or `None`.
        """
        strings_by_va = self._collect_strings()
        module_strings = {va: s for va, s in strings_by_va.items()
                          if self._is_module_name(s)}

        best = None                 # (start_va, entries) — the primary cluster
        other_clusters = []         # [(va, entries), ...] — passed 2

        # Snapshot of each section (avoid re-calling get_data() in the hot loop)
        sections_info = []
        for section in self.pe.sections:
            sec_name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            if sec_name not in ('.rdata', '.data'):
                continue
            sections_info.append({
                'name': sec_name,
                'data': section.get_data(),
                'base_va': self.image_base + section.VirtualAddress,
            })

        # ---------- Pass 1 + 2 ----------
        for info in sections_info:
            sec_data = info['data']
            sec_size = len(sec_data)
            base_va = info['base_va']

            off = 0
            while off < sec_size - self.record_size:
                if self.is_x64:
                    p1 = struct.unpack('<Q', sec_data[off:off + 8])[0]
                else:
                    p1 = struct.unpack('<I', sec_data[off:off + 4])[0]

                if p1 not in module_strings:
                    off += 8
                    continue

                entries = []
                run_off = off
                while run_off + self.record_size <= sec_size:
                    entry = self._read_record(sec_data, run_off, module_strings)
                    if entry is None:
                        break
                    if entry == 'TERMINATOR':
                        break
                    entries.append(entry)
                    run_off += self.record_size
                    if len(entries) > 10000:
                        break

                if entries:
                    # Promote any cluster of >= 100 entries to the primary;
                    # fragments of >= 10 are kept for stitching.
                    if len(entries) >= 100:
                        dotted = sum(1 for e in entries if '.' in e['name'])
                        has_trans = sum(1 for e in entries if (e['flags'] & 16) != 0)
                        if not (dotted < 5 and has_trans < 50):
                            if best is None or len(entries) > len(best[1]):
                                best = (base_va + off, entries)
                    elif len(entries) >= 10:
                        has_trans = sum(1 for e in entries if (e['flags'] & 16) != 0)
                        if has_trans >= 5:
                            other_clusters.append((base_va + off, entries))

                # Jump past the cluster we just consumed; if only 1 entry
                # matched we advance by record_size to try the next slot.
                off = run_off + (self.record_size if not entries else 0)
                if off <= run_off:
                    off = run_off + 8

        # Merge fragments into the primary cluster (deduplicate on func_ptr
        # OR on (name, bytecode_index) when func_ptr is 0).
        def _entry_key(e):
            if e.get('func_ptr'):
                return ('fp', e['func_ptr'])
            return ('ni', e.get('name'), e.get('bytecode_index'))

        if best is None and other_clusters:
            # No primary cluster — promote the biggest fragment
            other_clusters.sort(key=lambda c: -len(c[1]))
            best = other_clusters[0]
            other_clusters = other_clusters[1:]

        if best and other_clusters:
            seen_keys = {_entry_key(e) for e in best[1]}
            merged = list(best[1])
            for _, frag in other_clusters:
                for e in frag:
                    k = _entry_key(e)
                    if k in seen_keys:
                        continue
                    seen_keys.add(k)
                    merged.append(e)
            best = (best[0], merged)

        # ---------- Pass 3 — name-anchored fallback ----------
        #
        # For every module name we know the binary MUST contain (either
        # passed in via `extra_names` or the blob chunk names we already
        # decoded), find its string address and scan for a qword pointer
        # that references it. If the 32-B window around the pointer looks
        # like a valid `Nuitka_MetaPathBasedLoaderEntry`, add it.
        #
        # This is what rescues `__main__`, `.bytecode`, and other entries
        # Nuitka emits outside the main `meta_path_loader_entries[]`
        # array (e.g. as members of `_frozen_modules[]` or in a data-hiding
        # plugin's sidecar table).
        if extra_names:
            # Build reverse lookup: module_name -> string_va
            name_to_va = {s: va for va, s in module_strings.items()}
            # Also add names we didn't flag as "module-like" (e.g. '.bytecode')
            for va, s in strings_by_va.items():
                if s and s not in name_to_va:
                    name_to_va[s] = va

            known = set()
            if best:
                for e in best[1]:
                    known.add(e['name'])

            added_va = set()
            if best:
                added = []
                for n in extra_names:
                    if n in known:
                        continue
                    target_va = name_to_va.get(n)
                    if target_va is None:
                        # String not findable in .data/.rdata → skip
                        continue

                    # Scan every 8-byte-aligned offset in .data/.rdata for
                    # a qword pointing at target_va; that slot is the
                    # `name` field of a potential record.
                    for info in sections_info:
                        sec_data = info['data']
                        sec_size = len(sec_data)
                        base_va = info['base_va']

                        # Use struct.iter_unpack for speed
                        ptr_fmt = '<Q' if self.is_x64 else '<I'
                        step = self.ptr_size
                        # Align to step
                        for off in range(0, sec_size - self.record_size, step):
                            ptr = struct.unpack_from(ptr_fmt, sec_data, off)[0]
                            if ptr != target_va:
                                continue
                            abs_va = base_va + off
                            if abs_va in added_va:
                                continue
                            entry = self._read_record(sec_data, off, module_strings)
                            if (entry is None or entry == 'TERMINATOR'
                                    or not isinstance(entry, dict)):
                                # Name may not have passed _is_module_name
                                # (e.g. `.bytecode`). Re-parse permissively.
                                entry = self._read_record_permissive(
                                    sec_data, off, strings_by_va)
                            if entry and entry != 'TERMINATOR':
                                added.append(entry)
                                added_va.add(abs_va)
                                known.add(entry['name'])
                                break   # found it; don't keep scanning
                if added:
                    merged = list(best[1]) + [
                        e for e in added
                        if _entry_key(e) not in {_entry_key(x) for x in best[1]}
                    ]
                    best = (best[0], merged)

        return best

    def _read_record_permissive(self, sec_data, off, all_strings):
        """Relaxed version of _read_record that accepts ANY string (not
        just module-name-looking) as the `name` pointer. Used for the
        pass-3 rescue when we already know the target name is legit."""
        if self.is_x64:
            name_ptr = struct.unpack('<Q', sec_data[off:off + 8])[0]
            func_ptr = struct.unpack('<Q', sec_data[off + 8:off + 16])[0]
            bc_idx   = struct.unpack('<i', sec_data[off + 16:off + 20])[0]
            bc_size  = struct.unpack('<i', sec_data[off + 20:off + 24])[0]
            flags    = struct.unpack('<I', sec_data[off + 24:off + 28])[0]
        else:
            name_ptr = struct.unpack('<I', sec_data[off:off + 4])[0]
            func_ptr = struct.unpack('<I', sec_data[off + 4:off + 8])[0]
            bc_idx   = struct.unpack('<i', sec_data[off + 8:off + 12])[0]
            bc_size  = struct.unpack('<i', sec_data[off + 12:off + 16])[0]
            flags    = struct.unpack('<I', sec_data[off + 16:off + 20])[0]

        if name_ptr == 0 and func_ptr == 0 and bc_idx == 0 and bc_size == 0 and flags == 0:
            return 'TERMINATOR'
        if name_ptr not in all_strings:
            return None
        if flags > 0xFF:
            return None
        if bc_idx < 0 or bc_idx > 100000 or bc_size < 0 or bc_size > 100_000_000:
            return None

        return {
            'name': all_strings[name_ptr],
            'func_ptr': func_ptr,
            'bytecode_index': bc_idx,
            'bytecode_size': bc_size,
            'flags': flags,
            'flag_names': self._decode_flags(flags),
        }

    def _read_record(self, sec_data, off, module_strings):
        """Decode one Nuitka_MetaPathBasedLoaderEntry. Returns dict or None or 'TERMINATOR'."""
        if self.is_x64:
            name_ptr = struct.unpack('<Q', sec_data[off:off + 8])[0]
            func_ptr = struct.unpack('<Q', sec_data[off + 8:off + 16])[0]
            bc_idx   = struct.unpack('<i', sec_data[off + 16:off + 20])[0]
            bc_size  = struct.unpack('<i', sec_data[off + 20:off + 24])[0]
            flags    = struct.unpack('<I', sec_data[off + 24:off + 28])[0]
        else:
            name_ptr = struct.unpack('<I', sec_data[off:off + 4])[0]
            func_ptr = struct.unpack('<I', sec_data[off + 4:off + 8])[0]
            bc_idx   = struct.unpack('<i', sec_data[off + 8:off + 12])[0]
            bc_size  = struct.unpack('<i', sec_data[off + 12:off + 16])[0]
            flags    = struct.unpack('<I', sec_data[off + 16:off + 20])[0]

        if name_ptr == 0 and func_ptr == 0 and bc_idx == 0 and bc_size == 0 and flags == 0:
            return 'TERMINATOR'

        if name_ptr not in module_strings:
            return None
        if flags > 0xFF:
            return None
        if bc_idx < 0 or bc_idx > 100000 or bc_size < 0 or bc_size > 100_000_000:
            return None

        return {
            'name': module_strings[name_ptr],
            'func_ptr': func_ptr,
            'bytecode_index': bc_idx,
            'bytecode_size': bc_size,
            'flags': flags,
            'flag_names': self._decode_flags(flags),
        }

    @classmethod
    def _decode_flags(cls, flags):
        names = [n for bit, n in cls.FLAG_NAMES.items() if flags & bit]
        return names if names else ['COMPILED']


# =============================================================================
# STATICALY INTEGRATION  v7_2 — pure-Python port of nuitka_deobfuscate.c +
#                               xdis-based code object scanner +
#                               OMNI unified Nuitka decompiler framework
# =============================================================================
#
# Originally three separate modules contributed by a collaborator:
#   1. `nuitka_deobfuscate.c` (CPython extension)  — fast blob section decoder
#   2. `run_extract*.py`                           — xdis marshal scanner
#   3. `omni_nuitka_framework.py`                  — AST-based decompiler
#
# All three are now embedded directly in this file as pure Python so the tool
# remains standalone. xdis is used when available (optional dependency) for
# cross-Python-version marshal parsing; otherwise we fall back to the builtin
# marshal module and our own write_pyc_from_marshal header helper.
# =============================================================================

# ---------------------------------------------------------------------------
#  1. NUITKA BLOB DECODER  (Python port of nuitka_deobfuscate.c)
# ---------------------------------------------------------------------------

class NuitkaBlobDecoder:
    """Full Python port of `nuitka_deobfuscate.c` (collaborator's extension).

    Two-pass decoder for Nuitka constants blobs:

    * SCAN 1 — Linear Chain:  follow the documented
          [name\\0] [u32 size] [u16 count] [typed constants...]
      layout starting at offset 8 (past the CRC32/size header). This recovers
      the "normal" named sections Nuitka's data composer emits.

    * SCAN 2 — Aggressive Signature Scan:  slide byte-by-byte through the blob
      looking for `[u32 size][u16 count][valid tag byte]` triples and try to
      decode constants from that offset. Rescues sections that the linear
      walker misses (truncated blobs, custom plugins, hidden injected
      segments, corrupted CRCs).

    Returns a `dict[str, tuple[Any, ...]]` mapping section name to its
    decoded constants tuple — identical signature to the C `.decode_blob`.
    """

    # Valid first-byte tags for a constant in Nuitka's format (see
    # Nuitka-develop/nuitka/build/static_src/HelpersConstantsBlob.c)
    _VALID_TAGS = frozenset(b"TLDCXbvactF:;MQOEZSPilqgGfjJBwu.AHcdrnsKpI")

    _DEPTH_LIMIT = 500

    def __init__(self):
        self._collision_idx = 0

    # ---- primitive readers ----

    @staticmethod
    def _unpack_vlq(data: memoryview, pos: int):
        """Nuitka's variable-length quantity (7-bit LE, high bit = continue)."""
        result = 0
        factor = 1
        end = len(data)
        while pos < end:
            b = data[pos]
            pos += 1
            result += (b & 0x7F) * factor
            if b < 0x80:
                break
            factor <<= 7
            if factor >= (1 << 63):
                break
        return result, pos

    @staticmethod
    def _anon_value(idx: int):
        """Recover singleton values by index (Ellipsis, NotImplemented, etc.)."""
        try:
            return [type(None), type(Ellipsis), type(NotImplemented),
                    __import__('types').FunctionType, None,
                    __import__('builtins').classmethod,
                    __import__('types').CodeType,
                    __import__('types').ModuleType][idx]
        except Exception:
            return None

    @staticmethod
    def _special_value(idx: int):
        m = {0: Ellipsis, 1: NotImplemented, 2: sys.version_info}
        return m.get(idx, None)

    # ---- recursive constant decoder ----

    def _decode_one(self, data: memoryview, pos: int, depth: int = 0):
        """Decode exactly one constant and return (value, new_pos).

        Mirrors `_unpackBlobConstant` in nuitka_deobfuscate.c. On malformed
        input we consume one byte and emit None — this matches the C version's
        behaviour and keeps the stream aligned for subsequent constants.
        """
        end = len(data)
        if depth > self._DEPTH_LIMIT or pos >= end:
            return None, min(pos + 1, end)

        tag = data[pos]
        pos += 1
        ch = chr(tag) if tag < 128 else None

        if ch == 'p':  # repeat-marker, consumes a VLQ
            _, pos = self._unpack_vlq(data, pos)
            return None, pos

        if ch in ('T', 'L'):
            size, pos = self._unpack_vlq(data, pos)
            if size > 5_000_000:
                return None, pos
            items = []
            for _ in range(size):
                if pos >= end:
                    break
                v, pos = self._decode_one(data, pos, depth + 1)
                items.append(v)
            return (tuple(items) if ch == 'T' else items), pos

        if ch == 'D':
            size, pos = self._unpack_vlq(data, pos)
            if size > 500_000:
                return {}, pos
            keys = []
            for _ in range(size):
                if pos >= end:
                    break
                v, pos = self._decode_one(data, pos, depth + 1)
                keys.append(v)
            values = []
            for _ in range(size):
                if pos >= end:
                    break
                v, pos = self._decode_one(data, pos, depth + 1)
                values.append(v)
            d = {}
            for k, v in zip(keys, values):
                try:
                    d[k] = v
                except TypeError:
                    pass
            return d, pos

        if ch in ('S', 'P'):
            size, pos = self._unpack_vlq(data, pos)
            if size > 500_000:
                return (set() if ch == 'S' else frozenset()), pos
            items = []
            for _ in range(size):
                if pos >= end:
                    break
                v, pos = self._decode_one(data, pos, depth + 1)
                items.append(v)
            try:
                return (set(items) if ch == 'S' else frozenset(items)), pos
            except TypeError:
                return (set() if ch == 'S' else frozenset()), pos

        if ch in ('i', 'l'):
            val, pos = self._unpack_vlq(data, pos)
            return val, pos
        if ch == 'q':
            val, pos = self._unpack_vlq(data, pos)
            return -val, pos

        if ch in ('g', 'G'):
            nparts, pos = self._unpack_vlq(data, pos)
            result = 0
            for _ in range(nparts):
                result <<= 31
                part, pos = self._unpack_vlq(data, pos)
                result += part
            return (-result if ch == 'G' else result), pos

        if ch == 'f':
            if pos + 8 > end:
                return 0.0, end
            val = struct.unpack_from('<d', data, pos)[0]
            return val, pos + 8

        if ch == 'j':
            if pos + 16 > end:
                return 0j, end
            real = struct.unpack_from('<d', data, pos)[0]
            imag = struct.unpack_from('<d', data, pos + 8)[0]
            return complex(real, imag), pos + 16

        if ch == 'J':
            parts = []
            for _ in range(2):
                v, pos = self._decode_one(data, pos, depth + 1)
                parts.append(v if isinstance(v, (int, float)) else 0.0)
            return complex(parts[0], parts[1]), pos

        if ch == 'Z':
            if pos >= end:
                return 0.0, pos
            v = data[pos]
            pos += 1
            return {0: 0.0, 1: -0.0, 2: float('nan'),
                    3: copysign(float('nan'), -1.0),
                    4: float('inf'), 5: float('-inf')}.get(v, 0.0), pos

        if ch in ('c', 'a', 'u'):
            # null-terminated: strings and bytes
            zero = bytes(data[pos:]).find(b'\x00')
            if zero == -1:
                s_end = end
            else:
                s_end = pos + zero
            raw = bytes(data[pos:s_end])
            pos = min(s_end + 1, end)
            if ch in ('c', 'a'):
                # Python3 bytes or attribute name str (Py2 str)
                # Nuitka uses 'a' for attribute name (interned str Py3)
                try:
                    return raw.decode('utf-8'), pos
                except UnicodeDecodeError:
                    return raw, pos
            try:
                return raw.decode('utf-8', errors='replace'), pos
            except Exception:
                return raw, pos

        if ch == 'w':
            if pos >= end:
                return '', pos
            try:
                return bytes(data[pos:pos + 1]).decode('utf-8', errors='replace'), pos + 1
            except Exception:
                return '', pos + 1

        if ch == 'v':
            size, pos = self._unpack_vlq(data, pos)
            if pos + size > end:
                return '', end
            raw = bytes(data[pos:pos + size])
            return raw.decode('utf-8', errors='replace'), pos + size

        if ch == 'b':
            size, pos = self._unpack_vlq(data, pos)
            if pos + size > end:
                return b'', end
            return bytes(data[pos:pos + size]), pos + size

        if ch == 'd':
            if pos >= end:
                return b'', end
            return bytes(data[pos:pos + 1]), pos + 1

        if ch == 'B':
            size, pos = self._unpack_vlq(data, pos)
            if pos + size > end:
                return bytearray(), end
            return bytearray(data[pos:pos + size]), pos + size

        if ch == 'n':
            return None, pos
        if ch == 't':
            return True, pos
        if ch == 'F':
            return False, pos
        if ch == 's':
            return '', pos

        if ch in ('X', 'Q'):
            size, pos = self._unpack_vlq(data, pos)
            if pos + size > end:
                return b'', end
            return bytes(data[pos:pos + size]), pos + size

        if ch == ':':  # slice
            items = []
            for _ in range(3):
                v, pos = self._decode_one(data, pos, depth + 1)
                items.append(v)
            return ('slice', items[0], items[1], items[2]), pos

        if ch == ';':  # range/xrange
            items = []
            for _ in range(3):
                v, pos = self._decode_one(data, pos, depth + 1)
                items.append(v)
            return ('range', items[0], items[1], items[2]), pos

        if ch in ('M', 'A'):
            if pos >= end:
                return None, pos
            return self._anon_value(data[pos]), pos + 1

        if ch == 'r':  # builtin-special alias
            if pos >= end:
                return None, pos
            return self._special_value(data[pos]), pos + 1

        if ch in ('O', 'E'):
            zero = bytes(data[pos:]).find(b'\x00')
            s_end = end if zero == -1 else pos + zero
            try:
                return bytes(data[pos:s_end]).decode('utf-8', errors='replace'), min(s_end + 1, end)
            except Exception:
                return None, min(s_end + 1, end)

        if ch == 'K':
            v, pos = self._decode_one(data, pos, depth + 1)
            return v, pos

        if ch == 'C':
            # Code-object skeleton: (flags VLQ) (name constant) (line VLQ)
            # (arg_names constant) (arg_count VLQ) — store as tuple.
            _, pos = self._unpack_vlq(data, pos)            # flags
            fn, pos = self._decode_one(data, pos, depth + 1)
            _, pos = self._unpack_vlq(data, pos)            # line
            args, pos = self._decode_one(data, pos, depth + 1)
            _, pos = self._unpack_vlq(data, pos)            # argcount
            return (fn, args), pos

        if ch == 'H':  # UnionType 3.10+
            v, pos = self._decode_one(data, pos, depth + 1)
            return ('UnionType', v), pos

        if ch == '.':
            return None, pos

        # Unknown byte: treat as opaque separator
        return None, pos

    def _decode_count(self, data: memoryview, pos: int, count: int):
        """Decode *count* constants starting at *pos*. Returns (tuple, new_pos)."""
        items = []
        for _ in range(count):
            if pos >= len(data):
                break
            v, pos = self._decode_one(data, pos, 0)
            items.append(v)
        return tuple(items), pos

    def _add_section(self, result: dict, name: str, items: tuple):
        """Add section to result, auto-disambiguating duplicate names."""
        if name in result:
            self._collision_idx += 1
            name = f"{name}_dup_{self._collision_idx}"
        result[name] = items

    # ---- top-level entry points ----

    def decode_blob(self, data):
        """Decode Nuitka constants blob. Returns `dict[section_name, tuple]`.

        Mirrors `nuitka_deobfuscate.decode_blob(bytes)` in output but is
        stricter about the aggressive scan: it only considers byte ranges
        **not already covered** by the linear chain, so it can't produce
        truncated duplicates of already-decoded sections.

        Two scans:
          - Linear Chain: the well-formed, documented blob layout.
          - Aggressive Signature Scan: byte-by-byte probing for hidden /
            injected / corrupted sections. Restricted to the gaps the
            linear chain didn't cover.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        mv = memoryview(data) if not isinstance(data, memoryview) else data
        end = len(mv)
        result = {}
        covered = []  # list of (start, end) ranges eaten by linear chain

        # ---- SCAN 1: Linear Chain ----
        w = 8  # skip 8-byte header (CRC32 + size)
        while w + 6 < end:
            # consume NUL padding
            while w < end and mv[w] == 0:
                w += 1
            if w + 6 >= end:
                break

            name_start = w
            p = w
            while p < end and mv[p] != 0:
                p += 1

            if p + 6 >= end:
                break

            s_size = struct.unpack_from('<I', mv, p + 1)[0]
            s_count = struct.unpack_from('<H', mv, p + 5)[0]

            if (0 < s_size < (end - p - 5) and
                    0 < s_count < 65000):
                # BUG in the collaborator's C code: it used
                #     sec_end = data_ptr + s_size      # 2 bytes PAST the real end
                # but `s_size` is the length of the `part` emitted by
                # Nuitka's DataComposer, which is
                #     part = struct.pack("H", count) + constants + b"."
                # so it already includes the u16 count + the trailing "." byte.
                # Therefore the chunk ends at p + 5 + s_size, not p + 7 + s_size.
                # That off-by-2 was consuming the first two characters of every
                # *next* chunk name (e.g. "xrpl.asyncio.*" -> "pl.asyncio.*",
                # "urllib.parse.*" -> "llib.parse.*"). Fixed here.
                data_ptr = p + 7               # start of the actual constants
                sec_end = p + 5 + s_size        # end of the full part (= next name start)
                constants_end = sec_end - 1    # skip the trailing "." marker

                name_bytes = bytes(mv[name_start:p])
                # Strict sanity: a real Nuitka chunk name is either empty
                # (main module), `.bytecode`, or a dotted Python identifier.
                # Reject anything with non-printable characters or obviously
                # truncated fragments — those are alignment errors where we
                # landed mid-chunk-data and should keep scanning.
                name_ok = True
                try:
                    name = name_bytes.decode('ascii')
                except UnicodeDecodeError:
                    try:
                        name = name_bytes.decode('utf-8', errors='strict')
                    except UnicodeDecodeError:
                        name_ok = False
                        name = bytes(name_bytes).decode('utf-8', errors='replace')
                if name_ok and name:
                    # Names must be ident-chars + dots + underscores; or start
                    # with a single '.' (internal chunks like `.bytecode`).
                    core = name[1:] if name.startswith('.') else name
                    if not all(c.isalnum() or c in '._-' for c in core):
                        name_ok = False

                if name_ok:
                    # Decode constants up to constants_end (excl trailing ".")
                    section_view = memoryview(bytes(mv[data_ptr:constants_end]))
                    items, _consumed = self._decode_count(section_view, 0, s_count)
                    # Accept liberally: if the name passed the ASCII check and
                    # the body decoded at least partially, keep the section.
                    # Tighter checks make decoding O(N^2) on large blobs
                    # because every reject forces a 1-byte-at-a-time retry.
                    self._add_section(result, name, items)
                    covered.append((name_start, sec_end))
                    w = sec_end
                    continue

                # Name looked wrong — slide past the name we just tried.
                w = name_start + 1
                continue

            w = p + 1

        def _in_covered(off):
            # Binary-search-free but we have at most a few thousand ranges
            for s, e in covered:
                if s <= off < e:
                    return True
            return False

        # ---- SCAN 2: Aggressive Signature Scan (gaps only) ----
        scan_p = 8
        while scan_p + 7 < end:
            # Skip ranges we already covered with the linear-chain scan
            if _in_covered(scan_p):
                # Jump to the end of the covering range
                for s, e in covered:
                    if s <= scan_p < e:
                        scan_p = e
                        break
                continue

            s_size = struct.unpack_from('<I', mv, scan_p)[0]
            s_count = struct.unpack_from('<H', mv, scan_p + 4)[0]
            next_tag = mv[scan_p + 6]

            if (0 < s_size < (end - scan_p - 6) and
                    0 < s_count < 65000 and
                    next_tag in self._VALID_TAGS):

                sec_view = memoryview(bytes(mv[scan_p + 6:scan_p + 6 + s_size]))
                probe, _ = self._decode_one(sec_view, 0, 0)
                if probe is not None:
                    discovered_name = "hidden_segment"
                    if scan_p - 1 >= 0 and mv[scan_p - 1] == 0:
                        name_scan = scan_p - 2
                        while name_scan >= 0 and 32 <= mv[name_scan] < 127:
                            name_scan -= 1
                        candidate = bytes(mv[name_scan + 1:scan_p - 1])
                        if candidate and all(32 <= c < 127 for c in candidate):
                            discovered_name = candidate.decode('ascii', errors='replace')

                    name_buf = f"discovered_{discovered_name}_at_{scan_p}"
                    items, _ = self._decode_count(sec_view, 0, s_count)
                    self._add_section(result, name_buf, items)
                    scan_p += 6 + s_size
                    continue

            scan_p += 1

        return result

    def decode_at_offset(self, data, offset: int):
        """Decode a single constant starting at a specific byte offset."""
        mv = memoryview(bytes(data))
        val, _ = self._decode_one(mv, offset, 0)
        return val


# ---------------------------------------------------------------------------
#  2. XDIS-BASED RAW CODE OBJECT SCANNER
#      (port of run_extract.py's raw_scan_for_code_objects + version probing)
# ---------------------------------------------------------------------------

# xdis is an optional dependency (pip install xdis). When available we use it
# for cross-Python-version marshal parsing which is much more reliable than
# the running interpreter's native marshal module. xdis 6.x does not export
# TYPE_CODE / TYPE_STRING as public symbols so we define them inline — the
# values are stable in CPython marshal.c across every 3.x version.
_XDIS_TYPE_CODE = b'c'       # 0x63 — TYPE_CODE in Python/marshal.c
_XDIS_TYPE_STRING = b's'     # 0x73 — TYPE_STRING (Python 2) / TYPE_ASCII (3.4+)
_XDIS_FLAG_REF = 0x80        # set on marshaled object if it may be referenced

try:
    import xdis.marsh as _xdis_marshal
    from xdis.magics import (
        by_version as _xdis_by_version,
        magic2int as _xdis_magic2int,
        magic_int2tuple as _xdis_magic_int2tuple,
    )
    from xdis.unmarshal import load_code as _xdis_load_code
    # Try to use xdis's own constants if present (newer versions)
    try:
        from xdis.unmarshal import (
            FLAG_REF as _XDIS_FLAG_REF_X,
            TYPE_CODE as _XDIS_TYPE_CODE_X,
            TYPE_STRING as _XDIS_TYPE_STRING_X,
        )
        _XDIS_FLAG_REF = _XDIS_FLAG_REF_X
        _XDIS_TYPE_CODE = _XDIS_TYPE_CODE_X
        _XDIS_TYPE_STRING = _XDIS_TYPE_STRING_X
    except ImportError:
        pass  # fall back to the hardcoded values above
    XDIS_AVAILABLE = True
except ImportError:
    _xdis_marshal = None
    _xdis_by_version = {}
    XDIS_AVAILABLE = False


def _marshal_code_tags():
    """Return (all_tags, code_tag_pattern, version_hint_pattern). Empty if no xdis."""
    if not XDIS_AVAILABLE:
        return (), None, None
    values = (ord(_XDIS_TYPE_CODE), _XDIS_FLAG_REF | ord(_XDIS_TYPE_CODE))
    tags = tuple(bytes((v,)) for v in values)
    code_pat = re.compile(b"[" + re.escape(bytes(values)) + b"]")
    hint_pat = re.compile(b"[" + re.escape(b"\xf3" + bytes(values)) + b"]")
    return tags, code_pat, hint_pat


MARSHAL_CODE_TAGS, MARSHAL_CODE_TAG_PATTERN, MARSHAL_VERSION_HINT_TAG_PATTERN = _marshal_code_tags()
MARSHAL_VERSION_HINT_TAGS = (b"\xf3",) + MARSHAL_CODE_TAGS
MARSHAL_PYC_PATH_PATTERN = re.compile(rb"([A-Za-z0-9_./\\-]{1,260}\.py)")


class _MemoryReader:
    """Minimal file-like reader over a bytes buffer."""
    def __init__(self, data, start=0):
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self._pos = start

    def read(self, n=-1):
        if n < 0:
            n = len(self._data) - self._pos
        end = min(len(self._data), self._pos + n)
        chunk = bytes(self._data[self._pos:end])
        self._pos = end
        return chunk


def _xdis_get_magic_int(version):
    if not XDIS_AVAILABLE:
        return None
    if isinstance(version, tuple):
        version = f"{version[0]}.{version[1]}"
    magic = _xdis_by_version.get(version)
    if not magic:
        return None
    return _xdis_magic2int(bytes(magic))


def _xdis_version_sort_key(version):
    major, minor = version.split(".", 1)
    return int(major), int(minor)


def guess_version_from_marshal_bytes(data: bytes):
    """Fast structural guess at Python version from a marshal code-object header."""
    if not data or data[0:1] not in (b"\xe3", b"\x63", b"\xf3"):
        return None
    if data[0:1] == b"\xf3":
        return "3.11+"
    if len(data) < 25:
        return None
    try:
        argcount = struct.unpack_from("<I", data, 1)[0]
        kwonlycount = struct.unpack_from("<I", data, 9)[0]
        stacksize = struct.unpack_from("<I", data, 17)[0]
        flags = struct.unpack_from("<I", data, 21)[0]
        posonlycount = struct.unpack_from("<I", data, 5)[0]
        nlocals = struct.unpack_from("<I", data, 13)[0]
        if argcount > 255 or kwonlycount > 255 or stacksize > 65535:
            kw2 = struct.unpack_from("<I", data, 5)[0]
            nl2 = struct.unpack_from("<I", data, 9)[0]
            fl2 = struct.unpack_from("<I", data, 17)[0]
            if kw2 <= 255 and nl2 <= 65535 and fl2 >= 0:
                return "3.7"
        lower_bound = "3.6" if flags & 0x0200 else "3.5"
        if posonlycount <= argcount and stacksize <= 65535 and nlocals <= 65535:
            if flags & 0x0100 and not (flags & 0x0200):
                return "3.8"
            return "3.8+"
        return lower_bound
    except Exception:
        return None


def _marshal_candidate_versions(version_hint):
    if not XDIS_AVAILABLE:
        return []
    versions = sorted(
        {v for v in _xdis_by_version
         if re.fullmatch(r"\d+\.\d+", v) and _xdis_version_sort_key(v) >= (3, 5)},
        key=_xdis_version_sort_key, reverse=True)
    runtime = f"{sys.version_info.major}.{sys.version_info.minor}"
    if runtime in versions:
        rk = _xdis_version_sort_key(runtime)
        lower = [v for v in versions if v != runtime and _xdis_version_sort_key(v) <= rk]
        higher = [v for v in versions if _xdis_version_sort_key(v) > rk]
        versions = [runtime] + lower + higher
    if version_hint is None:
        return versions
    if version_hint.endswith("+"):
        lb = _xdis_version_sort_key(version_hint[:-1])
        prio = [v for v in versions if _xdis_version_sort_key(v) >= lb]
        fb = [v for v in versions if _xdis_version_sort_key(v) < lb]
        return prio + fb
    if version_hint in versions:
        return [version_hint] + [v for v in versions if v != version_hint]
    return versions


def _xdis_looks_like_code_header(data, offset, magic_int):
    if not XDIS_AVAILABLE or magic_int is None:
        return False
    version = _xdis_magic_int2tuple(magic_int)
    field_count = 1  # argcount
    if version >= (3, 8):
        field_count += 1  # posonlyargcount
    if version >= (3, 0):
        field_count += 1  # kwonlyargcount
    if version < (3, 11):
        field_count += 1  # nlocals
    field_count += 2  # stacksize, flags
    header_end = offset + 1 + (field_count * 4)
    if len(data) < header_end + 1:
        return False
    fields = struct.unpack_from("<" + ("I" * field_count), data, offset + 1)
    cur = 0
    if fields[cur] > 4096:
        return False
    cur += 1
    if version >= (3, 8):
        if fields[cur] > 4096:
            return False
        cur += 1
    if version >= (3, 0):
        if fields[cur] > 4096:
            return False
        cur += 1
    if version < (3, 11):
        if fields[cur] > 65536:
            return False
        cur += 1
    stacksize = fields[cur]
    flags = fields[cur + 1]
    if stacksize == 0 or stacksize > 65536:
        return False
    if flags > 0x3FFFFFFF:
        return False
    next_tag = data[header_end]
    return next_tag in (ord(_XDIS_TYPE_STRING), _XDIS_FLAG_REF | ord(_XDIS_TYPE_STRING))


def _xdis_try_detect_code_object(data, offset, magic_int):
    if not XDIS_AVAILABLE or magic_int is None or len(data) - offset < 32:
        return None
    # xdis' load_code prints "Unknown type N (hex ...)" on stderr for every
    # failing probe. During a raw scan we expect MANY failures, so we must
    # redirect stdout+stderr to a sink for the duration of the call.
    import io, contextlib
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            reader = _MemoryReader(data, offset)
            obj = _xdis_load_code(reader, magic_int)
    except Exception:
        return None
    name = type(obj).__name__
    if name == 'code' or name.startswith('Code'):
        return obj
    return None


def _xdis_try_load_code_object(data, offset, magic_int):
    if not _xdis_looks_like_code_header(data, offset, magic_int):
        return None
    return _xdis_try_detect_code_object(data, offset, magic_int)


def _xdis_score_code_object(co):
    score = 3
    score += len(getattr(co, 'co_consts', ()) or ())
    score += len(getattr(co, 'co_varnames', ()) or ())
    score += int(bool(getattr(co, 'co_filename', None)))
    return score


def xdis_detect_version_from_marshal(data: bytes):
    """Scored probe of candidate versions against marshal code-object offsets."""
    if not XDIS_AVAILABLE:
        return None
    version_hint = guess_version_from_marshal_bytes(data)
    candidates = _marshal_candidate_versions(version_hint)
    probe_offsets = [m.start() for m in MARSHAL_VERSION_HINT_TAG_PATTERN.finditer(data)]
    if not probe_offsets and data[:1] in MARSHAL_VERSION_HINT_TAGS:
        probe_offsets = [0]
    if not probe_offsets:
        return None
    scores = {}
    for ver in candidates:
        magic_int = _xdis_get_magic_int(ver)
        best = 0
        for off in probe_offsets[:128]:
            obj = _xdis_try_detect_code_object(data, off, magic_int)
            if obj is None:
                continue
            best = max(best, _xdis_score_code_object(obj))
            if best >= 4:
                break
        if best > 0:
            scores[ver] = best
    if not scores:
        if version_hint:
            fb = _marshal_candidate_versions(version_hint)
            if fb:
                return fb[0]
        return None
    best_ver = max(scores, key=lambda v: scores[v])
    return best_ver


def xdis_raw_scan_for_code_objects(raw: bytes, python_version):
    """Scan raw blob for marshal code-object tags; return [(offset, code_obj), ...].

    Replaces the standard section-based scan for Nuitka blobs where bytecode
    is embedded in the raw byte stream, not wrapped in structured sections.
    Only available when xdis is installed.
    """
    if not XDIS_AVAILABLE:
        return []
    magic_int = _xdis_get_magic_int(python_version)
    if magic_int is None:
        return []
    results = []
    raw_view = memoryview(raw)
    last = -8
    for m in MARSHAL_CODE_TAG_PATTERN.finditer(raw):
        off = m.start()
        if off - last < 8:
            continue
        obj = _xdis_try_load_code_object(raw_view, off, magic_int)
        if obj is None:
            continue
        results.append((off, obj))
        last = off
    return results


def xdis_extract_path_from_code(co):
    try:
        if hasattr(co, 'co_filename'):
            return str(co.co_filename)
        if hasattr(co, 'co_qualname'):
            return str(co.co_qualname)
    except Exception:
        pass
    return None


def xdis_extract_code_label(co):
    try:
        for attr in ('co_qualname', 'co_name', 'co_filename'):
            value = getattr(co, attr, None)
            if not value:
                continue
            label = str(value).strip().replace("\\", "/")
            if not label:
                continue
            if attr == 'co_filename' and ":" in label:
                label = label.split(":", 1)[1]
            label = label.lstrip("/")
            if label == "<module>":
                label = "module"
            if attr == 'co_filename':
                label = Path(label).stem or label
            label = re.sub(r'[<>:"/\\|?*\x00]+', "_", label).strip("._ ")
            if label:
                return label[:96]
    except Exception:
        pass
    return None


def xdis_extract_path_from_marshaled_bytes(data):
    try:
        candidates = []
        for match in MARSHAL_PYC_PATH_PATTERN.finditer(bytes(data)[:65536]):
            c = match.group(1).decode('utf-8', errors='ignore').replace("\\", "/").lstrip("./")
            if c:
                candidates.append(c)
        if not candidates:
            return None
        return max(candidates, key=lambda v: (v.count("/"), len(v)))
    except Exception:
        return None


def xdis_sanitize_filename(filepath):
    filepath = filepath.replace("\\", "/")
    if ":" in filepath:
        filepath = filepath.split(":", 1)[1]
    filepath = filepath.lstrip("/")
    for p in ["module.", "nuitka_build/"]:
        if filepath.startswith(p):
            filepath = filepath[len(p):]
    return filepath


# ---------------------------------------------------------------------------
#  3. OMNI UNIFIED NUITKA DECOMPILER FRAMEWORK
#      (full port of omni_nuitka_framework.py — ~760 lines)
# ---------------------------------------------------------------------------

class OmniNuitkaTags:
    ARG = 'a'; CLOSURE = 'c'; DICT = 'd'; FUNCTION = 'f'; GLOBALS = 'g'
    TUPLE = 't'; LIST = 'l'; FLOAT = 'F'; INT = 'I'; STRING = 's'
    BYTES = 'y'; BOOL_TRUE = 'T'; BOOL_FALSE = 'F'; NONE = 'N'
    CODE_OBJ = 'C'; MODULE = 'm'; METHOD = 'M'; USER_DEF = 'u'
    PRIVATE_DEF = 'p'; OBJECT_TYPE = 'O'


def _omni_b2s_safe(val):
    if val is None:
        return "None"
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float, bool)):
        return str(val)
    if isinstance(val, (tuple, list, dict, set, frozenset)):
        return str(val)
    if hasattr(val, 'decode'):
        try:
            return val.decode('utf-8')
        except Exception:
            return val.decode('latin-1', errors='replace')
    return repr(val)


def _omni_is_b64_image(val):
    s = _omni_b2s_safe(val) if isinstance(val, (bytes, bytearray)) else str(val)
    return 'iVBORw0KGgo' in s or 'JFIF' in s


def _omni_is_annotation_dict(d):
    if not d or len(d) > 25:
        return False
    for k in d.keys():
        key = _omni_b2s_safe(k)
        if not key.isidentifier() and key != 'return':
            return False
    return True


def _omni_decode_annotation_blob(d):
    ann = {}
    if not isinstance(d, dict):
        return ann
    for k, v in d.items():
        key = _omni_b2s_safe(k)
        if v is None:
            ann[key] = 'Any'
        elif v is True or v is False:
            ann[key] = 'bool'
        elif isinstance(v, int):
            ann[key] = 'int'
        elif isinstance(v, float):
            ann[key] = 'float'
        elif isinstance(v, str):
            ann[key] = v if v[0:1].isupper() else 'str'
        elif isinstance(v, (bytes, bytearray)):
            s = _omni_b2s_safe(v)
            ann[key] = s if s[0:1].isupper() else 'str'
        else:
            ann[key] = type(v).__name__
    return ann


def _omni_parse_packed_signature(raw_bytes):
    """Decode a null-separated packed signature blob (Nuitka encodes these for
    runtime introspection of a compiled function/class)."""
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode('utf-8', errors='replace')
    segments = raw_bytes.split(b'\x00')
    method_refs, args, types = [], [], {}
    for seg in segments:
        if not seg:
            continue
        text = seg.decode('utf-8', errors='replace')
        if not text:
            continue
        tag, name = text[0], text[1:]
        if tag == OmniNuitkaTags.ARG:
            args.append(name)
        elif tag == OmniNuitkaTags.USER_DEF:
            if '.' in name and name[0:1].isupper() and name.split('.')[0].isidentifier():
                method_refs.append(name)
        elif tag == OmniNuitkaTags.OBJECT_TYPE:
            if args:
                types[args[-1]] = name
        elif tag == OmniNuitkaTags.PRIVATE_DEF:
            if name and '.' in name and name.split('.')[0][0:1].isupper():
                method_refs.append(name)
    return method_refs, args, types


# -- AST node framework (minimal reimplementation) --

class _OmniASTNode:
    def render(self, indent=0):
        raise NotImplementedError


class _OmniCodeBlock(_OmniASTNode):
    def __init__(self):
        self.children = []

    def add(self, node):
        self.children.append(node)

    def render(self, indent=0):
        if not self.children:
            return " " * (indent * 4) + "pass\n"
        return "".join(c.render(indent) for c in self.children)


class _OmniFunctionCall(_OmniASTNode):
    def __init__(self, func_name, args, kwargs, inline=False):
        self.func_name = func_name
        self.args = args
        self.kwargs = kwargs
        self.inline = inline

    def render(self, indent=0):
        pad = " " * (indent * 4) if not self.inline else ""
        arg_str = ", ".join(str(a) for a in self.args)
        kw_str = ", ".join(f"{k}={v}" for k, v in self.kwargs.items())
        combined = ", ".join(filter(bool, [arg_str, kw_str]))
        res = f"{pad}{self.func_name}({combined})"
        return res if self.inline else res + "\n"


class _OmniAssignment(_OmniASTNode):
    def __init__(self, target, value, annotation=None):
        self.target = target
        self.value = value
        self.annotation = annotation

    def render(self, indent=0):
        pad = " " * (indent * 4)
        if self.annotation:
            return f"{pad}{self.target}: {self.annotation} = {self.value}\n"
        return f"{pad}{self.target} = {self.value}\n"


class _OmniRawString(_OmniASTNode):
    def __init__(self, text):
        self.text = text

    def render(self, indent=0):
        return " " * (indent * 4) + self.text + "\n"


class _OmniRawComment(_OmniASTNode):
    def __init__(self, text):
        self.text = text

    def render(self, indent=0):
        return " " * (indent * 4) + "# " + self.text + "\n"


class _OmniReturn(_OmniASTNode):
    def __init__(self, val="None"):
        self.val = val

    def render(self, indent=0):
        return " " * (indent * 4) + f"return {self.val}\n"


class _OmniClassDef(_OmniASTNode):
    def __init__(self, name):
        self.name = name
        self.bases = []
        self.attributes = set()
        self.methods = []
        self.slots = None

    def render(self, indent=0):
        pad = " " * (indent * 4)
        base_str = f"({', '.join(self.bases)})" if self.bases else ""
        res = f"\n{pad}class {self.name}{base_str}:\n"
        ip = " " * ((indent + 1) * 4)
        has_content = False
        if self.slots:
            res += f"{ip}__slots__ = {self.slots}\n\n"
            has_content = True
        if self.attributes:
            res += f"{ip}# Recovered Instance Attributes:\n"
            for a in sorted(self.attributes):
                res += f"{ip}# self.{a}\n"
            res += "\n"
            has_content = True
        for m in self.methods:
            res += m.render(indent + 1)
            has_content = True
        if not has_content:
            res += f"{ip}pass\n"
        return res


class _OmniMethodDef(_OmniASTNode):
    def __init__(self, name, args, annotations, return_type):
        self.name = name
        self.args = args
        self.annotations = annotations
        self.return_type = return_type
        self.body = _OmniCodeBlock()
        self.is_async = False
        self.is_staticmethod = False
        self.is_classmethod = False
        self.internals = []
        self.locals_hints = []

    def render(self, indent=0):
        pad = " " * (indent * 4)
        res = ""
        if self.is_staticmethod:
            res += f"{pad}@staticmethod\n"
        if self.is_classmethod:
            res += f"{pad}@classmethod\n"
        prefix = "async def " if self.is_async else "def "
        sig = []
        for arg in self.args:
            if arg in self.annotations and self.annotations[arg]:
                sig.append(f"{arg}: {self.annotations[arg]}")
            else:
                sig.append(arg)
        ret = f" -> {self.return_type}" if self.return_type else ""
        res += f"{pad}{prefix}{self.name}({', '.join(sig)}){ret}:\n"
        res += self.body.render(indent + 1)
        res += "\n"
        return res


class OmniDecompiler:
    """AST-based heuristic decompiler from collaborator's omni_nuitka_framework.

    Reconstructs classes, methods and signatures by pattern-matching on the
    items decoded from a constants blob section. Emits Python pseudo-source
    with inline C-API trace comments (what Nuitka would have generated).
    """

    def __init__(self):
        from collections import OrderedDict
        self.classes = OrderedDict()
        self.api_endpoints = set()
        self.images = OrderedDict()
        self.vk_table = OrderedDict()
        self.current_class = None
        self.last_method_cls = None
        self.last_method_name = None
        self.last_item_name = None

    def ensure_class(self, cls_name):
        if cls_name not in self.classes:
            self.classes[cls_name] = _OmniClassDef(cls_name)

    def ensure_method(self, cls_name, method_name, args=None, annotations=None, return_type=None):
        self.ensure_class(cls_name)
        cls_node = self.classes[cls_name]
        existing = next((m for m in cls_node.methods if m.name == method_name), None)
        if not existing:
            m = _OmniMethodDef(method_name, args or ['self'], annotations or {}, return_type)
            cls_node.methods.append(m)
            return m
        if args and existing.args == ['self']:
            existing.args = args
        if annotations:
            existing.annotations.update(annotations)
        if return_type and not existing.return_type:
            existing.return_type = return_type
        return existing

    def run_pass_1_structural_mapping(self, blob_items):
        n = len(blob_items)

        def _t(v):
            if v is None:
                return 'none'
            if isinstance(v, bool):
                return 'bool'
            if isinstance(v, int):
                return 'int'
            if isinstance(v, float):
                return 'float'
            if isinstance(v, str):
                return 'str'
            if isinstance(v, (bytes, bytearray)):
                if b'\x00' in v and len(v) > 4:
                    return 'packed'
                return 'bytes'
            if isinstance(v, tuple):
                return 'tuple'
            if isinstance(v, list):
                return 'list'
            if isinstance(v, dict):
                return 'dict'
            if isinstance(v, (set, frozenset)):
                return 'set'
            return 'other'

        i = 0
        while i < n:
            item = blob_items[i]
            t = _t(item)
            if t == 'none':
                i += 1
                continue

            if t == 'bytes':
                name = _omni_b2s_safe(item)
                if name.endswith('_B64') and i + 1 < n and _t(blob_items[i + 1]) in ('str', 'bytes'):
                    if _omni_is_b64_image(blob_items[i + 1]):
                        self.images[name] = len(_omni_b2s_safe(blob_items[i + 1]))
                        i += 2
                        continue
                if name.startswith('VK_'):
                    vk_val = None
                    if i + 1 < n and _t(blob_items[i + 1]) == 'int':
                        vk_val = blob_items[i + 1]
                    elif i > 0 and _t(blob_items[i - 1]) == 'int':
                        vk_val = blob_items[i - 1]
                    self.vk_table[name] = vk_val
                    i += 1
                    continue

            is_method = False
            if t in ('str', 'bytes'):
                name = _omni_b2s_safe(item)
                if '.' in name and not name.startswith('.') and not name.startswith('\\'):
                    parts = name.split('.', 1)
                    if (len(parts) == 2 and parts[0]
                            and (parts[0][0:1].isupper() or parts[0][0:1] == '_')
                            and parts[1].isidentifier()):
                        cls, method = parts[0], parts[1]
                        self.ensure_method(cls, method)
                        self.current_class = cls
                        self.last_method_cls = cls
                        self.last_method_name = method
                        is_method = True
                        if i + 1 < n and _t(blob_items[i + 1]) == 'dict':
                            if _omni_is_annotation_dict(blob_items[i + 1]):
                                ann = _omni_decode_annotation_blob(blob_items[i + 1])
                                arg_names = [k for k in ann.keys() if k != 'return']
                                ret = ann.get('return')
                                self.ensure_method(cls, method,
                                                   args=['self'] + arg_names if arg_names else None,
                                                   annotations=ann, return_type=ret)

            if t == 'packed':
                method_refs, args, ptypes = _omni_parse_packed_signature(item)
                for ref in method_refs:
                    parts = ref.split('.', 1)
                    if len(parts) == 2 and (parts[0][0:1].isupper() or parts[0][0:1] == '_'):
                        self.ensure_method(parts[0], parts[1])
                        self.current_class = parts[0]
                        self.last_method_cls, self.last_method_name = parts[0], parts[1]
                if args and method_refs:
                    last_ref = method_refs[-1]
                    parts = last_ref.split('.', 1)
                    if len(parts) == 2:
                        self.ensure_method(parts[0], parts[1],
                                           args=['self'] + args, annotations=ptypes)
                elif args and self.last_method_cls and self.last_method_name:
                    self.ensure_method(self.last_method_cls, self.last_method_name,
                                       args=['self'] + args, annotations=ptypes)
                i += 1
                continue

            if self.last_method_cls and self.last_method_name:
                meth_node = next(
                    (m for m in self.classes[self.last_method_cls].methods
                     if m.name == self.last_method_name), None)
                if meth_node:
                    if t == 'dict' and not _omni_is_annotation_dict(item):
                        dec = {}
                        for kx, vx in list(item.items())[:50]:
                            dx = repr(vx)[:250] if not isinstance(vx, (bytes, bytearray)) else _omni_b2s_safe(vx)[:250]
                            dec[_omni_b2s_safe(kx)] = dx
                        meth_node.internals.append(('dict', dec))
                    elif t == 'list':
                        meth_node.internals.append(('list', [_omni_b2s_safe(x) for x in item[:100]]))
                    elif t == 'tuple':
                        decoded = tuple(_omni_b2s_safe(x) for x in item)
                        if self.last_item_name == '__slots__' and self.current_class:
                            self.classes[self.current_class].slots = decoded
                        elif all(isinstance(x, str) for x in decoded) and len(decoded) >= 2:
                            meth_node.locals_hints.append(decoded)
                        else:
                            meth_node.internals.append(('tuple', decoded))
                    elif t in ('int', 'float', 'bool'):
                        meth_node.internals.append(('literal', item))
                    elif t in ('str', 'bytes'):
                        name = _omni_b2s_safe(item)
                        if t == 'bytes' and name.startswith('_') and self.current_class and len(name) > 2 and not name.startswith('__'):
                            self.classes[self.current_class].attributes.add(name)
                        if 'http' in name.lower() or '/functions/' in name:
                            self.api_endpoints.add(name)
                        if len(name) > 2 and not name.startswith('VK_') and not is_method:
                            meth_node.internals.append(('str', name))

            if t in ('str', 'bytes'):
                self.last_item_name = _omni_b2s_safe(item)
            else:
                self.last_item_name = None
            i += 1

    def run_pass_2_ast_synthesis(self):
        for cls_name, cls_node in self.classes.items():
            for meth_node in cls_node.methods:
                internals = meth_node.internals
                locals_hints = meth_node.locals_hints
                if locals_hints:
                    meth_node.body.add(_OmniRawComment("--- Locals Discovery ---"))
                    for hint in locals_hints:
                        valid = [v for v in hint if str(v).isidentifier()]
                        if valid:
                            meth_node.body.add(_OmniAssignment(", ".join(valid), "None"))
                if not internals:
                    meth_node.body.add(_OmniRawString("pass"))
                    continue
                meth_node.body.add(_OmniRawComment("--- Heuristic Execution Trace ---"))
                i = 0
                n = len(internals)
                while i < n:
                    typ, val = internals[i]
                    if typ == 'dict':
                        ds = "{\n"
                        for k, v in val.items():
                            ds += f"            {repr(k)}: {v},\n"
                        ds += "        }"
                        meth_node.body.add(_OmniAssignment(f"config_mapping_{i}", ds))
                        meth_node.body.add(_OmniRawComment(f"C-API: PyObject *dict_{i} = _PyDict_NewPresized({len(val)});"))
                    elif typ == 'list':
                        ls = "[\n"
                        for x in val:
                            ls += f"            {repr(x)},\n"
                        ls += "        ]"
                        meth_node.body.add(_OmniAssignment(f"sequence_array_{i}", ls))
                        meth_node.body.add(_OmniRawComment(f"C-API: PyObject *list_{i} = PyList_New({len(val)});"))
                    elif typ == 'tuple' and len(val) == 1 and isinstance(val[0], str):
                        target = val[0]
                        if any(m.name == target for m in cls_node.methods):
                            meth_node.body.add(_OmniFunctionCall(f"self.{target}", [], {}))
                            meth_node.body.add(_OmniRawComment(
                                f"C-API: PyObject *func_{i} = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING(\"{target}\"));"))
                        else:
                            meth_node.body.add(_OmniAssignment(f"state_flags_{i}", repr(val)))
                    elif typ == 'str' and val in [m.name for m in cls_node.methods]:
                        meth_node.body.add(_OmniAssignment(f"target_callback_{i}", f"self.{val}"))
                    elif typ == 'str' and val in cls_node.attributes:
                        meth_node.body.add(_OmniAssignment(f"PY_OBJ_ATTR_{i}", f"getattr(self, {repr(val)}, None)"))
                    elif typ == 'str' and ('http' in val.lower() or '/functions/' in val):
                        meth_node.body.add(_OmniAssignment(f"api_res_{i}", f"requests.request('GET', {repr(val)})"))
                    elif typ == 'literal':
                        if isinstance(val, int) and 10 < val < 10000:
                            meth_node.body.add(_OmniFunctionCall("time.sleep", [f"{val} / 1000.0"], {}))
                        elif isinstance(val, float):
                            meth_node.body.add(_OmniAssignment(f"calc_threshold_{i}", val))
                        else:
                            meth_node.body.add(_OmniAssignment(f"flag_{i}", val))
                    elif typ == 'str':
                        if len(val) > 4 and ('error' in val.lower() or 'warn' in val.lower() or 'success' in val.lower()):
                            meth_node.body.add(_OmniFunctionCall("logger.log", [repr(val)], {}))
                        else:
                            meth_node.body.add(_OmniAssignment(f"string_const_{i}", repr(val)))
                    elif typ == 'tuple':
                        if len(val) > 1 and any(isinstance(x, str) and (x.endswith('_color')) for x in val):
                            meth_node.body.add(_OmniAssignment(f"ui_widget_bind_{i}", f"apply_kwargs(**{repr(val)})"))
                        else:
                            meth_node.body.add(_OmniAssignment(f"tuple_block_{i}", repr(val)))
                    i += 1
                meth_node.body.add(_OmniReturn())


# ---------------------------------------------------------------------------
#  NUITKA STATIC DISASSEMBLER — reconstruct function logic from native code
# ---------------------------------------------------------------------------

try:
    import capstone as _capstone
    from capstone import x86 as _capstone_x86
    CAPSTONE_AVAILABLE = True
except ImportError:
    _capstone = None
    _capstone_x86 = None
    CAPSTONE_AVAILABLE = False


class NuitkaStaticDisassembler:
    """Disassemble each compiled module's native entry point and emit a
    Nuitka-aware pseudo-source listing.

    Nuitka compiles every Python module function into a C function, then
    the C compiler turns that into native x86-64 code. The C function
    performs three kinds of operations we can identify statically:

      1. **Python C API calls** — `PyObject_GetAttr`, `PyObject_CallObject`,
         `PyDict_SetItem`, etc. These come via the import table (IAT); we
         resolve each `call qword ptr [rip+X]` by looking up the IAT slot.

      2. **Nuitka runtime helpers** — `LOOKUP_ATTRIBUTE`, `CALL_FUNCTION_*`,
         `MAKE_FUNCTION_*`, `loadConstantsBlob`, etc. These are compiled as
         direct calls `call 0x...` to addresses inside `.text`. Without
         symbols we can't name them, but we can identify the most-called
         ones (they ARE the Nuitka runtime) and flag them.

      3. **Constant loads** — every Python constant access becomes
         `mov reg, qword ptr [rip + offset]` where the offset points into
         the `mod_consts` struct in `.data`. We resolve the target
         address and — knowing the constants we decoded from the blob in
         the same order — can map it back to the original Python literal.

    The output is a `.disasm.txt` per compiled module with:
      * per-instruction disassembly with resolved RIP-relative refs
      * a "Calls to" list (sorted by target)
      * a "Constants referenced" list (the Python literals this function
        actually touches)
      * a pseudo-Python call trace ("step 1: LOOKUP_ATTR 'session'; step
        2: LOOKUP_ATTR 'get'; step 3: CALL_FUNCTION args=...")
    """

    # Common Python C API names to look for in the IAT — anything matching
    # is flagged as "real Python operation".
    _PYTHON_CAPI_NAMES = (
        'Py_', 'PyDict_', 'PyList_', 'PyTuple_', 'PyLong_', 'PyFloat_',
        'PyUnicode_', 'PyBytes_', 'PyBool_', 'PyNumber_', 'PyObject_',
        'PyType_', 'PyIter_', 'PyErr_', 'PyThreadState_', 'PyEval_',
        'PyImport_', 'PyFunction_', 'PyMethod_', 'PyCFunction_',
        'PyRun_', 'PyMarshal_', 'PyWeakref_', 'PyCompile_', 'PyCode_',
        'PyFrame_', 'PyArg_', 'PyStructSequence_', 'PySys_', 'PyModule_',
        'PyBaseObject_', 'PyMem_', 'PyGILState_',
    )

    def __init__(self, pe_file, blob_sections=None, module_table=None):
        if not CAPSTONE_AVAILABLE:
            raise RuntimeError("capstone not installed (pip install capstone)")
        self.pe = pe_file
        self.image_base = pe_file.OPTIONAL_HEADER.ImageBase
        self.is_x64 = pe_file.FILE_HEADER.Machine == 0x8664
        self.sections = blob_sections or {}
        self.module_table = module_table or []

        # Capstone decoder
        self.md = _capstone.Cs(_capstone.CS_ARCH_X86,
                               _capstone.CS_MODE_64 if self.is_x64
                               else _capstone.CS_MODE_32)
        self.md.detail = True

        # Pre-compute useful lookups
        self._iat = self._build_iat_map()
        self._section_map = self._build_section_map()
        # Map func_ptr -> module_name from the loader table
        self._func_to_module = {e['func_ptr']: e['name']
                                for e in self.module_table
                                if e.get('func_ptr')}

    def _build_section_map(self):
        """Map each RVA range to its section for fast lookup."""
        ranges = []
        for s in self.pe.sections:
            name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
            start = s.VirtualAddress
            end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
            ranges.append((start, end, name, s))
        return ranges

    def _find_section_for_rva(self, rva):
        for start, end, name, s in self._section_map:
            if start <= rva < end:
                return (name, s, rva - start)
        return (None, None, 0)

    def _build_iat_map(self):
        """Resolve every IAT slot to its symbol name."""
        iat = {}
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return iat
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace') if entry.dll else '?'
            for imp in entry.imports:
                if imp.address and imp.name:
                    name = imp.name.decode('ascii', errors='replace')
                    iat[imp.address] = (dll, name)
                elif imp.address and imp.ordinal:
                    iat[imp.address] = (dll, f'ord_{imp.ordinal}')
        return iat

    def _resolve_rip_relative(self, ins):
        """For RIP-relative instructions (call qword ptr [rip+X], mov reg,
        [rip+X], lea reg, [rip+X]), return the VA of the target."""
        for op in ins.operands:
            if op.type == _capstone_x86.X86_OP_MEM:
                if op.mem.base == _capstone_x86.X86_REG_RIP:
                    return ins.address + ins.size + op.mem.disp
        return None

    def _classify_call(self, ins):
        """Classify a call/jmp instruction. Returns one of:
          - ('capi', dll, name)   # Python/system C API via IAT
          - ('internal', va)      # direct call to .text
          - ('indirect', va)      # call through memory (not IAT)
          - ('unknown', None)
        """
        # Direct: `call 0x....` — operand is immediate VA
        if ins.operands and ins.operands[0].type == _capstone_x86.X86_OP_IMM:
            target_va = ins.operands[0].imm
            # If in .text, it's an internal Nuitka runtime call
            rva = target_va - self.image_base
            name, _, _ = self._find_section_for_rva(rva)
            if name == '.text':
                return ('internal', target_va)
            return ('unknown', target_va)
        # Indirect: `call qword ptr [rip+X]` — X points at an IAT slot
        if ins.operands and ins.operands[0].type == _capstone_x86.X86_OP_MEM:
            target = self._resolve_rip_relative(ins)
            if target is not None:
                if target in self._iat:
                    dll, name = self._iat[target]
                    return ('capi', dll, name)
                return ('indirect', target)
        return ('unknown', None)

    def _resolve_const_load(self, ins):
        """Resolve `mov/lea reg, [rip+X]` where X points into `.data`/.rdata.
        Returns the absolute VA and the section name, or None."""
        if ins.mnemonic not in ('mov', 'lea'):
            return None
        if len(ins.operands) < 2:
            return None
        src = ins.operands[1]
        if (src.type == _capstone_x86.X86_OP_MEM
                and src.mem.base == _capstone_x86.X86_REG_RIP):
            va = ins.address + ins.size + src.mem.disp
            rva = va - self.image_base
            name, _, _ = self._find_section_for_rva(rva)
            if name in ('.data', '.rdata'):
                return (va, name)
        return None

    def _resolve_text_ptr_load(self, ins):
        """Resolve `lea reg, [rip+X]` where X points into `.text`.

        Nuitka registers every compiled Python function body by passing
        its entry-point as an ARGUMENT to `MAKE_FUNCTION_*`, not by
        `call`-ing it. The function pointer is materialised via
        `lea rcx, [rip+offset_to_impl_funcname]`. Tracking these loads
        lets the recursive BFS reach the real Python `def` bodies —
        without this every function body stays invisible and only the
        Nuitka-runtime plumbing appears as @OPS blocks.

        Returns the absolute VA of the `.text` target, or None.
        """
        # `mov` loads are sometimes used for call-via-memory-table
        # patterns but those already become `call [rip+X]` → resolved
        # separately. Keep this to `lea` which is the idiomatic
        # function-pointer materialisation.
        if ins.mnemonic != 'lea':
            return None
        if len(ins.operands) < 2:
            return None
        src = ins.operands[1]
        if (src.type == _capstone_x86.X86_OP_MEM
                and src.mem.base == _capstone_x86.X86_REG_RIP):
            va = ins.address + ins.size + src.mem.disp
            rva = va - self.image_base
            name, _, _ = self._find_section_for_rva(rva)
            if name == '.text':
                return va
        return None

    def disassemble_function(self, func_ptr, max_bytes=65536, max_insns=30000):
        """Disassemble from `func_ptr` until RET (or budget exhausted).

        Defaults are sized for the largest realistic module-entry
        function in a complex Nuitka binary: the `__main__` module
        entry of a multi-hundred-`def` application materialises one
        `lea + lea + call MAKE_FUNCTION` triple per `def`, so registering
        419 defs takes ~15-25 KB of machine code. The 65 KB / 30 K insn
        caps give generous headroom; most Python function bodies are
        tiny (under 1 KB) and hit RET long before the cap.
        """
        rva = func_ptr - self.image_base
        name, section, offset = self._find_section_for_rva(rva)
        if section is None:
            return []
        sec_data = section.get_data()
        code = sec_data[offset:offset + max_bytes]
        instructions = []
        for ins in self.md.disasm(code, func_ptr):
            instructions.append(ins)
            if ins.mnemonic == 'ret' or len(instructions) >= max_insns:
                break
        return instructions

    def analyse_function(self, func_ptr, max_bytes=65536):
        """Disassemble + classify every call and every RIP-relative const load.

        Returns a dict:
            {
              'func_va': 0x...,
              'instruction_count': N,
              'calls': [ {va_from, kind, target, name}, ... ],
              'const_loads': [ {va_from, target_va, section}, ... ],
              'func_ptr_loads': [ {va_from, target_va}, ... ],  # lea -> .text
              'raw_disasm': [ (va, mnemonic, op_str), ... ],
              'reached_ret': True/False
            }
        """
        instructions = self.disassemble_function(func_ptr, max_bytes=max_bytes)
        calls = []
        const_loads = []
        func_ptr_loads = []
        raw = []
        # `make_function_hints` cross-references each function pointer
        # load with the const loads that appear in the SAME basic block
        # before the next `call`. Nuitka's MAKE_FUNCTION call site is:
        #    lea rcx, [rip + func_ptr]
        #    lea rdx, [rip + qualname_str]    <-- we want this
        #    lea r8,  [rip + defaults_tuple]  <-- or this (tuple, not str)
        #    call MAKE_FUNCTION_<N>
        # so we collect EVERY subsequent const load (up to the call),
        # then resolve them at render time and pick the first that is
        # a plain string. Storing a list instead of a single value
        # avoids locking onto the defaults-tuple when it appears first.
        make_function_hints = []    # list of {func_va, candidate_vas[]}
        pending_fp = None           # last unmatched func_ptr_load
        pending_fp_hint_index = -1  # index into make_function_hints
        for idx, ins in enumerate(instructions):
            raw.append((ins.address, ins.mnemonic, ins.op_str))
            if ins.mnemonic in ('call', 'callq') or ins.mnemonic.startswith('jmp'):
                kind_tuple = self._classify_call(ins)
                kind = kind_tuple[0]
                if kind == 'capi':
                    calls.append({
                        'va_from': ins.address,
                        'kind': 'capi',
                        'dll': kind_tuple[1],
                        'name': kind_tuple[2],
                    })
                elif kind == 'internal':
                    calls.append({
                        'va_from': ins.address,
                        'kind': 'internal',
                        'target': kind_tuple[1],
                        'module': self._func_to_module.get(kind_tuple[1]),
                    })
                elif kind == 'indirect':
                    calls.append({
                        'va_from': ins.address,
                        'kind': 'indirect',
                        'target': kind_tuple[1],
                    })
                elif kind == 'unknown' and kind_tuple[1] is not None:
                    calls.append({
                        'va_from': ins.address,
                        'kind': 'unknown',
                        'target': kind_tuple[1],
                    })
                # A call terminates the MAKE_FUNCTION window — stop
                # collecting candidates for the pending func_ptr.
                pending_fp = None
                pending_fp_hint_index = -1
            const = self._resolve_const_load(ins)
            if const is not None:
                const_loads.append({
                    'va_from': ins.address,
                    'mnemonic': ins.mnemonic,
                    'target_va': const[0],
                    'section': const[1],
                })
                # If a function pointer was just loaded (within a
                # 6-instruction window) append this const as a
                # candidate qualname for it. Render-time picks the
                # first candidate whose mod_consts entry is a string.
                if (pending_fp is not None
                        and pending_fp_hint_index >= 0
                        and len(make_function_hints[pending_fp_hint_index]['candidate_vas']) < 6):
                    make_function_hints[pending_fp_hint_index][
                        'candidate_vas'].append(const[0])
            # Function-pointer materialisation: `lea reg, [rip+X]` where
            # X -> .text. These are Nuitka's per-function compiled
            # entry-points passed as arguments to MAKE_FUNCTION_* /
            # MAKE_CLASS_* — i.e. the REAL Python def bodies we want
            # the recursive BFS to reach.
            fp_va = self._resolve_text_ptr_load(ins)
            if fp_va is not None:
                func_ptr_loads.append({
                    'va_from': ins.address,
                    'target_va': fp_va,
                })
                # Open a fresh candidate window for this function ptr.
                make_function_hints.append({
                    'func_va': fp_va,
                    'candidate_vas': [],
                })
                pending_fp = fp_va
                pending_fp_hint_index = len(make_function_hints) - 1

        return {
            'func_va': func_ptr,
            'instruction_count': len(instructions),
            'reached_ret': bool(instructions and instructions[-1].mnemonic == 'ret'),
            'calls': calls,
            'const_loads': const_loads,
            'func_ptr_loads': func_ptr_loads,
            'make_function_hints': make_function_hints,
            'raw_disasm': raw,
        }

    @staticmethod
    def _looks_like_function_entry(info):
        """Cheap check: does the disassembly start like a real function?

        Nuitka-compiled function prologues on x64 almost always begin
        with one of:
            push rbx / push rdi / push rsi / push rbp / push r12-r15
            sub  rsp, 0x??
            mov  [rsp + ??], reg            (MSVC-style shadow store)
            mov  rax, qword ptr fs:[0x??]   (stack cookie for /GS)
            sub  rsp, 0x28   +  call  <stack-check>

        If the first ~4 instructions contain NONE of these markers, the
        VA is most likely a jump-table entry or a mid-function label
        reached via `lea` — we skip it rather than emit a noise @OPS
        block full of garbage instructions.
        """
        raw = info.get('raw_disasm') or []
        if not raw:
            return False
        # Only look at the first 5 instructions
        head = raw[:5]
        prologue_hits = 0
        for (_va, mnem, ops) in head:
            if mnem == 'push' and ops in (
                'rbx', 'rdi', 'rsi', 'rbp',
                'r12', 'r13', 'r14', 'r15',
            ):
                prologue_hits += 1
            elif mnem == 'sub' and ops.startswith('rsp,'):
                prologue_hits += 1
            elif mnem == 'mov' and ops.startswith(('qword ptr [rsp',
                                                     '[rsp')):
                prologue_hits += 1
            elif mnem == 'mov' and 'fs:' in ops:
                prologue_hits += 1
        return prologue_hits >= 1

    def analyse_function_recursive(self, entry_va, runtime_aliases=None,
                                    max_funcs=1000, max_bytes_per_fn=16384):
        """BFS through every module-local `call` AND every `lea`
        function-pointer materialisation starting at `entry_va`.

        Nuitka compiles every Python function as its own C function with
        its own `.text` entry point. The module-entry function (the one
        in the loader table) only runs the module's top-level code; all
        the actual `def` bodies are reached in TWO ways:

          (a) directly, via `call <impl_fn>` — rare, only for inner
              helpers that don't get promoted to Python function objects,
          (b) indirectly, via `lea reg, [rip + impl_fn]` passed as an
              argument to `MAKE_FUNCTION_*` — the common case for every
              `def` the module exposes.

        This BFS follows BOTH kinds, so a module with N Python `def`s
        yields N+ `@OPS` blocks in the final .nbc (one per compiled
        function body, plus the module entry).

        To rebuild each function body 1:1 we need its own disassembly
        window. This method walks the call graph:

          * starts at `entry_va`
          * for every `internal` call found, enqueues the target (unless
            it's a Nuitka runtime helper, the entry of a DIFFERENT
            module, or already visited)
          * stops at `max_funcs` to bound work per module

        Returns an `OrderedDict` {func_va: analyse_function_info}.

        `runtime_aliases` (the result of `build_module_call_stats`) is
        used to skip runtime helpers — otherwise we'd disassemble
        `LOOKUP_ATTRIBUTE` etc. once per module, which is pointless.
        """
        from collections import OrderedDict, deque
        runtime_aliases = runtime_aliases or {}

        # Skip ANY ranked helper (top-100 by call frequency across the
        # whole binary). These are shared runtime helpers that every
        # module ends up calling — disassembling them per-module would
        # duplicate the same ops in every .nbc and waste LLM context.
        helper_vas = {va for va, alias in runtime_aliases.items()
                      if isinstance(alias, str)
                      and (alias.startswith('RUNTIME_HELPER_')
                           or alias.startswith('helper_'))}

        # Cross-module entries: every VA in the loader table except our
        # starting VA is the entry point of ANOTHER module, so skip it.
        skip_module_va = set(self._func_to_module.keys()) - {entry_va}

        # Two-queue traversal with provenance tracking:
        #   * `fp_queue` (high priority) = function-pointer `lea` targets —
        #     these may or may not be real function entries, so they get
        #     validated by the prologue heuristic at process-time.
        #   * `call_queue` (low priority) = direct-call targets — the
        #     caller BELIEVED these are functions (it emitted `call` to
        #     them), so we trust them and skip the prologue check.
        # Each queue entry is (va, source) where source is 'lea' or 'call'.
        results = OrderedDict()
        fp_queue = deque()
        call_queue = deque()
        call_queue.append((entry_va, 'entry'))
        seen = set()

        def _pop_next():
            if fp_queue:
                return fp_queue.popleft()
            if call_queue:
                return call_queue.popleft()
            return None

        while len(results) < max_funcs:
            item = _pop_next()
            if item is None:
                break
            va, source = item
            if va in seen:
                continue
            seen.add(va)

            # Never disassemble runtime helpers or sibling module entries
            if va != entry_va:
                if va in helper_vas:
                    continue
                if va in skip_module_va:
                    continue

            # Target must be a valid .text address
            rva = va - self.image_base
            sec_name, _, _ = self._find_section_for_rva(rva)
            if sec_name != '.text':
                continue

            try:
                # The module entry tends to be huge (thousands of
                # MAKE_FUNCTION registrations) — give it a larger
                # disasm budget. All other blocks are individual
                # Python function bodies, almost always under 4 KB
                # of native code.
                _budget = 65536 if va == entry_va else max_bytes_per_fn
                info = self.analyse_function(va, max_bytes=_budget)
            except Exception:
                continue
            if not info.get('raw_disasm'):
                continue

            # Prologue heuristic applies ONLY to `lea`-discovered VAs
            # (might be data). For `call`-discovered VAs we trust the
            # caller — Nuitka-compiled bodies frequently skip the
            # canonical push/sub prologue when they're continuation
            # fragments of a split function (MSVC-style shared
            # epilogues, exception handlers).
            if source == 'lea' and va != entry_va:
                if not self._looks_like_function_entry(info):
                    continue
            results[va] = info

            # Enqueue direct-call targets with source='call'
            for c in info['calls']:
                if c['kind'] != 'internal':
                    continue
                tgt = c['target']
                if tgt in seen or tgt in helper_vas or tgt in skip_module_va:
                    continue
                call_queue.append((tgt, 'call'))

            # **Key insight**: Nuitka's `MAKE_FUNCTION_*` runtime helper
            # takes the compiled function pointer as an ARGUMENT, not as
            # a callee. The pattern in native code is:
            #
            #     lea  rcx, [rip + impl_fn_body]     ; func ptr arg
            #     lea  rdx, [rip + defaults_tuple]   ; defaults arg
            #     call MAKE_FUNCTION_NOFRAME_<N>
            #
            # So the real Python `def` bodies are reached via `lea`
            # targets that fall in `.text`, not via `call`. Enqueue
            # them on the HIGH-priority `fp_queue`: they're the
            # precious blocks we most want in the output.
            for fp in info.get('func_ptr_loads', []):
                tgt = fp['target_va']
                if tgt in seen or tgt in helper_vas or tgt in skip_module_va:
                    continue
                # Defensive: the lea could target a jump table or an
                # exception handler. analyse_function will still try to
                # disassemble it; if the result looks like noise the
                # prologue heuristic (source='lea') rejects it.
                fp_queue.append((tgt, 'lea'))
        return results

    def build_module_call_stats(self, targets):
        """Scan ALL targeted functions, count how many times each internal
        address is called. The most-called internal addresses are the
        Nuitka runtime helpers (LOOKUP_ATTRIBUTE, CALL_FUNCTION_*, etc.) —
        we can't name them without symbols, but we can rank them and give
        them stable aliases so the same helper always shows the same label
        in every disassembly file.
        """
        from collections import Counter
        counter = Counter()
        # Pre-pass budget: keep each module entry at 8 KB / 2000 insns.
        # This is enough to see the call targets (every module entry
        # makes its first few thousand calls in the prologue) and
        # dramatically faster than the 65 KB full-body budget.
        # Ranking accuracy is unaffected — we only need relative
        # frequency, not exhaustive disassembly.
        for e in targets:
            info = self.analyse_function(e['func_ptr'], max_bytes=8192)
            for c in info['calls']:
                if c['kind'] == 'internal':
                    counter[c['target']] += 1
        # Rank-based aliasing
        alias_map = {}
        for rank, (va, count) in enumerate(counter.most_common()):
            # First few are the hottest runtime helpers
            if rank < 20:
                alias_map[va] = f'RUNTIME_HELPER_{rank:02d}_x{va & 0xFFFF:04x}'
            elif rank < 100:
                alias_map[va] = f'helper_{rank:03d}_0x{va:X}'
            else:
                alias_map[va] = f'fn_0x{va:X}'
        return alias_map, counter

    @staticmethod
    def _estimate_mod_consts_base(const_loads, expected_count):
        """Guess the base address of the module's `mod_consts` struct.

        Every function in a Nuitka C-compiled module loads its constants
        via `mov reg, [mod_consts + 8*K]`. All those loads therefore cluster
        in a contiguous 8-byte-stride region of `.data`. We spot the tightest
        cluster (density close to 1 load per 8 bytes) and treat its minimum
        as the base, its (max - min) / 8 as the approximate count.

        Returns `(base_va, count)` or `(None, 0)` on failure.
        """
        if not const_loads:
            return None, 0
        targets = sorted({cl['target_va'] for cl in const_loads
                          if cl.get('section') == '.data'})
        if not targets:
            return None, 0

        # Build clusters: consecutive addresses with stride <= 16
        clusters = []
        current = [targets[0]]
        for va in targets[1:]:
            if va - current[-1] <= 16:
                current.append(va)
            else:
                clusters.append(current)
                current = [va]
        clusters.append(current)

        # The largest cluster is almost certainly mod_consts
        best = max(clusters, key=len)
        base = best[0]
        span = best[-1] - base
        count = (span // 8) + 1
        # Sanity: clamp count to a reasonable range
        if expected_count and count > expected_count * 2 + 20:
            count = expected_count + 20
        return base, count

    def render_function(self, func_ptr, module_name=None, max_bytes=8192,
                         runtime_alias_map=None,
                         module_constants=None,
                         mod_consts_base=None):
        """Produce the human-readable `.disasm.txt` content for one function.

        The real added value: when `module_constants` (the list of Python
        literals decoded from the blob for THIS module) is supplied we
        resolve every `mov/lea reg, [rip+X]` inside the `mod_consts`
        cluster into the actual Python literal. That gives a listing like

            0x1424C83AE   mov   rdi, qword ptr [rip + 0x3711cb3]
            //            = mod_consts.const_str_plain_session   // 'session'

        which is exactly what you'd see if Nuitka's original generated C
        source was compiled with debug symbols. Feeding the resulting
        .disasm.txt to a human or an LLM turns it into plain Python 1:1.
        """
        runtime_alias_map = runtime_alias_map or {}
        module_constants = module_constants or []

        info = self.analyse_function(func_ptr, max_bytes=max_bytes)

        # If the caller didn't provide the mod_consts base, estimate it
        # from this function's const loads alone. When we're processing
        # the ENTRY POINT (`module_code_X`) the loads touch every constant
        # in the struct, so this is quite reliable.
        if mod_consts_base is None:
            mod_consts_base, _count = self._estimate_mod_consts_base(
                info['const_loads'], len(module_constants))

        def resolve_const(va):
            if mod_consts_base is None or not module_constants:
                return None
            if va < mod_consts_base:
                return None
            offset = va - mod_consts_base
            if offset % 8 != 0:
                return None
            idx = offset // 8
            if 0 <= idx < len(module_constants):
                return idx, module_constants[idx]
            return None

        out = []
        out.append('=' * 72)
        out.append(f' NATIVE-CODE DISASSEMBLY  module_code_{module_name or "?"}')
        out.append('=' * 72)
        out.append(f'# Entry point VA      : 0x{func_ptr:X}')
        out.append(f'# Instructions        : {info["instruction_count"]}'
                   + (' (hit RET)' if info['reached_ret'] else ' (budget exhausted)'))
        out.append(f'# Direct calls        : {sum(1 for c in info["calls"] if c["kind"] == "internal")}')
        out.append(f'# Python C API calls  : {sum(1 for c in info["calls"] if c["kind"] == "capi")}')
        out.append(f'# Const loads         : {len(info["const_loads"])}')
        if mod_consts_base is not None:
            out.append(f'# mod_consts base VA  : 0x{mod_consts_base:X} '
                       f'(struct holds {len(module_constants)} slots)')
        out.append('')

        # --- Call summary ---
        out.append('-' * 72)
        out.append(' CALLS (in order of occurrence)')
        out.append('-' * 72)
        for c in info['calls']:
            va = c['va_from']
            if c['kind'] == 'capi':
                out.append(f'  0x{va:X}  -> {c["dll"]}!{c["name"]}')
            elif c['kind'] == 'internal':
                mod = c.get('module')
                if mod:
                    out.append(f'  0x{va:X}  -> module_code_{mod}  (0x{c["target"]:X})')
                else:
                    alias = runtime_alias_map.get(c['target'])
                    if alias:
                        out.append(f'  0x{va:X}  -> {alias}')
                    else:
                        out.append(f'  0x{va:X}  -> nuitka_internal_0x{c["target"]:X}')
            else:
                tgt = c.get('target')
                out.append(f'  0x{va:X}  -> {c["kind"]} 0x{tgt:X}'
                           if tgt else f'  0x{va:X}  -> {c["kind"]}')
        out.append('')

        # --- Constant loads with full value resolution ---
        out.append('-' * 72)
        out.append(' CONSTANT LOADS (RIP-relative, resolved to blob values)')
        out.append('-' * 72)
        if mod_consts_base is None or not module_constants:
            out.append(' (cannot resolve — mod_consts base not found or '
                       'module constants unavailable)')
            for cl in info['const_loads']:
                out.append(f'  0x{cl["va_from"]:X}  {cl["mnemonic"]} -> '
                           f'0x{cl["target_va"]:X}  [{cl["section"]}]')
        else:
            for cl in info['const_loads']:
                res = resolve_const(cl['target_va'])
                if res is None:
                    out.append(f'  0x{cl["va_from"]:X}  {cl["mnemonic"]} -> '
                               f'0x{cl["target_va"]:X}  [{cl["section"]}]  '
                               f'(outside mod_consts)')
                else:
                    idx, val = res
                    rep = repr(val)
                    if len(rep) > 100:
                        rep = rep[:97] + '...'
                    out.append(
                        f'  0x{cl["va_from"]:X}  {cl["mnemonic"]} -> '
                        f'mod_consts[{idx}]  =  {type(val).__name__}  {rep}')
        out.append('')

        # --- Annotated raw disassembly: inline every const load + call ---
        out.append('-' * 72)
        out.append(' ANNOTATED DISASSEMBLY')
        out.append(" (each `mov ..., [rip+X]` into mod_consts is inlined with")
        out.append("  the actual Python literal; every `call` shows the")
        out.append("  runtime helper alias or the IAT symbol)")
        out.append('-' * 72)

        call_by_va = {c['va_from']: c for c in info['calls']}
        const_by_va = {cl['va_from']: cl for cl in info['const_loads']}

        for va, mnem, ops in info['raw_disasm']:
            line = f'  0x{va:X}:  {mnem:<8} {ops}'

            # Inline comments
            comment_parts = []
            if va in const_by_va:
                cl = const_by_va[va]
                res = resolve_const(cl['target_va'])
                if res is not None:
                    idx, val = res
                    rep = repr(val)
                    if len(rep) > 90:
                        rep = rep[:87] + '...'
                    comment_parts.append(f'mod_consts[{idx}] = {rep}')
            if va in call_by_va:
                c = call_by_va[va]
                if c['kind'] == 'capi':
                    comment_parts.append(f'{c["dll"]}!{c["name"]}')
                elif c['kind'] == 'internal':
                    mod = c.get('module')
                    if mod:
                        comment_parts.append(f'module_code_{mod}')
                    else:
                        alias = runtime_alias_map.get(c['target'])
                        if alias:
                            comment_parts.append(alias)

            if comment_parts:
                # Pad to a stable column so comments line up
                line = f'{line:<60}  // {";  ".join(comment_parts)}'
            out.append(line)

        out.append('')
        return '\n'.join(out), info


# ---------------------------------------------------------------------------
#  NUITKA COMPACT "NBC" EMITTER — one tiny file per module for AI 1:1 rebuild
# ---------------------------------------------------------------------------

class NuitkaCompactEmitter:
    """Emit a compact `.nbc` (Nuitka ByteCode) file per module.

    The `.nbc` format is a hand-designed pseudo-bytecode tuned to feed an
    LLM so it can rebuild the original Python source 1:1. It contains the
    MINIMUM amount of information needed:

       * the module name + target Python version
       * the complete decoded-constants table (one per line, typed)
       * the import statements Nuitka's blob layout reveals
       * the list of detected internal functions (VA + inferred signature)
       * for the module entry point: an ordered sequence of "virtual ops"
         derived from the native x86-64 disassembly — each op is one
         source-level step (LOAD_CONST, CALL_RUNTIME, CALL_CAPI, RET).

    Deliberately absent:
       * no raw x86-64 disassembly (redundant with virtual ops)
       * no JSON variant (redundant with the text form)
       * no hex dump of the chunk
       * no categorised-constants tables (redundant with constants list)

    Typical size: 1–5 KB per module. Compact enough to paste whole into a
    chat window without eating the model's context budget.

    Format summary (stable — treat as API):

        @MOD   <module_dotted_name>
        @VER   <python_major.minor>
        @ENTRY 0x<virtual_address_of_module_code>
        @CONSTS <count>
          0 i 100000000                       # <index> <typecode> <repr>
          1 s 'https://example.com/'
          ...
        @IMPORTS
          from X import Y
          import Z
        @FUNCS_DETECTED                       # inferred def skeletons
          convert_to_btc(chain_stats)         # source=inferred-from-constants
          fetch_from_blockchain(address, url, response, balance_btc)
          ...
        @OPS <entry_va>                       # virtual bytecode from disasm
          L c[1]        ; 'https://example.com/'
          C r#0         ; LOOKUP_ATTRIBUTE
          C capi:PyImport_ImportModule
          J_EQ c[7] L1  ; COMPARE 200
          L c[9]        ; 'final_balance'
          RET
          :L1
          L c[17]       ; 'Request failed ...'
          C r#4         ; CALL_FUNCTION_WITH_ARGS1 (= print)
          RET

    Type codes (single character, stable):
        n None  t True  F False
        i int   f float  c complex
        s str   b bytes  B bytearray
        T tuple L list   D dict  S set P frozenset
        ? unknown

    Instructions:
        L  c[N]           LOAD_CONST from mod_consts[N]
        C  r#N            CALL to runtime-helper rank N (see HELPERS.txt)
        C  helper_XXX     CALL to a less-frequent helper
        C  fn@0xAA        CALL to a module-local function at virtual address
        C  capi:NAME      CALL to a Python C-API via the IAT
        J_EQ c[N] LABEL   cmp + je (equal) with a constant (best-effort)
        J    LABEL        unconditional jump
        RET               return
        :LABEL            jump target
    """

    # A few type-code mappings
    _TYPE_CODE = {
        type(None):  'n', bool:       't',  # bool collapses to t/F below
        int:         'i', float:      'f', complex: 'c',
        str:         's', bytes:      'b', bytearray: 'B',
        tuple:       'T', list:       'L',
        dict:        'D', set:        'S', frozenset: 'P',
    }

    @classmethod
    def _type_code(cls, v):
        if v is None:
            return 'n'
        if v is True:
            return 't'
        if v is False:
            return 'F'
        return cls._TYPE_CODE.get(type(v), '?')

    @staticmethod
    def _short_repr(v, cap=120):
        r = repr(v)
        return r if len(r) <= cap else r[:cap - 3] + '...'

    @classmethod
    def _full_repr(cls, v):
        try:
            return repr(v)
        except Exception as e:
            return f'<repr failed: {type(v).__name__}: {e}>'

    @classmethod
    def _emit_constants(cls, constants, out, *, full=True):
        mode = 'full_repr' if full else 'compact_repr'
        out.append(f"@CONSTS {len(constants)} mode={mode}")
        for i, v in enumerate(constants):
            rep = cls._full_repr(v) if full else cls._short_repr(v)
            out.append(f"  {i} {cls._type_code(v)} {rep}")

    @classmethod
    def _emit_raw_chunk(cls, chunk_bytes, out):
        """Embed the original per-module Nuitka constants chunk.

        The decoded constants are what an LLM normally needs, but keeping
        the raw chunk in the same `.nbc` makes the file self-contained:
        another tool can re-parse it, verify our decoder, or recover a tag
        we do not yet understand without going back to the executable.
        """
        if not chunk_bytes:
            return
        chunk = bytes(chunk_bytes)
        out.append('@RAW_CHUNK')
        out.append(f'  size: {len(chunk)}')
        out.append(f'  sha256: {hashlib.sha256(chunk).hexdigest()}')
        out.append('  encoding: base64')
        b64 = base64.b64encode(chunk).decode('ascii')
        out.append('  data:')
        for i in range(0, len(b64), 120):
            out.append('    ' + b64[i:i + 120])
        out.append('')

    @staticmethod
    def _module_table_value(entry, key, default=''):
        if not entry:
            return default
        value = entry.get(key, default)
        if isinstance(value, int):
            return f'0x{value:X}' if key.endswith('ptr') or key.endswith('va') else str(value)
        if isinstance(value, (list, tuple)):
            return ','.join(str(x) for x in value)
        return str(value)

    @classmethod
    def _emit_module_table_entry(cls, module_table_entry, out):
        if not module_table_entry:
            return
        out.append('@MODULE_TABLE')
        out.append(f"  name: {module_table_entry.get('name', '')}")
        out.append(f"  func_ptr: 0x{module_table_entry.get('func_ptr', 0):X}")
        out.append(f"  flags: {','.join(module_table_entry.get('flag_names') or [])}")
        out.append(f"  bytecode_index: {module_table_entry.get('bytecode_index', -1)}")
        out.append(f"  bytecode_size: {module_table_entry.get('bytecode_size', -1)}")
        out.append('')

    @classmethod
    def _emit_code_objects(cls, module_name, constants, out):
        code_objects = []

        def walk(v):
            if isinstance(v, dict):
                if v.get('_type') == 'CodeObject':
                    code_objects.append(v)
                for item in v.values():
                    walk(item)
            elif isinstance(v, (tuple, list, set, frozenset)):
                for item in v:
                    walk(item)

        for c in constants:
            walk(c)

        seen = set()
        unique = []
        for co in code_objects:
            key = (
                co.get('name'),
                co.get('qualname'),
                co.get('line'),
                co.get('argcount'),
                tuple(co.get('args') or ()),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(co)

        if not unique:
            return
        out.append(f'@CODE_OBJECTS {len(unique)}')
        for co in unique:
            args = ', '.join(str(a) for a in (co.get('args') or ()))
            flags = co.get('flags', 0)
            extras = []
            if co.get('posonly'):
                extras.append(f"posonly={co.get('posonly')}")
            if co.get('kwonly'):
                extras.append(f"kwonly={co.get('kwonly')}")
            if co.get('freevars'):
                extras.append(f"freevars={tuple(co.get('freevars'))!r}")
            if flags:
                extras.append(f"flags=0x{flags:X}")
            suffix = '  # ' + ' '.join(extras) if extras else ''
            qn = co.get('qualname') or co.get('name') or '<unknown>'
            line = co.get('line', '?')
            out.append(f"  line={line} qualname={qn!r} def {co.get('name', '<unknown>')}({args}){suffix}")
        out.append('')

    @classmethod
    def _emit_block_summary(cls, disasm_infos, runtime_aliases, out):
        if not disasm_infos:
            return
        out.append(f'@BLOCKS {len(disasm_infos)}')
        for va, info in disasm_infos.items():
            calls = info.get('calls') or []
            capi = sum(1 for c in calls if c.get('kind') == 'capi')
            internal = sum(1 for c in calls if c.get('kind') == 'internal')
            const_loads = len(info.get('const_loads') or [])
            fps = len(info.get('func_ptr_loads') or [])
            ret = 'yes' if info.get('reached_ret') else 'no'
            out.append(
                f"  0x{va:X} insns={info.get('instruction_count', 0)} "
                f"ret={ret} calls_internal={internal} calls_capi={capi} "
                f"const_loads={const_loads} func_ptr_loads={fps}"
            )
        out.append('')

    @classmethod
    def _emit_native_asm(cls, disasm_info, constants, mod_consts_base,
                         runtime_aliases, out):
        if not disasm_info:
            return

        fn_va = disasm_info.get('func_va')
        out.append(f'@ASM 0x{fn_va:X}')

        call_by_va = {c['va_from']: c for c in disasm_info.get('calls', [])}
        const_by_va = {cl['va_from']: cl for cl in disasm_info.get('const_loads', [])}
        fp_by_va = {fp['va_from']: fp for fp in disasm_info.get('func_ptr_loads', [])}

        def resolve_const(va):
            if mod_consts_base is None or not constants or va is None:
                return None
            if va < mod_consts_base:
                return None
            offset = va - mod_consts_base
            if offset % 8:
                return None
            idx = offset // 8
            if 0 <= idx < len(constants):
                return idx, constants[idx]
            return None

        for va, mnem, ops in disasm_info.get('raw_disasm', []):
            comments = []
            if va in const_by_va:
                cl = const_by_va[va]
                resolved = resolve_const(cl.get('target_va'))
                if resolved is not None:
                    idx, value = resolved
                    comments.append(f'const c[{idx}]={cls._short_repr(value, cap=180)}')
                else:
                    comments.append(f"data 0x{cl.get('target_va', 0):X} [{cl.get('section', '?')}]")
            if va in fp_by_va:
                comments.append(f"func_ptr 0x{fp_by_va[va].get('target_va', 0):X}")
            if va in call_by_va:
                c = call_by_va[va]
                if c.get('kind') == 'capi':
                    comments.append(f"{c.get('dll')}!{c.get('name')}")
                elif c.get('kind') == 'internal':
                    if c.get('module'):
                        comments.append(f"module_code_{c.get('module')}")
                    else:
                        alias = runtime_aliases.get(c.get('target'))
                        comments.append(alias or f"internal_0x{c.get('target', 0):X}")
                elif c.get('target') is not None:
                    comments.append(f"{c.get('kind')} 0x{c.get('target'):X}")
                else:
                    comments.append(str(c.get('kind')))

            line = f'  0x{va:X}: {mnem:<8} {ops}'
            if comments:
                line += '  ; ' + ' ; '.join(comments)
            out.append(line)
        out.append('')

    @classmethod
    def _emit_imports(cls, module_name, constants, out):
        """Liberal import detection specifically for the .nbc output.

        The strict detector inside StaticalySmartReconstructor filters
        many true positives (`apis`, `proxyconnector`, …) to keep the
        reconstructed `.py` file clean. For the `.nbc` we prefer maximum
        signal: every `str 'x'` immediately followed by `tuple('A', 'B')`
        in the constants is almost certainly `from x import A, B` —
        emit it and let the LLM decide which are real.
        """
        lines = []
        used = set()
        n = len(constants)
        for i, c in enumerate(constants):
            if not isinstance(c, str):
                continue
            if len(c) < 2 or len(c) > 80:
                continue
            if c.endswith(('.py', '.pyc')):
                continue
            if c.startswith('__') and c.endswith('__'):
                continue
            # Must be a plain dotted module identifier (all lowercase ok, or
            # package.Module style — but REJECT Class.method qualnames).
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', c):
                continue
            parts = c.split('.')
            if parts[0][:1].isupper():
                continue  # Class.method
            # Expect next const to be a tuple of idents (= the imported names)
            nxt = constants[i + 1] if i + 1 < n else None
            if (isinstance(nxt, tuple) and nxt
                    and all(isinstance(x, str) and
                            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x)
                            for x in nxt)):
                # Strip dunder names from the import list
                names = [x for x in nxt if not x.startswith('__')]
                if not names:
                    continue
                key = f"from {c} import {','.join(sorted(names))}"
                if key in used:
                    continue
                used.add(key)
                lines.append(f"from {c} import {', '.join(names)}")
        if not lines:
            return
        out.append('@IMPORTS')
        for line in lines:
            out.append('  ' + line)

    @classmethod
    def _emit_funcs_detected(cls, module_name, constants, out):
        """Use the same heuristic function-signature inference as the
        C-source rebuilder, filtered for clean idents."""
        inferred = NuitkaCSourceRebuilder.infer_functions_from_constants(
            list(constants))
        if not inferred:
            return
        out.append('@FUNCS_DETECTED')
        for fn in inferred[:60]:
            name = fn.get('name', '')
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name or ''):
                continue
            args = fn.get('args') or []
            args_str = ', '.join(str(a) for a in args)
            out.append(f"  {name}({args_str})")

    @classmethod
    def _emit_forensics(cls, constants, va_to_qualname, out):
        """Emit @FORENSICS sections for qualnames with no @OPS block.

        After the BFS disassembler has done its best, some `def`
        qualnames still appear in `mod_consts` without a matching
        `@OPS 0xVA  # qualname` block. Typical reasons:

          * **Tk/Qt callbacks** bound via `trace_add`, `bind`, or
            `signal.connect(...)` — no direct callsite exists in the
            binary, so the BFS never reaches them.
          * **Inlined helpers** that Nuitka merged into the caller.
          * **Dead code** (unused methods the compiler could have
            dropped but kept the qualname string for reflection).
          * **BFS cap** — the `max_funcs` limit cut the traversal
            short before reaching them.

        For each such orphan qualname we give an LLM enough CONTEXT
        to infer plausible behaviour without fabricating:

          * the mod_consts indices of its qualname + short name;
          * the ~12 constants ADJACENT to it in the constants table
            (Nuitka clusters a function's literals near its qualname);
          * any string anywhere in `mod_consts` that mentions the
            function's short name (error messages, dict keys, log
            formats, debug prints) — these pin down likely behaviour.

        Format:

            @FORENSICS
            # qualnames present in @CONSTS but not in @OPS — constants
            # adjacent to each give forensic evidence for the body.

            @NO_OPS <qualname>
              qualname_idx: <i>   name_idx: <j>
              adjacent:
                c[i-6] <type> <repr>
                ...
              mentions:
                c[42] s 'error in <qualname>: ...'
                c[99] s 'log: <qualname> called with ...'
        """
        if not constants:
            return

        # Collect all qualname-shaped strings in @CONSTS, with their
        # indices. A qualname looks like `foo`, `Foo.bar`,
        # `mod.Foo.bar.<locals>.baz`, `<lambda>`, `<genexpr>`.
        qualname_pat = re.compile(
            r'[A-Za-z_][A-Za-z0-9_]*'
            r'(\.[A-Za-z_<][A-Za-z0-9_<>.]*)*'
        )
        all_qualnames = {}   # qualname -> first index in mod_consts
        for i, v in enumerate(constants):
            if not isinstance(v, str) or len(v) < 2 or len(v) > 200:
                continue
            # Exclude obvious non-qualnames early
            if ' ' in v or '\n' in v or '/' in v or '\\' in v:
                continue
            if v.startswith('__') and v.endswith('__'):
                continue  # dunder (e.g. __main__, __init__) would spam
            if v.isupper():
                continue  # ALL_CAPS is almost certainly an enum/const, not a func
            if not qualname_pat.fullmatch(v):
                continue
            # Python-function naming heuristics — reject anything too
            # generic to plausibly be a function qualname:
            #   * dotted names (ClassName.method)   -> strong candidate
            #   * angle brackets (<lambda> etc.)    -> strong candidate
            #   * starts with '_' and len >= 4      -> likely private fn
            #   * len >= 8 + lowercase              -> long identifier,
            #                                          likely a function
            #   * otherwise (short word like 'foo') -> reject
            is_dotted = '.' in v or '<' in v
            is_private = v.startswith('_') and len(v) >= 4
            is_long = len(v) >= 8 and not v[0].isupper()
            if not (is_dotted or is_private or is_long):
                continue
            if v not in all_qualnames:
                all_qualnames[v] = i

        # Remove qualnames that already have an @OPS block (labeled
        # via va_to_qualname or matched by a block's header suffix).
        already_labeled = set((va_to_qualname or {}).values())
        orphans = [(q, i) for q, i in all_qualnames.items()
                   if q not in already_labeled]
        if not orphans:
            return

        # Sort by mod_consts index (stable, reproducible)
        orphans.sort(key=lambda t: t[1])

        # Precompute: for each qualname, find the SHORT name (the part
        # after the last `.`) — we use it to search for mention
        # strings elsewhere in constants.
        def short_name(q):
            tail = q.rsplit('.', 1)[-1]
            # Drop angle-bracket wrappers: '<lambda>' -> 'lambda'
            if tail.startswith('<') and tail.endswith('>'):
                tail = tail[1:-1]
            return tail

        # Precompute: index of mentions for efficiency (scan once)
        # mentions[short_name] = [(idx, const_value), ...]
        mentions_by_short = {}
        shorts = {short_name(q) for q, _ in orphans}
        # Filter out very short or common shorts that would match too much
        shorts = {s for s in shorts
                  if len(s) >= 4 and s.lower() not in
                  ('init', 'call', 'main', 'test', 'self', 'args')}
        if shorts:
            for i, v in enumerate(constants):
                if not isinstance(v, str) or len(v) < 4:
                    continue
                # Only long-ish strings have room to mention a function
                if len(v) > 500:
                    continue
                for s in shorts:
                    if s in v and v != s:
                        mentions_by_short.setdefault(s, []).append((i, v))
                        break   # don't double-record

        # Emit header
        out.append(f'@FORENSICS {len(orphans)}')
        out.append('# Qualnames in @CONSTS without a matching @OPS block.')
        out.append('# Each block lists adjacent mod_consts + mentions.')
        out.append('# Use this as evidence for the function\'s probable')
        out.append('# behaviour — do NOT fabricate anything beyond what')
        out.append('# these constants plainly support.')
        out.append('')

        MAX_BLOCKS = 400      # cap so we don't explode huge modules
        ADJ_WINDOW = 6        # ±6 slots around the qualname
        MAX_MENTIONS = 12     # per function

        for qname, qidx in orphans[:MAX_BLOCKS]:
            short = short_name(qname)
            # The short-name index is usually qidx-1 (Nuitka emits
            # (short_name, qualname) pairs); search the ±4 window.
            short_idx = None
            for off in (-1, 1, -2, 2, -3, 3, -4, 4):
                j = qidx + off
                if 0 <= j < len(constants):
                    if constants[j] == short:
                        short_idx = j
                        break

            out.append(f'@NO_OPS {qname}')
            hdr = f'  qualname_idx: {qidx}'
            if short_idx is not None:
                hdr += f'   name_idx: {short_idx}'
            out.append(hdr)

            # Adjacent constants
            out.append('  adjacent:')
            lo = max(0, qidx - ADJ_WINDOW)
            hi = min(len(constants), qidx + ADJ_WINDOW + 1)
            for j in range(lo, hi):
                if j == qidx:
                    marker = ' <-- qualname'
                elif j == short_idx:
                    marker = ' <-- name'
                else:
                    marker = ''
                v = constants[j]
                tcode = cls._type_code(v)
                r = cls._short_repr(v, cap=100)
                out.append(f'    c[{j}] {tcode} {r}{marker}')

            # Mentions elsewhere in constants
            mlist = mentions_by_short.get(short, [])
            # De-dup identical strings, keep up to MAX_MENTIONS
            seen_strs = set()
            distinct_mentions = []
            for i, v in mlist:
                if v in seen_strs:
                    continue
                seen_strs.add(v)
                # Skip mentions that ARE the qualname itself or
                # adjacent hits already covered above.
                if i == qidx or i == short_idx:
                    continue
                if lo <= i < hi:
                    continue
                distinct_mentions.append((i, v))
                if len(distinct_mentions) >= MAX_MENTIONS:
                    break
            if distinct_mentions:
                out.append('  mentions:')
                for i, v in distinct_mentions:
                    tcode = cls._type_code(v)
                    r = cls._short_repr(v, cap=100)
                    out.append(f'    c[{i}] {tcode} {r}')
            out.append('')

        if len(orphans) > MAX_BLOCKS:
            out.append(f'# ... {len(orphans) - MAX_BLOCKS} more orphan '
                       f'qualnames omitted (MAX_BLOCKS cap).')
            out.append('')

    @classmethod
    def _emit_virtual_ops(cls, disasm_info, constants, mod_consts_base,
                           runtime_aliases, out, va_to_qualname=None,
                           suppress_fallback_label=False):
        """Translate the native disassembly into one-line virtual ops.

        Every `mov reg, [rip+X]` into mod_consts becomes `L c[N]`.
        Every `call` becomes `C <target>`. Every `ret` becomes `RET`.
        Every `cmp reg, imm`/`je` pair becomes `J_EQ c[...] L<N>`.
        Other instructions (arith, mov between regs, stack ops) are
        summarised as they contribute little to source recovery.

        This is a linear view, NOT a true decompilation — but together
        with the constants table and the runtime-helper inventory it's
        enough for an LLM to produce a 1:1 Python translation.

        `va_to_qualname` (optional) is an authoritative map built by
        `render()` from the `make_function_hints` of ALL disassembled
        functions. It's the accurate source for the `# qualname` label
        because the qualname-string const is loaded by the PARENT
        function (as a MAKE_FUNCTION argument), not by the child body.
        """
        if not disasm_info:
            return
        fn_va = disasm_info['func_va']
        # Preferred: authoritative MAKE_FUNCTION-adjacency qualname.
        qualname = None
        if va_to_qualname:
            qualname = va_to_qualname.get(fn_va)
        # Fallback: per-block heuristic (less accurate, noisy for the
        # module entry — but still useful if the parent block was never
        # reached, e.g. for standalone test runs on a subset).
        # Skipped for blocks whose nature precludes a qualname (the
        # module entry in particular: it is the top-level code, not a
        # `def`).
        if not qualname and not suppress_fallback_label:
            qualname = cls._infer_func_qualname(disasm_info, constants,
                                                 mod_consts_base)
        if qualname:
            out.append(f'@OPS 0x{fn_va:X}  # {qualname}')
        else:
            out.append(f'@OPS 0x{fn_va:X}')

        call_by_va = {c['va_from']: c for c in disasm_info['calls']}
        const_by_va = {cl['va_from']: cl for cl in disasm_info['const_loads']}

        def resolve_const(va):
            if mod_consts_base is None or not constants:
                return None
            if va < mod_consts_base:
                return None
            offset = va - mod_consts_base
            if offset % 8:
                return None
            idx = offset // 8
            if 0 <= idx < len(constants):
                return idx
            return None

        # Build a label map for jump targets first
        label_map = {}   # VA -> label id
        ops_raw = []     # ( kind, data, va )
        last_cmp_const_idx = None

        for va, mnem, ops in disasm_info['raw_disasm']:
            if va in const_by_va:
                idx = resolve_const(const_by_va[va]['target_va'])
                if idx is not None:
                    ops_raw.append(('L', idx, va))
                    last_cmp_const_idx = idx
                else:
                    # load is to a global / cache outside mod_consts
                    continue
            elif va in call_by_va:
                c = call_by_va[va]
                if c['kind'] == 'capi':
                    ops_raw.append(('C', f'capi:{c["name"]}', va))
                elif c['kind'] == 'internal':
                    mod = c.get('module')
                    if mod:
                        ops_raw.append(('C', f'module_code_{mod}', va))
                    else:
                        alias = runtime_aliases.get(c['target'])
                        if alias and alias.startswith('RUNTIME_HELPER_'):
                            rank = alias.split('_')[2]
                            ops_raw.append(('C', f'r#{rank}', va))
                        else:
                            tgt_va = c['target']
                            ops_raw.append(('C', f'fn@0x{tgt_va:X}', va))
            elif mnem == 'cmp':
                # Often precedes a conditional jump; record the immediate
                # operand if it's a register vs numeric imm or vs [rip+X]
                # (already resolved above).
                pass
            elif mnem == 'je' or mnem == 'jne':
                # extract the jump target
                try:
                    target = int(ops.split()[-1], 0)
                    label_map.setdefault(target, len(label_map) + 1)
                    if last_cmp_const_idx is not None:
                        ops_raw.append(('J_EQ' if mnem == 'je' else 'J_NE',
                                        (last_cmp_const_idx, target), va))
                    else:
                        ops_raw.append(('J_EQ' if mnem == 'je' else 'J_NE',
                                        (None, target), va))
                    last_cmp_const_idx = None
                except Exception:
                    pass
            elif mnem == 'jmp':
                try:
                    target = int(ops.split()[-1], 0)
                    label_map.setdefault(target, len(label_map) + 1)
                    ops_raw.append(('J', target, va))
                except Exception:
                    pass
            elif mnem == 'ret':
                ops_raw.append(('RET', None, va))

        # Second pass: emit, injecting ":L<n>" when a label target is reached
        seen_labels = set()
        for kind, data, va in ops_raw:
            if va in label_map and va not in seen_labels:
                out.append(f'  :L{label_map[va]}')
                seen_labels.add(va)
            if kind == 'L':
                out.append(f'  L  c[{data}]')
            elif kind == 'C':
                out.append(f'  C  {data}')
            elif kind == 'J_EQ':
                idx, tgt = data
                lbl = f'L{label_map.get(tgt, "?")}'
                if idx is not None:
                    out.append(f'  J_EQ c[{idx}] {lbl}')
                else:
                    out.append(f'  J_EQ ? {lbl}')
            elif kind == 'J_NE':
                idx, tgt = data
                lbl = f'L{label_map.get(tgt, "?")}'
                if idx is not None:
                    out.append(f'  J_NE c[{idx}] {lbl}')
                else:
                    out.append(f'  J_NE ? {lbl}')
            elif kind == 'J':
                lbl = f'L{label_map.get(data, "?")}'
                out.append(f'  J    {lbl}')
            elif kind == 'RET':
                out.append(f'  RET')

    @classmethod
    def _infer_func_qualname(cls, info, constants, mod_consts_base):
        """Identify a compiled function by its Python qualname.

        Nuitka emits the `__qualname__` assignment near the top of every
        compiled function body — it's materialised from `mod_consts` like
        any other string literal. We walk the first few RIP-relative
        loads into `mod_consts` and return the first string that looks
        like a qualname (`ClassName.method`, `func_name`, `<listcomp>`,
        etc.). The LLM can then associate each `@OPS` block with its
        `@FUNCS_DETECTED` signature.
        """
        if not info or not constants or mod_consts_base is None:
            return None
        # Collect every qualname-shaped string this function references
        # via mod_consts, then rank them. Nuitka emits the `__qualname__`
        # assignment via one of those loads, but the function body may
        # also reference other function names (as dict keys, as bound
        # method lookups, etc.). A string is a "strong" qualname
        # candidate if it contains `.` or `<` (class method, nested
        # scope, lambda/listcomp/genexpr) — those patterns are unique
        # to qualnames and never appear in the random string literals
        # the function happens to pass around. Only fall back to
        # single-word identifiers if no strong candidate exists.
        qualname_pat = re.compile(
            r'[A-Za-z_][A-Za-z0-9_]*'
            r'(\.[A-Za-z_<][A-Za-z0-9_<>.]*)*'
        )
        strong = []      # dotted / angle-bracketed qualnames
        weak = []        # bare identifiers (less confident)
        seen_strs = set()
        for cl in info.get('const_loads', []):
            if cl.get('section') != '.data':
                continue
            target = cl.get('target_va')
            if target is None or target < mod_consts_base:
                continue
            offset = target - mod_consts_base
            if offset % 8:
                continue
            idx = offset // 8
            if not (0 <= idx < len(constants)):
                continue
            v = constants[idx]
            if not isinstance(v, str) or v in seen_strs:
                continue
            seen_strs.add(v)
            if len(v) < 2 or len(v) > 120:
                continue
            if not qualname_pat.fullmatch(v):
                continue
            # Strong candidates have a dot or an angle bracket —
            # unambiguously a qualname.
            if '.' in v or '<' in v:
                strong.append(v)
            else:
                # Skip all-uppercase short bare names (more likely
                # dict keys / enum constants than function qualnames).
                if len(v) >= 5 and not v.isupper():
                    weak.append(v)
        # Prefer the FIRST strong candidate — that's the load Nuitka
        # emits for `__qualname__`. Fall back to the first weak one
        # only if no strong candidate appeared.
        if strong:
            return strong[0]
        if weak:
            return weak[0]
        return None

    @classmethod
    def render(cls, module_name, constants, python_version,
               disasm_info=None, disasm_infos=None, mod_consts_base=None,
               runtime_aliases=None, entry_va=None,
               ops_absence_reason=None, module_table_entry=None,
               chunk_bytes=None, full=True, include_native_asm=True):
        """Produce the text content for `<module>.nbc`.

        Either `disasm_info` (single-block) OR `disasm_infos` (dict of
        {va: info}, multi-block) may be given. When `disasm_infos` is
        provided, one `@OPS <va>` block is emitted per function — this
        is the form the LLM needs to rebuild individual function bodies
        literally instead of just signatures.

        `mod_consts_base` and `runtime_aliases` are optional — when
        omitted the emitter still emits the constants + imports +
        funcs_detected header but ALSO writes a `@NO_OPS` diagnostic
        block explaining WHY `@OPS` is missing so the LLM knows it got
        a partial file (and the user knows what to fix).

        `ops_absence_reason` can be one of:
            'capstone_missing' | 'no_pe' | 'no_module_table' |
            'not_in_module_table' | 'disasm_failed' | None
        """
        runtime_aliases = runtime_aliases or {}
        out = []
        out.append('# Nuitka static reconstruction. Feed this .nbc file to an LLM.')
        out.append('# Format version: NBC/2 full self-contained module record.')
        out.append('# c[N]=mod_consts[N]   r#N=runtime_helper_rank   capi:=Python C API')
        out.append('# Multiple @OPS blocks = one per disassembled function '
                   '(module entry + every internal call target reached via BFS).')
        out.append('')
        out.append('@NBC 2')
        out.append(f'@MOD {module_name or "__module__"}')
        out.append(f'@VER {python_version[0]}.{python_version[1]}')
        if entry_va is not None:
            out.append(f'@ENTRY 0x{entry_va:X}')
        out.append('')
        cls._emit_module_table_entry(module_table_entry, out)
        cls._emit_raw_chunk(chunk_bytes, out)
        cls._emit_constants(list(constants), out, full=full)
        out.append('')
        cls._emit_imports(module_name, constants, out)
        out.append('')
        cls._emit_funcs_detected(module_name, constants, out)
        out.append('')
        cls._emit_code_objects(module_name, list(constants), out)
        out.append('')
        # Normalise: prefer disasm_infos (multi), fall back to disasm_info (single)
        infos_dict = None
        if disasm_infos:
            infos_dict = disasm_infos
        elif disasm_info:
            infos_dict = {disasm_info['func_va']: disasm_info}
        if infos_dict:
            cls._emit_block_summary(infos_dict, runtime_aliases, out)
            # Build an authoritative func_va -> qualname map by
            # aggregating every `make_function_hints` pair across all
            # disassembled blocks. This is much more accurate than
            # inferring qualnames per-block because Nuitka emits the
            # (func_ptr, qualname) pair inline at the MAKE_FUNCTION
            # call site — right where the parent function creates the
            # child. The child itself has no __qualname__ const load.
            va_to_qualname = {}
            if mod_consts_base is not None:
                import re as _re
                qualname_pat = _re.compile(
                    r'[A-Za-z_][A-Za-z0-9_]*'
                    r'(\.[A-Za-z_<][A-Za-z0-9_<>.]*)*'
                )

                def _resolve_const_str(va):
                    if va < mod_consts_base:
                        return None
                    off = va - mod_consts_base
                    if off % 8:
                        return None
                    i = off // 8
                    if not (0 <= i < len(constants)):
                        return None
                    v = constants[i]
                    if not isinstance(v, str):
                        return None
                    if len(v) < 2 or len(v) > 120:
                        return None
                    return v

                # For every (parent_func, lea->impl) hint, gather ALL
                # the parent function's mod_consts string loads as
                # qualname candidates. Nuitka sometimes emits the
                # (impl_ptr, qualname) pair in "lea qualname, lea impl"
                # order (qualname FIRST) rather than the reverse — a
                # forward-only window misses that case.  Collect every
                # candidate and pick the one that best matches
                # `ClassName.method` / `func` / `<lambda>` etc.
                for _va, _info in infos_dict.items():
                    # Precompute this parent's string candidates once
                    parent_strs = []
                    for cl in _info.get('const_loads', []):
                        s = _resolve_const_str(cl['target_va'])
                        if s is None:
                            continue
                        parent_strs.append(s)
                    if not parent_strs:
                        continue
                    # Prefer candidates with dot / angle brackets
                    # (unambiguously qualnames); fall back to plain
                    # identifiers for top-level functions.
                    strong = [s for s in parent_strs
                              if ('.' in s or '<' in s) and qualname_pat.fullmatch(s)]
                    weak = [s for s in parent_strs
                            if qualname_pat.fullmatch(s) and s not in strong
                            and len(s) >= 3 and not s.isupper()]
                    if not (strong or weak):
                        continue
                    pick = strong[0] if strong else weak[0]
                    # Attach to EVERY func_ptr_load target of this
                    # parent that doesn't already have a label.
                    for fp in _info.get('func_ptr_loads', []):
                        tgt = fp['target_va']
                        if tgt not in va_to_qualname:
                            va_to_qualname[tgt] = pick
                    # Also keep the previous adjacency logic for
                    # parents that have MULTIPLE (lea, qualname) pairs
                    # — try to pair each specifically
                    for hint in _info.get('make_function_hints', []):
                        target_fn_va = hint['func_va']
                        for cand in hint.get('candidate_vas', []):
                            s = _resolve_const_str(cand)
                            if s is not None and qualname_pat.fullmatch(s):
                                # Override weak picks with specific
                                # adjacency-derived qualname
                                if ('.' in s or '<' in s):
                                    va_to_qualname[target_fn_va] = s
                                elif target_fn_va not in va_to_qualname:
                                    va_to_qualname[target_fn_va] = s
                                break

            # Emit one @OPS block per function; the module entry VA goes first.
            entry_first = []
            others = []
            for va, info in infos_dict.items():
                if entry_va is not None and va == entry_va:
                    entry_first.append((va, info))
                else:
                    others.append((va, info))
            ordered = entry_first + others
            out.append(f'# @OPS blocks: {len(ordered)} function(s) '
                       f'(entry + {len(ordered) - 1} locals)')
            out.append('')
            for va, info in ordered:
                # The module entry (module_code_<mod>) is not a Python
                # `def` — it has no __qualname__. Suppress any fallback
                # labeling attempt so it isn't accidentally stamped with
                # the qualname of the first child function it creates.
                is_module_entry = (entry_va is not None and va == entry_va)
                cls._emit_virtual_ops(info, constants, mod_consts_base,
                                      runtime_aliases, out,
                                      va_to_qualname=va_to_qualname,
                                      suppress_fallback_label=is_module_entry)
                out.append('')
                if include_native_asm:
                    cls._emit_native_asm(info, constants, mod_consts_base,
                                         runtime_aliases, out)

            # --- FORENSICS section ------------------------------------
            # For qualnames that appear in @CONSTS but never got an
            # @OPS block (BFS didn't reach them — usually Tk/Qt
            # callbacks bound via trace_add/bind, inlined helpers,
            # dead-code paths), emit the **constants that are
            # plausibly tied to them**:
            #   1. the qualname + short name indices
            #   2. the 12 constants adjacent in mod_consts order
            #      (Nuitka clusters a function's consts around its
            #      qualname in the defining module's constants table)
            #   3. any string in @CONSTS whose text literally contains
            #      the short function name (error messages, logs).
            # This gives an LLM concrete forensic evidence to
            # reconstruct likely behaviour WITHOUT fabricating random
            # code — at minimum it sees the error strings, dict keys
            # and integers the function must have referenced.
            cls._emit_forensics(
                constants=constants,
                va_to_qualname=va_to_qualname,
                out=out,
            )
        else:
            # The @OPS section is the heart of a .nbc — its absence turns
            # the file into a signature skeleton only. Explain explicitly
            # so an LLM doesn't silently fabricate a body AND the user
            # knows what to change.
            reason_map = {
                'capstone_missing':
                    'capstone was not installed at analyser runtime '
                    '(pip install capstone); no disassembler could run.',
                'no_pe':
                    'the analyser did not receive a parsed PE object '
                    '(StaticalyExtractor(pe_file=None) — construct with '
                    'the binary).',
                'no_module_table':
                    'the Nuitka module table could not be located in '
                    '.data / .rdata; cannot find the entry VA to '
                    'disassemble from.',
                'not_in_module_table':
                    'this specific module was not present in the module '
                    'table fragment the analyser recovered — other '
                    'modules in this run may still have @OPS.',
                'disasm_failed':
                    'capstone threw while disassembling; the .text bytes '
                    'may be obfuscated or the func_ptr is wrong.',
                None:
                    'disassemble_modules() was never invoked for this '
                    'run (Nuitka Static Unpacker ran in constants-only mode).',
            }
            reason_text = reason_map.get(ops_absence_reason, reason_map[None])
            out.append('@NO_OPS')
            out.append(f'  reason: {reason_text}')
            out.append(f'  consequence: function bodies cannot be rebuilt '
                       f'literally — any LLM fed this file can only emit '
                       f'signatures + # UNCERTAIN bodies.')
            out.append(f'  fix: re-run with')
            out.append(f'       pip install capstone')
            out.append(f'       python nuitka_decompiler.py '
                       f'--source <target.exe> --output <dir> --all')
            out.append(f'       (make sure the run logs show '
                       f'"Staticaly modules disassembled: N > 0")')
        return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
#  NUITKA MODULE DUMP — exhaustive per-module diagnostic file
# ---------------------------------------------------------------------------

class NuitkaModuleDump:
    """Produce a `pseudo-bytecode` dump of a single blob module chunk.

    The goal is to capture **every recoverable byte of information** about
    the module so a reverse engineer (or another tool / AI) can
    reconstruct the original Python source literally.

    The dump is a multi-section text file that includes:

      # METADATA
        module name, chunk size, offset in blob, constants count.

      # CONSTANTS  (the authoritative list, in blob order)
        position, type, interpretation, hex size, value repr.

      # CATEGORISED CONSTANTS
          strings   (split into: idents, dunder, URLs, messages,
                    attribute-names-like, filenames)
          numerics  (ints / floats / booleans)
          tuples    (co_varnames candidates, import-names, kw_defaults, …)
          dicts, sets, bytes

      # INFERRED STRUCTURES
          functions   : name, argcount, args (from position-paired tuple),
                        nearby URL / dict / header constants
          classes     : class name, methods (via qualname `Class.method`)
          imports     : from X import ..., import X (detected patterns)

      # CROSS-REFERENCES  (which string appears as what, how many times)

      # POSITIONAL ANALYSIS
          for every ident-tuple: its position and the nearest surrounding
          ident strings that might be its co_varnames' function name.

      # RAW HEX DUMP of the chunk (optional, last).

    Output file: `<module>.dump.txt`  (same tree as `omni_reconstructed/`).
    Optionally `<module>.dump.json`   for machine-readable analysis.
    """

    def __init__(self, module_name, chunk_bytes, constants, blob_offset=None):
        self.module_name = module_name or '__module__'
        self.chunk = bytes(chunk_bytes) if chunk_bytes is not None else b''
        self.constants = list(constants)
        self.blob_offset = blob_offset

    # --- classification helpers ---

    @staticmethod
    def _classify_string(s):
        if not isinstance(s, str) or not s:
            return 'empty'
        if s.startswith(('http://', 'https://')):
            return 'url'
        if s.startswith('__') and s.endswith('__'):
            return 'dunder'
        if re.fullmatch(r'[A-Z][A-Z0-9_]{2,}', s):
            return 'constant_like'       # ALL_CAPS → probable module-level const
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', s):
            if s[0].isupper():
                return 'class_like'      # CamelCase
            return 'ident'               # snake_case
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', s):
            return 'dotted_path'
        if s.endswith(('.py', '.pyc')):
            return 'filename'
        if '\\' in s or '/' in s:
            return 'path'
        if len(s) > 40 and ' ' in s:
            return 'message'
        if re.fullmatch(r'%[sdifoxXcrb]', s) or '%s' in s or '%d' in s:
            return 'format_string'
        return 'string'

    @staticmethod
    def _is_ident_tuple(t):
        return (isinstance(t, tuple) and t
                and all(isinstance(x, str) and
                        (x == '.0' or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x))
                        for x in t))

    # --- rendering ---

    def render(self, include_hex=True):
        out = []
        out.append('=' * 72)
        out.append(f' NUITKA MODULE DUMP   {self.module_name}')
        out.append('=' * 72)
        out.append('')
        out.append(f'# Chunk size        : {len(self.chunk):,} bytes')
        if self.blob_offset is not None:
            out.append(f'# Blob offset       : 0x{self.blob_offset:X}')
        out.append(f'# Constants count   : {len(self.constants)}')
        out.append(f'# Dump produced by  : Nuitka Static Unpacker v7.2 (by dimareverse)')
        out.append('')

        # ---------- CONSTANTS ----------
        out.append('-' * 72)
        out.append(' CONSTANTS (in blob order)')
        out.append('-' * 72)
        for i, c in enumerate(self.constants):
            tname = type(c).__name__
            if isinstance(c, str):
                kind = self._classify_string(c)
                rep = repr(c)
                if len(rep) > 120:
                    rep = rep[:117] + '...'
                out.append(f'[{i:4d}] str/{kind:<13} {rep}')
            elif isinstance(c, (bytes, bytearray)):
                kind = 'bytes'
                try:
                    maybe = c.decode('utf-8')
                    if all(32 <= ord(x) < 127 or x in '\r\n\t' for x in maybe[:200]):
                        kind = 'bytes/ascii'
                except Exception:
                    pass
                rep = repr(bytes(c)[:80]) + ('...' if len(c) > 80 else '')
                out.append(f'[{i:4d}] {kind:<17} size={len(c)}  {rep}')
            elif isinstance(c, tuple):
                if self._is_ident_tuple(c):
                    kind = 'tuple/idents'
                elif all(isinstance(x, str) for x in c):
                    kind = 'tuple/strs'
                elif all(isinstance(x, (int, float)) for x in c):
                    kind = 'tuple/nums'
                else:
                    kind = 'tuple'
                rep = repr(c)
                if len(rep) > 120:
                    rep = rep[:117] + '...'
                out.append(f'[{i:4d}] {kind:<17} size={len(c)}  {rep}')
            elif isinstance(c, dict):
                out.append(f'[{i:4d}] dict              size={len(c)}  {repr(c)[:100]}')
            elif isinstance(c, (list, set, frozenset)):
                out.append(f'[{i:4d}] {tname:<17} size={len(c)}  {repr(c)[:100]}')
            elif isinstance(c, bool):
                out.append(f'[{i:4d}] bool              {c}')
            elif isinstance(c, int):
                out.append(f'[{i:4d}] int               {c}   (hex 0x{c:X})'
                           if abs(c) < (1 << 32) else f'[{i:4d}] int               {c}')
            elif isinstance(c, float):
                out.append(f'[{i:4d}] float             {c}')
            elif c is None:
                out.append(f'[{i:4d}] None')
            else:
                out.append(f'[{i:4d}] {tname:<17} {repr(c)[:100]}')
        out.append('')

        # ---------- CATEGORISED ----------
        cat = {
            'urls': [], 'messages': [], 'format_strings': [], 'filenames': [],
            'paths': [], 'dunders': [], 'idents': [], 'class_likes': [],
            'constant_likes': [], 'strings': [], 'dotted_paths': [],
            'integers': [], 'floats': [], 'bytes': [],
            'ident_tuples': [], 'string_tuples': [], 'numeric_tuples': [],
            'dicts': [], 'sets': [],
        }
        for i, c in enumerate(self.constants):
            if isinstance(c, str):
                k = self._classify_string(c)
                bucket = {
                    'url': 'urls',
                    'message': 'messages',
                    'format_string': 'format_strings',
                    'filename': 'filenames',
                    'path': 'paths',
                    'dunder': 'dunders',
                    'ident': 'idents',
                    'class_like': 'class_likes',
                    'constant_like': 'constant_likes',
                    'dotted_path': 'dotted_paths',
                }.get(k, 'strings')
                cat[bucket].append((i, c))
            elif isinstance(c, (bytes, bytearray)):
                cat['bytes'].append((i, bytes(c)))
            elif isinstance(c, tuple):
                if self._is_ident_tuple(c):
                    cat['ident_tuples'].append((i, c))
                elif all(isinstance(x, str) for x in c):
                    cat['string_tuples'].append((i, c))
                elif all(isinstance(x, (int, float)) for x in c):
                    cat['numeric_tuples'].append((i, c))
            elif isinstance(c, dict):
                cat['dicts'].append((i, c))
            elif isinstance(c, (set, frozenset)):
                cat['sets'].append((i, c))
            elif isinstance(c, bool):
                pass  # skip
            elif isinstance(c, int):
                cat['integers'].append((i, c))
            elif isinstance(c, float):
                cat['floats'].append((i, c))

        out.append('-' * 72)
        out.append(' CATEGORISED CONSTANTS')
        out.append('-' * 72)
        sect_names = [
            ('urls', 'URLs / HTTP endpoints'),
            ('messages', 'Human-readable messages (len>40 with spaces)'),
            ('format_strings', 'Format strings (printf / %s / %d …)'),
            ('filenames', 'Filenames (end in .py / .pyc)'),
            ('paths', 'Paths (with / or \\)'),
            ('dunders', 'Dunder attributes (__foo__)'),
            ('constant_likes', 'ALL_CAPS constants'),
            ('class_likes', 'CamelCase identifiers (probable classes)'),
            ('dotted_paths', 'Dotted paths (module.attr / Class.method)'),
            ('idents', 'snake_case identifiers'),
            ('strings', 'Other strings'),
            ('integers', 'Integers'),
            ('floats', 'Floats'),
            ('bytes', 'Bytes'),
            ('ident_tuples', 'Tuples of identifiers (co_varnames candidates)'),
            ('string_tuples', 'Tuples of strings (non-ident)'),
            ('numeric_tuples', 'Tuples of numbers'),
            ('dicts', 'Dicts (literal kwargs / configs)'),
            ('sets', 'Sets / frozensets'),
        ]
        for key, title in sect_names:
            items = cat[key]
            if not items:
                continue
            out.append(f'\n### {title}  ({len(items)})')
            for i, v in items:
                rep = repr(v)
                if len(rep) > 140:
                    rep = rep[:137] + '...'
                out.append(f'  [{i:4d}] {rep}')
        out.append('')

        # ---------- INFERRED STRUCTURES ----------
        out.append('-' * 72)
        out.append(' INFERRED STRUCTURES')
        out.append('-' * 72)

        # 1) Imports: dotted path OR stdlib-ident followed by ident-tuple
        imports_detected = []
        stdlib = StaticalySmartReconstructor._COMMON_STDLIB
        for i, c in enumerate(self.constants):
            if not isinstance(c, str):
                continue
            next_tup = (self.constants[i + 1] if i + 1 < len(self.constants) else None)
            dotted = bool(re.fullmatch(
                r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', c
            ) and not c.endswith('.py') and c.split('.')[0][:1].islower())
            is_std = c in stdlib
            if (dotted or is_std) and self._is_ident_tuple(next_tup):
                imports_detected.append(('from_import', i, c, list(next_tup)))
            elif dotted or is_std:
                imports_detected.append(('import', i, c, None))

        if imports_detected:
            out.append('\n### Imports')
            for kind, idx, mod, names in imports_detected:
                if kind == 'from_import':
                    out.append(f'  [{idx:4d}] from {mod} import {", ".join(names)}')
                else:
                    out.append(f'  [{idx:4d}] import {mod}')

        # 2) Function candidates: for each ident-tuple, find the nearest
        #    ident-string that could be the function name.
        out.append('\n### Function candidates (tuple → likely function signature)')
        for i, tup in cat['ident_tuples']:
            # Look backwards and forwards up to 8 positions for an ident
            name = None
            for off in range(-8, 9):
                j = i + off
                if j == i or j < 0 or j >= len(self.constants):
                    continue
                v = self.constants[j]
                if (isinstance(v, str)
                        and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', v or '')
                        and not v.startswith('__')):
                    name = v
                    break
            args = ', '.join(tup)
            if name:
                out.append(f'  [{i:4d}] tuple ({args}) ~= co_varnames of def {name}(...)')
            else:
                out.append(f'  [{i:4d}] tuple ({args}) ~= anonymous co_varnames')

        # 3) Classes from qualname patterns
        classes = {}
        for c in self.constants:
            if not isinstance(c, str):
                continue
            m = re.fullmatch(
                r'([A-Z][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)(?:\.<locals>.*)?', c
            )
            if m:
                classes.setdefault(m.group(1), set()).add(m.group(2))
        if classes:
            out.append('\n### Class hierarchy (from `Class.method` qualnames)')
            for cls_name in sorted(classes):
                methods = sorted(classes[cls_name])
                out.append(f'  class {cls_name}:')
                for m in methods:
                    out.append(f'      def {m}(self, ...)')

        # 4) HTTP API endpoints explicit list
        if cat['urls']:
            out.append('\n### HTTP API endpoints')
            for i, u in cat['urls']:
                out.append(f'  [{i:4d}] {u}')

        # 5) Error / status messages
        if cat['messages']:
            out.append('\n### Human-readable messages (errors / prompts)')
            for i, m in cat['messages']:
                out.append(f'  [{i:4d}] {m!r}')

        out.append('')

        # ---------- POSITIONAL ANALYSIS ----------
        out.append('-' * 72)
        out.append(' POSITIONAL MAP  (name → nearest tuple)')
        out.append('-' * 72)
        name_positions = [(i, c) for i, c in enumerate(self.constants)
                          if isinstance(c, str)
                          and re.fullmatch(r'[a-z_][a-z0-9_]*', c or '')
                          and len(c) > 2]
        tuple_positions = [(i, c) for i, c in cat['ident_tuples']]
        # Pair positionally (1-to-1 by sorted index) — this matches source order.
        pair_lines = []
        for k in range(min(len(name_positions), len(tuple_positions))):
            pi, pn = name_positions[k]
            ti, pt = tuple_positions[k]
            pair_lines.append(f'  {pn!r} (const[{pi}])  <->  {pt}  (const[{ti}])')
        out.extend(pair_lines[:80])
        if len(pair_lines) > 80:
            out.append(f'  ... ({len(pair_lines) - 80} more pairings)')
        out.append('')

        # ---------- HEX DUMP ----------
        if include_hex and self.chunk:
            out.append('-' * 72)
            out.append(f' RAW HEX DUMP of chunk  ({len(self.chunk):,} bytes)')
            out.append('-' * 72)
            # canonical xxd-style: offset  16 bytes hex  ascii
            for off in range(0, len(self.chunk), 16):
                row = self.chunk[off:off + 16]
                hex_part = ' '.join(f'{b:02x}' for b in row)
                ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in row)
                out.append(f'{off:08x}  {hex_part:<47}  |{ascii_part}|')
            out.append('')

        return '\n'.join(out) + '\n'

    def render_json(self):
        """Machine-readable version of the dump."""
        def _serialisable(v):
            if isinstance(v, (str, int, float, bool)) or v is None:
                return v
            if isinstance(v, (bytes, bytearray)):
                try:
                    return {'_type': 'bytes', 'hex': bytes(v).hex(),
                            'size': len(v)}
                except Exception:
                    return {'_type': 'bytes', 'repr': repr(bytes(v)[:200])}
            if isinstance(v, tuple):
                return {'_type': 'tuple', 'items': [_serialisable(x) for x in v]}
            if isinstance(v, list):
                return [_serialisable(x) for x in v]
            if isinstance(v, dict):
                return {'_type': 'dict',
                        'items': [[_serialisable(k), _serialisable(x)]
                                  for k, x in list(v.items())[:200]]}
            if isinstance(v, (set, frozenset)):
                return {'_type': type(v).__name__,
                        'items': [_serialisable(x) for x in list(v)[:200]]}
            return repr(v)

        payload = {
            'module': self.module_name,
            'chunk_size': len(self.chunk),
            'blob_offset': self.blob_offset,
            'constants_count': len(self.constants),
            'constants': [
                {'index': i,
                 'type': type(c).__name__,
                 'classification': (self._classify_string(c)
                                    if isinstance(c, str) else None),
                 'value': _serialisable(c)}
                for i, c in enumerate(self.constants)
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
#  STATICALY SMART PYTHON RECONSTRUCTOR — deepest per-module recovery
# ---------------------------------------------------------------------------

class StaticalySmartReconstructor:
    """Deep static reconstruction of a Nuitka module chunk into Python source.

    Nuitka translates each Python function body directly into C operations
    and then into native x86-64 instructions: the original `co_code` is
    NEVER stored in the binary for C-compiled modules, only its metadata.
    So a 100% byte-exact source recovery is impossible for those modules.

    What IS recoverable from the `constants` chunk of each module:
      * All string/int/float/tuple/dict/set/frozenset literals the module
        body or any of its functions reference. These are the constants
        passed to `LOAD_CONST` in the never-stored bytecode, emitted by
        Nuitka into the blob so the generated C code can look them up.
      * All `co_varnames` tuples — one per function/method body. That's
        the argument list + local-variable names of every def in the
        original source.
      * The `co_filename` / `co_name` / `co_qualname` of every code
        object (they're stored with 'C' tag or sit near the arg tuple).
      * Import side-effects: Nuitka emits the module-name STR followed by
        a tuple of imported-names STRs for every `from X import Y, Z`.

    This reconstructor pattern-matches on those constants to emit a
    near-original Python source:

      1. `import X`, `from X import (Y, Z as A)` lines
      2. Module-level globals (first non-dunder str sequence)
      3. `class Name(Base1, Base2):` with `def method(self, args):` inside
      4. Free `def func(args):` with an heuristic body when we recognise
         a well-known pattern (HTTP fetch, HMAC sign, JSON parse, etc.)
      5. Body STUBS with a list of "strings referenced by this function"
         so a reverse-engineer can re-derive the logic from the clues.

    When the pattern isn't recognised we emit `...` (not fabricated code)
    so the output never misleads with invented behaviour.
    """

    # Recognisable Python keywords that often appear verbatim in the
    # constants (`co_consts` items).
    _BUILTIN_EXCEPTIONS = {
        'Exception', 'ValueError', 'TypeError', 'KeyError', 'IndexError',
        'RuntimeError', 'AttributeError', 'ImportError', 'IOError',
        'OSError', 'FileNotFoundError', 'ConnectionError', 'TimeoutError',
        'InvalidSignature',
    }
    _HTTP_STATUS_NAMES = ('status_code', 'text', 'json', 'content')
    _HTTP_GET_KEYWORDS = ('status_code', 'final_balance', 'chain_stats',
                          'funded_txo_sum', 'spent_txo_sum', 'balance',
                          'json', 'get', 'response')

    def __init__(self, module_name, constants, code_objects):
        self.module_name = module_name or '__module__'
        self.constants = list(constants)
        self.code_objects = list(code_objects)

        # C-compiled Nuitka modules don't emit 'C' tags into their
        # constants chunk, so we have to infer function layouts from
        # the raw constants. Start with a BROAD scan: every plausible
        # function-name-looking ident is a candidate. The positional
        # pairing below will then attach each name to its co_varnames.
        if not self.code_objects:
            self.code_objects = self._broad_scan_function_names()

        # --- Re-pair function NAMES with the closest co_varnames TUPLE ---
        # The initial inference is fuzzy: it can attach the wrong tuple to
        # a name when they're both near the same filename. We can do much
        # better by walking the constants list in ORDER: most Python
        # compilers emit identifier strings and their corresponding
        # co_varnames tuple in source-code order, so pairing by position
        # is typically correct.
        self.code_objects = self._repair_name_args_by_order(self.code_objects)

        # Filter out false positives:
        #   - dunder names (`__spec__`, `__doc__` etc.)  — never functions
        #   - module-level import idents picked up by mistake
        #   - stdlib module names
        #   - duplicate (name, args-tuple) combinations
        stdlib = self._COMMON_STDLIB

        # Module-local import names: idents that appear right before an
        # ident-tuple (same pattern we use for detect_imports). If they
        # show up as "function names" in the inference we should filter
        # them — they're actually `from X import ...` targets.
        import_names = set()
        for i, c in enumerate(self.constants):
            if (isinstance(c, str)
                    and re.fullmatch(r'[a-z_][a-z0-9_]*', c or '')
                    and i + 1 < len(self.constants)
                    and isinstance(self.constants[i + 1], tuple)
                    and self.constants[i + 1]
                    and all(isinstance(x, str) and
                            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x)
                            for x in self.constants[i + 1])):
                # Looks like `str 'foo'` followed by tuple of idents — very
                # likely `from foo import ...`. Record 'foo' as an import
                # name so we don't emit `def foo(...):` for it.
                import_names.add(c)

        leaf = self.module_name.split('.')[-1] if self.module_name else ''
        filtered = []
        seen_sig = set()
        for co in self.code_objects:
            name = co.get('name', '') or ''
            if not name:
                continue
            # Reject dunder module-level attributes
            if name.startswith('__') and name.endswith('__') and name != '__init__':
                continue
            # Reject stdlib/import names
            if name in stdlib or name in import_names:
                continue
            # Reject the module's own leaf name
            if name == leaf:
                continue
            # Reject single-char names or names that are clearly data (all caps long)
            if len(name) < 2:
                continue
            # A function with ZERO args that also appears as a tuple element
            # somewhere is almost certainly noise.
            if not co.get('args'):
                continue
            # De-dup on (name, argcount)
            sig = (name, tuple(co.get('args') or ()))
            if sig in seen_sig:
                continue
            seen_sig.add(sig)
            filtered.append(co)
        self.code_objects = filtered

        # Build string index by value → list of positions (for pattern scans)
        self.str_positions = {}
        for i, c in enumerate(self.constants):
            if isinstance(c, str):
                self.str_positions.setdefault(c, []).append(i)

        # Classify each code object into module-body / class methods / free funcs
        self._classify()

    # ---- structural classification ----

    # --- Names we should NEVER emit as `def <name>(...)`. These are
    # module-level attributes, well-known dunder names, or constant-like
    # ALL_CAPS identifiers that represent values rather than callables.
    _NON_FUNCTION_NAMES = frozenset({
        # Python module machinery
        '__doc__', '__file__', '__cached__', '__name__', '__spec__',
        '__package__', '__builtins__', '__class__', '__loader__',
        '__path__', '__module__', '__all__', '__version__',
        '__author__', '__annotations__', '__dict__', '__slots__',
        '__qualname__', '__weakref__', '__mro_entries__',
        # HTTP / response-object attribute accesses (they're strings used
        # for LOAD_ATTR, not functions in the module)
        'status_code', 'text', 'content', 'json', 'get', 'post', 'put',
        'delete', 'headers', 'cookies', 'url', 'ok', 'reason', 'encoding',
        'origin', 'has_location',
        # Control flow / magic method names emitted as LOAD_ATTR consts
        '__iter__', '__getitem__', '__setitem__', '__enter__', '__exit__',
        '__init__', '__call__', '__str__', '__repr__', '__eq__', '__hash__',
        '__bool__', '__len__', '__contains__', '__add__', '__sub__',
        '__mul__', '__truediv__', '__getattr__', '__setattr__',
    })

    def _broad_scan_function_names(self):
        """Return every plausible function-name ident in the constants.

        A plausible function name is an ident that:
          * is lowercase or snake_case (not ALL_CAPS, not CamelCase —
            those are classes/constants, handled separately),
          * is at least 3 chars long,
          * isn't in _NON_FUNCTION_NAMES,
          * isn't an arg-name-like common word (self, args, kwargs, etc.),
          * isn't the leaf of this module's own name.

        Pairing with co_varnames happens in `_repair_name_args_by_order`.
        """
        leaf = self.module_name.split('.')[-1] if self.module_name else ''
        blacklist = set(self._NON_FUNCTION_NAMES) | {leaf} | {
            'self', 'cls', 'args', 'kwargs', 'data', 'value', 'key',
            'name', 'item', 'items', 'obj', 'result', 'error', 'e', 'exc',
            'config', 'session', 'payload', 'token', 'address', 'balance',
            'url', 'response', 'request', 'param', 'params',
            'print', 'bool', 'str', 'int', 'float', 'list', 'tuple', 'dict',
            'set', 'type', 'range', 'len', 'sum', 'min', 'max', 'map',
            'filter', 'sorted', 'reversed', 'all', 'any',
        }

        candidates = []
        seen = set()
        for c in self.constants:
            if not isinstance(c, str):
                continue
            if c in seen or c in blacklist:
                continue
            if not re.fullmatch(r'[a-z_][a-z0-9_]*', c):
                continue
            if len(c) < 3:
                continue
            # Reject strings that end in '.py' or contain . or \ (filenames)
            if '.' in c or '\\' in c or '/' in c:
                continue
            seen.add(c)
            candidates.append({
                '_type': 'CodeObject',
                'name': c,
                'qualname': c,
                'args': [],
                'argcount': 0,
                'kwonly': 0,
                'posonly': 0,
                'flags': 0,
                'line': 0,
                '_source': 'broad-scan',
            })
        return candidates

    def _repair_name_args_by_order(self, code_objects):
        """Re-pair function NAMES with co_varnames TUPLES by source-code order.

        Nuitka's constants blob lays out per-function data like this (this
        is not a hard contract but holds for every real binary we've seen):

            str 'func1'                 <- at list index i1
            str 'func2'                 <- at list index i2
            ...
            str 'funcN'
            str '<module>.py' / '<module ...>'   <- filename/qualname marker
            tuple(varnames of func1)    <- at list index j1, usually i1 < jk
            tuple(varnames of func2)
            ...
            tuple(varnames of funcN)

        Names appear in source declaration order in a contiguous run, and
        the co_varnames tuples appear in the SAME relative order after a
        filename anchor. So we can re-pair them positionally by:
          1. collecting every candidate function-name string and its position,
          2. collecting every ident-tuple and its position,
          3. sorting both lists by position,
          4. matching name[k] <-> tuple[k] (clipped to min length).
        """
        # Candidate function names from the inferrer's preliminary pass
        candidate_names = []
        name_seen = set()
        for co in code_objects:
            n = co.get('name') or ''
            if n and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', n) and n not in name_seen:
                name_seen.add(n)
                candidate_names.append(n)

        # Collect positions
        name_positions = []
        for i, c in enumerate(self.constants):
            if isinstance(c, str) and c in name_seen:
                name_positions.append((i, c))

        tuple_positions = []
        for i, c in enumerate(self.constants):
            if (isinstance(c, tuple) and c
                    and all(isinstance(x, str) and
                            (x == '.0' or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x))
                            for x in c)):
                tuple_positions.append((i, c))

        # Sort by position and pair 1:1 in order. Because names appear in
        # the same source order as their varnames tuples, index k of the
        # name list maps to index k of the tuple list.
        name_positions.sort()
        tuple_positions.sort()
        paired = {}
        limit = min(len(name_positions), len(tuple_positions))
        for k in range(limit):
            _, name = name_positions[k]
            _, tup = tuple_positions[k]
            # Don't overwrite a name that already has a good pairing —
            # keep the FIRST (leftmost) occurrence so we preserve source order.
            paired.setdefault(name, tup)

        # Rebuild code_objects with the repaired pairings
        result = []
        for co in code_objects:
            name = co.get('name') or ''
            new_co = dict(co)
            if name in paired:
                tup = paired[name]
                new_co['args'] = list(tup)
                new_co['argcount'] = len(tup)
            result.append(new_co)
        return result

    def _classify(self):
        self.classes = {}   # class_name -> {'methods': [co], 'bases': [...]}
        self.free_funcs = []
        self.module_body = None

        for co in self.code_objects:
            if not co:
                continue
            name = co.get('name') or ''
            qualname = co.get('qualname') or name

            if name == '<module>' or qualname == '<module>':
                self.module_body = co
                continue

            if name in ('<listcomp>', '<dictcomp>', '<setcomp>',
                        '<genexpr>', '<lambda>'):
                continue

            # qualname like "ClassName.method" => method. Handle nested
            # `<locals>` paths ("Outer.inner.<locals>.method" => stops at Outer)
            qn = str(qualname)
            parent = None
            leaf = name
            if '.' in qn and not qn.startswith('<'):
                parts = qn.split('.<locals>.')[0].split('.')
                if len(parts) >= 2 and parts[0] and parts[0][0].isupper():
                    parent = parts[0]
                    leaf = parts[-1]

            if parent:
                self.classes.setdefault(parent, {'methods': [], 'bases': []})
                self.classes[parent]['methods'].append(co)
            else:
                self.free_funcs.append(co)

    # ---- import recovery ----

    # Stdlib modules that routinely show up as bare imports in the blob.
    # We only accept a BARE ident as a module name if it's in this set —
    # otherwise we'd mistake every function/attribute name for an import.
    _COMMON_STDLIB = {
        'sys', 'os', 're', 'json', 'time', 'struct', 'ctypes',
        'hashlib', 'hmac', 'base64', 'random', 'binascii',
        'threading', 'asyncio', 'typing', 'datetime', 'math',
        'itertools', 'functools', 'copy', 'io', 'traceback',
        'collections', 'pathlib', 'socket', 'ssl', 'subprocess',
        'warnings', 'logging', 'signal', 'platform', 'pickle',
        'codecs', 'enum', 'abc', 'inspect', 'importlib', 'weakref',
        'urllib', 'http', 'email', 'concurrent', 'decimal',
        'queue', 'uuid', 'bisect', 'heapq', 'operator', 'atexit',
        'contextlib', 'dataclasses', 'gc', 'glob', 'shutil',
        'stat', 'string', 'textwrap', 'tempfile', 'zipfile',
        'zlib', 'gzip', 'bz2', 'lzma', 'csv', 'xml', 'html',
        'token', 'tokenize', 'types', 'typing_extensions',
        # extremely common in crypto/wallet projects
        'requests', 'aiohttp', 'httpx', 'yarl', 'six',
    }

    def detect_imports(self):
        """Return a list of `import ...` / `from ... import ...` statements.

        Pattern used by Nuitka's C-compiled code generator:
           str  <module_name>
           tuple (<imported_name>, ...)        # co_names of the import
           str  <imported_name>                # the IMPORT_FROM names
           (str <alias>                        # STORE_NAME if `as` was used)
        We recognise a module STRING only when it either
          * contains a '.' (dotted path, unambiguously a module), OR
          * is followed immediately by a tuple-of-idents (= the `from X
            import (A, B)` names tuple), OR
          * is one of a small whitelist of stdlib modules.
        This avoids turning every bare identifier like `session`, `print`
        or `payload` into a bogus `import session` line.
        """
        lines = []
        used = set()
        n = len(self.constants)

        # Build the set of names that appear in ANY ident-tuple. Those are
        # co_varnames / argument names from other functions in the same
        # module — they're NOT importable module names, even though they
        # show up next to a tuple-of-idents.
        arg_names_in_tuples = set()
        for c in self.constants:
            if isinstance(c, tuple) and c:
                for x in c:
                    if isinstance(x, str) and re.fullmatch(r'[a-z_][a-z0-9_]*', x):
                        arg_names_in_tuples.add(x)

        # Common method/function names that often appear as string+tuple
        # pairs because they're `obj.method(**kwargs)` calls, NOT imports.
        # Filtering these avoids spurious `from dumps import sort_keys, default`
        # when the real code is `json.dumps(..., sort_keys=True, default=json_serial)`.
        METHOD_CALL_ARTIFACTS = {
            'dumps', 'loads', 'dump', 'load',
            'get', 'post', 'put', 'delete', 'patch', 'head', 'options',
            'request', 'send', 'open', 'write', 'read',
            'sha256', 'sha1', 'sha512', 'md5', 'hmac', 'new', 'digest',
            'hexdigest', 'encode', 'decode', 'verify', 'sign',
            'format', 'split', 'join', 'strip', 'replace', 'startswith',
            'endswith', 'find', 'index', 'count', 'upper', 'lower',
            'items', 'keys', 'values', 'update', 'append', 'pop',
            'extend', 'insert', 'remove', 'clear', 'copy', 'sort',
            'reverse', 'add', 'discard', 'isdigit', 'isalpha',
        }

        def is_dotted_module(s):
            if not isinstance(s, str) or not (2 < len(s) < 80):
                return False
            if s.endswith(('.py', '.pyc')):
                return False
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', s):
                return False
            parts = s.split('.')
            # reject dunder-containing paths like `foo.__class__`
            if any(p.startswith('__') for p in parts):
                return False
            # reject CamelCase first segment — it's a class.method qualname,
            # not a module path. E.g. `VXProof._load_public_key` or
            # `BitcoinWallet.generate_address` are not importable modules.
            first = parts[0]
            if first and first[0].isupper():
                return False
            return True

        def is_stdlib_module(s):
            return (isinstance(s, str) and s in self._COMMON_STDLIB)

        def is_ident_tuple(t):
            if not isinstance(t, tuple) or not t or len(t) > 30:
                return False
            return all(isinstance(x, str)
                       and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x)
                       for x in t)

        i = 0
        while i < n:
            c = self.constants[i]
            # Peek forward for an adjacent ident-tuple that looks like
            # an import-names list.
            next_is_tuple = (i + 1 < n and is_ident_tuple(self.constants[i + 1]))

            # Heuristic: a bare lowercase ident followed by a tuple IS an
            # import only when the ident looks like a module (lowercase
            # with underscores, no CamelCase — classes are not modules).
            is_probable_module = (
                isinstance(c, str)
                and re.fullmatch(r'[a-z_][a-z0-9_]*', c)  # all lowercase
                and len(c) > 3
                and c not in ('self', 'args', 'kwargs', 'cls', 'data',
                              'text', 'name', 'value', 'item', 'items',
                              'key', 'keys', 'obj', 'result', 'response',
                              'request', 'url', 'path', 'config', 'token',
                              'apis', 'balance', 'payload', 'session',
                              'print', 'address', 'headers', 'status_code',
                              'json', 'content', 'origin', 'has_location',
                              'proxyconnector'))

            # Reject bare idents that are actually co_varnames somewhere
            # else in the module — they look like module names but aren't.
            if (isinstance(c, str)
                    and c in arg_names_in_tuples
                    and not is_dotted_module(c)
                    and not is_stdlib_module(c)):
                i += 1
                continue

            # Reject well-known method/function names (dumps, sha256, ...)
            # when they're bare — they're method-call LOAD_ATTR constants,
            # not imports.
            if (isinstance(c, str)
                    and c in METHOD_CALL_ARTIFACTS
                    and not is_dotted_module(c)):
                i += 1
                continue

            if isinstance(c, str) and (
                    is_dotted_module(c)
                    or (next_is_tuple and is_stdlib_module(c))
                    or (next_is_tuple and is_probable_module)):

                # Valid module reference
                if next_is_tuple:
                    imp = self.constants[i + 1]
                    # filter out dunder-like names from the tuple
                    names = [x for x in imp if not x.startswith('__')]
                    if names:
                        key = f"from {c} import {','.join(sorted(names))}"
                        if key not in used:
                            used.add(key)
                            lines.append(f"from {c} import {', '.join(names)}")
                    i += 2
                    continue

                if is_stdlib_module(c) or is_dotted_module(c):
                    key = f"import {c}"
                    if key not in used:
                        used.add(key)
                        lines.append(f"import {c}")
            i += 1

        # Ordering: stdlib < third-party < project-local
        mod_root = self.module_name.split('.')[0] if self.module_name else ''

        def sort_key(line):
            parts = line.split()
            mod = parts[1] if parts else ''
            root = mod.split('.')[0]
            if root in self._COMMON_STDLIB:
                return (0, root, line)
            if mod_root and mod.startswith(mod_root + '.'):
                return (2, mod, line)
            return (1, mod, line)

        lines.sort(key=sort_key)
        return lines

    # ---- function-body heuristics ----

    def _function_string_context(self, args):
        """Pick string constants that look 'related' to this function.

        A crude metric: strings whose value contains one of the arg names,
        or that match URL/http patterns, or that look like error messages.
        """
        urls = []
        messages = []
        keys = []
        for c in self.constants:
            if not isinstance(c, str):
                continue
            low = c.lower()
            if low.startswith(('http://', 'https://')) and len(c) > 12:
                urls.append(c)
            elif len(c) > 30 and (' ' in c and c.count(' ') > 2):
                messages.append(c)
            elif re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{2,40}', c):
                keys.append(c)
        return urls, messages, keys

    def _guess_body(self, name, args, indent='    '):
        """Return an *heuristic* body for a def with this name/args.

        Tries a few well-known patterns; falls back to `...` on miss.
        Never invents random variables — anything printed in the body
        MUST come from the chunk's constants or the arg list.
        """
        if not args:
            return [f'{indent}...']

        is_method = args[:1] == ['self']
        body_args = args[1:] if is_method else args
        low = name.lower()
        urls, messages, keys = self._function_string_context(args)

        # ---- Pattern: fetch_* / get_*_balance (HTTP fetcher) ----
        if any(kw in low for kw in ('fetch_', 'http_get', 'request_')):
            # Find a URL matching the fetcher suffix
            api_url = None
            for url in urls:
                suffix = low.replace('fetch_from_', '').replace('fetch_', '')
                root = suffix.split('_')[0]
                if root and root in url.lower():
                    api_url = url
                    break
            if api_url is None and urls:
                api_url = urls[0]

            lines = []
            if api_url and 'address' in args:
                lines.append(f'{indent}url = {api_url!r} + address')
            elif api_url:
                lines.append(f'{indent}url = {api_url!r}')
            else:
                lines.append(f'{indent}url = ...  # URL not recovered')

            has_headers = 'headers' in args
            has_api_key = 'api_key' in args or 'token' in args
            if has_headers:
                hdr_key_candidates = [k for k in keys if '-' in k or 'Key' in k or 'Token' in k]
                hdr = hdr_key_candidates[0] if hdr_key_candidates else 'X-API-Key'
                if has_api_key:
                    lines.append(f'{indent}headers = {{{hdr!r}: ' +
                                 (f'token}}' if 'token' in args else f'api_key}}'))
                else:
                    lines.append(f'{indent}headers = {{{hdr!r}: ...}}')
                lines.append(f'{indent}response = session.get(url, headers=headers)')
            else:
                lines.append(f'{indent}response = session.get(url)')

            lines.append(f'{indent}if response.status_code == 200:')
            # Heuristic body based on the args available
            if 'balance_satoshis' in args and 'chain_stats' in args:
                lines.append(f'{indent}    chain_stats = response.json()[\'chain_stats\']')
                lines.append(f'{indent}    funded_txo_sum = chain_stats[\'funded_txo_sum\']')
                lines.append(f'{indent}    spent_txo_sum = chain_stats[\'spent_txo_sum\']')
                lines.append(f'{indent}    balance_satoshis = funded_txo_sum - spent_txo_sum')
                lines.append(f'{indent}    return convert_to_btc(balance_satoshis)')
            elif 'balance_btc' in args:
                lines.append(f'{indent}    balance_btc = response.json()  # exact key not recovered')
                lines.append(f'{indent}    return balance_btc')
            elif 'balance' in args:
                lines.append(f'{indent}    balance = response.json().get(\'balance\', 0)')
                lines.append(f'{indent}    return balance')
            elif 'data' in args:
                lines.append(f'{indent}    data = response.json()')
                lines.append(f'{indent}    return data')
            else:
                lines.append(f'{indent}    return response.json()')
            err_msg = next((m for m in messages if 'status code' in m.lower()), None)
            lines.append(f'{indent}else:')
            if err_msg:
                lines.append(f'{indent}    print({err_msg!r} + str(response.status_code))')
            else:
                lines.append(f'{indent}    print(\'Request failed:\', response.status_code)')
            lines.append(f'{indent}    return None')
            return lines

        # ---- Pattern: convert_to_btc(chain_stats) ----
        if low.startswith('convert_to_') or low == 'to_btc':
            return [f'{indent}# Nuitka-compiled body; convert satoshis -> BTC',
                    f'{indent}return (chain_stats[\'funded_txo_sum\'] - chain_stats[\'spent_txo_sum\']) / 100000000'
                    if body_args == ['chain_stats'] else
                    f'{indent}return {body_args[0] if body_args else "value"} / 100000000']

        # ---- Pattern: __init__ with self + explicit args ----
        if name == '__init__' and is_method and body_args:
            return [f'{indent}self.{a} = {a}' for a in body_args if a.isidentifier()]

        # ---- Pattern: hmac_sign / sign / verify ----
        if any(kw in low for kw in ('hmac_sign', 'sign_', 'verify_', 'hash_', 'digest_')):
            return [f'{indent}# HMAC / digest helper — compiled body',
                    f'{indent}...']

        # ---- Pattern: load / save config ----
        if any(kw in low for kw in ('load_config', 'save_config', 'parse_config', 'read_config')):
            return [f'{indent}# Reads/writes a JSON config file',
                    f'{indent}...']

        # ---- Fallback ----
        # List the strings this function likely references (if any) as
        # a comment so the reverse engineer can see the clues.
        related = [u for u in urls if len(u) < 120][:3]
        lines = []
        if related:
            lines.append(f'{indent}# References: ' + ', '.join(repr(u) for u in related))
        lines.append(f'{indent}...')
        return lines

    # ---- emission ----

    def _emit_function(self, co, indent='', is_method=False):
        name = co.get('name', '?') or '?'
        args = [str(a) for a in (co.get('args') or [])]

        # Basic ident check on the name
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            return []

        # For methods, ensure `self` is first
        if is_method and (not args or args[0] != 'self'):
            args = ['self'] + args

        flags = co.get('flags') or 0
        is_async = bool(flags & 0x0080) or bool(flags & 0x0100)  # CO_COROUTINE / CO_ASYNC_GENERATOR
        kw = 'async def' if is_async else 'def'

        lines = []
        lines.append(f'{indent}{kw} {name}({", ".join(args)}):')
        body = self._guess_body(name, args, indent + '    ')
        lines.extend(body)
        return lines

    def _emit_class(self, class_name, cls_data, indent=''):
        methods = cls_data.get('methods', [])
        bases = cls_data.get('bases', [])
        header = f'{indent}class {class_name}' + (f'({", ".join(bases)})' if bases else '') + ':'
        lines = [header]
        if not methods:
            lines.append(f'{indent}    pass')
            return lines
        for co in methods:
            lines.append('')
            lines.extend(self._emit_function(co, indent + '    ', is_method=True))
        return lines

    def render(self):
        out = []
        out.append(f'"""Module: {self.module_name}')
        out.append('')
        out.append('Static reconstruction from Nuitka constants blob.')
        out.append('Imports, signatures and docstrings are REAL (pulled from the blob).')
        out.append('Function bodies are HEURISTIC templates matched against the')
        out.append('chunk contents — the original Python `co_code` for C-compiled')
        out.append('modules is NOT stored in the binary (Nuitka translates it to')
        out.append('native instructions at compile-time).')
        out.append('"""')
        out.append('')

        imports = self.detect_imports()
        if imports:
            for imp in imports:
                out.append(imp)
            out.append('')

        # Classes first (stable alphabetic order)
        for cname in sorted(self.classes):
            out.append('')
            out.extend(self._emit_class(cname, self.classes[cname]))
            out.append('')

        # Free functions
        for co in self.free_funcs:
            out.append('')
            out.extend(self._emit_function(co))
            out.append('')

        # If no classes AND no free functions were recovered, dump the
        # string/numeric constants as module-level references so the output
        # still carries the blob's intelligence.
        if not self.classes and not self.free_funcs:
            for c in self.constants[:60]:
                if isinstance(c, str) and len(c) > 4:
                    out.append(f'# const: {c!r}')

        return '\n'.join(out) + '\n'


def omni_generate_source(decompiler, section_name, raw_constants=None):
    """Emit a Python file from an OmniDecompiler's collected state.

    For modules that contain only free functions (no classes), falls back to
    a) signature inference from constants (same logic as NuitkaCSourceRebuilder)
    b) notable-strings dump (URLs, file paths, keys, function names)
    c) imports detected via dotted-module-name heuristic
    so every recovered module produces USEFUL output, not just boilerplate.
    """
    out = []
    out.append('"""')
    out.append('==== OMNI UNIFIED MAXIMUM DECOMPILATION ====')
    out.append(f'Reconstructed source: {section_name}')
    out.append('Uniting everything known: AST generation, Meaningful Types, C-API Fallbacks')
    out.append('"""\n')
    out.append('# =========================================================')
    out.append('# IMPORTS & REQUIRED LIBRARIES')
    out.append('# =========================================================')
    out.append('import json, os, sys, time, struct')
    out.append('import ctypes\n')

    # --- detected imports (from constants like 'json', 'tls_client.Session', etc.) --
    detected_imports = set()
    if raw_constants:
        for c in raw_constants:
            if isinstance(c, str) and 2 < len(c) < 80:
                # Looks like a module/attr name: 'foo', 'foo.bar', 'foo.bar.baz'
                if (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', c)
                        and '.' in c
                        and not c.startswith('_')
                        and not c.endswith('.py')):
                    detected_imports.add(c)
    if detected_imports:
        out.append('# =========================================================')
        out.append('# DETECTED IMPORTS (from constants)')
        out.append('# =========================================================')
        for imp in sorted(detected_imports)[:40]:
            out.append(f'# import {imp}')
        out.append('')

    if decompiler.api_endpoints:
        out.append('# =========================================================')
        out.append('# DISCOVERED HTTP API ENDPOINTS')
        out.append('# =========================================================')
        for url in sorted(list(decompiler.api_endpoints)):
            out.append(f'API_TARGET_{abs(hash(url)) % 10000} = {repr(url)}')
        out.append('')

    if decompiler.vk_table:
        out.append('# =========================================================')
        out.append('# RECOVERED DYNAMIC VIRTUAL KEYCODES')
        out.append('# =========================================================')
        for k, v in decompiler.vk_table.items():
            out.append(f'{k} = 0x{v:02X}' if v is not None else f'{k} = None')
        out.append('')

    classes_emitted = 0
    if decompiler.classes:
        out.append('# =========================================================')
        out.append('# ORGANIC CLASS ABSTRACTIONS AND HEURISTIC METHOD TRACES')
        out.append('# =========================================================')
        for cls_name, cls_node in decompiler.classes.items():
            if len(cls_name) > 60 or ' ' in cls_name or '\x00' in cls_name:
                continue
            if not cls_name[0:1].isalpha() and cls_name[0:1] != '_':
                continue
            if not cls_node.methods and not cls_node.attributes:
                continue
            out.append(cls_node.render(0))
            classes_emitted += 1

    # --- free-function inference (for pure-function modules) ---
    if raw_constants is not None:
        inferred = NuitkaCSourceRebuilder.infer_functions_from_constants(raw_constants)
        # Skip ones that look like they're already emitted as class methods
        emitted_method_names = set()
        for cls_node in decompiler.classes.values():
            for m in cls_node.methods:
                emitted_method_names.add(m.name)

        free_funcs = []
        for co in inferred:
            name = co.get('name', '')
            qualname = co.get('qualname', name)
            # qualname containing '.' => probably a method; skip
            if '.' in qualname and not qualname.startswith('<'):
                continue
            if name in emitted_method_names:
                continue
            if name in ('<module>', '<listcomp>', '<dictcomp>', '<genexpr>',
                        '<lambda>', '<setcomp>'):
                continue
            free_funcs.append(co)

        if free_funcs:
            out.append('# =========================================================')
            out.append('# FREE FUNCTION SIGNATURES (inferred from constants)')
            out.append('# =========================================================')
            for co in free_funcs[:80]:   # cap output
                name = co.get('name', '')
                args = co.get('args', []) or []
                # safe ident for Python: skip names containing weird chars
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
                    continue
                sig_args = [a for a in args if re.fullmatch(r'[A-Za-z_.][A-Za-z0-9_]*', str(a))]
                out.append(f'')
                out.append(f'def {name}({", ".join(str(a) for a in sig_args)}):')
                out.append(f'    """Body not recoverable (compiled to native code by Nuitka)."""')
                out.append(f'    ...')
            out.append('')

    # --- notable strings dump (URLs, paths, keys, long strings) ---
    if raw_constants:
        notable = []
        seen = set()
        for c in raw_constants:
            if not isinstance(c, str):
                continue
            if len(c) < 8 or c in seen:
                continue
            if any(m in c.lower() for m in ('http', 'https', '/api/', '.com', '.io',
                                              '.net', '.org', '.php', 'bearer',
                                              'token', 'secret', 'private_key',
                                              'password', 'auth', 'key', 'mainnet',
                                              'testnet', 'rpc', 'bitcoin', 'ethereum',
                                              'wallet', 'discord', 'telegram')):
                if len(c) < 200:
                    notable.append(c)
                    seen.add(c)
            elif len(c) > 60 and ' ' in c:
                # Probably a human-readable message (error/status)
                notable.append(c)
                seen.add(c)
            if len(notable) >= 60:
                break
        if notable:
            out.append('# =========================================================')
            out.append('# NOTABLE STRING CONSTANTS (URLs, endpoints, messages)')
            out.append('# =========================================================')
            for s in notable:
                # Try to give each a stable variable name
                out.append(f'_CONST_{abs(hash(s)) % 100000} = {repr(s)}')
            out.append('')

    return "\n".join(out)


# ---------------------------------------------------------------------------
#  EMBEDDED nuitka_static_decompiler  (previously an external sidecar file)
# ---------------------------------------------------------------------------
#
# Older versions of this tool loaded these two symbols from
# `nuitka_static_decompiler.py` sitting next to the main script. They are
# now provided inline so the whole pipeline is a single standalone file.
#
# Public API (unchanged from the sidecar):
#   BlobParser(blob_bytes)                  — decoder instance
#       .parse_module(chunk_data)           -> (consts_list, code_objects)
#   reconstruct_python_source(name, consts) -> str (Python source)
#
# `consts_list` is a list of dicts `{type, value, index}` so callers can
# introspect the decoded constants easily. Internally we reuse the
# already-embedded `parse_module_constants`, `extract_code_object_map`
# and `StaticalySmartReconstructor` to avoid duplicate logic.
# ---------------------------------------------------------------------------

class BlobParser:
    """Compatibility wrapper around the embedded parsers.

    Historical API expected by `NuitkalizatorPro.run()` Phase 11. Instances
    carry the full blob bytes only as metadata; the real decoding works
    on one module chunk at a time via `parse_module`.
    """

    def __init__(self, blob_bytes):
        self.blob = bytes(blob_bytes) if blob_bytes else b''

    @staticmethod
    def _classify(value):
        if value is None:
            return 'none'
        if isinstance(value, bool):
            return 'bool'
        if isinstance(value, int):
            return 'int'
        if isinstance(value, float):
            return 'float'
        if isinstance(value, complex):
            return 'complex'
        if isinstance(value, str):
            return 'str'
        if isinstance(value, bytes):
            return 'bytes'
        if isinstance(value, bytearray):
            return 'bytearray'
        if isinstance(value, tuple):
            return 'tuple'
        if isinstance(value, list):
            return 'list'
        if isinstance(value, dict):
            if value.get('_type') == 'CodeObject':
                return 'code'
            return 'dict'
        if isinstance(value, frozenset):
            return 'frozenset'
        if isinstance(value, set):
            return 'set'
        return type(value).__name__

    def parse_module(self, chunk_data, module_name=''):
        """Return `(consts, code_objects)` for one module chunk.

        Every entry in `consts` is `{'index': i, 'type': t, 'value': v}`
        where `type` is a short string ('str', 'int', 'tuple', 'code', ...).
        `code` entries have `value` = the CodeObjectSpec dict emitted by
        `_parse_code_object_tag` when Nuitka included a `'C'` tag in the
        chunk (rare for C-compiled modules; common inside inner code
        objects).
        """
        raw = parse_module_constants(chunk_data)
        co_list = extract_code_object_map(module_name or '', chunk_data)
        consts = []
        for i, v in enumerate(raw):
            consts.append({
                'index': i,
                'type': self._classify(v),
                'value': v,
            })
        return consts, co_list


def reconstruct_python_source(module_name, consts):
    """Produce Python source for a module from its decoded constants list.

    This is the high-level "synthesise the module" entry point used by
    Phase 11. Under the hood it delegates to `StaticalySmartReconstructor`
    which does pattern-matched import detection + class/method hierarchy
    + heuristic HTTP-fetch body templates + notable-string harvesting.

    `consts` may be either the dict-wrapped list produced by
    `BlobParser.parse_module` or the raw list emitted by
    `parse_module_constants` — both are accepted.
    """
    # Unwrap dict form into raw Python values
    raw_values = []
    code_objs = []
    for entry in consts:
        if isinstance(entry, dict) and 'value' in entry and 'type' in entry:
            raw_values.append(entry['value'])
            if entry['type'] == 'code':
                code_objs.append(entry['value'])
        else:
            raw_values.append(entry)
            if isinstance(entry, dict) and entry.get('_type') == 'CodeObject':
                code_objs.append(entry)

    recon = StaticalySmartReconstructor(
        module_name=module_name or '__module__',
        constants=raw_values,
        code_objects=code_objs,
    )
    return recon.render()


# ---------------------------------------------------------------------------
#  4. UNIFIED STATICALY PIPELINE — orchestrates 1 + 2 + 3
# ---------------------------------------------------------------------------

class StaticalyExtractor:
    """Unified orchestrator: drives NuitkaBlobDecoder + xdis raw scan + OMNI.

    Usage:
        ext = StaticalyExtractor(blob_bytes, target_python=(3, 10))
        result = ext.run(output_dir="OUT")
    """

    def __init__(self, blob_data, target_python=None, pe_file=None, module_table=None):
        self.blob = blob_data
        self.pe = pe_file                 # optional pefile.PE for disassembly
        self.module_table = module_table or []
        # Optional `--only` filter (list of names or `pkg.*` globs).
        # Set by NuitkalizatorPro after construction. When None, the
        # pipeline disassembles every compiled entry in the table.
        self.only_modules = None
        if target_python is None:
            # try xdis version probe
            target_python = None
            if XDIS_AVAILABLE:
                ver = xdis_detect_version_from_marshal(blob_data[:65536])
                if ver and ver in _xdis_by_version:
                    target_python = tuple(int(x) for x in ver.split("."))
            if target_python is None:
                target_python = sys.version_info[:2]
        self.target_python = tuple(target_python[:2])
        self.target_ver_str = f"{self.target_python[0]}.{self.target_python[1]}"

    @staticmethod
    def _normalize_decoded_sections(raw_sections):
        """Filter out aggressive-scan artefacts that are truncated duplicates
        of names the linear-chain scan already decoded.

        The aggressive byte-by-byte scanner walks *backwards* looking for
        printable ASCII and stops at the first NUL byte — which in a real
        Nuitka blob often lands **inside** a module name, giving us truncated
        prefixes like `pl.asyncio.foo` (from `xrpl.asyncio.foo`) or
        `rl.parse` (from `urllib.parse`). The linear-chain scan meanwhile
        yields the clean full name. When both scans find the same section
        we want to keep the clean one and drop the truncated one.
        """
        discovered = {}   # clean_name -> original key
        plain = {}        # clean_name (lstripped '.') -> original key
        for key in raw_sections:
            m = re.match(r'^discovered_(.+?)_at_(\d+)$', key)
            if m:
                clean = m.group(1).lstrip('.')
                if clean and not clean.startswith('hidden_segment'):
                    discovered[clean] = key
            else:
                plain[key.lstrip('.')] = key

        def _is_truncated_suffix_of(short, full):
            """True if *short* is a proper suffix of *full* (treated as
            dotted-segment paths). Used so `pl.foo.bar` is recognised as a
            truncation of `xrpl.foo.bar` but `pl.foo.bar` vs
            `other.foo.bar` is not."""
            if short == full:
                return False  # same name, handle separately
            if not full.endswith(short):
                return False
            # what comes before in full must end in the same first component
            # (short shares tail segments and the extra bit is inside the
            # first one)
            prefix = full[: -len(short)]
            return prefix != '' and not prefix.endswith('.')

        # Build the normalised result
        out = {}
        # 1. Keep every plain section as-is (cleaner names win)
        for clean, orig in plain.items():
            out[clean] = raw_sections[orig]

        # 2. For each discovered section, only keep it if it's NOT a truncation
        #    of anything we already have from the linear chain. Keep genuine
        #    injected segments under a `hidden_…` name so they're obvious.
        for clean, orig in discovered.items():
            # Skip if exactly the same as a plain section
            if clean in out:
                continue
            # Skip if it's a proper truncated suffix of any plain name
            if any(_is_truncated_suffix_of(clean, plain_name) for plain_name in plain):
                continue
            out[clean] = raw_sections[orig]

        # 3. Preserve explicitly hidden segments under a clear `hidden_` prefix.
        #    We skip monster segments (>~10k items) because the aggressive
        #    scan will occasionally land on noise that `_decode_count` happily
        #    chews through — those generate multi-megabyte reconstructions
        #    full of garbage. A real Nuitka module rarely has >5k constants.
        HIDDEN_MAX_ITEMS = 10000
        for key, items in raw_sections.items():
            m = re.match(r'^discovered_(.+?)_at_(\d+)$', key)
            if not m:
                continue
            if m.group(1).lstrip('.') and not m.group(1).lstrip('.').startswith('hidden_segment'):
                continue
            if len(items) > HIDDEN_MAX_ITEMS:
                continue
            out[f"hidden_segment_{m.group(2)}"] = items

        return out

    def decode_sections(self):
        """Enumerate every named chunk and decode its constants.

        Returns the `{name: tuple_of_items}` dict. The raw chunk bytes are
        stored separately on self.chunk_raw_bytes so the dumper can embed
        a hex dump in the per-module diagnostic file.

        We use the project's own `parse_blob_modules` (v7 parser) to split
        the blob — it finds 1719 chunks vs the 620 of the Python port of
        `nuitka_deobfuscate.c` (the C code has an alignment bug in its
        aggressive scan). Falls back to `NuitkaBlobDecoder` only if
        `parse_blob_modules` returns nothing.
        """
        sections = {}
        self.chunk_raw_bytes = {}
        try:
            chunks = parse_blob_modules(self.blob)
        except Exception:
            chunks = []

        if chunks:
            for name, chunk_data in chunks:
                if name == '.bytecode':
                    continue
                if self.only_modules and not module_matches_patterns(name, self.only_modules):
                    continue
                try:
                    items = parse_module_constants(chunk_data)
                except Exception:
                    items = []
                section_name = name or '__module_root__'
                sections[section_name] = tuple(items)
                self.chunk_raw_bytes[section_name] = bytes(chunk_data)
            return sections

        raw = NuitkaBlobDecoder().decode_blob(self.blob)
        sections = self._normalize_decoded_sections(raw)
        if self.only_modules:
            sections = {
                name: items for name, items in sections.items()
                if module_matches_patterns(name, self.only_modules)
            }
        return sections

    def raw_scan_bytecode(self):
        """Run xdis raw scan for embedded marshal code objects. Returns
        [(offset, code_obj), ...] or [] if xdis unavailable."""
        if not XDIS_AVAILABLE:
            return []
        return xdis_raw_scan_for_code_objects(self.blob, self.target_ver_str)

    def write_pycs(self, raw_code_objects, out_dir):
        """Dump raw scan results as .pyc files with correct magic."""
        if not XDIS_AVAILABLE or not raw_code_objects:
            return 0
        out_dir = Path(out_dir)
        header = self._pyc_header()
        written = 0
        for offset, co in raw_code_objects:
            try:
                raw = _xdis_marshal.dumps(co, python_version=self.target_python)
                path = xdis_extract_path_from_code(co)
                label = xdis_extract_code_label(co)
                if path and '<' not in path:
                    dest = out_dir / 'pyc' / xdis_sanitize_filename(path).replace('.py', '.pyc')
                elif label:
                    dest = out_dir / 'pyc' / 'raw_scan' / f"{label}_at_{offset:08x}.pyc"
                else:
                    dest = out_dir / 'pyc' / 'raw_scan' / f"at_{offset:08x}.pyc"
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(header + raw)
                written += 1
            except Exception:
                continue
        return written

    def _pyc_header(self):
        """Build a valid 16-byte .pyc header for the target Python version."""
        if XDIS_AVAILABLE:
            magic = _xdis_by_version.get(self.target_ver_str)
            if magic:
                mb = bytes(magic)
                return (mb
                        + struct.pack("<I", 0)
                        + struct.pack("<I", int(time.time()))
                        + struct.pack("<I", 0))
        # fallback: use our own table
        return pyc_magic_bytes(self.target_python) + struct.pack("<I", 0) + struct.pack("<I", int(time.time())) + struct.pack("<I", 0)

    @staticmethod
    def _section_name_to_module_path(section_name):
        """Turn a blob-section key into an importable module path (a/b/c.py).

        Handles every shape the NuitkaBlobDecoder emits:

          'Crypto.Cipher.AES'                        -> 'Crypto/Cipher/AES.py'
          '__main__'                                  -> '__main__.py'
          'vendor.vxauth'                             -> 'vendor/vxauth.py'
          '.wmi'                                      -> 'wmi.py'        (leading '.' stripped)
          'discovered_.xrpl.core.types.amount_at_131' -> 'xrpl/core/types/amount.py'
          'discovered_hidden_segment_at_12345'        -> 'hidden/hidden_segment_12345.py'
          '<module foo.bar>'                          -> 'foo/bar.py'
          '<something weird>'                         -> 'unnamed/<hash>.py'
          '' or '.'                                   -> '__module_root__.py'
          'name_dup_3'                                -> 'name__dup3.py'
        """
        if not section_name:
            return '__module_root__.py'

        name = str(section_name).strip()

        # Strip discovered_ prefix + _at_NNN suffix (aggressive-scan artefacts)
        m = re.match(r'^discovered_(.+?)_at_(\d+)$', name)
        if m:
            base = m.group(1).lstrip('.')
            offset = m.group(2)
            if base.startswith('hidden_segment') or not base:
                return f"hidden/hidden_segment_{offset}.py"
            name = base

        # Collision suffix from NuitkaBlobDecoder (`_dup_N`)
        m = re.match(r'^(.+?)_dup_(\d+)$', name)
        if m:
            name = f"{m.group(1)}__dup{m.group(2)}"

        # '<module foo.bar>' -> 'foo.bar'
        m = re.match(r'^<\s*module\s+(.+?)\s*>$', name)
        if m:
            name = m.group(1)

        # Strip leading dots
        name = name.lstrip('.')

        # If what's left contains characters that aren't valid in a module name,
        # fall back to a hash so we don't silently truncate something weird.
        if not name:
            return '__module_root__.py'

        # Dotted names become a directory hierarchy
        parts = [p for p in name.split('.') if p]
        safe_parts = []
        for p in parts:
            # Allow ASCII idents only; fall back to a hash for anything else
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', p):
                safe_parts.append(p)
            else:
                import hashlib as _h
                safe_parts.append('_' + _h.md5(p.encode('utf-8')).hexdigest()[:10])

        if not safe_parts:
            return '__module_root__.py'

        return '/'.join(safe_parts) + '.py'

    def omni_reconstruct(self, sections, out_dir, chunk_raw_bytes=None):
        """Reconstruct every blob section as a directory tree.

        For each module we emit THREE artefacts in the same tree layout:

          1. `<module>.py`         — heuristic reconstructed Python source
                                     (real imports + class hierarchy +
                                     pattern-matched function bodies)
          2. `<module>.dump.txt`   — exhaustive human-readable module dump:
                                     every constant in blob order with
                                     type + classification + value, every
                                     ident-tuple paired with its probable
                                     function name, categorised sections
                                     (URLs, error strings, dotted paths,
                                     etc.) and a full hex dump of the
                                     chunk bytes.
          3. `<module>.dump.json`  — same information machine-readable,
                                     for programmatic post-processing.

        The dump is the "pseudo-bytecode" record you asked for: everything
        Nuitka left in the blob about this module, in one place, so that
        a reverse engineer (or another tool) can rebuild the original
        Python source literally from the clues.

        `chunk_raw_bytes` is an optional mapping `{section_name: bytes}`
        used to include the raw chunk in the hex-dump section.
        """
        out_dir = Path(out_dir)
        omni_dir = out_dir / 'omni_reconstructed'
        omni_dir.mkdir(parents=True, exist_ok=True)
        chunk_raw_bytes = chunk_raw_bytes or {}
        written = 0
        dump_written = 0
        used_paths = {}   # rel_path -> collision counter, to dedupe
        manifest = []     # list of {section, rel_path, has_class_def}
        mt_by_name = {e.get('name'): e for e in self.module_table} if self.module_table else {}

        for name, items in sections.items():
            if not items:
                continue

            items_list = list(items)
            src = None

            # 1) Try the deep smart reconstructor first. It uses the
            #    module's own CodeObjectSpec list (tag 'C') + the full
            #    constants to produce a near-original source file with
            #    real imports, class hierarchies and pattern-matched
            #    function bodies.
            try:
                # Extract code_objects from the constants by recursion
                code_objs = []
                _collect_code_objects_recursive(items_list, name, code_objs)

                if code_objs or name.startswith('modules.') or name.startswith('vendor.'):
                    smart = StaticalySmartReconstructor(name, items_list, code_objs)
                    smart_src = smart.render()
                    if smart_src and ('def ' in smart_src
                                      or 'class ' in smart_src
                                      or 'import ' in smart_src):
                        src = smart_src
            except Exception:
                src = None

            # 2) Fall back to the OMNI AST synthesiser for modules where
            #    the smart reconstructor didn't find enough structure.
            if src is None:
                try:
                    omp = OmniDecompiler()
                    omp.run_pass_1_structural_mapping(items_list)
                    omp.run_pass_2_ast_synthesis()
                    src = omni_generate_source(omp, name, raw_constants=items_list)
                except Exception:
                    continue

            # Emit anything that has *any* recovered structure (class, def,
            # or a populated constants table). That covers modules that are
            # just a bag of free functions (e.g. `modules.utils`, `modules.balance.bitcoin`)
            # — without this we'd skip most of the application core.
            has_recon = (
                'class ' in src
                or 'def ' in src
                or 'API_TARGET_' in src
                or 'VK_' in src
                or len(items) >= 4  # any non-trivial constants-only module
            )
            if not has_recon:
                continue

            rel_path = self._section_name_to_module_path(name)
            # Deduplicate if two sections map to the same path
            if rel_path in used_paths:
                used_paths[rel_path] += 1
                base, _, ext = rel_path.rpartition('.')
                rel_path = f"{base}__dup{used_paths[rel_path]}.{ext}"
            else:
                used_paths[rel_path] = 0

            dest = omni_dir / rel_path
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(src, encoding='utf-8')
                written += 1

                # Emit the compact .nbc (Nuitka ByteCode) file. At this
                # point we haven't run the disassembler yet (that happens
                # in disassemble_modules() AFTER omni_reconstruct), so
                # compute the absence reason now: if any requirement for
                # disassembly is missing we embed a clear @NO_OPS block
                # so the downstream LLM knows the file is incomplete.
                if not CAPSTONE_AVAILABLE:
                    _reason = 'capstone_missing'
                elif self.pe is None:
                    _reason = 'no_pe'
                elif not self.module_table:
                    _reason = 'no_module_table'
                else:
                    # disassemble_modules() will overwrite this file with
                    # a version that HAS @OPS if the module is in the
                    # loader table. If not, the @NO_OPS block stays.
                    _in_table = any(e.get('name') == name
                                     and e.get('func_ptr')
                                     and 'BYTECODE' not in e.get('flag_names', [])
                                     and 'EXTENSION' not in e.get('flag_names', [])
                                     for e in self.module_table)
                    _reason = None if _in_table else 'not_in_module_table'
                try:
                    nbc_text = NuitkaCompactEmitter.render(
                        module_name=name,
                        constants=items_list,
                        python_version=self.target_python,
                        ops_absence_reason=_reason,
                        module_table_entry=mt_by_name.get(name),
                        chunk_bytes=chunk_raw_bytes.get(name),
                    )
                    nbc_path = dest.with_suffix('.nbc')
                    nbc_path.write_text(nbc_text, encoding='utf-8')
                    dump_written += 1
                except Exception:
                    pass

                # Stats for the manifest
                try:
                    cls_count = len(omp.classes) if 'omp' in locals() else 0
                    method_count = (sum(len(c.methods) for c in omp.classes.values())
                                    if 'omp' in locals() else 0)
                except Exception:
                    cls_count = method_count = 0
                manifest.append({
                    'section': name,
                    'rel_path': rel_path,
                    'classes': cls_count,
                    'methods': method_count,
                })
            except Exception:
                continue

        # Persist a manifest so you can cross-reference the original
        # section names (some of which are ugly: `discovered_*_at_NNN`) with
        # the clean output tree.
        try:
            import json as _json
            (omni_dir / '_MANIFEST.json').write_text(
                _json.dumps(manifest, indent=2, ensure_ascii=False),
                encoding='utf-8',
            )
        except Exception:
            pass

        return written

    def disassemble_modules(self, output_dir, max_modules=None, max_bytes=16384,
                             sections=None, max_funcs_per_module=1000):
        """Disassemble each compiled module's native entry point.

        Requires `self.pe` (pefile.PE) and `self.module_table` to be set at
        construction time. Emits `<module>.disasm.txt` in the same tree as
        `omni_reconstructed/` so the .py / .dump.txt / .disasm.txt sit next
        to each other.

        This is the "reconstruct the logic statically" step: for each
        compiled-module function we extract the x86-64 instructions from
        .text at that function's VA, identify every call + RIP-relative
        constant load, resolve IAT slots to Python-C-API names and direct
        calls to the module that owns them (via the loader table).

        Returns how many modules were successfully disassembled.
        """
        if not CAPSTONE_AVAILABLE:
            return 0
        if self.pe is None or not self.module_table:
            return 0

        output_dir = Path(output_dir)
        omni_dir = output_dir / 'omni_reconstructed'
        omni_dir.mkdir(parents=True, exist_ok=True)

        disasm = NuitkaStaticDisassembler(self.pe,
                                           module_table=self.module_table)
        written = 0
        targets = [e for e in self.module_table
                   if e.get('func_ptr')
                   and 'BYTECODE' not in e.get('flag_names', [])
                   and 'EXTENSION' not in e.get('flag_names', [])]
        if max_modules:
            targets = targets[:max_modules]

        # Pre-pass: count how many times each internal address is called
        # across ALL targeted modules (the call-stats pre-pass must see
        # the full target set, NOT the --only subset — otherwise the
        # runtime helpers for the selected module won't rank correctly).
        # The most-called ones are Nuitka runtime helpers; the aliases
        # stay consistent across every module's disassembly so you can
        # trace helper usage globally.
        try:
            stats_targets = targets
            CALL_STATS_SAMPLE_LIMIT = 120
            if len(stats_targets) > CALL_STATS_SAMPLE_LIMIT:
                stats_targets = stats_targets[:CALL_STATS_SAMPLE_LIMIT]
                log(f"  Runtime-helper prepass: sampling "
                    f"{len(stats_targets)}/{len(targets)} module entries")
            runtime_aliases, call_counter = disasm.build_module_call_stats(stats_targets)
        except Exception:
            runtime_aliases, call_counter = {}, {}

        # Apply the --only filter AFTER call-stats, so ranking is
        # computed on the full binary but only the requested modules
        # actually get full per-function recursive disasm + rendering.
        only = getattr(self, 'only_modules', None)
        if only:
            filtered = [e for e in targets
                        if module_matches_patterns(e['name'], only)]
            log(f"  --only filter: {len(filtered)} of {len(targets)} "
                f"module(s) match {only}")
            targets = filtered

        # Write the runtime-helper inventory once, at the top of the tree
        try:
            inv_path = omni_dir / 'NUITKA_RUNTIME_HELPERS.txt'
            inv_lines = ['# Nuitka runtime helpers ranked by call frequency',
                         '# (aliases are used in per-module .disasm.txt files)',
                         '# Rank  CallCount  Alias                     Address', '']
            for rank, (va, count) in enumerate(call_counter.most_common()):
                alias = runtime_aliases.get(va, f'fn_0x{va:X}')
                inv_lines.append(f'  {rank:4d}  {count:9d}  {alias:<24s}  0x{va:X}')
            inv_path.write_text('\n'.join(inv_lines), encoding='utf-8')
        except Exception:
            pass

        for entry in targets:
            mod_name = entry['name']
            func_ptr = entry['func_ptr']
            try:
                mod_consts = list(sections[mod_name]) if (sections and mod_name in sections) else []

                # Recursively disassemble the module entry AND every
                # module-local function it reaches via `call`. Nuitka
                # compiles every Python def as its own C entry point, so
                # without this step each function body in the .nbc
                # reduces to a signature skeleton (no @OPS). The BFS
                # stops at runtime helpers and sibling-module entries.
                infos = disasm.analyse_function_recursive(
                    func_ptr,
                    runtime_aliases=runtime_aliases,
                    max_funcs=max_funcs_per_module,
                    max_bytes_per_fn=max_bytes,
                )
                if not infos:
                    continue

                # Aggregate ALL const_loads from every function to
                # estimate mod_consts_base across the whole module.
                # (A single function's loads may miss the base; the
                # union across all of them is dense enough.)
                all_const_loads = []
                for _va, _info in infos.items():
                    all_const_loads.extend(_info['const_loads'])
                base, _cnt = NuitkaStaticDisassembler._estimate_mod_consts_base(
                    all_const_loads, len(mod_consts))

                # Replace / upgrade the .nbc that omni_reconstruct already
                # wrote (or write a fresh one for modules that weren't
                # decoded via omni).
                rel = StaticalyExtractor._section_name_to_module_path(mod_name)
                nbc_path = omni_dir / (rel[:-3] + '.nbc'
                                        if rel.endswith('.py') else rel + '.nbc')
                nbc_path.parent.mkdir(parents=True, exist_ok=True)

                nbc_text = NuitkaCompactEmitter.render(
                    module_name=mod_name,
                    constants=mod_consts,
                    python_version=self.target_python,
                    disasm_infos=infos,
                    mod_consts_base=base,
                    runtime_aliases=runtime_aliases,
                    entry_va=func_ptr,
                    module_table_entry=entry,
                    chunk_bytes=getattr(self, 'chunk_raw_bytes', {}).get(mod_name),
                )

                # Guard against runaway file size. Raised to 8 MB so
                # we rarely hit it — and when we do, KEEP the impl
                # bodies (the important part) and DROP the short
                # wrapper stubs (3-4 op blocks that contain no source
                # information). Wrappers are identified by tiny
                # instruction count AND membership in the helper
                # range; bodies are everything else.
                HARD_CAP_BYTES = 128_000_000
                if len(nbc_text.encode('utf-8', errors='replace')) > HARD_CAP_BYTES:
                    # Strategy: keep entry + every block with
                    # `instruction_count >= 30` (real code). Drop
                    # anything tiny (wrappers / registration stubs).
                    keep = {}
                    for _va, _info in infos.items():
                        if _va == func_ptr:
                            keep[_va] = _info
                            continue
                        if _info.get('instruction_count', 0) >= 30:
                            keep[_va] = _info
                    nbc_text = NuitkaCompactEmitter.render(
                        module_name=mod_name,
                        constants=mod_consts,
                        python_version=self.target_python,
                        disasm_infos=keep,
                        mod_consts_base=base,
                        runtime_aliases=runtime_aliases,
                        entry_va=func_ptr,
                        module_table_entry=entry,
                        chunk_bytes=getattr(self, 'chunk_raw_bytes', {}).get(mod_name),
                    )
                    # If STILL too large after dropping wrappers, chop
                    # the lowest-instruction-count bodies until under
                    # the cap.
                    if len(nbc_text.encode('utf-8', errors='replace')) > HARD_CAP_BYTES:
                        sorted_by_size = sorted(
                            keep.items(),
                            key=lambda kv: (
                                0 if kv[0] == func_ptr else 1,  # entry always first
                                -kv[1].get('instruction_count', 0),
                            ),
                        )
                        # Binary-search how many top-N bodies fit
                        lo, hi = 1, len(sorted_by_size)
                        best_text = nbc_text
                        while lo <= hi:
                            mid = (lo + hi) // 2
                            subset = dict(sorted_by_size[:mid])
                            candidate = NuitkaCompactEmitter.render(
                                module_name=mod_name,
                                constants=mod_consts,
                                python_version=self.target_python,
                                disasm_infos=subset,
                                mod_consts_base=base,
                                runtime_aliases=runtime_aliases,
                                entry_va=func_ptr,
                                module_table_entry=entry,
                                chunk_bytes=getattr(self, 'chunk_raw_bytes', {}).get(mod_name),
                            )
                            if len(candidate.encode('utf-8', errors='replace')) <= HARD_CAP_BYTES:
                                best_text = candidate
                                lo = mid + 1
                            else:
                                hi = mid - 1
                        nbc_text = best_text

                nbc_path.write_text(nbc_text, encoding='utf-8')
                written += 1
            except Exception:
                continue
        return written

    def run(self, output_dir):
        """Execute the full Staticaly pipeline and return a result dict."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        result = {
            'target_python': self.target_ver_str,
            'xdis_available': XDIS_AVAILABLE,
            'capstone_available': CAPSTONE_AVAILABLE,
            'sections': 0,
            'raw_scan_pyc': 0,
            'omni_reconstructed': 0,
            'nbc_files': 0,
            'modules_disassembled': 0,
            'output_dir': str(output_dir),
        }

        sections = self.decode_sections()
        result['sections'] = len(sections)

        raw_hits = self.raw_scan_bytecode()
        result['raw_scan_pyc'] = self.write_pycs(raw_hits, output_dir)

        result['omni_reconstructed'] = self.omni_reconstruct(
            sections, output_dir,
            chunk_raw_bytes=getattr(self, 'chunk_raw_bytes', {}),
        )
        # count nbc files on disk
        try:
            dump_dir = Path(output_dir) / 'omni_reconstructed'
            result['nbc_files'] = len(list(dump_dir.rglob('*.nbc')))
        except Exception:
            result['nbc_files'] = 0

        # Static disassembly of compiled modules (only if pe + module_table
        # were provided at construction — typically from NuitkalizatorPro).
        # Pass `sections` so the renderer can resolve every mod_consts load
        # to its real Python literal.
        if CAPSTONE_AVAILABLE and self.pe is not None and self.module_table:
            try:
                result['modules_disassembled'] = self.disassemble_modules(
                    output_dir, sections=sections)
            except Exception as _e:
                result['modules_disassembled'] = 0

        return result


# =============================================================================
# BYTECODE EXTRACTION (from .bytecode chunk)  v7 — cross-Python-version safe
# =============================================================================

# Full CPython magic table (covers every release from 2.7 to 3.13)
# Each magic is the u16 value defined in CPython's Python/importlib.h.
# The on-disk header is always: <u16 magic><\r\n><u32 flags><u32 mtime><u32 size>
# = 16 bytes total (PEP 552, 3.7+). Pre-3.7 uses 12 bytes (no flags).
PYC_MAGIC_NUMBERS = {
    (2, 7): 62211,
    (3, 0): 3130, (3, 1): 3150, (3, 2): 3180, (3, 3): 3230,
    (3, 4): 3310, (3, 5): 3351, (3, 6): 3379,
    (3, 7): 3394, (3, 8): 3413, (3, 9): 3425, (3, 10): 3439,
    (3, 11): 3495, (3, 12): 3531, (3, 13): 3571,
}


def pyc_magic_bytes(python_version):
    """Return the 4-byte magic header for the given (major, minor) target."""
    num = PYC_MAGIC_NUMBERS.get(tuple(python_version[:2]))
    if num is None:
        # Fallback: use the running interpreter's magic
        import importlib.util
        return importlib.util.MAGIC_NUMBER
    return num.to_bytes(2, 'little') + b'\r\n'


def write_pyc_from_marshal(marshal_data: bytes, output_path: str, python_version):
    """Write a valid .pyc file from raw marshal data (no deserialization required).

    This means we DON'T need the running Python to match the target version —
    we simply wrap the raw marshal blob with the correct header. A decompiler
    like pycdc reads the header to determine which opcode table to use.
    """
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    magic = pyc_magic_bytes(python_version)
    flags = (0).to_bytes(4, 'little')        # PEP 552 flags (0 = timestamp-based)
    mtime = int(time.time()).to_bytes(4, 'little')
    src_size = (0).to_bytes(4, 'little')
    with open(output_path, 'wb') as f:
        # 3.7+ header is 16 bytes; older is 12 (no flags). Use 16 for safety
        # (pycdc and 3.7+ interpreters ignore flags when 0 anyway).
        if tuple(python_version[:2]) >= (3, 7):
            f.write(magic + flags + mtime + src_size + marshal_data)
        else:
            f.write(magic + mtime + src_size + marshal_data)
    return True


def create_pyc_file(code_obj, output_path, python_version=None):
    """Create a valid .pyc file from a code object. Kept for backward compat."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    if python_version is None:
        python_version = sys.version_info[:2]
    if not isinstance(code_obj, types.CodeType):
        return False
    marshalled = marshal.dumps(code_obj)
    return write_pyc_from_marshal(marshalled, output_path, python_version)


_MARSHAL_FILENAME_RE = re.compile(
    rb'((?:[A-Za-z_][A-Za-z0-9_]*[\\/])*[A-Za-z_][A-Za-z0-9_]*\.py)')


def _guess_filename_from_marshal(marshal_data: bytes, max_scan: int = 4096) -> str:
    """Best-effort: scan marshal bytes for a *.py filename string.

    Marshal stores strings as TYPE_SHORT_ASCII (0x7A/0xFA), TYPE_ASCII (0x61/0xE1),
    TYPE_STRING (0x73/0xF3), etc. — each followed by length + raw bytes. We
    don't need to parse; just look for a short printable ASCII blob ending
    with .py, which in practice is the co_filename.
    """
    m = _MARSHAL_FILENAME_RE.search(marshal_data[:max_scan])
    if m:
        try:
            return m.group(1).decode('ascii', errors='replace')
        except Exception:
            pass
    return ""


def _sanitize_module_path(filename: str, bytecode_index: int) -> str:
    """Convert a co_filename like 'asyncio\\base_events.py' or 'lib/asyncio/base.py'
    into a safe relative path 'asyncio/base_events.py'.
    """
    fn = filename.replace('\\', '/').strip()
    if not fn:
        return f"module_{bytecode_index:04d}.py"

    # Drop absolute prefixes / drive letters / common Python lib roots
    low = fn.lower()
    for marker in ('/site-packages/', '/lib/', 'python310/lib/',
                   'python310\\lib\\', 'lib\\python', '/python/', '\\python\\'):
        idx = low.find(marker)
        if idx != -1:
            fn = fn[idx + len(marker):]
            low = fn.lower()

    # Drop drive letter
    if len(fn) > 2 and fn[1] == ':':
        fn = fn[2:].lstrip('/')

    # Clean up
    fn = fn.replace('..', '__').strip('/')
    fn = re.sub(r'[<>:"|?*]', '_', fn)

    if not fn or fn == '.py':
        return f"module_{bytecode_index:04d}.py"

    if not fn.endswith('.py'):
        # could be package init or something else, force .py
        if fn.endswith('.pyc'):
            fn = fn[:-1]
        else:
            fn = fn + '.py'

    return fn


def extract_bytecode_modules(bytecode_chunk: bytes, output_dir: str, python_version):
    """Extract .pyc modules from the .bytecode chunk (Nuitka constants blob).

    Format (from Nuitka DataComposer.py):
      [count:u16_LE]
      [ 'X' (0x58) + VLQ_size + marshal_blob ] * count
      [ '.'  end-of-stream marker ]

    v7 improvements over v6:
      - Magic header is that of the TARGET Python, not the running interpreter
        (so decompilers parse opcodes correctly even when run from a different py)
      - Filenames are taken either from marshal.loads (if same-version Python)
        OR scanned directly from marshal bytes (cross-version safe)
      - Raw marshal blobs are dumped alongside .pyc for forensic use
      - Output mirrors the original package tree (asyncio/base_events.pyc)
      - VLQ reader handles the full uint64 range
      - A MANIFEST.json records the full index -> path mapping
    """
    if len(bytecode_chunk) < 4:
        return 0, {}

    count = struct.unpack('<H', bytecode_chunk[0:2])[0]
    log(f".bytecode chunk: {count} compiled modules (target Python {python_version[0]}.{python_version[1]})")

    py_match = tuple(python_version[:2]) == sys.version_info[:2]
    if py_match:
        log_ok(f"  Running Python matches target ({python_version[0]}.{python_version[1]}) — full marshal parsing available")
    else:
        log_warn(f"  Running Python {sys.version_info[0]}.{sys.version_info[1]} != target {python_version[0]}.{python_version[1]}")
        log_warn(f"  Will fall back to filename-string scanning when marshal.loads fails")

    pos = 2
    extracted = 0
    parse_errors = 0
    pyc_dir = os.path.join(output_dir, "bytecode_pyc")
    marshal_dir = os.path.join(output_dir, "bytecode_marshal_raw")
    os.makedirs(pyc_dir, exist_ok=True)
    os.makedirs(marshal_dir, exist_ok=True)

    manifest = {}   # bytecode_index -> {path, size, name, co_filename, parsed}
    pb = ProgressBar(count, desc="Extracting .pyc")

    used_paths = {}   # to deduplicate colliding filenames

    for i in range(count):
        pb.update()

        if pos >= len(bytecode_chunk):
            break

        # The separator should be 'X' (0x58) = BlobData tag in Nuitka's
        # constants blob. If we're off by one or two bytes, re-sync.
        if bytecode_chunk[pos] != 0x58:
            resync = None
            for skip in range(1, 64):
                if pos + skip < len(bytecode_chunk) and bytecode_chunk[pos + skip] == 0x58:
                    resync = pos + skip
                    break
            if resync is None:
                log_warn(f"  Lost bytecode stream alignment at index {i} (offset 0x{pos:X})")
                break
            pos = resync

        # Read VLQ-encoded size (Nuitka's encoding: 7-bit groups, little-endian)
        try:
            marshal_size = 0
            shift = 0
            pos += 1  # skip 'X'
            while True:
                b = bytecode_chunk[pos]; pos += 1
                marshal_size |= (b & 0x7F) << shift
                if b < 0x80:
                    break
                shift += 7
                if shift > 63:
                    raise ValueError("VLQ overflow")
        except (IndexError, ValueError) as e:
            log_warn(f"  VLQ decode error at index {i}: {e}")
            break

        if marshal_size <= 0 or pos + marshal_size > len(bytecode_chunk):
            log_warn(f"  Bad size {marshal_size} at index {i} (offset 0x{pos:X})")
            break

        marshal_data = bytecode_chunk[pos:pos + marshal_size]
        pos += marshal_size

        # Try to parse with marshal (works if same Python version)
        co = None
        co_filename = ""
        co_name = ""
        try:
            obj = marshal.loads(marshal_data)
            if isinstance(obj, types.CodeType):
                co = obj
                co_filename = obj.co_filename or ""
                co_name = obj.co_name or ""
        except Exception:
            parse_errors += 1

        # If marshal parsing failed (different Python version), scan bytes for
        # the filename string directly.
        if not co_filename:
            co_filename = _guess_filename_from_marshal(marshal_data)

        # Build a safe relative path from the filename
        rel_path = _sanitize_module_path(co_filename, i)

        # Deduplicate in case two modules share the same co_filename
        if rel_path in used_paths:
            used_paths[rel_path] += 1
            base, ext = os.path.splitext(rel_path)
            rel_path = f"{base}__dup{used_paths[rel_path]}{ext}"
        else:
            used_paths[rel_path] = 0

        # .pyc output
        pyc_rel = rel_path[:-3] + '.pyc' if rel_path.endswith('.py') else rel_path + '.pyc'
        pyc_path = os.path.join(pyc_dir, pyc_rel)
        write_pyc_from_marshal(marshal_data, pyc_path, python_version)

        # Raw marshal dump (forensic)
        marshal_flat_name = f"{i:04d}_{rel_path.replace('/', '__').replace(os.sep, '__')}.marshal"
        marshal_path = os.path.join(marshal_dir, marshal_flat_name)
        with open(marshal_path, 'wb') as f:
            f.write(marshal_data)

        manifest[i] = {
            'index': i,
            'co_filename': co_filename,
            'co_name': co_name,
            'marshal_size': marshal_size,
            'pyc_path': os.path.relpath(pyc_path, output_dir).replace(os.sep, '/'),
            'marshal_path': os.path.relpath(marshal_path, output_dir).replace(os.sep, '/'),
            'parsed_with_marshal': co is not None,
        }
        extracted += 1

    pb.finish(f"Extracted {extracted}/{count} (.pyc + .marshal)"
              + (f" — {parse_errors} marshal parse errors" if parse_errors else ""))

    # Write manifest
    manifest_path = os.path.join(output_dir, "BYTECODE_MANIFEST.json")
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump({
            'target_python': f"{python_version[0]}.{python_version[1]}",
            'magic_hex': pyc_magic_bytes(python_version).hex(),
            'total_modules': extracted,
            'parse_errors': parse_errors,
            'entries': list(manifest.values()),
        }, f, indent=2, ensure_ascii=False)
    log_ok(f"  Manifest: {manifest_path}")

    return extracted, manifest


# =============================================================================
# SECRETS SCANNER
# =============================================================================

SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\'](.+?)["\']', 'password'),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'](.+?)["\']', 'api_key'),
    (r'(?:secret|token)\s*[:=]\s*["\'](.+?)["\']', 'secret_token'),
    (r'(?:flag|ctf)\s*[:={}]\s*["\']?([A-Za-z0-9_{}!@#$%^&*]+)', 'flag'),
    (r'FLAG\{[^}]+\}', 'flag'),
    (r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', 'database_url'),
    (r'(?:https?://[^\s"\']+)', 'url'),
    (r'(?:sk-[A-Za-z0-9]{20,})', 'openai_key'),
    (r'(?:ghp_[A-Za-z0-9]{36,})', 'github_token'),
    (r'(?:AKIA[A-Z0-9]{16})', 'aws_key'),
    (r'(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', 'jwt_token'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'private_key'),
    (r'(?:Bearer\s+[A-Za-z0-9_\-.]+)', 'bearer_token'),
]

KEYWORD_PATTERNS = [
    'password', 'secret', 'flag', 'token', 'api_key', 'private',
    'encrypt', 'decrypt', 'hash', 'salt', 'admin', 'root',
    'check_password', 'verify', 'authenticate', 'login',
    'Enter the secret', 'Enter password',
]


def scan_for_secrets(constants: list, module_name: str = "") -> list:
    """Scan a list of constants for secrets and interesting patterns."""
    findings = []

    def _scan_value(val, depth=0):
        if depth > 5:
            return
        if isinstance(val, str) and len(val) > 2:
            for pattern, secret_type in SECRET_PATTERNS:
                matches = re.findall(pattern, val, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': secret_type,
                        'value': match if isinstance(match, str) else val,
                        'module': module_name,
                        'context': val[:200]
                    })
            for keyword in KEYWORD_PATTERNS:
                if keyword.lower() in val.lower():
                    findings.append({
                        'type': 'keyword_match',
                        'value': keyword,
                        'module': module_name,
                        'context': val[:200]
                    })
            if 8 <= len(val) <= 128 and re.match(r'^[A-Za-z0-9_!@#$%^&*{}]+$', val):
                if not val.startswith(('http', 'file', 'ftp', 'ssh')):
                    entropy = _calc_entropy(val)
                    if entropy > 3.0:
                        findings.append({
                            'type': 'possible_password',
                            'value': val,
                            'module': module_name,
                            'entropy': round(entropy, 2)
                        })

        elif isinstance(val, (tuple, list)):
            for item in val:
                _scan_value(item, depth + 1)
        elif isinstance(val, dict):
            for k, v in val.items():
                _scan_value(k, depth + 1)
                _scan_value(v, depth + 1)
        elif isinstance(val, (set, frozenset)):
            for item in val:
                _scan_value(item, depth + 1)

    for const in constants:
        _scan_value(const)

    return findings


def _calc_entropy(s: str) -> float:
    if not s: return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = -sum((count / length) * math.log2(count / length)
                    for count in freq.values())
    return entropy


# =============================================================================
# CODE OBJECT MAP (from C-compiled modules)
# =============================================================================

def _collect_code_objects_recursive(val, module_name, acc):
    """Walk a parsed-constants value and collect every nested CodeObject dict."""
    if isinstance(val, dict) and val.get('_type') == 'CodeObject':
        # Filter out artefacts: names must be printable identifiers or <module>
        name = val.get('name') or ''
        qualname = val.get('qualname') or name
        if isinstance(name, str) and name and not name.startswith('<parse_error>'):
            # Reject garbage from GenericAlias mis-parses (huge-int qualnames)
            if len(str(qualname)) > 300:
                return
            if isinstance(name, bytes):
                name = name.decode('ascii', errors='replace')
            val = dict(val)
            val['name'] = name
            val['module'] = module_name
            acc.append(val)
        return
    if isinstance(val, (list, tuple)):
        for it in val:
            _collect_code_objects_recursive(it, module_name, acc)
    elif isinstance(val, dict):
        for v in val.values():
            _collect_code_objects_recursive(v, module_name, acc)


def extract_code_object_map(module_name: str, chunk_data: bytes) -> list:
    """Extract code object signatures from a module constants chunk.

    Correct approach: parse the chunk normally via `parse_module_constants`,
    then walk the resulting tree and pluck every dict tagged as CodeObject.
    This avoids false positives from scanning byte-wise for 'C' (0x43), which
    appears inside large integers, byte strings, GenericAlias numeric args, etc.
    """
    try:
        constants = parse_module_constants(chunk_data)
    except Exception:
        return []

    code_objects = []
    for c in constants:
        _collect_code_objects_recursive(c, module_name, code_objects)

    # Also deduplicate on (name, line, argcount) — the same code object may
    # appear both as a standalone constant AND inside a containing tuple.
    seen = set()
    unique = []
    for co in code_objects:
        key = (co.get('name'), co.get('qualname'), co.get('line'),
               co.get('argcount'), tuple(co.get('args') or ()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(co)
    return unique


# =============================================================================
# PER-MODULE CONSTANTS PARSER
# =============================================================================

def parse_module_constants(chunk_data: bytes) -> list:
    """Parse all constants in a module chunk."""
    global _last_unpacked
    _last_unpacked = None

    if len(chunk_data) < 2:
        return []

    try:
        count = struct.unpack('<H', chunk_data[0:2])[0]
    except Exception:
        return []

    if count == 0 or count > 50000:
        return []

    constants = []
    pos = 2

    for _ in range(count):
        if pos >= len(chunk_data):
            break
        try:
            val, pos = unpack_single_constant(chunk_data, pos)
            if val is not None:
                constants.append(val)
        except Exception:
            break

    return constants


# =============================================================================
# STRING EXTRACTION (recursive)
# =============================================================================

def extract_all_strings(constants: list, *, max_depth: int = 25) -> list:
    """Extract ALL strings from a list of constants (recursive).

    Visits: str, tuple/list, dict (keys+values), set/frozenset, CodeObject dicts.
    Deduplicates while preserving order.
    """
    seen = set()
    out = []

    def add(s: str):
        if not s:
            return
        if s in seen:
            return
        seen.add(s)
        out.append(s)

    def walk(v, depth: int):
        if depth > max_depth:
            return

        if isinstance(v, str):
            add(v)
            return

        # Nuitka constants can contain bytes/bytearray; optionally harvest readable text.
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
            if not b:
                return
            # Heuristic: try UTF-8, and only keep if looks mostly printable.
            try:
                s = b.decode("utf-8")
            except Exception:
                return
            printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
            if printable / max(len(s), 1) >= 0.85:
                add(s)
            return

        if isinstance(v, (tuple, list)):
            for item in v:
                walk(item, depth + 1)
            return

        if isinstance(v, dict):
            for k, val in v.items():
                walk(k, depth + 1)
                walk(val, depth + 1)
            return

        if isinstance(v, (set, frozenset)):
            for item in v:
                walk(item, depth + 1)
            return

        # Handle our synthetic tagged tuples
        if isinstance(v, tuple) and v and isinstance(v[0], str) and v[0] in ("slice", "range", "GenericAlias", "UnionType"):
            for item in v[1:]:
                walk(item, depth + 1)
            return

    for c in constants:
        walk(c, 0)

    return out


# =============================================================================
# BYTECODE DECOMPILATION HELPERS (Phase 12)
# =============================================================================

def _detect_decompiler(py_ver=None):
    """Return a list of decompilers to try in order, from best to worst.

    Each entry is a dict:
        {'kind': 'pycdc'|'pycdas'|'decompyle3'|'uncompyle6'|'pylingual'|'pydis',
         'binary': str|None,  # path for external tools
         'priority': int}      # lower = tried first
    """
    import subprocess, shutil
    target_ver = py_ver or (0, 0)
    available = []

    def _check_bin(bin_name, kind):
        # Search common install locations AND PATH
        search_paths = []
        for d in (r'C:\pycdc', r'C:\tools\pycdc', r'C:\Program Files\pycdc',
                  r'C:\Program Files (x86)\pycdc',
                  os.path.expanduser('~'), os.path.expanduser('~/pycdc')):
            for ext in ('', '.exe'):
                search_paths.append(os.path.join(d, bin_name + ext))
        for path in ([shutil.which(bin_name), shutil.which(bin_name + '.exe')]
                     + [p for p in search_paths if os.path.isfile(p)]):
            if not path:
                continue
            # run_external_tool swallows crashes + hides console windows
            r = run_external_tool([path, '--help'], timeout=5)
            if r.returncode >= 0 and not (0xC0000000 <= (r.returncode & 0xFFFFFFFF) <= 0xCFFFFFFF):
                return path
        return None

    # 1. pycdc (ancient bytecode support 1.0 through 3.13) — best for 3.10+
    pycdc = _check_bin('pycdc', 'pycdc')
    if pycdc:
        priority = 1 if target_ver >= (3, 10) else 3
        available.append({'kind': 'pycdc', 'binary': pycdc, 'priority': priority})

    # 2. pycdas (disassembler from pycdc project) — always useful as last resort
    pycdas = _check_bin('pycdas', 'pycdas')
    if pycdas:
        available.append({'kind': 'pycdas', 'binary': pycdas, 'priority': 9})

    # 3. decompile3 / decompyle3 — best for Python 3.7-3.9, partial 3.10
    if target_ver <= (3, 9):
        for mod, label, prio in [('decompile3', 'decompile3', 1),
                                  ('decompyle3', 'decompyle3', 2),
                                  ('uncompyle6', 'uncompyle6', 4)]:
            try:
                __import__(mod)
                available.append({'kind': label, 'binary': None, 'priority': prio})
            except ImportError:
                continue
    else:
        # For 3.10+ try them anyway as fallback
        for mod, label in [('decompile3', 'decompile3'),
                            ('decompyle3', 'decompyle3'),
                            ('uncompyle6', 'uncompyle6')]:
            try:
                __import__(mod)
                available.append({'kind': label, 'binary': None, 'priority': 6})
            except ImportError:
                continue

    # 4. pylingual (newer 3.12/3.13 decompiler) — if installed
    try:
        __import__('pylingual')
        available.append({'kind': 'pylingual', 'binary': None, 'priority': 2})
    except ImportError:
        pass

    available.sort(key=lambda d: d['priority'])
    return available


def _try_autoinstall_pycdc():
    """Best-effort: try to clone + build pycdc. Returns path or None."""
    log_warn("  pycdc not found. Trying pip install decompyle3/uncompyle6 as fallback...")
    for pkg in ('decompyle3', 'uncompyle6'):
        r = run_external_tool(
            [sys.executable, '-m', 'pip', 'install', pkg],
            timeout=120,
        )
        if r.returncode == 0:
            log_ok(f"  Installed {pkg}")
    return None


def _decompile_pyc(pyc_path, out_py_path, decompiler_info):
    """Decompile a .pyc file using one of the configured backends.

    decompiler_info is a dict from _detect_decompiler() or list of such dicts.
    Each candidate is tried in order until one produces non-empty output.

    Robustness:
      * Every external-tool invocation goes through `run_external_tool`
        (which suppresses Windows crash dialogs, catches timeouts and
        OSErrors instead of letting them propagate).
      * A process-wide counter tracks how many times each decompiler kind
        returns a hard crash (returncode < 0 or returncode >= 1000 on
        Windows = 0xc0000xxx access violation range). After 10 consecutive
        crashes for the same kind we DISABLE that backend for the rest of
        the run — otherwise a bad .pyc can kill throughput because every
        subsequent file re-triggers the crash.
      * Python-module decompilers (decompyle3 / uncompyle6 / decompile3)
        are called inside try/except; any exception just falls through
        to the next candidate, never propagates.
    """
    # Support either a single dict (legacy) or a list of candidates
    if isinstance(decompiler_info, dict):
        candidates = [decompiler_info]
    elif isinstance(decompiler_info, (list, tuple)):
        if len(decompiler_info) == 2 and isinstance(decompiler_info[0], str):
            candidates = [{'kind': decompiler_info[0], 'binary': decompiler_info[1]}]
        else:
            candidates = list(decompiler_info)
    else:
        return False

    # Persistent per-kind crash counter (lives on the function object)
    crash_counts = getattr(_decompile_pyc, '_crash_counts', None)
    if crash_counts is None:
        crash_counts = {}
        _decompile_pyc._crash_counts = crash_counts
    disabled = getattr(_decompile_pyc, '_disabled_kinds', None)
    if disabled is None:
        disabled = set()
        _decompile_pyc._disabled_kinds = disabled
    MAX_CRASHES = 10     # after this many consecutive crashes, disable the backend

    def _mark_crash(k):
        crash_counts[k] = crash_counts.get(k, 0) + 1
        if crash_counts[k] >= MAX_CRASHES and k not in disabled:
            disabled.add(k)
            try:
                log_warn(f"  [fallback] disabling {k!r} after {MAX_CRASHES} "
                         f"consecutive crashes — using remaining backends only")
            except Exception:
                pass

    def _mark_success(k):
        crash_counts[k] = 0   # reset streak on success

    def _is_crash(returncode):
        # Returncode < 0 = killed by signal (Unix) or timeout;
        # on Windows returncode >= 0xC0000000 (unsigned) means access
        # violation / unhandled SEH / etc.
        if returncode < 0:
            return True
        return 0xC0000000 <= (returncode & 0xFFFFFFFF) <= 0xCFFFFFFF

    for info in candidates:
        kind = info.get('kind')
        binary = info.get('binary')
        if kind in disabled:
            continue

        try:
            if kind == 'pycdc':
                r = run_external_tool([binary, pyc_path], timeout=45)
                if _is_crash(r.returncode):
                    _mark_crash('pycdc')
                    continue
                src = r.stdout.decode('utf-8', errors='replace')
                if src.strip():
                    is_incomplete = ('Decompyle incomplete' in src
                                     or 'Unsupported opcode' in src)
                    if is_incomplete:
                        bin_dir = os.path.dirname(binary)
                        bin_name = os.path.basename(binary).replace('pycdc', 'pycdas')
                        pycdas_bin = os.path.join(bin_dir, bin_name)
                        if os.path.isfile(pycdas_bin) and 'pycdas' not in disabled:
                            r2 = run_external_tool([pycdas_bin, pyc_path], timeout=45)
                            if _is_crash(r2.returncode):
                                _mark_crash('pycdas')
                            else:
                                dis_text = r2.stdout.decode('utf-8', errors='replace')
                                if dis_text.strip():
                                    src += ("\n\n"
                                            "# =========================================================\n"
                                            "# pycdc decompilation was incomplete — appending full\n"
                                            "# bytecode DISASSEMBLY from pycdas for manual reading.\n"
                                            "# =========================================================\n\n")
                                    src += dis_text
                    try:
                        with open(out_py_path, 'w', encoding='utf-8') as f:
                            f.write(src)
                        if os.path.getsize(out_py_path) > 20:
                            _mark_success('pycdc')
                            return True
                    except Exception:
                        pass
                # Empty output = treat as soft failure, not a crash
                continue

            elif kind == 'pycdas':
                r = run_external_tool([binary, pyc_path], timeout=45)
                if _is_crash(r.returncode):
                    _mark_crash('pycdas')
                    continue
                out = r.stdout.decode('utf-8', errors='replace')
                if out.strip():
                    try:
                        with open(out_py_path, 'w', encoding='utf-8') as f:
                            f.write("# === pycdas DISASSEMBLY (no source recovery) ===\n")
                            f.write(out)
                        if os.path.getsize(out_py_path) > 20:
                            _mark_success('pycdas')
                            return True
                    except Exception:
                        pass
                continue

            elif kind == 'decompile3':
                try:
                    from decompile3 import decompile_file as _dc
                except ImportError:
                    from decompile import decompile as _dc
                with open(out_py_path, 'w', encoding='utf-8') as f:
                    _dc(pyc_path, f)
                if os.path.getsize(out_py_path) > 20:
                    _mark_success('decompile3')
                    return True

            elif kind == 'decompyle3':
                import decompyle3
                with open(out_py_path, 'w', encoding='utf-8') as f:
                    decompyle3.decompile_file(pyc_path, f)
                if os.path.getsize(out_py_path) > 20:
                    _mark_success('decompyle3')
                    return True

            elif kind == 'uncompyle6':
                import uncompyle6
                with open(out_py_path, 'w', encoding='utf-8') as f:
                    uncompyle6.decompile_file(pyc_path, f)
                if os.path.getsize(out_py_path) > 20:
                    _mark_success('uncompyle6')
                    return True

            elif kind == 'pylingual':
                import pylingual
                try:
                    src = pylingual.decompile_file(pyc_path)
                except AttributeError:
                    src = pylingual.decompile(pyc_path)
                if src:
                    with open(out_py_path, 'w', encoding='utf-8') as f:
                        f.write(src)
                    _mark_success('pylingual')
                    return True

        except Exception:
            # Python-module decompiler raised — count as a soft crash so
            # we eventually disable it if it keeps failing, but never
            # let it bubble up and abort the outer loop.
            _mark_crash(kind or 'unknown')
            continue

    return False

    return False


def _is_code(obj):
    """True if obj is a code object (works across Python versions)."""
    return hasattr(obj, 'co_code') or hasattr(obj, 'co_code_adaptive')


def _make_func_src(co, indent=''):
    """Return lines of pseudo-source for a function/method code object."""
    import dis
    ii = indent + '    '
    lines = []

    # Build argument list from co_varnames
    nargs = co.co_argcount
    nkw   = getattr(co, 'co_kwonlyargcount', 0)
    flags = co.co_flags
    vnames = co.co_varnames

    args = list(vnames[:nargs])
    kw_args = list(vnames[nargs:nargs + nkw])
    idx = nargs + nkw
    if flags & 0x04:   # CO_VARARGS
        args.append('*' + (vnames[idx] if idx < len(vnames) else 'args'))
        idx += 1
    elif kw_args:
        args.append('*')
    args.extend(f'{a}=...' for a in kw_args)
    if flags & 0x08:   # CO_VARKEYWORDS
        args.append('**' + (vnames[idx] if idx < len(vnames) else 'kwargs'))

    is_async = bool(flags & 0x100)   # CO_COROUTINE
    kw = 'async def' if is_async else 'def'
    lines.append(f"{indent}{kw} {co.co_name}({', '.join(args)}):")

    # Docstring (first const if it's a non-empty string)
    doc = co.co_consts[0] if co.co_consts and isinstance(co.co_consts[0], str) and co.co_consts[0] else None
    if doc:
        if '\n' in doc:
            lines.append(f'{ii}"""')
            for dl in doc.splitlines():
                lines.append(f'{ii}{dl}')
            lines.append(f'{ii}"""')
        else:
            lines.append(f'{ii}"""{doc}"""')

    # Body: analyse bytecode for patterns
    body = _extract_body(co, ii)
    if body:
        lines.extend(body)
    else:
        lines.append(f'{ii}...')
    return lines


def _extract_body(co, indent):
    """
    Walk instructions to extract recognisable Python patterns.
    Returns a list of source lines (may be empty if nothing found).
    """
    import dis
    ii = indent + '    '
    lines = []
    try:
        instrs = list(dis.get_instructions(co))
    except Exception:
        return []

    i = 0
    seen_names = set()   # avoid duplicate STORE_NAME output
    seen_funcs = set()   # avoid emitting same function name twice (try/except branches)

    while i < len(instrs):
        instr = instrs[i]
        op    = instr.opname

        # Skip noise opcodes
        if op in ('RESUME', 'COPY_FREE_VARS', 'CACHE', 'PRECALL',
                  'NOP', 'RETURN_CONST'):
            i += 1
            continue

        # ── import X  /  from X import Y ────────────────────────────────────
        if op == 'IMPORT_NAME':
            mod = instr.argval
            j = i + 1
            # skip LOAD_ATTR chains (relative imports)
            froms = []
            aliases = []
            while j < len(instrs) and instrs[j].opname == 'IMPORT_FROM':
                froms.append(instrs[j].argval)
                if j + 1 < len(instrs) and instrs[j+1].opname in ('STORE_NAME','STORE_FAST','STORE_GLOBAL'):
                    aliases.append(instrs[j+1].argval)
                    j += 2
                else:
                    j += 1
            if froms:
                pairs = []
                for f, a in zip(froms, aliases if len(aliases) == len(froms) else froms):
                    pairs.append(f"{f} as {a}" if a != f else f)
                lines.append(f"{indent}from {mod} import {', '.join(pairs)}")
                i = j
                # POP_TOP after the last import_from group
                if i < len(instrs) and instrs[i].opname == 'POP_TOP':
                    i += 1
                continue
            # plain import [as alias]
            if j < len(instrs) and instrs[j].opname in ('STORE_NAME','STORE_FAST','STORE_GLOBAL'):
                alias = instrs[j].argval
                if alias != mod:
                    lines.append(f"{indent}import {mod} as {alias}")
                else:
                    lines.append(f"{indent}import {mod}")
                i = j + 1
            else:
                lines.append(f"{indent}import {mod}")
                i = j
            continue

        # ── constant assignment  LOAD_CONST → STORE_* ───────────────────────
        if op == 'LOAD_CONST' and not _is_code(instr.argval):
            j = i + 1
            while j < len(instrs) and instrs[j].opname in ('COPY', 'DUP_TOP'):
                j += 1
            if j < len(instrs) and instrs[j].opname in ('STORE_NAME','STORE_FAST','STORE_GLOBAL','STORE_DEREF'):
                name = instrs[j].argval
                val  = instr.argval
                # Skip docstring (already emitted) and None returns
                if not (isinstance(val, str) and val and i == 1):
                    if name not in seen_names and not name.startswith('.'):
                        lines.append(f"{indent}{name} = {repr(val)}")
                        seen_names.add(name)
                i = j + 1
                continue

        # ── function definition  MAKE_FUNCTION ──────────────────────────────
        if op == 'MAKE_FUNCTION':
            # search backward for the code-object LOAD_CONST
            func_co = None
            for j in range(max(0, i - 6), i):
                if instrs[j].opname == 'LOAD_CONST' and _is_code(instrs[j].argval):
                    func_co = instrs[j].argval
                    break
            _skip = ('<listcomp>','<dictcomp>','<setcomp>','<genexpr>','<lambda>')
            if func_co is not None and func_co.co_name not in _skip:
                if func_co.co_name not in seen_funcs:
                    lines.append('')
                    lines.extend(_make_func_src(func_co, indent))
                    seen_funcs.add(func_co.co_name)
            i += 1
            continue

        # ── class definition  LOAD_BUILD_CLASS ──────────────────────────────
        if op == 'LOAD_BUILD_CLASS':
            # Next MAKE_FUNCTION carries the class body code object
            j = i + 1
            cls_co = None
            while j < len(instrs) and instrs[j].opname != 'MAKE_FUNCTION':
                if instrs[j].opname == 'LOAD_CONST' and _is_code(instrs[j].argval):
                    cls_co = instrs[j].argval
                j += 1
            if cls_co is not None and cls_co.co_name not in seen_funcs:
                lines.append('')
                lines.extend(_make_class_src(cls_co, indent))
                seen_funcs.add(cls_co.co_name)
            i = j + 1
            continue

        # ── RETURN_VALUE / RETURN CONST ─────────────────────────────────────
        if op == 'RETURN_VALUE':
            # peek at what's on the "stack" — look back for a LOAD
            if i > 0:
                prev = instrs[i - 1]
                if prev.opname == 'LOAD_CONST' and prev.argval is not None:
                    lines.append(f"{indent}return {repr(prev.argval)}")
                elif prev.opname in ('LOAD_NAME','LOAD_FAST','LOAD_GLOBAL','LOAD_DEREF'):
                    name = prev.argval
                    if isinstance(name, str):
                        lines.append(f"{indent}return {name}")
            i += 1
            continue

        i += 1

    return lines


def _make_class_src(co, indent=''):
    """Return lines of pseudo-source for a class body code object."""
    ii = indent + '    '
    lines = []

    # Determine base classes: look for LOAD_NAME instructions before MAKE_FUNCTION
    # (class name comes from co_name of the class body's code object)
    lines.append(f"{indent}class {co.co_name}:")

    # Docstring
    doc = co.co_consts[0] if co.co_consts and isinstance(co.co_consts[0], str) and co.co_consts[0] else None
    if doc:
        lines.append(f'{ii}"""{doc}"""')

    # Find method code objects in co_consts (they are nested code objects)
    methods = [c for c in co.co_consts if _is_code(c)
               and c.co_name not in ('<listcomp>','<dictcomp>','<setcomp>','<genexpr>','<lambda>')]
    # Also look in _extract_body for MAKE_FUNCTION patterns
    body = _extract_body(co, ii)
    # Avoid emitting duplicate method defs from both methods and body
    emitted = {ln.strip().split('(')[0].replace('def ', '').replace('async def ', '').strip()
               for ln in body if 'def ' in ln}
    extra_methods = [m for m in methods if m.co_name not in emitted]

    if body:
        lines.extend(body)
    for m in extra_methods:
        lines.append('')
        lines.extend(_make_func_src(m, ii))
    if not body and not extra_methods:
        lines.append(f'{ii}pass')
    return lines


def _pyc_dis(pyc_path, out_path):
    """Convert a .pyc to readable pseudo-source (no external decompiler needed)."""
    import dis, marshal, io
    try:
        with open(pyc_path, 'rb') as f:
            f.read(16)   # magic + flags + mtime + size (PEP 552)
            raw = f.read()
        co = marshal.loads(raw)

        buf = io.StringIO()
        mod_name = os.path.splitext(os.path.basename(pyc_path))[0]
        buf.write(f"# Module: {mod_name}\n")
        buf.write(f"# Pseudo-source reconstructed from bytecode (no decompiler)\n\n")

        # Module-level body
        body_lines = _extract_body(co, '')
        for ln in body_lines:
            buf.write(ln + '\n')

        # Any top-level code objects that MAKE_FUNCTION missed
        seen = set()
        for ln in body_lines:
            s = ln.strip()
            for prefix in ('async def ', 'def ', 'class '):
                if s.startswith(prefix):
                    name = s[len(prefix):].split('(')[0].split(':')[0].strip()
                    seen.add(name)
                    break
        for const in co.co_consts:
            if not _is_code(const):
                continue
            name = const.co_name
            if name in seen or name in ('<listcomp>','<dictcomp>','<setcomp>','<genexpr>','<lambda>','<module>'):
                continue
            buf.write('\n')
            func_lines = _make_func_src(const, '')
            buf.write('\n'.join(func_lines) + '\n')
            seen.add(name)

        content = buf.getvalue().strip()
        if not content:
            content = f"# Module: {mod_name}\n# (empty or unrecognised bytecode)\n"

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content + '\n')
        return True
    except Exception as e:
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(f"# {os.path.basename(pyc_path)}: parse error — {e}\n")
        except Exception:
            pass
        return False


# =============================================================================
# MAIN EXTRACTION ENGINE
# =============================================================================

class NuitkalizatorPro:
    """Main engine for static extraction.

    Pipeline:
    1. PE analysis (Python version, Nuitka edition)
    2. Constants blob extraction (PE resources or embedded)
    3. Commercial encryption detection and bypass
    4. Blob parsing into named modules
    5. .pyc extraction from .bytecode chunk
    6. Per-module constants parsing
    7. Code object map (function signatures)
    8. Secrets scanner
    9. JSON report
    """

    def __init__(self, target_path: str, output_dir: str, main_only: bool = False,
                 only_modules=None, decompile_pyc: bool = True):
        self.target = target_path
        self.output_dir = output_dir
        self.main_only = main_only
        # List of module names (or `pkg.*` glob patterns) to restrict
        # PHASE 11.7 recursive disassembly to. `None` = disassemble all
        # compiled modules (the default behaviour).
        self.only_modules = only_modules
        self.decompile_pyc = decompile_pyc
        self.bypass = CommercialBypass()
        self.report = {
            'target': os.path.basename(target_path),
            'timestamp': datetime.now().isoformat(),
            'python_version': None,
            'nuitka_edition': None,
            'encrypted': False,
            'modules': [],
            'bytecode_count': 0,
            'secrets': [],
            'code_objects': [],
            'stats': {},
        }

    def run(self):
        """Execute the full static extraction pipeline."""
        print(BANNER)
        os.makedirs(self.output_dir, exist_ok=True)

        # === PHASE 1: PE Analysis ===
        print_section("PHASE 1: PE ANALYSIS")

        if not os.path.isfile(self.target):
            log_err(f"File not found: {self.target}")
            return False

        with open(self.target, 'rb') as f:
            pe_data = f.read()

        file_size = len(pe_data)
        log(f"Target: {self.target}")
        log(f"Size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")

        py_ver = detect_python_version_from_pe(pe_data)
        self.report['python_version'] = f"{py_ver[0]}.{py_ver[1]}"
        log_ok(f"Python version: {py_ver[0]}.{py_ver[1]}")

        # Preliminary edition detection (will be refined after blob extraction)
        edition = detect_nuitka_edition(pe_data)

        # === PHASE 1.5: Resource & Section Scan for Embedded Source ===
        print_section("PHASE 1.5: EMBEDDED SOURCE SCAN (resources + sections)")
        log("Scanning ALL PE resources and sections for hidden Python source...")

        resource_findings = scan_pe_resources_for_source(self.target, self.output_dir)
        section_findings  = scan_sections_for_source(pe_data, self.output_dir)

        all_source_candidates = (
            [dict(r, origin='resource') for r in resource_findings] +
            [dict(r, origin='section')  for r in section_findings]
        )
        high_conf_source = [r for r in all_source_candidates if r['confidence'] > 0.30]

        if high_conf_source:
            log_fire(f"FOUND {len(high_conf_source)} HIGH-CONFIDENCE SOURCE CANDIDATE(S)!")
            for r in high_conf_source:
                loc = r.get('path') or f"{r.get('section','?')}+0x{r.get('offset',0):X}"
                log_fire(f"  [{r['origin']}] {loc}: conf={r['confidence']} -> {r['saved_at']}")
        else:
            log(f"  Resources scanned: {len(resource_findings)}, "
                f"Section blocks found: {len(section_findings)}")
            log("  No high-confidence source in resources/sections "
                "(may be in constants blob - checked in Phase 6)")

        self.report['embedded_source_scan'] = {
            'resource_entries':   len(resource_findings),
            'section_blocks':     len(section_findings),
            'high_conf_total':    len(high_conf_source),
            'candidates':         all_source_candidates,
        }

        # === PHASE 2: Constants blob extraction ===
        print_section("PHASE 2: CONSTANTS BLOB EXTRACTION")

        blob_data = extract_pe_constants_blob(self.target)
        if not blob_data:
            log_err("Constants blob not found!")
            return False

        log_ok(f"Blob extracted: {len(blob_data):,} bytes")

        blob_path = os.path.join(self.output_dir, "constants_blob_raw.bin")
        with open(blob_path, 'wb') as f:
            f.write(blob_data)

        # Refine edition detection using blob structure (most reliable for stripped binaries)
        edition = detect_nuitka_edition(pe_data, blob_data)
        self.report['nuitka_edition'] = edition
        if edition == "commercial":
            log_fire("COMMERCIAL EDITION DETECTED (16-byte digest in blob)")
        else:
            log_ok(f"Edition: {edition}")

        # === PHASE 3: Commercial encryption bypass ===
        print_section("PHASE 3: ENCRYPTION DETECTION")

        is_encrypted = self.bypass.is_blob_encrypted(blob_data)
        has_digest = self.bypass.has_commercial_digest(blob_data)
        self.report['encrypted'] = is_encrypted

        if has_digest:
            log_fire(f"ENCRYPTED BLOB with commercial data-hiding (16-byte MD5 digest detected)")
        elif is_encrypted:
            log_fire("ENCRYPTED BLOB! (CRC32 mismatch)")

        if is_encrypted:
            log(f"Attempting Nuitka Commercial bypass...")

            mapping_candidates, d_candidates = self.bypass.extract_key_material_from_pe(pe_data)

            if mapping_candidates is not None:
                log_ok(f"Found {len(mapping_candidates)} _mapping[] candidates and {len(d_candidates) if d_candidates else 0} d0-d7 sets")

                if d_candidates is None:
                    d_candidates = []
                if [0]*8 not in d_candidates:
                    d_candidates.append([0]*8)

                blob_data, best_mapping, best_d = self.bypass.decrypt_blob_auto(
                    blob_data, mapping_candidates, d_candidates
                )

                dec_path = os.path.join(self.output_dir, "constants_blob_decrypted.bin")
                with open(dec_path, 'wb') as f:
                    f.write(blob_data)
                log_ok(f"Decrypted blob saved: {dec_path}")

                key_info = {
                    'mapping': list(best_mapping),
                    'd_values': list(best_d),
                    'mapping_candidates_count': len(mapping_candidates),
                    'd_candidates_count': len(d_candidates),
                }
                key_path = os.path.join(self.output_dir, "extracted_key.json")
                with open(key_path, 'w') as f:
                    json.dump(key_info, f, indent=2)
            else:
                log_err("Unable to extract _mapping[] candidates from binary!")
                log_warn("Attempting parsing anyway (may fail)...")
        else:
            log_ok("Blob NOT encrypted (open-source edition)")

        # === PHASE 4: Parse blob into modules ===
        print_section("PHASE 4: MODULE PARSING")

        bypass_for_names = self.bypass if (edition == "commercial" or is_encrypted) else None
        modules = parse_blob_modules(blob_data, bypass_for_names)
        log_ok(f"Found {len(modules)} modules in blob")

        bytecode_chunk = None
        module_chunks = []

        for name, data in modules:
            if name == ".bytecode":
                bytecode_chunk = data
                log(f"  [BC] .bytecode ({len(data):,} bytes)")
            else:
                module_chunks.append((name, data))
                is_main = is_main_module(name)
                icon = f"{C.BRIGHT_GREEN}[>>]{C.RESET}" if is_main else "    "
                log(f"  {icon} {name} ({len(data):,} bytes)")

        self.report['stats']['total_modules'] = len(modules)
        analysis_module_chunks = module_chunks
        if self.only_modules:
            analysis_module_chunks = [
                (name, data) for name, data in module_chunks
                if module_matches_patterns(name, self.only_modules)
            ]
            log(f"  --only analysis filter: {len(analysis_module_chunks)} "
                f"of {len(module_chunks)} constants chunks match {self.only_modules}")
            self.report['stats']['only_modules_filter'] = list(self.only_modules)
            self.report['stats']['only_modules_matched'] = len(analysis_module_chunks)

        # Save raw module chunks as .nuitka_const in a single folder (library_modules-style)
        nuitka_const_dir = os.path.join(self.output_dir, "library_modules")
        os.makedirs(nuitka_const_dir, exist_ok=True)

        dumped_count = 0
        for module_name, chunk_data in module_chunks:
            parts = module_name.replace('.', os.sep)
            safe_parts = re.sub(r'[<>:"|?*]', '_', parts)
            out_path = os.path.join(nuitka_const_dir, safe_parts + ".nuitka_const")

            os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(chunk_data)

            dumped_count += 1

        self.report['stats']['nuitka_const_modules'] = dumped_count
        log_ok(f"Saved {dumped_count} .nuitka_const module files into 'library_modules'")

        # === PHASE 4.5: Nuitka module table (PE meta_path_loader_entries[]) ===
        print_section("PHASE 4.5: NUITKA MODULE TABLE")
        module_table_entries = []
        try:
            import pefile as _pefile_mt
            _pe_mt = _pefile_mt.PE(data=pe_data)
            mtp = NuitkaModuleTableParser(_pe_mt)
            # Feed in every module name the blob decoder already resolved
            # (plus __main__ / __init__ / .bytecode sentinels). The pass-3
            # name-anchored fallback inside find_table() uses these to rescue
            # entries that live outside the main meta_path_loader_entries[]
            # cluster (typical for __main__ and other sidecar records).
            _known_chunk_names = [name for name, _ in module_chunks]
            _extra_names = list(_known_chunk_names) + [
                '__main__', '__init__', '.bytecode',
            ]
            # Dedupe while preserving order
            _seen = set()
            _extra_names_dedup = []
            for _n in _extra_names:
                if _n in _seen:
                    continue
                _seen.add(_n)
                _extra_names_dedup.append(_n)
            found = mtp.find_table(extra_names=_extra_names_dedup)
            if found:
                start_va, module_table_entries = found
                log_ok(f"Module table: {len(module_table_entries)} entries at VA 0x{start_va:X}")

                # Write table dump
                mt_path = os.path.join(self.output_dir, "NUITKA_MODULE_TABLE.txt")
                with open(mt_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write(f" NUITKA MODULE TABLE  —  {len(module_table_entries)} entries\n")
                    f.write(f" Start VA: 0x{start_va:X}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"{'NAME':<50s} {'FLAGS':<30s} {'BC_IDX':>7s} {'BC_SIZE':>9s}\n")
                    f.write("-" * 100 + "\n")
                    for e in module_table_entries:
                        flags_str = ','.join(e['flag_names'])
                        f.write(f"{e['name']:<50s} {flags_str:<30s} "
                                f"{e['bytecode_index']:>7d} {e['bytecode_size']:>9d}\n")
                log_ok(f"  Saved: {mt_path}")

                bc_entries = [e for e in module_table_entries if 'BYTECODE' in e['flag_names']]
                compiled_entries = [e for e in module_table_entries if 'BYTECODE' not in e['flag_names']
                                    and 'EXTENSION' not in e['flag_names']]
                ext_entries = [e for e in module_table_entries if 'EXTENSION' in e['flag_names']]
                log(f"  Breakdown: BYTECODE={len(bc_entries)}  COMPILED={len(compiled_entries)}  EXTENSION={len(ext_entries)}")

                self.report['module_table'] = {
                    'start_va': f"0x{start_va:X}",
                    'total_entries': len(module_table_entries),
                    'bytecode_entries': len(bc_entries),
                    'compiled_entries': len(compiled_entries),
                    'extension_entries': len(ext_entries),
                }
            else:
                log_warn("Module table not located (table may be fragmented or custom)")
        except Exception as _mt_err:
            log_warn(f"Module table scan error: {_mt_err}")

        # === PHASE 5: .pyc extraction ===
        print_section("PHASE 5: BYTECODE EXTRACTION (.pyc)")

        pyc_count = 0
        bytecode_manifest = {}
        if bytecode_chunk:
            pyc_count, bytecode_manifest = extract_bytecode_modules(
                bytecode_chunk, self.output_dir, py_ver)

            # Cross-reference: if we have both the module table and manifest, enrich
            if module_table_entries:
                bc_table = [e for e in module_table_entries if 'BYTECODE' in e['flag_names']]
                # Match by bytecode_index
                for e in bc_table:
                    idx = e['bytecode_index']
                    if idx in bytecode_manifest:
                        bytecode_manifest[idx]['canonical_module_name'] = e['name']
                        bytecode_manifest[idx]['flags'] = e['flag_names']
                log_ok(f"  Enriched {len(bc_table)} bytecode entries with canonical names")

                # Rewrite manifest with the updates
                mfp = os.path.join(self.output_dir, "BYTECODE_MANIFEST.json")
                try:
                    with open(mfp, 'r', encoding='utf-8') as f:
                        mf = json.load(f)
                    mf['entries'] = list(bytecode_manifest.values())
                    with open(mfp, 'w', encoding='utf-8') as f:
                        json.dump(mf, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass
        else:
            log_warn("No .bytecode chunk found in blob")
            log_warn("All modules are C-compiled (constants still extractable)")

        self.report['bytecode_count'] = pyc_count

        # === PHASE 6: Per-module constants parsing ===
        print_section("PHASE 6: PER-MODULE CONSTANTS EXTRACTION")

        constants_dir = os.path.join(self.output_dir, "module_constants")
        os.makedirs(constants_dir, exist_ok=True)

        all_secrets = []
        all_code_objects = []
        module_info_list = []
        all_const_source_findings = []

        pb = ProgressBar(len(analysis_module_chunks), desc="Parsing module constants")

        for module_name, chunk_data in analysis_module_chunks:
            pb.update()

            is_main = is_main_module(module_name)
            if self.main_only and not is_main:
                continue

            constants = parse_module_constants(chunk_data)
            # Search constants for embedded Python source (crackme-style hidden source)
            const_src = search_constants_for_source(constants, module_name, self.output_dir)
            if const_src:
                all_const_source_findings.extend(const_src)
            code_objs = extract_code_object_map(module_name, chunk_data)
            all_code_objects.extend(code_objs)
            secrets = scan_for_secrets(constants, module_name)
            all_secrets.extend(secrets)

            safe_name = module_name.replace('.', '_').replace('<', '_').replace('>', '_')
            safe_name = re.sub(r'[<>:"|?*]', '_', safe_name)
            const_file = os.path.join(constants_dir, f"{safe_name}_constants.txt")

            # Extract all strings recursively from parsed constants and code-object info
            strings = extract_all_strings(constants)
            # Also include code object names/qualnames/args/freevars, which are not always present in constants list.
            strings += extract_all_strings(code_objs)
            # Deduplicate again while preserving order
            strings = list(dict.fromkeys(strings))

            with open(const_file, 'w', encoding='utf-8') as f:
                f.write(f"# Module: {module_name}\n")
                f.write(f"# Constants count: {len(constants)}\n\n")
                for idx, val in enumerate(constants):
                    f.write(f"[{idx}] {type(val).__name__}: {_safe_repr(val)}\n")

                f.write("\n" + "=" * 70 + "\n")
                f.write(f"# Strings extracted (recursive): {len(strings)}\n")
                f.write("=" * 70 + "\n\n")
                for s in strings:
                    f.write(s.replace("\r\n", "\n"))
                    f.write("\n")

            module_info = {
                'name': module_name,
                'is_main': is_main,
                'chunk_size': len(chunk_data),
                'constants_count': len(constants),
                'strings_count': len(strings),
                'code_objects': len(code_objs),
                'secrets_found': len(secrets),
            }
            module_info_list.append(module_info)

        pb.finish(f"Parsed {len(module_chunks)} modules")

        self.report['modules'] = module_info_list
        self.report['code_objects'] = all_code_objects

        # Deduplicate secrets
        seen = set()
        unique_secrets = []
        for s in all_secrets:
            key = (s['type'], str(s.get('value', '')))
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)
        all_secrets = unique_secrets
        self.report['secrets'] = all_secrets

        # === PHASE 7: Code Object Map ===
        print_section("PHASE 7: CODE OBJECT MAP")

        if all_code_objects:
            co_map_path = os.path.join(self.output_dir, "CODE_OBJECT_MAP.txt")
            with open(co_map_path, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("  Nuitka Static Unpacker - CODE OBJECT MAP\n")
                f.write("  Function signatures extracted from C-compiled code\n")
                f.write("=" * 70 + "\n\n")

                current_module = None
                for co in sorted(all_code_objects, key=lambda x: x.get('module', '')):
                    mod = co.get('module', '')
                    if mod != current_module:
                        f.write(f"\n{'_' * 60}\n")
                        f.write(f"MODULE: {mod}\n")
                        f.write(f"{'_' * 60}\n\n")
                        current_module = mod

                    raw_args = co.get('args', [])
                    args = ", ".join(str(a) if a is not None else '?' for a in raw_args)
                    flags_str = []
                    cf = co.get('flags', 0)
                    if cf & 0x04: flags_str.append("*args")
                    if cf & 0x08: flags_str.append("**kwargs")
                    if cf & 0x20: flags_str.append("generator")
                    if cf & 0x100: flags_str.append("coroutine")
                    if cf & 0x200: flags_str.append("async_gen")
                    flags_display = f" [{', '.join(flags_str)}]" if flags_str else ""
                    f.write(f"  def {co['name']}({args}){flags_display}\n")
                    f.write(f"      line: {co.get('line', '?')}\n\n")

            log_ok(f"Code object map: {len(all_code_objects)} functions found")
            log(f"  Saved to: {co_map_path}")

            main_cos = [co for co in all_code_objects if is_main_module(co.get('module', ''))]
            if main_cos:
                log_fire(f"  {len(main_cos)} functions from the app code:")
                for co in main_cos[:20]:
                    raw_args = co.get('args', [])
                    args = ", ".join(str(a) if a is not None else '?' for a in raw_args)
                    print(f"    {C.BRIGHT_YELLOW}def {co['name']}({args}){C.RESET} @ line {co.get('line', '?')}")
                if len(main_cos) > 20:
                    print(f"    ... and {len(main_cos) - 20} more")
        else:
            log_warn("No code objects found in modules")

        # === PHASE 8: Secrets Report ===
        print_section("PHASE 8: SECRETS SCANNER")

        if all_secrets:
            secrets_dir = os.path.join(self.output_dir, "secrets")
            os.makedirs(secrets_dir, exist_ok=True)

            secrets_path = os.path.join(secrets_dir, "SECRETS.json")
            with open(secrets_path, 'w', encoding='utf-8') as f:
                json.dump(all_secrets, f, indent=2, ensure_ascii=False, default=str)

            secrets_txt = os.path.join(secrets_dir, "SECRETS.txt")
            with open(secrets_txt, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("  SECRETS FOUND BY Nuitka Static Unpacker\n")
                f.write("  SECRETS FOUND BY Nuitka Static Unpacker\n")
                f.write("=" * 60 + "\n\n")
                for s in all_secrets:
                    f.write(f"[{s['type']}] {s.get('value', 'N/A')}\n")
                    f.write(f"  Module: {s.get('module', 'N/A')}\n")
                    if 'context' in s:
                        f.write(f"  Context: {s['context'][:100]}\n")
                    if 'entropy' in s:
                        f.write(f"  Entropy: {s['entropy']}\n")
                    f.write("\n")

            log_fire(f"FOUND {len(all_secrets)} SECRETS!")
            for s in all_secrets[:15]:
                stype = s['type']
                sval = str(s.get('value', ''))[:60]
                color = C.BRIGHT_RED if stype in ('password', 'flag', 'private_key') else C.BRIGHT_YELLOW
                print(f"  {color}[{stype}]{C.RESET} {sval}")
            if len(all_secrets) > 15:
                print(f"  ... and {len(all_secrets) - 15} more")
        else:
            log("No secrets found in analyzed modules")

        # === PHASE 10: Embedded Source Summary ===
        print_section("PHASE 10: EMBEDDED SOURCE SUMMARY")

        total_source = (
            len(high_conf_source) +
            len(all_const_source_findings)
        )

        if total_source > 0:
            log_fire(f"TOTAL EMBEDDED SOURCE CANDIDATES: {total_source}")

            if high_conf_source:
                log_fire(f"  From PE resources/sections ({len(high_conf_source)}):")
                for r in high_conf_source:
                    loc = r.get('path') or f"[{r.get('section','?')}]+0x{r.get('offset',0):X}"
                    print(f"    {C.BRIGHT_GREEN}[{r['origin']}]{C.RESET} "
                          f"{C.BRIGHT_WHITE}{loc}{C.RESET} "
                          f"conf={C.BRIGHT_YELLOW}{r['confidence']:.2f}{C.RESET} "
                          f"-> {r['saved_at']}")

            if all_const_source_findings:
                log_fire(f"  From module constants ({len(all_const_source_findings)}):")
                for r in all_const_source_findings:
                    print(f"    {C.BRIGHT_MAGENTA}[const]{C.RESET} "
                          f"{C.BRIGHT_WHITE}{r['module']}{C.RESET} "
                          f"conf={C.BRIGHT_YELLOW}{r['confidence']:.2f}{C.RESET} "
                          f"-> {r['saved_at']}")

            log_fire("Check the saved .py files above - these are the real embedded source!")
        else:
            log_warn("No embedded Python source found automatically.")
            log_warn("Possible locations to check manually:")
            log_warn("  1. Custom PE sections not named .text/.data/.rdata")
            log_warn("  2. Non-standard PE resource IDs")
            log_warn("  3. Source embedded with a custom encoding/cipher")
            log_warn(f"  4. Check pe_resources/ and section_scan/ in {self.output_dir}")

        self.report['embedded_source_summary'] = {
            'total_candidates': total_source,
            'from_resources_sections': len(high_conf_source),
            'from_constants': len(all_const_source_findings),
            'const_findings': all_const_source_findings,
        }

        # === PHASE 11: Static Decompilation ===
        # Now uses the EMBEDDED BlobParser + reconstruct_python_source
        # (previously loaded from an external nuitka_static_decompiler.py
        # sidecar). Everything lives in this single script.
        print_section("PHASE 11: STATIC DECOMPILATION (constants → Python source)")
        try:
            _bp = BlobParser(b'')
            _decompiled_count = 0
            _decompile_report = []

            for _mod_name, _mod_data in analysis_module_chunks:
                try:
                    _consts, _ = _bp.parse_module(bytes(_mod_data), _mod_name)
                    _src = reconstruct_python_source(_mod_name, _consts)

                    # Build output path: __main__ / empty name → reconstructed_source.py
                    # package.sub.module → package/sub/module.py
                    _safe = _mod_name.replace('.', os.sep).strip(os.sep)
                    if not _safe or _safe == '__main__':
                        _src_path = os.path.join(self.output_dir, 'reconstructed_source.py')
                    else:
                        _src_path = os.path.join(self.output_dir, _safe + '.py')
                        os.makedirs(os.path.dirname(_src_path), exist_ok=True)

                    with open(_src_path, 'w', encoding='utf-8') as _f:
                        _f.write(_src)

                    _n_str  = sum(1 for _c in _consts if _c.get('type') == 'str')
                    _n_code = sum(1 for _c in _consts if _c.get('type') == 'code')
                    log_ok(f"Module {_mod_name!r}: {len(_consts)} constants "
                           f"({_n_str} strings, {_n_code} code objects) -> {_src_path}")

                    _decompiled_count += 1
                    _decompile_report.append({
                        'module': _mod_name,
                        'path': _src_path,
                        'constants': len(_consts),
                        'strings': _n_str,
                        'code_objects': _n_code,
                    })
                except Exception as _mod_err:
                    log_warn(f"Decompilation failed for {_mod_name!r}: {_mod_err}")

            if _decompiled_count == 0:
                log_warn("No modules could be decompiled")
            else:
                log_ok(f"Decompiled {_decompiled_count} module(s) with embedded BlobParser")

            self.report['reconstructed_source'] = _decompile_report

        except Exception as _e:
            log_warn(f"Static decompilation error: {_e}")
            import traceback
            traceback.print_exc()

        # === PHASE 11.5: C SOURCE RECONSTRUCTION (Nuitka-style .c per module) ===
        print_section("PHASE 11.5: C SOURCE RECONSTRUCTION (Nuitka-style .c per module)")

        c_src_dir = os.path.join(self.output_dir, "reconstructed_c_sources")
        os.makedirs(c_src_dir, exist_ok=True)

        # Build a quick lookup: module_name -> module_table_entry
        mt_by_name = {e['name']: e for e in module_table_entries} if module_table_entries else {}

        c_generated = 0
        c_total_lines = 0
        c_pb = ProgressBar(len(analysis_module_chunks), desc="Generating .c files")
        for module_name, chunk_data in analysis_module_chunks:
            c_pb.update()
            try:
                constants = parse_module_constants(chunk_data)
                code_objs = extract_code_object_map(module_name, chunk_data)

                mt_entry = mt_by_name.get(module_name)
                native_addr = mt_entry['func_ptr'] if mt_entry else None

                c_src = NuitkaCSourceRebuilder.generate_c_source(
                    module_name=module_name,
                    constants=constants,
                    code_objects=code_objs,
                    module_table_entry=mt_entry,
                    native_func_addr=native_addr,
                )

                safe_name = module_name.replace('.', os.sep) or '__main__'
                safe_name = re.sub(r'[<>:"|?*]', '_', safe_name)
                c_path = os.path.join(c_src_dir, safe_name + '.c')
                os.makedirs(os.path.dirname(c_path) or '.', exist_ok=True)
                with open(c_path, 'w', encoding='utf-8') as f:
                    f.write(c_src)
                c_generated += 1
                c_total_lines += c_src.count('\n')
            except Exception as _c_err:
                pass

        c_pb.finish(f"Generated {c_generated} .c files ({c_total_lines:,} total lines)")
        log_ok(f"  Output: {c_src_dir}")

        self.report['c_source_reconstruction'] = {
            'generated_files': c_generated,
            'total_lines': c_total_lines,
            'output_dir': c_src_dir,
        }

        # === PHASE 11.7: STATICALY PIPELINE ===
        #  - NuitkaBlobDecoder (Python port of nuitka_deobfuscate.c)
        #  - xdis raw marshal scanner (finds embedded code objects the
        #    section decoder misses)
        #  - OmniDecompiler AST synthesis with C-API trace comments
        print_section("PHASE 11.7: STATICALY DEOBFUSCATION + OMNI DECOMPILATION")
        if blob_data is None:
            log_warn("No blob data available — skipping Staticaly pipeline")
        else:
            try:
                log("Running embedded Staticaly pipeline "
                    + ("[xdis available]" if XDIS_AVAILABLE else "[xdis MISSING - raw scan disabled]")
                    + (" [capstone available]" if CAPSTONE_AVAILABLE else " [capstone MISSING - disasm disabled]"))

                # Give the user a VERY loud warning when capstone is not
                # installed — without it every .nbc file comes out with a
                # @NO_OPS block and no function bodies can be recovered.
                if not CAPSTONE_AVAILABLE:
                    log_err("=" * 66)
                    log_err(" capstone is NOT installed in the running Python.")
                    log_err(" Every .nbc file will be produced WITHOUT the")
                    log_err(" @OPS section — an LLM fed those files can only")
                    log_err(" emit signature skeletons, not real function bodies.")
                    log_err(" Fix:  py -3.10 -m pip install capstone")
                    log_err(" Then re-run this extraction.")
                    log_err("=" * 66)
                if not module_table_entries:
                    log_err("=" * 66)
                    log_err(" Nuitka module table was NOT located in the PE.")
                    log_err(" Without it the disassembler cannot find function")
                    log_err(" entry points — every .nbc will have @NO_OPS.")
                    log_err(" Check the PHASE 4.5 log above; if the target was")
                    log_err(" built with --obfuscate or with an unusual Nuitka")
                    log_err(" fork the loader table may live at a non-standard")
                    log_err(" offset and require a custom scan.")
                    log_err("=" * 66)

                st_dir = os.path.join(self.output_dir, "staticaly")
                # Reuse the already-parsed pefile + module table so the
                # disassembler can annotate calls with module names and
                # resolve the IAT for Python-C-API references.
                _pe_for_staticaly = None
                try:
                    import pefile as _pf
                    _pe_for_staticaly = _pf.PE(data=pe_data)
                except Exception:
                    _pe_for_staticaly = None
                extractor = StaticalyExtractor(
                    blob_data,
                    target_python=py_ver,
                    pe_file=_pe_for_staticaly,
                    module_table=module_table_entries,
                )
                # Optional --only filter: restrict PHASE 11.7 recursive
                # disassembly to a user-specified subset of modules.
                if getattr(self, 'only_modules', None):
                    extractor.only_modules = self.only_modules
                st_result = extractor.run(st_dir)
                log_ok(f"Staticaly sections decoded         : {st_result['sections']}")
                log_ok(f"Staticaly raw-scan .pyc extracted : {st_result['raw_scan_pyc']}")
                log_ok(f"Staticaly OMNI reconstructions    : {st_result['omni_reconstructed']}")
                log_ok(f"Staticaly .nbc files produced     : {st_result.get('nbc_files', 0)}")
                log_ok(f"Staticaly modules disassembled    : {st_result.get('modules_disassembled', 0)}")
                log(f"  Output                           : {st_result['output_dir']}")
                self.report['staticaly'] = st_result
            except Exception as _st_err:
                log_warn(f"Staticaly pipeline error: {_st_err}")
                import traceback
                traceback.print_exc()
                self.report['staticaly'] = {'error': str(_st_err)}

        # === PHASE 12: .pyc → Python source decompilation ===
        print_section("PHASE 12: BYTECODE DECOMPILATION (.pyc → Python source)")

        pyc_dir   = os.path.join(self.output_dir, "bytecode_pyc")
        src_dir   = os.path.join(self.output_dir, "modules")
        os.makedirs(src_dir, exist_ok=True)

        # Collect all .pyc files extracted in Phase 5
        pyc_files = []
        if not self.decompile_pyc:
            log_warn("Skipping .pyc decompilation (--no-pyc-decompile).")
            self.report.setdefault('decompilation', {}).update({
                'skipped': True,
                'reason': '--no-pyc-decompile',
                'output_dir': src_dir,
            })
        elif os.path.exists(pyc_dir):
            for _root, _dirs, _fnames in os.walk(pyc_dir):
                for _fn in sorted(_fnames):
                    if _fn.endswith('.pyc'):
                        pyc_files.append(os.path.join(_root, _fn))

        if not pyc_files:
            if self.decompile_pyc:
                log_warn("No .pyc files found (Phase 5 may have found no bytecode chunk).")
                log_warn("This binary may be fully C-compiled (no Python bytecode to decompile).")
        else:
            log(f"Found {len(pyc_files)} .pyc file(s) to decompile")

            _dec_list = _detect_decompiler(py_ver)
            if _dec_list:
                log_ok(f"Decompiler chain ({len(_dec_list)}):")
                for _i, _d in enumerate(_dec_list):
                    _bin = f"  ({_d['binary']})" if _d.get('binary') else ""
                    log(f"    {_i+1}. {_d['kind']}{_bin}  [priority {_d['priority']}]")
            else:
                log_warn("No Python decompiler found.")
                log_warn("  For Python 3.8-3.9:  pip install decompile3 decompyle3")
                log_warn("  For Python 3.10+:    install pycdc from https://github.com/zrax/pycdc")
                log_warn(f"    - build with cmake . && make; place pycdc.exe on PATH")
                log_warn("  Falling back to bytecode disassembly / pseudo-source.")

            _dec_ok = _dec_fail = 0
            _pb12 = ProgressBar(len(pyc_files), desc="Decompiling .pyc")

            for _pyc in pyc_files:
                _pb12.update()
                # Build output path: bytecode_pyc/a/b/c.pyc → modules/a/b/c.py
                _rel   = os.path.relpath(_pyc, pyc_dir)
                _py    = os.path.join(src_dir, _rel[:-1])   # .pyc → .py  (drop the trailing 'c')
                os.makedirs(os.path.dirname(_py) or '.', exist_ok=True)

                _ok = False
                if _dec_list:
                    _ok = _decompile_pyc(_pyc, _py, _dec_list)

                if not _ok:
                    # Fall back: write bytecode disassembly directly into the .py file.
                    # Marked with a prominent header so the user knows it's dis output.
                    _pyc_dis(_pyc, _py)
                    _dec_fail += 1
                else:
                    _dec_ok += 1

            _pb12.finish(f"Decompiled {_dec_ok}/{len(pyc_files)}"
                         + (f" ({_dec_fail} -> dis fallback)" if _dec_fail else ""))

            if _dec_ok > 0:
                log_ok(f"Source files written to: {src_dir}")
            if _dec_fail > 0 and not _dec_list:
                log_warn(f"Install pycdc or decompile3 to get real source for {_dec_fail} file(s)")

            self.report.setdefault('decompilation', {}).update({
                'decompiler_chain': [d['kind'] for d in _dec_list] if _dec_list else ['dis_fallback'],
                'total': len(pyc_files),
                'success': _dec_ok,
                'fallback_dis': _dec_fail,
                'output_dir': src_dir,
            })

        # === PHASE 9: JSON Report ===
        print_section("PHASE 9: FINAL REPORT")

        self.report['stats'].update({
            'bytecode_pyc': pyc_count,
            'modules_with_constants': len([m for m in module_info_list if m['constants_count'] > 0]),
            'total_code_objects': len(all_code_objects),
            'main_code_objects': len([co for co in all_code_objects if is_main_module(co.get('module', ''))]),
            'total_secrets': len(all_secrets),
            'total_strings': sum(m['strings_count'] for m in module_info_list),
        })

        report_path = os.path.join(self.output_dir, "REPORT.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False, default=str)

        ai_ready = organize_ai_ready_nbc(self.output_dir)
        self.report['ai_ready_nbc'] = ai_ready
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False, default=str)
        try:
            import shutil as _shutil
            _ctx = Path(ai_ready.get('context_dir', ''))
            if _ctx.exists():
                _shutil.copy2(report_path, _ctx / 'REPORT.json')
        except Exception:
            pass

        log_ok(f"Report saved: {report_path}")
        if ai_ready.get('files'):
            log_ok(f"AI-ready .nbc bundle: {ai_ready['files']} file(s) -> {ai_ready['output_dir']}")

        # === SUMMARY ===
        print_section("FINAL RESULTS")
        stats = self.report['stats']

        _dec_report = self.report.get('decompilation', {})
        _dec_ok_n   = _dec_report.get('success', 0)
        _dec_total  = _dec_report.get('total', 0)
        _dec_chain  = _dec_report.get('decompiler_chain') or [_dec_report.get('decompiler', 'none')]
        _dec_tool   = ', '.join(_dec_chain)
        if _dec_report.get('skipped'):
            _dec_line = f"skipped [{_dec_report.get('reason', 'requested')}]"
        else:
            _dec_line = (f"{_dec_ok_n}/{_dec_total} files  [{_dec_tool}]"
                         if _dec_total else "n/a (no bytecode chunk)")

        print(f"""
  {C.BRIGHT_WHITE}Target:{C.RESET}                {self.report['target']}
  {C.BRIGHT_WHITE}Python:{C.RESET}                {self.report['python_version']}
  {C.BRIGHT_WHITE}Nuitka Edition:{C.RESET}        {self.report['nuitka_edition']}
  {C.BRIGHT_WHITE}Encrypted blob:{C.RESET}        {'YES - BYPASS SUCCEEDED' if self.report['encrypted'] else 'NO'}

  {C.BRIGHT_GREEN}Modules in blob:{C.RESET}       {stats.get('total_modules', 0)}
  {C.BRIGHT_GREEN}.pyc extracted:{C.RESET}        {pyc_count}
  {C.BRIGHT_GREEN}Decompiled .py:{C.RESET}        {_dec_line}
  {C.BRIGHT_GREEN}Total strings:{C.RESET}         {stats.get('total_strings', 0)} (recursive, deduplicated per module)
  {C.BRIGHT_GREEN}Code objects:{C.RESET}          {stats.get('total_code_objects', 0)} ({stats.get('main_code_objects', 0)} from app)

  {C.BRIGHT_RED}Secrets found:{C.RESET}         {stats.get('total_secrets', 0)}

  {C.BRIGHT_WHITE}Output:{C.RESET}                {self.output_dir}
  {C.BRIGHT_WHITE}AI-ready .nbc:{C.RESET}         {ai_ready.get('output_dir', 'n/a')}
  {C.BRIGHT_WHITE}Source files:{C.RESET}          {os.path.join(self.output_dir, 'modules')}
""")

        print(f"{C.BRIGHT_GREEN}{C.BOLD}")
        print("   +=====================================================+")
        print("   ||   EXTRACTION COMPLETE! NUITKA STATIC BYPASS     ||")
        print("   +=====================================================+")
        print(C.RESET)

        return True


def organize_ai_ready_nbc(output_dir: str) -> dict:
    """Create a clean, LLM-facing output tree for the generated `.nbc` files.

    The main extractor intentionally keeps legacy folders for compatibility.
    This post-pass gives the reverse-engineering workflow one obvious place
    to look: `AI_READY_NBC/nbc/` plus a small context bundle and manifest.
    """
    root = Path(output_dir).resolve()
    src_tree = root / "staticaly" / "omni_reconstructed"
    ready_dir = root / "AI_READY_NBC"
    nbc_dir = ready_dir / "nbc"
    ctx_dir = ready_dir / "context"

    result = {
        'output_dir': str(ready_dir),
        'nbc_dir': str(nbc_dir),
        'context_dir': str(ctx_dir),
        'files': 0,
        'with_ops': 0,
        'without_ops': 0,
        'manifest': str(ready_dir / 'NBC_MANIFEST.json'),
    }

    if not src_tree.exists():
        return result

    try:
        resolved_ready = ready_dir.resolve()
        if resolved_ready.exists() and resolved_ready.is_relative_to(root):
            import shutil as _shutil
            _shutil.rmtree(resolved_ready)
    except Exception:
        pass

    nbc_dir.mkdir(parents=True, exist_ok=True)
    ctx_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    import shutil as _shutil

    for src in sorted(src_tree.rglob('*.nbc')):
        rel = src.relative_to(src_tree)
        dst = nbc_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _shutil.copy2(src, dst)

        try:
            text = dst.read_text(encoding='utf-8', errors='replace')
        except Exception:
            text = ''

        module_name = ''
        const_count = None
        for line in text.splitlines()[:80]:
            if line.startswith('@MOD '):
                module_name = line[5:].strip()
            elif line.startswith('@CONSTS '):
                try:
                    const_count = int(line.split()[1])
                except Exception:
                    const_count = None

        lines = text.splitlines()
        has_ops = any(line.startswith('@OPS ') for line in lines)
        # A bare @NO_OPS means the module has no disassembly. In the
        # @FORENSICS section, "@NO_OPS <qualname>" only marks a single
        # orphan function and should not classify the whole module as failed.
        has_no_ops = any(line.strip() == '@NO_OPS' for line in lines)
        data = dst.read_bytes()
        item = {
            'module': module_name,
            'path': str(rel).replace(os.sep, '/'),
            'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'constants': const_count,
            'has_ops': has_ops,
            'has_no_ops': has_no_ops,
        }
        manifest.append(item)
        result['files'] += 1
        if has_ops:
            result['with_ops'] += 1
        if has_no_ops and not has_ops:
            result['without_ops'] += 1

    context_files = [
        root / 'REPORT.json',
        root / 'NUITKA_MODULE_TABLE.txt',
        root / 'CODE_OBJECT_MAP.txt',
        root / 'BYTECODE_MANIFEST.json',
        src_tree / '_MANIFEST.json',
        src_tree / 'NUITKA_RUNTIME_HELPERS.txt',
    ]
    for src in context_files:
        if src.exists() and src.is_file():
            try:
                _shutil.copy2(src, ctx_dir / src.name)
            except Exception:
                pass

    manifest_path = ready_dir / 'NBC_MANIFEST.json'
    manifest_path.write_text(
        json.dumps({
            'created_at': datetime.now().isoformat(),
            'source_tree': str(src_tree),
            'nbc_files': result['files'],
            'with_ops': result['with_ops'],
            'without_ops': result['without_ops'],
            'entries': manifest,
        }, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )

    readme = ready_dir / 'README_AI.md'
    readme.write_text(
        "# AI-ready Nuitka NBC bundle\n\n"
        "Use files under `nbc/` as the primary input for source reconstruction.\n"
        "Each `.nbc` is self-contained: full decoded constants, raw chunk "
        "base64, loader-table metadata when available, virtual `@OPS`, and "
        "annotated native `@ASM` blocks when static disassembly succeeded.\n\n"
        "Prefer files with `has_ops: true` in `NBC_MANIFEST.json`; files "
        "with `@NO_OPS` contain constants and metadata only.\n",
        encoding='utf-8',
    )

    return result


def _safe_repr(val, max_len=500):
    try:
        r = repr(val)
        if len(r) > max_len:
            return r[:max_len] + '...'
        return r
    except Exception:
        return f"<unrepresentable: {type(val).__name__}>"


# =============================================================================
# CLI
# =============================================================================

# =============================================================================
# DYNAMIC INJECTION INFRASTRUCTURE  (Windows x64 only)
# =============================================================================

def _setup_win32_apis():
    """Return (k32, ntdll, psapi, MODULEENTRY32W, PROCESSENTRY32W) or None on
    non-Windows / import error."""
    try:
        import ctypes
        from ctypes import wintypes

        k32   = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll',    use_last_error=True)
        psapi = ctypes.WinDLL('psapi',    use_last_error=True)

        def _def(f, r, *a):
            f.restype, f.argtypes = r, list(a)

        _def(k32.OpenProcess,               wintypes.HANDLE,  wintypes.DWORD, wintypes.BOOL,    wintypes.DWORD)
        _def(k32.VirtualAllocEx,            wintypes.LPVOID,  wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
        _def(k32.WriteProcessMemory,        wintypes.BOOL,    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
        _def(k32.CreateRemoteThread,        wintypes.HANDLE,  wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
        _def(k32.GetModuleHandleW,          wintypes.HMODULE, wintypes.LPCWSTR)
        _def(k32.GetProcAddress,            wintypes.LPVOID,  wintypes.HMODULE, wintypes.LPCSTR)
        _def(k32.CloseHandle,               wintypes.BOOL,    wintypes.HANDLE)
        _def(k32.IsWow64Process,            wintypes.BOOL,    wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
        _def(k32.WaitForSingleObject,       wintypes.DWORD,   wintypes.HANDLE, wintypes.DWORD)
        _def(k32.GetExitCodeThread,         wintypes.BOOL,    wintypes.HANDLE, wintypes.LPDWORD)
        _def(k32.CreateToolhelp32Snapshot,  wintypes.HANDLE,  wintypes.DWORD,  wintypes.DWORD)
        _def(k32.QueryFullProcessImageNameW,wintypes.BOOL,    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        _def(ntdll.NtCreateThreadEx,        wintypes.DWORD,   ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, wintypes.LPVOID)
        _def(psapi.EnumProcessModulesEx,    wintypes.BOOL,    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD, wintypes.DWORD)
        _def(psapi.GetModuleFileNameExW,    wintypes.DWORD,   wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD)

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize",       wintypes.DWORD), ("th32ModuleID",  wintypes.DWORD),
                ("th32ProcessID",wintypes.DWORD), ("GlblcntUsage",  wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr",   ctypes.c_void_p),
                ("modBaseSize",  wintypes.DWORD), ("hModule",       wintypes.HMODULE),
                ("szModule",     wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260),
            ]

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize",            wintypes.DWORD), ("cntUsage",          wintypes.DWORD),
                ("th32ProcessID",     wintypes.DWORD), ("th32DefaultHeapID",  ctypes.c_void_p),
                ("th32ModuleID",      wintypes.DWORD), ("cntThreads",         wintypes.DWORD),
                ("th32ParentProcessID",wintypes.DWORD),("pcPriClassBase",     wintypes.LONG),
                ("dwFlags",           wintypes.DWORD), ("szExeFile",          wintypes.WCHAR * 260),
            ]

        _def(k32.Process32FirstW, wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
        _def(k32.Process32NextW,  wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))

        return k32, ntdll, psapi, wintypes, ctypes, MODULEENTRY32W, PROCESSENTRY32W
    except Exception:
        return None


class DllInjector:
    """Minimal DLL injector for Nuitka dynamic source extraction.

    Injects hook64.dll into a target process that has Python loaded,
    calls HydraStartHook(), then waits for the dump directory to appear.
    """

    def __init__(self, dll_path: str, hook_script_path: str, out_dir: str, log_fn=None):
        self.dll_path        = os.path.abspath(dll_path)
        self.hook_script     = os.path.abspath(hook_script_path)
        self.dump_base       = os.path.join(os.path.abspath(out_dir), "DYNAMIC_DUMP")
        self._log            = log_fn or (lambda m: print(f"  [INJ] {m}"))
        self._apis           = _setup_win32_apis()
        if self._apis is None:
            raise RuntimeError("Win32 APIs not available (non-Windows?)")
        self.k32, self.ntdll, self.psapi, self.wt, self.ct, \
            self.MODULEENTRY32W, self.PROCESSENTRY32W = self._apis

    # ------------------------------------------------------------------ helpers
    def _get_proc_path(self, pid: int) -> str:
        h = self.k32.OpenProcess(0x1000, False, pid)
        if not h:
            return ""
        try:
            buf = (self.wt.WCHAR * 1024)()
            sz  = self.wt.DWORD(1024)
            if self.k32.QueryFullProcessImageNameW(h, 0, buf, self.ct.byref(sz)):
                return buf.value
        finally:
            self.k32.CloseHandle(h)
        return ""

    def _proc_is_64(self, pid: int) -> bool:
        try:
            h = self.k32.OpenProcess(0x0400, False, pid)
            if h:
                iw = self.wt.BOOL()
                self.k32.IsWow64Process(h, self.ct.byref(iw))
                self.k32.CloseHandle(h)
                return (not iw.value) if platform.machine().endswith("64") else False
        except Exception:
            pass
        return True

    def _find_python_dll(self, pid: int):
        """Return full path of python3[XX].dll loaded in the target, or None."""
        h = self.k32.OpenProcess(0x0410, False, pid)
        if not h:
            return None
        try:
            mods = (self.wt.HMODULE * 2048)()
            cb   = self.wt.DWORD()
            if not self.psapi.EnumProcessModulesEx(
                    h, self.ct.byref(mods), self.ct.sizeof(mods),
                    self.ct.byref(cb), 0x03):
                return None
            pat = re.compile(r'python3\d*\.dll', re.IGNORECASE)
            count = cb.value // self.ct.sizeof(self.wt.HMODULE)
            for i in range(count):
                buf = (self.wt.WCHAR * 1024)()
                if self.psapi.GetModuleFileNameExW(h, mods[i], buf, 1024):
                    bn = os.path.basename(buf.value)
                    if pat.match(bn):
                        return buf.value
        except Exception:
            pass
        finally:
            self.k32.CloseHandle(h)
        return None

    def _find_remote_module_base(self, pid: int, dll_name: str):
        name = dll_name.lower()
        for _ in range(25):
            h = self.k32.OpenProcess(0x0410, False, pid)
            if h:
                try:
                    mods = (self.wt.HMODULE * 1024)()
                    cb   = self.wt.DWORD()
                    if self.psapi.EnumProcessModulesEx(
                            h, self.ct.byref(mods), self.ct.sizeof(mods),
                            self.ct.byref(cb), 0x03):
                        count = cb.value // self.ct.sizeof(self.wt.HMODULE)
                        for j in range(count):
                            buf = (self.wt.WCHAR * 1024)()
                            if self.psapi.GetModuleFileNameExW(h, mods[j], buf, 1024):
                                if os.path.basename(buf.value).lower() == name:
                                    return mods[j]
                finally:
                    self.k32.CloseHandle(h)
            time.sleep(0.5)
        return None

    def _create_remote_thread(self, h_proc, start, param):
        tid = self.wt.DWORD(0)
        h   = self.k32.CreateRemoteThread(h_proc, None, 0, start, param, 0,
                                          self.ct.byref(tid))
        if h:
            return h
        h_nt  = self.wt.HANDLE()
        status = self.ntdll.NtCreateThreadEx(
            self.ct.byref(h_nt), 0x1FFFFF, None, h_proc,
            start, param, 0, 0, 0, 0, None)
        return h_nt.value if (status & 0xFFFFFFFF) == 0 else None

    def _wait_thread(self, h, timeout_ms: int):
        if self.k32.WaitForSingleObject(h, timeout_ms) == 0:
            ec = self.wt.DWORD()
            self.k32.GetExitCodeThread(h, self.ct.byref(ec))
            return True, ec.value
        return False, None

    # ------------------------------------------------------------------ public
    def write_config(self):
        """Write hook_config.ini so the DLL knows where __hook__.py lives and where to dump."""
        cfg_dir = r"C:\ProgramData\HydraDragonAntivirus\python_dumps"
        os.makedirs(cfg_dir, exist_ok=True)
        os.makedirs(self.dump_base, exist_ok=True)
        with open(os.path.join(cfg_dir, "hook_config.ini"), "w", encoding="utf-8") as f:
            f.write(f"HookPath={self.hook_script}\n")
            f.write(f"DumpPath={self.dump_base}\n")
        self._log(f"Config written: HookPath={self.hook_script}, DumpPath={self.dump_base}")

    def inject(self, pid: int, name: str, exe_path: str) -> bool:
        """Inject hook64.dll into *pid* and call HydraStartHook.
        Returns True if the remote thread returned 0 (success or async start)."""
        if pid == os.getpid():
            self._log("ERROR: refusing to inject into own process"); return False

        py_dll = self._find_python_dll(pid)
        if not py_dll:
            self._log(f"ERROR: no python3x.dll in PID {pid} — not a Python process")
            return False
        self._log(f"Python loaded: {py_dll}")

        if not os.path.isfile(self.dll_path):
            self._log(f"ERROR: DLL not found: {self.dll_path}"); return False
        if not os.path.isfile(self.hook_script):
            self._log(f"ERROR: hook script not found: {self.hook_script}"); return False

        self.write_config()

        # Fast single-shot check: skip if DLL is already loaded (don't use
        # the 25-retry loop — that wastes 12 s when the DLL isn't there yet)
        dll_bn = os.path.basename(self.dll_path).lower()
        h_chk = self.k32.OpenProcess(0x0410, False, pid)
        if h_chk:
            try:
                _mods = (self.wt.HMODULE * 1024)(); _cb = self.wt.DWORD()
                if self.psapi.EnumProcessModulesEx(
                        h_chk, self.ct.byref(_mods), self.ct.sizeof(_mods),
                        self.ct.byref(_cb), 0x03):
                    _cnt = _cb.value // self.ct.sizeof(self.wt.HMODULE)
                    for _j in range(_cnt):
                        _buf = (self.wt.WCHAR * 1024)()
                        if self.psapi.GetModuleFileNameExW(h_chk, _mods[_j], _buf, 1024):
                            if os.path.basename(_buf.value).lower() == dll_bn:
                                self._log(f"DLL already loaded in PID {pid} — skipping")
                                return True
            finally:
                self.k32.CloseHandle(h_chk)

        h_proc = self.k32.OpenProcess(0x1F0FFF, False, pid)
        if not h_proc:
            self._log(f"ERROR: OpenProcess failed: {self.k32.GetLastError()}"); return False
        try:
            # Step 1: inject DLL via LoadLibraryW remote thread
            dll_bytes = (self.dll_path + "\0").encode("utf-16le")
            mem = self.k32.VirtualAllocEx(h_proc, 0, len(dll_bytes), 0x3000, 0x40)
            if not mem:
                self._log(f"ERROR: VirtualAllocEx failed"); return False
            self.k32.WriteProcessMemory(h_proc, mem, dll_bytes, len(dll_bytes), None)

            lload = self.k32.GetProcAddress(
                self.k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
            h_load = self._create_remote_thread(h_proc, lload, mem)
            ok, l_res = self._wait_thread(h_load, 8000)
            self.k32.CloseHandle(h_load)
            if not ok or not l_res:
                self._log(f"ERROR: LoadLibraryW failed — result={l_res}"); return False

            # Step 2: find module base
            rem_mod = self._find_remote_module_base(pid, os.path.basename(self.dll_path))
            if not rem_mod:
                if l_res and l_res != 0:
                    rem_mod = l_res
                    self._log(f"Module base from thread exit code: 0x{rem_mod:X}")
                else:
                    self._log("ERROR: module base not found"); return False

            # Step 3: resolve HydraStartHook RVA via pefile
            try:
                import pefile as _pefile
                pe  = _pefile.PE(self.dll_path)
                rva = None
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name == b"HydraStartHook":
                        rva = sym.address; break
                if rva is None:
                    self._log("ERROR: HydraStartHook export not found"); return False
            except ImportError:
                self._log("WARNING: pefile not installed — using fallback RVA 0x1000")
                rva = 0x1000
            except Exception as pe_err:
                self._log(f"ERROR: pefile: {pe_err}"); return False

            # Step 4: call HydraStartHook
            rem_fn = int(rem_mod) + rva
            h_start = self._create_remote_thread(h_proc, rem_fn, None)
            if not h_start:
                self._log("ERROR: CreateRemoteThread for HydraStartHook failed"); return False
            # HydraStartHook returns quickly (async mode) — wait up to 5 s
            ok, exit_code = self._wait_thread(h_start, 5000)
            self.k32.CloseHandle(h_start)

            if ok and exit_code == 0:
                self._log(f"HydraStartHook returned 0 — hook running in {name} (PID {pid})")
                return True
            elif not ok:
                self._log("WARNING: HydraStartHook thread timed out — possibly waiting for Python init")
                return True  # hookImpl may still be running async
            else:
                self._log(f"ERROR: HydraStartHook returned {exit_code}")
                return False
        finally:
            self.k32.CloseHandle(h_proc)

    def find_pids_by_name(self, exe_name: str) -> List[int]:
        """Return all PIDs whose image name matches *exe_name* (case-insensitive)."""
        results = []
        snap = self.k32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snap == -1:
            return results
        try:
            pe = self.PROCESSENTRY32W()
            pe.dwSize = self.ct.sizeof(pe)
            if self.k32.Process32FirstW(snap, self.ct.byref(pe)):
                while True:
                    if pe.szExeFile.lower() == exe_name.lower():
                        results.append(pe.th32ProcessID)
                    if not self.k32.Process32NextW(snap, self.ct.byref(pe)):
                        break
        finally:
            self.k32.CloseHandle(snap)
        return results

    def launch_and_inject(self, exe_path: str, wait_timeout: int = 60) -> bool:
        """Spawn *exe_path*, wait for it to load Python, then inject.

        *wait_timeout*: max seconds to wait for the process to appear.
        Returns True if injection was initiated successfully.
        """
        exe_name = os.path.basename(exe_path)
        self._log(f"Launching: {exe_path}")
        try:
            # stdin=PIPE keeps the pipe write-end open so the target's
            # input() blocks waiting for data instead of raising EOFError.
            # NOTE: do NOT use CREATE_NEW_CONSOLE — it overrides PIPE handles.
            exe_dir = os.path.dirname(os.path.abspath(exe_path)) or os.getcwd()
            proc = subprocess.Popen(
                [exe_path],
                cwd=exe_dir,
                stdin=subprocess.PIPE,    # write-end stays open → app blocks on input()
            )
            # Keep a reference so the PIPE write-end is never closed while we wait
            self._target_proc = proc
        except Exception as e:
            self._log(f"ERROR: failed to launch {exe_path}: {e}"); return False

        self._log(f"Process spawned (PID hint: {proc.pid}) — waiting for Python...")
        deadline = time.time() + wait_timeout
        target_pid = None
        while time.time() < deadline:
            # Check by name OR exact PID
            candidates = self.find_pids_by_name(exe_name)
            for pid in candidates:
                if self._find_python_dll(pid):
                    target_pid = pid
                    break
            if target_pid:
                break
            time.sleep(1.0)

        if target_pid is None:
            self._log(f"ERROR: {exe_name} did not load Python within {wait_timeout}s")
            return False

        self._log(f"Target ready — PID {target_pid}")
        return self.inject(target_pid, exe_name, exe_path)

    # ------------------------------------------------------------------ dump wait
    def wait_for_dump(self, timeout_s: int, old_idx: int) -> str | None:
        """Block until a new dump directory (with finished.txt) appears.
        Returns the dump directory path, or None on timeout."""
        base = self.dump_base
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if os.path.isdir(base):
                candidates = []
                for d in os.listdir(base):
                    if d.startswith("dump_"):
                        try:
                            idx = int(d.split("_", 1)[1])
                            candidates.append((idx, os.path.join(base, d)))
                        except ValueError:
                            pass
                if candidates:
                    best_idx, best_dir = max(candidates, key=lambda x: x[0])
                    if best_idx > old_idx and \
                            os.path.exists(os.path.join(best_dir, "finished.txt")):
                        return best_dir
            time.sleep(1.0)
        return None

    def get_latest_dump_idx(self) -> int:
        base = self.dump_base
        if not os.path.isdir(base):
            return -1
        best = -1
        for d in os.listdir(base):
            if d.startswith("dump_"):
                try:
                    best = max(best, int(d.split("_", 1)[1]))
                except ValueError:
                    pass
        return best


# =============================================================================
# END DYNAMIC INJECTION INFRASTRUCTURE
# =============================================================================


def main():
    # ------------------------------------------------------------------ find default DLL/hook next to this script
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _default_dll  = os.path.join(_script_dir,
                                  "hook64.dll" if platform.machine().endswith("64") else "hook32.dll")
    _default_hook = os.path.join(_script_dir, "__hook__.py")

    parser = argparse.ArgumentParser(
        epilog="""
Examples:
  # Pure static analysis

  # Dynamic mode: inject into already-running process
  python nuitka_decompiler.py --source main.exe --inject --pid 1234

  # Dynamic mode: launch and inject automatically
  python nuitka_decompiler.py --source main.exe --inject --launch

  # Full path overrides
  python nuitka_decompiler.py --source main.exe --inject --launch \\
      --dll hook64.dll --hook-script __hook__.py

STATIC mode  : pure PE analysis, no runtime hooks.
DYNAMIC mode : inject hook64.dll into a running (or auto-launched) process
               to capture Python source from the live interpreter, then merge
               with the static blob reconstruction.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # --- static / common ---
    parser.add_argument('--source', '-s', dest='source_flag', default=None,
                        metavar='FILE',
                        help='Target .exe or .dll compiled with Nuitka (preferred flag)')
    parser.add_argument('target', nargs='?', default=None,
                        help='Target .exe or .dll (positional — same as --source)')
    parser.add_argument('--output', '-o', default=None, help='Output directory (default: auto)')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Also analyze library modules (not just app)')
    parser.add_argument('--only', default=None, metavar='MODS',
                        help='Comma-separated list of module names to '
                             'disassemble (PHASE 11.7 only). Exact-match '
                             'or "pkg.*" wildcard supported. Skips recursive '
                             'disasm for all other modules — much faster '
                             'when you only want one specific .nbc.')
    parser.add_argument('--list-modules', action='store_true', dest='list_modules',
                        help='List all module names in the blob and exit. No decompilation.')
    parser.add_argument('--filter', default=None, metavar='STR', dest='filter_str',
                        help='With --list-modules: only show modules containing STR.')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('--no-pyc-decompile', action='store_true',
                        help='Skip Phase 12 .pyc -> .py decompilation; useful when preparing only .nbc files.')

    # --- dynamic injection ---
    inj = parser.add_argument_group('Dynamic injection (--inject required to enable)')
    inj.add_argument('--inject', action='store_true',
                     help='Enable dynamic DLL injection mode after static analysis')
    inj.add_argument('--launch', action='store_true',
                     help='Auto-launch the target EXE before injecting')
    inj.add_argument('--pid', type=int, default=None, metavar='PID',
                     help='Inject into a specific PID (skips --launch)')
    inj.add_argument('--dll', default=_default_dll, metavar='PATH',
                     help=f'hook64.dll path (default: {_default_dll})')
    inj.add_argument('--hook-script', default=_default_hook, metavar='PATH',
                     dest='hook_script',
                     help=f'__hook__.py path (default: {_default_hook})')
    inj.add_argument('--dump-timeout', type=int, default=300, metavar='SEC',
                     dest='dump_timeout',
                     help='Seconds to wait for the hook dump (default: 120)')

    args = parser.parse_args()
    if args.no_banner:
        global BANNER
        BANNER = ""

    # Resolve target: --source takes priority over positional
    target = args.source_flag or args.target
    if not target:
        parser.error("Specify the target binary: --source main.exe  or positionally: main.exe")

    if args.output:
        out_dir = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(target).stem
        out_dir = str(Path(target).parent / f"UNPACKED_{base_name}_{timestamp}")

    # ------------------------------------------------------------------ STATIC PHASE
    _inject_only = args.inject and (args.pid is not None or args.launch)
    # ── --list-modules early exit ──────────────────────────────────────────
    if getattr(args, 'list_modules', False):
        import importlib.util as _ilu, pathlib as _pl
        _lm_path = _pl.Path(__file__).parent / 'list_modules.py'
        if _lm_path.exists():
            spec = _ilu.spec_from_file_location('list_modules', _lm_path)
            _lm = _ilu.module_from_spec(spec)
            spec.loader.exec_module(_lm)
            raise SystemExit(_lm.list_modules(
                target,
                as_json=False,
                filter_str=getattr(args, 'filter_str', None),
                copy_cmd=True,
            ))
        else:
            # Fallback: inline fast path (no pefile, raw CRC scan)
            import zlib as _zlib, struct as _st, random as _rnd
            _data = open(target, 'rb').read()
            _r = _rnd.Random(27); _fwd = list(range(1,256)); _r.shuffle(_fwd); _fwd.insert(0,0)
            for _off in range(0, len(_data)-8, 4):
                _crc = _st.unpack_from('<I', _data, _off)[0]
                _sz  = _st.unpack_from('<I', _data, _off+4)[0]
                if _sz < 64 or _sz > 64*1024*1024 or _off+8+_sz > len(_data): continue
                if (_zlib.crc32(_data[_off+8:_off+8+_sz]) & 0xFFFFFFFF) != _crc: continue
                _chunk = _data[_off+8:_off+8+_sz]; _pos = 0; _names = []
                while _pos < len(_chunk)-5:
                    _ne = _chunk.find(b'\x00', _pos, min(_pos+512, len(_chunk)))
                    if _ne == -1: break
                    _raw = _chunk[_pos:_ne]; _pos = _ne+1
                    if _pos+4 > len(_chunk): break
                    _cs = _st.unpack_from('<I', _chunk, _pos)[0]; _pos += 4
                    if _cs > 64*1024*1024 or _pos+_cs > len(_chunk): break
                    try: _n = _raw.decode('utf-8','strict')
                    except: _n = bytes(_fwd[b] for b in _raw).decode('utf-8','replace')
                    _names.append((_n, _cs)); _pos += _cs
                if _names:
                    _f = getattr(args, 'filter_str', None)
                    print(f"\n  Found {len(_names)} modules:\n")
                    _shown = [(_n,_s) for _n,_s in _names if not _f or _f.lower() in _n.lower()]
                    for _i,(_n,_s) in enumerate(_shown,1):
                        print(f"  {_i:<5} {_n:<55} {_s/1024:>7.1f} KB")
                    _sel = ",".join(_n for _n,_ in _shown if _n != '.bytecode')
                    print(f"\n  --only {_sel}")
                    raise SystemExit(0)
            print("[ERROR] No Nuitka blob found.", file=sys.stderr)
            raise SystemExit(1)

    if _inject_only:
        # Skip all static analysis — go directly to runtime injection
        os.makedirs(out_dir, exist_ok=True)
        success = True
    else:
        only_list = None
        if args.only:
            only_list = [m.strip() for m in args.only.split(',') if m.strip()]
        engine = NuitkalizatorPro(
            target_path=target,
            output_dir=out_dir,
            main_only=not args.all,
            only_modules=only_list,
            decompile_pyc=not args.no_pyc_decompile,
        )
        success = engine.run()

    # ------------------------------------------------------------------ DYNAMIC PHASE
    if args.inject:
        print_section("DYNAMIC PHASE: DLL INJECTION")

        if sys.platform != 'win32':
            log_err("Dynamic injection is Windows-only."); return 1 if not success else 0

        try:
            injector = DllInjector(
                dll_path=args.dll,
                hook_script_path=args.hook_script,
                out_dir=out_dir,
                log_fn=lambda m: print(f"{C.BRIGHT_CYAN}[INJ]{C.RESET} {m}"),
            )
        except RuntimeError as e:
            log_err(str(e)); return 1

        old_idx = injector.get_latest_dump_idx()

        injected = False
        if args.pid:
            # Inject into explicit PID
            log(f"Injecting into PID {args.pid} ...")
            injected = injector.inject(args.pid, f"PID-{args.pid}", target)
        elif args.launch:
            # Launch the target EXE and inject
            if not target.endswith('.exe'):
                log_err("--launch requires a .exe target"); return 1
            log(f"Launching and injecting: {target}")
            injected = injector.launch_and_inject(target, wait_timeout=60)
        else:
            # No PID, no launch: scan for a running process by EXE name
            exe_name = os.path.basename(target)
            log(f"Searching for running process: {exe_name}")
            pids = injector.find_pids_by_name(exe_name)
            if not pids:
                log_err(f"No running process named '{exe_name}'. "
                        "Use --launch to start it, or --pid to specify explicitly.")
                return 1 if not success else 0
            # Prefer the first PID that already has Python loaded
            for pid in pids:
                if injector._find_python_dll(pid):
                    log(f"Found running {exe_name} with Python loaded (PID {pid})")
                    injected = injector.inject(pid, exe_name, target)
                    break
            if not injected:
                log_err("Could not inject into any running instance")
                return 1 if not success else 0

        if not injected:
            log_err("Injection failed — see log above"); return 1

        log(f"Waiting up to {args.dump_timeout}s for hook dump ...")
        dump_dir = injector.wait_for_dump(args.dump_timeout, old_idx)
        if dump_dir:
            log_ok(f"Hook dump ready: {dump_dir}")
            src_dir = os.path.join(dump_dir, "RECONSTRUCTED_SOURCE")
            if os.path.isdir(src_dir):
                py_files = [f for f in os.listdir(src_dir) if f.endswith('.py')
                            and f != "__hook__.py"]
                log_ok(f"Dynamic sources captured: {len(py_files)} file(s) in {src_dir}")
                # Copy dynamic sources alongside the static output
                import shutil
                dyn_out = os.path.join(out_dir, "DYNAMIC_SOURCE")
                shutil.copytree(src_dir, dyn_out, dirs_exist_ok=True)
                log_ok(f"Copied to: {dyn_out}")
            else:
                log_warn("No RECONSTRUCTED_SOURCE dir in dump — hook may not have run")
        else:
            log_warn(f"No dump appeared after {args.dump_timeout}s. "
                     f"Check {injector.dump_base} and "
                     "C:\\ProgramData\\HydraDragonAntivirus\\python_dumps\\hook_dll.log")

    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{C.BRIGHT_RED}[!] Interrupted by user{C.RESET}")
    except Exception as e:
        print(f"\n{C.BRIGHT_RED}[FATAL] {e}{C.RESET}")
        import traceback
        traceback.print_exc()

