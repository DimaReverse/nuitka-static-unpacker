# Architecture

The entire tool is implemented in `nuitka_decompiler.py` (~10,000 lines). This document maps out the major components and how data flows through them.

---

## Extraction pipeline (static mode)

```
target.exe / target.dll
        │
        ▼
   PE Analysis
   (Python version from imports, edition detection)
        │
        ▼
   Blob Extraction
   (PE resources → __constants_data / __nuitka_constants)
        │
        ▼
   CommercialBypass          ← only if blob is encrypted
   (locate _mapping[], d0-d7 in PE .text/.rdata,
    brute-validate combinations with CRC32,
    decrypt blob in place)
        │
        ▼
   NuitkaBlobDecoder
   (parse named module chunks, unpack constant tags,
    reconstruct code object metadata)
        │
        ▼
   NuitkaModuleTableParser
   (scan .data/.rdata for module name/flag/blob-index table)
        │
        ▼
   NuitkaStaticDisassembler
   (walk code object trees, extract function signatures,
    argument names, line numbers, nested code objects)
        │
        ▼
   OmniDecompiler
   (try decompiler backend chain: pycdc → pycdas →
    decompyle3 → uncompyle6 → decompile3 → pylingual → dis)
        │
        ▼
   NuitkaCompactEmitter / StaticalySmartReconstructor
   (write per-module artifacts, secrets scan, REPORT.json)
```

---

## Key classes

### `CommercialBypass`

Handles detection and decryption of Nuitka Commercial's `data-hiding` plugin output.

**Detection**: checks whether `CRC32(payload) == stored_crc`. Mismatch → encrypted.

**Key extraction**: scans PE sections for the 256-byte `_mapping[]` table and the 8-byte digest `d0`–`d7`. Both are hardcoded in the binary. Module names use a separate `_mapping2` always seeded with `Random(27)` — recoverable without the binary.

**Decryption strategy**: try all `_mapping` candidates × all `d0–d7` candidates, validate each with CRC32 before accepting.

### `NuitkaBlobDecoder`

Parses the decrypted (or plaintext) blob into named module chunks. Handles Nuitka constant tag format: type tags, recursive structures, code objects, strings, numbers, tuples, dicts, sets, frozensets.

### `NuitkaModuleTableParser`

Scans PE `.data` and `.rdata` sections for the Nuitka module registration table (module names, flags, blob index). Works by pattern-matching the expected table layout.

### `NuitkaCSourceRebuilder`

Reconstructs a C-level structural view from the parsed module/blob data. Useful for understanding how the compiled binary maps back to Python package structure.

### `OmniDecompiler`

Wraps all decompiler backends behind a uniform interface. Each backend is tried in priority order; failures are caught and the next backend is tried. Produces the best available `.py` output per module.

### `NuitkaStaticDisassembler`

Recursively walks code object trees extracted from the blob. Extracts: function names, argument counts and names, line number tables, nested functions and classes, default values.

### `NuitkaCompactEmitter`

Writes structured per-module output: `constants.json`, `code_objects.json`, `.pyc`, `.py` (if decompiled), and feeds the global report.

### `StaticalySmartReconstructor`

Higher-level reconstruction pipeline. Applies heuristics to improve recovered structure: module hierarchy inference, import reconstruction, partial source scaffolding.

### `NuitkalizatorPro`

Main engine. Coordinates all phases in order, owns the `REPORT.json` accumulator, writes the final summary.

### `DllInjector` (Windows only)

Injects a hook DLL into a live process that has Python loaded. Calls `HydraStartHook()`, then polls for the dump directory. Copied dump goes to `DYNAMIC_SOURCE/` alongside static output.

---

## Suggested refactor (future)

The monolithic structure made iteration fast during research. A cleaner split for v2:

```
nuitka_decompiler/
  __main__.py         ← cli entry point
  core/
    pe.py             ← PE analysis, blob extraction
    bypass.py         ← CommercialBypass
    blob.py           ← NuitkaBlobDecoder, tag parsing
    module_table.py   ← NuitkaModuleTableParser
    code_objects.py   ← NuitkaStaticDisassembler
  decompilers/
    backends.py       ← individual backend wrappers
    omni.py           ← OmniDecompiler
  emitters/
    artifacts.py      ← NuitkaCompactEmitter
    report.py         ← JSON report writer
    secrets.py        ← secrets scanner
  dynamic/
    injector.py       ← DllInjector
  utils/
    colors.py
    progress.py
    logging.py
```
