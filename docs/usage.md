# Usage

Use this tool only on binaries you own, are authorized to inspect, or are
handling for legitimate defensive research.

## Prerequisites

- Python 3.8+
- `pefile` (required)
- Optional: `capstone`, `xdis`, decompiler backends (see `requirements.txt`)

## Basic usage

```bash
python nuitka_decompiler.py --source authorized_target.exe
```

Output goes to `./output/` by default.

## Flags reference

| Flag | Short | Description |
|------|-------|-------------|
| `--source PATH` | `-s` | Authorized target `.exe` or `.dll` (required) |
| `--output DIR` | `-o` | Output directory (default: `./output`) |
| `--all` | `-a` | Include stdlib/library modules (default: main module only) |
| `--only MODULES` | | Comma-separated list of module names or `pkg.*` glob patterns to restrict recursive disassembly to |
| `--no-banner` | | Suppress the ASCII banner |
| `--inject` | | Enable dynamic DLL injection after static analysis (authorized lab use only) |
| `--launch` | | Launch the target EXE before injecting |
| `--pid PID` | | Inject into a specific authorized running PID |
| `--dll PATH` | | Path to custom hook DLL (default: `hook64.dll` in script dir) |
| `--hook-script PATH` | | Path to hook Python script |
| `--dump-timeout N` | | Seconds to wait for dynamic dump (default: 60) |

## Examples

### Analyze a target, include all modules, custom output dir

```bash
python nuitka_decompiler.py -s authorized_target.exe -a -o ./analysis_out
```

### Restrict to one package and its submodules

```bash
python nuitka_decompiler.py -s authorized_target.exe --only myapp,myapp.*
```

### Static analysis + dynamic injection in one pass

```bash
python nuitka_decompiler.py -s authorized_target.exe -a --inject --launch
```

### Inject into already-running process

```bash
python nuitka_decompiler.py -s authorized_target.exe --inject --pid 5432
```

## Understanding the output

After a successful run, the output directory will contain:

```
output/
├── REPORT.json                 ← Full summary: modules, stats, secrets
├── secrets.txt                 ← Potential credentials / keys found
│
├── main_module/
│   ├── constants.json          ← All extracted constants (recursive)
│   ├── code_objects.json       ← Function signatures, arg names, line numbers
│   ├── main_module.pyc         ← Raw bytecode blob
│   └── main_module.py          ← Decompiled source (if a backend succeeded)
│
├── other_module/
│   └── ...
│
└── DYNAMIC_SOURCE/             ← Only present if --inject was used
    └── *.py                    ← Live-captured Python source
```

### REPORT.json fields

```json
{
  "target": "app.exe",
  "timestamp": "2026-04-23T...",
  "python_version": "3.11",
  "nuitka_edition": "commercial",
  "encrypted": true,
  "modules": [ ... ],
  "bytecode_count": 42,
  "secrets": [ ... ],
  "code_objects": [ ... ],
  "stats": { ... }
}
```

## Troubleshooting

**`pefile not found`** — run `pip install pefile`

**`Blob not found`** — the tool scans PE resources and embedded sections. Some unusual Nuitka builds embed the blob differently. Open an issue with the Nuitka version.

**`CRC mismatch after all bypass attempts`** — could be an unsupported commercial encryption variant. Open an issue with the Nuitka version and sanitized error output; do not post proprietary bytes, secrets, or private samples publicly.

**Decompiler backends all fail** — the raw `.pyc` is still extracted. You can try decompiling it manually with any compatible tool.

**Windows crash dialogs from pycdc** — the tool suppresses these via `SetErrorMode`. If you still see them, run with `--no-banner` and check if the issue reproduces.
