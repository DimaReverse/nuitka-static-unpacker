<div align="center">

```
 _   _       _ _   _         _ _          _             
| \ | |_   _(_) |_| | ____ _| (_)______ _| |_ ___  _ __ 
|  \| | | | | | __| |/ / _` | | |_  / _` | __/ _ \| '__|
| |\  | |_| | | |_|   < (_| | | |/ / (_| | || (_) | |   
|_| \_|\__,_|_|\__|_|\_\__,_|_|_/___\__,_|\__\___/|_|   
```

**Nuitka Static Unpacker · Authorized Nuitka binary analysis · Pure Python**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Lines](https://img.shields.io/badge/lines%20of%20code-10%2C000%2B-orange?style=flat-square)](nuitka_decompiler.py)
[![Nuitka](https://img.shields.io/badge/nuitka-1.x%20–%204.0-purple?style=flat-square)](https://nuitka.net)
[![Status](https://img.shields.io/badge/status-active%20research-brightgreen?style=flat-square)]()

*Analyze authorized Nuitka-compiled Python binaries and extract constants, module metadata, and bytecode artifacts — with a single script.*

</div>

---

## What is this?

**Nuitka Static Unpacker** is a *static-first* analysis tool for Python binaries compiled with [Nuitka](https://nuitka.net/). It extracts constants, module structures, code object metadata, and `.pyc` artifacts from Nuitka builds you own or are authorized to inspect — and includes research-grade handling for Nuitka Commercial `data-hiding` metadata when present.

It can also optionally switch to a **dynamic mode** via DLL injection for controlled lab analysis of processes you are allowed to instrument.

This project is independent and is not affiliated with, endorsed by, or maintained by the Nuitka project.

---

## Responsible use

This repository is published for legitimate reverse engineering, interoperability research, malware analysis, defensive security work, and education.

Use it only on software you own, software you have explicit permission to analyze, malware/suspicious samples handled for defensive purposes, or CTF/lab targets where reverse engineering is expected.

Do **not** use it to bypass licenses, defeat DRM/access controls, recover proprietary source without permission, extract secrets for unauthorized access, or violate software licenses, contracts, platform terms, or local law. This is not legal advice; if a target is not clearly authorized, do not analyze it.

See [`ETHICS.md`](ETHICS.md) for the detailed responsible-use policy.

---

## Use cases

- **Malware analysis / DFIR**: extract embedded `.pyc`, strings/constants, and module structure from suspicious Nuitka-packed samples.
- **Authorized security audits**: quickly inventory hardcoded secrets, URLs, tokens, and configuration shipped inside compiled binaries.
- **CTFs / training challenges**: recover bytecode and high-level structure for reversing challenges compiled with Nuitka.
- **Interoperability research**: understand how a Nuitka binary maps back to Python packages/modules and code objects.
- **Regression / build verification**: compare extracted constants/modules across builds to detect unexpected changes.
- **Triage before deeper reversing**: get a fast static report (`REPORT.json`, constants dumps) before opening IDA/Ghidra.

---

## Quick start

### Supported targets

This tool works with:
- **`.exe` files** compiled with Nuitka (any edition: open-source or commercial)
- **`.dll` files** compiled with Nuitka — common in modern Nuitka builds where the entry point is packaged as a DLL
- Both standard Nuitka and Nuitka Commercial (with data-hiding encryption)
- **Nuitka versions 1.x through 4.0** — including Nuitka Commercial 4.0.6 (verified)

Analysis mode is identical regardless of file type — just pass `--source target.dll` instead of `.exe`.

### Important (onefile targets)

If your authorized target is a **Nuitka onefile** executable, analyze the inner Nuitka payload rather than the outer launcher. Depending on the wrapper, you may need to extract the embedded payload first:

| Outer protection | Extraction tool |
|---|---|
| Plain Nuitka onefile (no packer) | [nuitka-extractor](https://github.com/extremecoders-re/nuitka-extractor) |
| **Themida / WinLicense** + Nuitka onefile | [nuitka-themida-unpacker](https://github.com/DimaReverse/nuitka-themida-unpacker) ← companion repo, for owned/authorized targets only |

If you skip this step, you may hit:

```text
PHASE 2: CONSTANTS BLOB EXTRACTION ||
=================================================================
[!!] Blob not found in RT_RCDATA, searching for static embedding...
[!!] Constants blob not found!
```

```bash
pip install -r requirements.txt
python nuitka_decompiler.py --source authorized_target.exe
```

More examples and the full flag reference: [`docs/usage.md`](docs/usage.md).

---

## What's new in v7.4

### Update: faster `.nbc` generation with `--nbc-only`

v7.4 adds a focused fast path for AI-ready NBC generation. When your next step
is source reconstruction from `.nbc`, use `--nbc-only` to skip the slower
classic-analysis phases and write only the handoff bundle:

```bash
python nuitka_decompiler.py --source authorized_target.exe --list-modules --filter myapp
python nuitka_decompiler.py --source authorized_target.exe --output OUT --only myapp,myapp.* --nbc-only
```

`--nbc-only` still extracts the constants blob, parses the Nuitka module table,
decodes selected module constants, disassembles selected compiled modules, and
writes `OUT/AI_READY_NBC/`. It skips embedded-source scans, `.pyc` extraction,
heuristic `.py` output, C-source output, secrets reports, `.nuitka_const`
dumps, and `.pyc -> .py` decompilation.

The v7.4 path also reduces overhead by suppressing the full 1700+ module log in
NBC-only mode and by limiting runtime-helper prepass work to the selected
modules plus a small context sample.

Real benchmark on `main.exe` from this repo:

| Selection | Output | Time | Result |
|---|---:|---:|---|
| `__main__,modules.worker` | 2 `.nbc` | `151.09s` | 2/2 with `@OPS` |
| `__main__,modules,modules.*,vendor,vendor.*` | 32 `.nbc` | `215.19s` | 32/32 with `@OPS` |

For comparison, the same 32-module focused NBC generation before `--nbc-only`
took about `307s`. The startup cost is still significant because the PE, blob,
module list, and loader table must be parsed once; after that, adding more
selected modules is much cheaper than the first module.

---

## What's new in v7.3

### Update: AI-ready NBC/2 reconstruction bundle

The static pipeline now emits self-contained `.nbc` files intended for
maximum-fidelity source reconstruction by an LLM or a human reverse engineer.
These files are the best handoff format for source rebuilding because they keep
the decoded constants, module metadata, code object metadata, native evidence,
and provenance together in one text artifact.

The clean handoff directory is:

```text
OUT/
|-- AI_READY_NBC/
|   |-- nbc/                  # primary .nbc files to feed to the AI
|   |-- context/              # REPORT, module table, runtime helpers, manifests
|   |-- NBC_MANIFEST.json     # file list, hashes, has_ops/has_no_ops status
|   `-- README_AI.md
```

Recommended focused workflow:

```bash
python nuitka_decompiler.py --source authorized_target.exe --list-modules --filter myapp
python nuitka_decompiler.py --source authorized_target.exe --output OUT --only myapp,myapp.* --no-pyc-decompile
```

`--no-pyc-decompile` skips the classic `.pyc -> .py` backend phase and keeps the
run focused on the richer NBC/LLM evidence bundle. For the fastest NBC-only
workflow, use the v7.4 `--nbc-only` mode above.

Each `NBC/2` file can include:

- full decoded `@CONSTS` with untruncated Python `repr()` values
- `@RAW_CHUNK` with base64 of the original Nuitka constants chunk
- loader-table metadata in `@MODULE_TABLE`
- `@CODE_OBJECTS`, `@BLOCKS`, `@OPS`, and annotated native `@ASM`
- `@FORENSICS` evidence for functions whose bodies were not reached

#### Rebuilding source with an LLM and the skill

Use this flow for authorized samples where you want the highest-fidelity Python
reconstruction possible:

1. List modules first, then pick only the package or files you actually need.
2. Generate the AI bundle with `--output OUT --only package,package.* --nbc-only` on v7.4, or `--output OUT --only package,package.* --no-pyc-decompile` on v7.3.
3. Open `OUT/AI_READY_NBC/NBC_MANIFEST.json` and prioritize entries with `"has_ops": true`.
4. Feed the LLM one `.nbc` file at a time from `OUT/AI_READY_NBC/nbc/`.
5. Add optional context files from `OUT/AI_READY_NBC/context/`, especially `REPORT.json`, `NUITKA_MODULE_TABLE.txt`, `NUITKA_RUNTIME_HELPERS.txt`, `_MANIFEST.json`, and `BYTECODE_MANIFEST.json` when present.
6. Give the LLM the rebuilder instructions from `nuitka-nbc-rebuilder-skill/SKILL.md`, or use the standalone prompt in `nuitka-nbc-rebuilder-skill/PROMPT.md`.
7. Ask for evidence-backed Python and require uncertain spans to stay marked as `# UNCERTAIN`.
8. Review every `# UNCERTAIN` marker manually before treating the rebuilt file as source-equivalent.

For a package, rebuild in dependency order when possible: `__init__`, config and
utility modules, core modules, then the entrypoint. For large targets, avoid
passing the whole bundle at once; use the manifest plus `--only` to keep each LLM
job small and auditable.

Minimal prompt:

```text
Rebuild this NBC module into Python with maximum fidelity.
Use only evidence from @CONSTS, @OPS, @ASM, @FORENSICS and the provided context files.
Mark unsupported spans with # UNCERTAIN.
```

**Important accuracy note:** no static Nuitka decompiler can guarantee a
perfect 1:1 reproduction of the original `.py` file in every case. Comments,
formatting, some local variable names, and optimized/inlined control flow may
be unrecoverable. The `.nbc` format is designed to maximize evidence and make
an AI mark uncertain spans explicitly instead of fabricating code.

- **`list_modules.py`** — standalone script: lists every module inside a binary in ~1 second, zero decompilation, zero output files
- **`--list-modules` flag** — same functionality directly inside `nuitka_decompiler.py`
- **`--filter STR`** — narrow the module list to names containing a string
- **`--copy-cmd`** — prints a ready-to-paste `--only` command at the end

### Workflow: pick only the .nbc files you want

Instead of waiting for the full pipeline to process every module, you can now inspect the module list first and decompile only what you actually need:

```bash
# Step 1 — list all modules in ~1 second
python list_modules.py authorized_target.exe

# Step 2 — filter by name
python list_modules.py authorized_target.exe --filter myapp

# Step 3 — get a ready-to-paste command
python list_modules.py authorized_target.exe --filter myapp --copy-cmd
# Output:  python nuitka_decompiler.py --source authorized_target.exe --only myapp,myapp.utils

# Step 4 — decompile only those modules, skip everything else
python nuitka_decompiler.py --source authorized_target.exe --only myapp,myapp.utils
```

Or without the separate script, directly inside the main tool:

```bash
python nuitka_decompiler.py --source authorized_target.exe --list-modules
python nuitka_decompiler.py --source authorized_target.exe --list-modules --filter config
```

---

## Documentation

- [`docs/usage.md`](docs/usage.md) — CLI flags, examples, troubleshooting
- [`docs/architecture.md`](docs/architecture.md) — pipeline + key components
- [`docs/nuitka_blob_format.md`](docs/nuitka_blob_format.md) — constants blob format notes
- [`docs/roadmap.md`](docs/roadmap.md) — roadmap / known gaps
- [`nuitka-nbc-rebuilder-skill/`](nuitka-nbc-rebuilder-skill/) - LLM skill and prompt for rebuilding Python from AI-ready `.nbc` files

---

## The story behind this project

I started building this project in 2023, during one of the hardest periods of my life.

At the time, I was dealing with severe isolation and a constant feeling of being misunderstood. I had been diagnosed on the autism spectrum, but instead of receiving support that matched my actual abilities, I was often treated as if I were incapable.

I was pushed into programs designed for people with significantly different needs than mine, placed in environments where I didn't belong, and repeatedly told — directly and indirectly — that I wouldn't be able to work, live independently, or even get a driver's license.

On top of that, I had to deal with ongoing medical and administrative processes (including support/guardianship-style arrangements) that left me feeling like pieces of my autonomy were being taken away day by day — through pressure, conditional "help", and situations where saying "no" didn't feel like a real option.

At school, things weren't better. I experienced heavy and persistent bullying, to the point where attending classes became extremely difficult. Over time, I stopped going regularly and was no longer able to complete my final year in the standard way.

Outside of school, my social life almost disappeared. I lost most of my friends and spent long periods of time alone. Many nights were spent online, playing games with older people simply because they treated me with more respect than people my own age.

During that time, I didn't have much — but I had a computer and an internet connection.

I started diving deep into how software works internally. What began as curiosity turned into an obsession: reading PE formats, analyzing compiled binaries, experimenting with reverse engineering, and slowly understanding how Nuitka transforms Python code into something that looks almost unreadable.

This project didn't come from a structured plan.  
It came from persistence.

Each small step — extracting one more constant, understanding one more structure, improving the tool slightly — felt like progress in a moment where everything else felt stuck.

Over time, this turned into a serious, multi-year effort.  
Multiple rewrites, failed attempts, and long nights of trial and error eventually led to what is now version 7.4.

Today, I'm in a different phase of my life.  
I'm working towards finishing my studies, building independence, and continuing to grow in the field of reverse engineering and software security — despite everything I was told I wouldn't be able to do.

Open-sourcing this project is part of that process.

It's a way to share something real that came out of a difficult period, and to connect with people who are interested in understanding how software truly works under the surface.

If this project helps you, or if you build something on top of it, that means more than you might think.

— dimareverse

---

## Features

- **Single-file tool**: everything lives in `nuitka_decompiler.py` (no package install required beyond Python deps).
- **Static-first analysis**: PE parsing, Python version detection, constants/blob discovery and decoding.
- **Commercial `data-hiding` metadata support (static)**: includes a research implementation that can normalize supported protected constants metadata for authorized analysis.
- **Module table parsing**: recovers module list/metadata from PE sections when available.
- **Fast module listing**: `list_modules.py` / `--list-modules` — see all module names in ~1 second without running the full pipeline.
- **`.pyc` extraction**: recovers bytecode and writes per-module artifacts.
- **Code object map**: function signatures / args / line metadata (where recoverable).
- **AI-ready NBC/2 bundle**: writes self-contained `.nbc` evidence files plus a rebuilder skill workflow for LLM-assisted source reconstruction.
- **NBC-only fast path**: `--nbc-only` writes `AI_READY_NBC` without slower `.pyc`, source, C-output, and secrets phases.
- **Secrets scanner**: finds likely passwords/keys/URLs in extracted constants.
- **Multi-backend decompilation**: tries multiple decompilers and falls back gracefully.
- **JSON report**: writes a global `REPORT.json` plus per-module outputs.
- **Optional dynamic mode (Windows)**: DLL injection workflow for controlled lab analysis of owned/authorized processes.

**Compatibility:** tested and verified against **Nuitka 4.0.6** (open-source and Commercial editions). The blob format, constant tag set, CodeObject structure, and `data-hiding` encryption algorithm are all confirmed compatible. Older versions (1.x–3.x) remain supported as before.

### Research note: Commercial `data-hiding` handling

Nuitka Commercial's `data-hiding` plugin encrypts the constants blob using:
- A **substitution cipher** with a 256-byte `_mapping[]` table hardcoded in the binary
- **XOR** with a running counter + MD5 digest feedback (`d0`–`d7`, also hardcoded)
- Module names obfuscated with a second mapping seeded with `Random(27)` — always reconstructible without the binary

For authorized targets, the tool locates the relevant metadata in the PE's `.text`/`.rdata` sections, validates candidates with CRC32, and normalizes the blob before parsing.

---

## Companion repos

| Repo | What it does |
|---|---|
| [nuitka-themida-unpacker](https://github.com/DimaReverse/nuitka-themida-unpacker) | Pipeline for owned/authorized targets protected with **Themida/WinLicense + Nuitka onefile**: extracts the embedded payload and feeds it here |
| [nuitka-extractor](https://github.com/extremecoders-re/nuitka-extractor) | Unpacks plain Nuitka onefile executables (no Themida) |

---

## Supported decompiler backends

The tool tries these in order, falling back gracefully:

- [`pycdc`](https://github.com/zrax/pycdc) (external CLI)
- [`pycdas`](https://github.com/zrax/pycdc) (disassembly fallback)
- [`decompyle3`](https://github.com/rocky/python-decompile3)
- [`uncompyle6`](https://github.com/rocky/python-uncompyle6)
- [`decompile3`](https://github.com/rocky/decompile3)
- [`pylingual`](https://pylingual.io/) (API-based)
- Built-in `dis` module (always available)

---

## Installation

```bash
git clone https://github.com/DimaReverse/nuitka-static-unpacker.git
cd nuitka-static-unpacker
pip install -r requirements.txt
```

Optional: install external decompiler backends for best results:
```bash
pip install uncompyle6 decompyle3 decompile3
# For pycdc/pycdas: build from source or grab a release from https://github.com/zrax/pycdc
```

---

## Usage

### Basic static analysis

```bash
python nuitka_decompiler.py --source authorized_target.exe
```

### Include all library modules (not just main)

```bash
python nuitka_decompiler.py --source authorized_target.exe --all
```

### Custom output directory

```bash
python nuitka_decompiler.py --source authorized_target.exe --output ./unpacked
```

### List all modules without decompiling anything

```bash
python list_modules.py authorized_target.exe
python list_modules.py authorized_target.exe --filter myapp --copy-cmd
```

### Restrict to specific modules (fast)

```bash
python nuitka_decompiler.py --source authorized_target.exe --only mypackage,mypackage.utils
```

### Dynamic mode: inject into running process

```bash
python nuitka_decompiler.py --source authorized_target.exe --inject --launch
```

Or inject by PID:
```bash
python nuitka_decompiler.py --source authorized_target.exe --inject --pid 1234
```

---

## Output structure

```
output/
├── MODULE_NAME/
│   ├── constants.json       # All extracted constants
│   ├── code_objects.json    # Function signatures, arg names, line numbers
│   ├── module.pyc           # Extracted bytecode
│   └── module.py            # Decompiled source (if backend available)
├── REPORT.json              # Full extraction report
├── secrets.txt              # Potential passwords, keys, tokens found
└── DYNAMIC_SOURCE/          # (if --inject used) live-captured sources
```

The AI-assisted reconstruction workflow also writes:

```text
output/
`-- AI_READY_NBC/
    |-- nbc/                  # Feed these .nbc files to the LLM
    |-- context/              # Reports, helper notes, module table, manifests
    |-- NBC_MANIFEST.json     # Start here to choose modules with has_ops=true
    `-- README_AI.md          # Per-run handoff notes
```

### Important note about extracted `.pyc`

In many real-world Nuitka builds, **most extracted `.pyc` files are bundled libraries / stdlib modules**, not the application's "interesting" code. This is normal.

Tips:
- Use `list_modules.py` first to get an overview before committing to a full run.
- Use `REPORT.json` and the per-module `constants.json` / `code_objects.json` to quickly locate the app's own modules.
- If you already know the package name, run with `--only myapp,myapp.*` to focus the pipeline and avoid drowning in library output.

---

## Architecture

The codebase is a single ~10,000 line Python file. Here is a high-level map of the major components:

```
CommercialBypass
  └── Detects encryption, extracts _mapping[] and d0-d7, decrypts blob

NuitkaBlobDecoder
  └── Parses named module chunks, unpacks Nuitka constant tags

NuitkaModuleTableParser
  └── Scans PE .data/.rdata for module name/flag/index table

NuitkaCSourceRebuilder
  └── Reconstructs C-level structure from parsed data

OmniDecompiler
  └── Orchestrates multi-backend decompilation with fallback chain

NuitkaStaticDisassembler
  └── Walks code object trees, maps function signatures and metadata

NuitkaCompactEmitter
  └── Writes per-module artifacts and structured output

StaticalySmartReconstructor
  └── Higher-level reconstruction pipeline with heuristics

NuitkalizatorPro
  └── Main engine: coordinates all phases, writes REPORT.json

DllInjector
  └── Windows-only: injects hook DLL, waits for dynamic dump
```

See [`docs/architecture.md`](docs/architecture.md) for deeper detail.

---

## Requirements

```
pefile>=2023.2.7
capstone>=5.0.1      # optional: enhanced disassembly
xdis>=6.1.1          # optional: cross-version .pyc support
```

See [`requirements.txt`](requirements.txt) for the full list.

---

## Responsible use

This tool is intended for:
- Security research and malware analysis
- Auditing software you own or have permission to analyze
- Educational study of compiled Python internals
- CTF challenges

**Do not use it on software you do not have authorization to analyze.** Respect licenses and applicable law.

This repository is published for legitimate reverse engineering, interoperability research, malware analysis, and defensive security work. If you're unsure whether your use is permitted, get authorization first.

---

## Contributing

Issues, pull requests, and feedback are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

If you find a security-sensitive issue, please report it privately first. See [`SECURITY.md`](SECURITY.md).

---

## Acknowledgements

- Thanks to **OMΣGΛΛΛ** for sharing reference materials and guidance that helped me understand Nuitka Commercial internals for research and analysis.
- Thanks to **[@Siradankullanici](https://github.com/Siradankullanici)** for helping me a lot during the last period to finalize this project.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Donations

If you want to support the project:

- **BTC**: `bc1qa36fz0726e858l6enj7pt3359j20z98npl3av0`
- **LTC**: `ltc1qpszucslm3zyq2caemrrxr6dxx7kh28nx7xrgpc`
- **ETH**: `0x8541027655a7DfC7150F9bc9E603300048AeE022`

---

<div align="center">

*Built during some hard years. Shared in the hope it helps someone.*

**⭐ If this saved you time, a star means a lot.**

</div>

---

## Star History

<a href="https://www.star-history.com/?repos=DimaReverse%2Fnuitka-static-unpacker&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=DimaReverse/nuitka-static-unpacker&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=DimaReverse/nuitka-static-unpacker&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=DimaReverse/nuitka-static-unpacker&type=date&legend=top-left" />
 </picture>
</a>
