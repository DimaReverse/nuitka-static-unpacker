<div align="center">

```
 _   _       _ _   _         _ _          _             
| \ | |_   _(_) |_| | ____ _| (_)______ _| |_ ___  _ __ 
|  \| | | | | | __| |/ / _` | | |_  / _` | __/ _ \| '__|
| |\  | |_| | | |_|   < (_| | | |/ / (_| | || (_) | |   
|_| \_|\__,_|_|\__|_|\_\__,_|_|_/___\__,_|\__\___/|_|   
```

**Nuitka Static Unpacker · Nuitka Commercial “data-hiding” research · Pure Python**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Lines](https://img.shields.io/badge/lines%20of%20code-10%2C000%2B-orange?style=flat-square)](nuitka_decompiler.py)
[![Status](https://img.shields.io/badge/status-active%20research-brightgreen?style=flat-square)]()

*Analyze Nuitka-compiled Python binaries and extract the embedded constants/modules/bytecode — with a single script.*

</div>

---

## What is this?

**Nuitka Static Unpacker** is a *static-first* analysis tool for Python binaries compiled with [Nuitka](https://nuitka.net/). It extracts constants, module structures, code object metadata, and `.pyc` files from **open-source** Nuitka builds — and includes a research-grade implementation that can *attempt* to decrypt the constants blob used by Nuitka Commercial’s `data-hiding` plugin (when present).

It can also optionally switch to a **dynamic mode** via DLL injection to capture live Python source at runtime.

---

## Use cases

- **Malware analysis / DFIR**: extract embedded `.pyc`, strings/constants, and module structure from suspicious Nuitka-packed samples.
- **Authorized security audits**: quickly inventory hardcoded secrets, URLs, tokens, and configuration shipped inside compiled binaries.
- **CTFs / crackmes**: recover bytecode and high-level structure for reversing challenges compiled with Nuitka.
- **Interoperability research**: understand how a Nuitka binary maps back to Python packages/modules and code objects.
- **Regression / build verification**: compare extracted constants/modules across builds to detect unexpected changes.
- **Triage before deeper reversing**: get a fast static report (`REPORT.json`, constants dumps) before opening IDA/Ghidra.

---

## Quick start

### Important (onefile targets)

If your target is a **Nuitka onefile** executable, you often need to **extract the embedded files first** (embedded `.exe` / `.pyd` / `.dll` payloads).  
Use [Extreme Coder’s `nuitka-extractor`](https://github.com/extremecoders-re/nuitka-extractor) to unpack the onefile, then run this tool on the extracted binary.

If you skip this step, you may hit:

```text
PHASE 2: CONSTANTS BLOB EXTRACTION ||
=================================================================
[!!] Blob not found in RT_RCDATA, searching for static embedding...
[!!] Constants blob not found!
```

```bash
pip install -r requirements.txt
python nuitka_decompiler.py --source target.exe
```

More examples and the full flag reference: [`docs/usage.md`](docs/usage.md).

---

## Documentation

- [`docs/usage.md`](docs/usage.md) — CLI flags, examples, troubleshooting
- [`docs/architecture.md`](docs/architecture.md) — pipeline + key components
- [`docs/nuitka_blob_format.md`](docs/nuitka_blob_format.md) — constants blob format notes
- [`docs/roadmap.md`](docs/roadmap.md) — roadmap / known gaps

## The story behind this project

I started building this project in 2023, during one of the hardest periods of my life.

At the time, I was dealing with severe isolation and a constant feeling of being misunderstood. I had been diagnosed on the autism spectrum, but instead of receiving support that matched my actual abilities, I was often treated as if I were incapable.

I was pushed into programs designed for people with significantly different needs than mine, placed in environments where I didn’t belong, and repeatedly told — directly and indirectly — that I wouldn’t be able to work, live independently, or even get a driver’s license.

On top of that, I had to deal with ongoing medical and administrative processes (including support/guardianship-style arrangements) that left me feeling like pieces of my autonomy were being taken away day by day — through pressure, conditional “help”, and situations where saying “no” didn’t feel like a real option.

At school, things weren’t better. I experienced heavy and persistent bullying, to the point where attending classes became extremely difficult. Over time, I stopped going regularly and was no longer able to complete my final year in the standard way.

Outside of school, my social life almost disappeared. I lost most of my friends and spent long periods of time alone. Many nights were spent online, playing games with older people simply because they treated me with more respect than people my own age.

During that time, I didn’t have much — but I had a computer and an internet connection.

I started diving deep into how software works internally. What began as curiosity turned into an obsession: reading PE formats, analyzing compiled binaries, experimenting with reverse engineering, and slowly understanding how Nuitka transforms Python code into something that looks almost unreadable.

This project didn’t come from a structured plan.  
It came from persistence.

Each small step — extracting one more constant, understanding one more structure, improving the tool slightly — felt like progress in a moment where everything else felt stuck.

Over time, this turned into a serious, multi-year effort.  
Multiple rewrites, failed attempts, and long nights of trial and error eventually led to what is now version 7.2.

Today, I’m in a different phase of my life.  
I’m working towards finishing my studies, building independence, and continuing to grow in the field of reverse engineering and software security — despite everything I was told I wouldn’t be able to do.

Open-sourcing this project is part of that process.

It’s a way to share something real that came out of a difficult period, and to connect with people who are interested in understanding how software truly works under the surface.

If this project helps you, or if you build something on top of it, that means more than you might think.

— dimareverse

---

## Features

- **Single-file tool**: everything lives in `nuitka_decompiler.py` (no package install required beyond Python deps).
- **Static-first analysis**: PE parsing, Python version detection, constants/blob discovery and decoding.
- **Commercial `data-hiding` support (static)**: includes a research implementation that can attempt to recover key material from the binary and decrypt the constants blob (when present), then parse it normally.
- **Module table parsing**: recovers module list/metadata from PE sections when available.
- **`.pyc` extraction**: recovers bytecode and writes per-module artifacts.
- **Code object map**: function signatures / args / line metadata (where recoverable).
- **Secrets scanner**: finds likely passwords/keys/URLs in extracted constants.
- **Multi-backend decompilation**: tries multiple decompilers and falls back gracefully.
- **JSON report**: writes a global `REPORT.json` plus per-module outputs.
- **Optional dynamic mode (Windows)**: DLL injection workflow to capture live sources.

**Compatibility note:** this has **not been tested yet on Nuitka v4 binaries** — format/layout changes may require updates.

### How the Commercial bypass works

Nuitka Commercial's `data-hiding` plugin encrypts the constants blob using:
- A **substitution cipher** with a 256-byte `_mapping[]` table hardcoded in the binary
- **XOR** with a running counter + MD5 digest feedback (`d0`–`d7`, also hardcoded)
- Module names obfuscated with a second mapping seeded with `Random(27)` — always reconstructible without the binary

The tool locates both tables in the PE's `.text`/`.rdata` sections, tries all valid combinations with CRC32 validation, and decrypts the blob before parsing. Module names are always recoverable independently.

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
git clone https://github.com/<your-user>/nuitka-decompiler.git
cd nuitka-decompiler
pip install -r requirements.txt
```

Optional: install external decompiler backends for best results:
```bash
pip install uncompyle6 decompyle3 decompile3
# For pycdc/pycdas: build from source or grab a release from https://github.com/zrax/pycdc
```

Related tool (embedded extraction):
- [Extreme Coder’s `nuitka-extractor`](https://github.com/extremecoders-re/nuitka-extractor) — useful for **onefile** builds to extract embedded files (e.g. `.exe`, `.pyd`, `.dll`) from the main executable before deeper analysis.

---

## Usage

### Basic static analysis

```bash
python nuitka_decompiler.py --source target.exe
```

### Include all library modules (not just main)

```bash
python nuitka_decompiler.py --source target.exe --all
```

### Custom output directory

```bash
python nuitka_decompiler.py --source target.exe --output ./unpacked
```

### Restrict to specific modules

```bash
python nuitka_decompiler.py --source target.exe --only mypackage,mypackage.utils
```

### Dynamic mode: inject into running process

```bash
python nuitka_decompiler.py --source target.exe --inject --launch
```

Or inject by PID:
```bash
python nuitka_decompiler.py --source target.exe --inject --pid 1234
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

### Important note about extracted `.pyc`

In many real-world Nuitka builds, **most extracted `.pyc` files are bundled libraries / stdlib modules**, not the application’s “interesting” code. This is normal.

Tips:
- Use `REPORT.json` and the per-module `constants.json` / `code_objects.json` to quickly locate the app’s own modules.
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

This repository is published for legitimate reverse engineering, interoperability research, malware analysis, and defensive security work — **not** for piracy, stalking competitors, or bypassing licenses. If you’re unsure whether your use is permitted, don’t run it.

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
