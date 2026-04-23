# Nuitka Blob Format

This document describes what the tool knows about the Nuitka constants blob format, based on reverse engineering and cross-referencing with the open-source Nuitka codebase.

---

## Open-source blob layout

```
[0:4]   CRC32 of payload (little-endian uint32)
[4:8]   Payload size in bytes (little-endian uint32)
[8:]    Payload — sequence of named module chunks
```

Each module chunk:

```
[0:4]   Chunk size (uint32 LE)
[4:N]   Module name (null-terminated UTF-8)
[N:]    Constants data for this module
```

---

## Commercial (encrypted) blob layout

```
[0:4]   CRC32 of *decrypted* payload (uint32 LE)
[4:8]   Declared payload size (uint32 LE)
[8:24]  Encrypted MD5 digest (16 bytes)
[24:]   Encrypted payload
```

Detection: if `CRC32(data[8:8+declared_size]) != stored_crc`, the blob is encrypted.
Secondary check: `(total_size - 8 - declared_size) == 16` → commercial digest present.

### Encryption algorithm

```python
# Pseudocode reconstructed from DataHidingPlugin.py

key = _mapping      # 256-byte substitution table (inverse), hardcoded in PE
d   = [d0,d1,d2,d3,d4,d5,d6,d7]   # 8 MD5 digest bytes, hardcoded in PE

for i, byte in enumerate(ciphertext):
    step1 = key[byte]                    # substitution
    step2 = step1 ^ (i & 0xFF)          # XOR with counter
    step3 = step2 ^ d[i % 8]            # XOR with digest byte
    plaintext[i] = step3
```

### Module name obfuscation

Module names use a separate `_mapping2` table always seeded with `random.Random(27)`. This is independent of the binary — the tool reconstructs it without scanning the PE:

```python
import random
r = random.Random(27)
fwd = list(range(1, 256))
r.shuffle(fwd)
fwd.insert(0, 0)
# fwd[encoded_byte] = decoded_byte
```

---

## Constant tag format

Inside each module's data, constants are encoded with type tags. Known tags:

| Tag | Type |
|-----|------|
| `b` | bytes |
| `s` | str (UTF-8) |
| `i` | int (variable length) |
| `f` | float |
| `c` | complex |
| `T` | True |
| `F` | False |
| `N` | None |
| `t` | tuple |
| `l` | list |
| `d` | dict |
| `S` | set |
| `Z` | frozenset |
| `C` | code object |
| `e` | ellipsis |

Code object chunks carry: argcount, nlocals, stacksize, flags, bytecode blob, constants (recursive), names, varnames, filename, name, firstlineno, lnotab.

---

## Notes on version variance

The blob format has shifted across Nuitka versions. Known divergence points:

- Nuitka < 1.x: simpler chunk layout, no digest field in commercial builds
- Nuitka 1.x–2.x: current format described above
- The `_mapping2` seed (27) has been stable across all versions tested

If you encounter a blob the tool fails to parse, open an issue with the Nuitka version and the hex of the first 64 bytes of the blob.
