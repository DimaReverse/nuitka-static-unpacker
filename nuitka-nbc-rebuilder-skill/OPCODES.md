# NBC/2 Opcode and Section Reference

`.nbc` files are UTF-8 text records produced by `nuitka_decompiler.py`. Each
file describes one Nuitka module and is designed for evidence-backed source
reconstruction.

## Layout

| Tag | Meaning |
|---|---|
| `@NBC 2` | format marker |
| `@MOD <name>` | dotted module name |
| `@VER <X.Y>` | target CPython version |
| `@ENTRY 0xVA` | native module-entry function |
| `@MODULE_TABLE` | loader-table metadata |
| `@RAW_CHUNK` | original constants chunk, base64 encoded |
| `@CONSTS <n> mode=full_repr` | authoritative `mod_consts` table |
| `@IMPORTS` | suggested import statements |
| `@FUNCS_DETECTED` | inferred function signatures |
| `@CODE_OBJECTS` | preserved code-object metadata |
| `@BLOCKS` | native block summary |
| `@OPS 0xVA # qualname` | virtual operation stream for one block |
| `@ASM 0xVA` | annotated native assembly for the same block |
| `@FORENSICS` | context for functions without reachable `@OPS` |
| `@NO_OPS` | missing disassembly marker |

## Constants

`@CONSTS` rows use:

```text
<index> <type_code> <python_repr>
```

Type codes:

| Code | Python type |
|---|---|
| `n` | `None` |
| `t` | `True` |
| `F` | `False` |
| `i` | `int` |
| `f` | `float` |
| `c` | `complex` |
| `s` | `str` |
| `b` | `bytes` |
| `B` | `bytearray` |
| `T` | `tuple` |
| `L` | `list` |
| `D` | `dict` |
| `S` | `set` |
| `P` | `frozenset` |
| `?` | unknown |

Every literal in the rebuilt Python should come from this table unless it is a
tiny structural value such as `0`, `1`, `2`, or `-1`.

## Virtual Operations

| Op | Meaning |
|---|---|
| `L c[N]` | load `mod_consts[N]` |
| `C r#N` | call ranked Nuitka runtime helper |
| `C helper_*` | call less common helper |
| `C fn@0xVA` | call local native block; look for `@OPS 0xVA` |
| `C module_code_X` | call another module entry |
| `C capi:NAME` | call Python C-API symbol |
| `J_EQ c[N] Lx` | jump to `Lx` if comparison equals constant |
| `J_NE c[N] Lx` | jump to `Lx` if comparison does not equal constant |
| `J_EQ ? Lx` | branch with unknown comparator |
| `J Lx` | unconditional branch |
| `:Lx` | label |
| `RET` | return |

`@OPS` is a source-level hint, not a complete decompiler. Use the matching
`@ASM` block to confirm ambiguous control flow, call targets, and attributes.

## Runtime Helper Rank Hints

Ranks are inferred per binary by call frequency. They are useful but not
absolute. Prefer `AI_READY_NBC/context/NUITKA_RUNTIME_HELPERS.txt` when present.

Common meanings:

| Rank | Likely meaning |
|---|---|
| `r#0` | attribute lookup |
| `r#1` | no-argument call |
| `r#2` | one-argument call |
| `r#3` | two-argument call |
| `r#4` | three-argument call |
| `r#5` | positional/variadic call |
| `r#6`-`r#8` | globals or string-dict lookup/update |
| `r#9`-`r#13` | import or method-call helper |
| `r#14+` | make-function, class creation, globals update, or cold helper |

## Python C-API Hints

| C-API | Python-level interpretation |
|---|---|
| `PyImport_ImportModule` | `import X` |
| `PyImport_ImportModuleLevel*` | relative or from-import |
| `PyObject_GetAttrString` | `obj.name` |
| `PyObject_SetAttrString` | `obj.name = value` |
| `PyObject_Call*` | `obj(...)` |
| `PyObject_IsTrue` | truthiness test |
| `PyDict_GetItem` | `d[k]` |
| `PyDict_SetItem` | `d[k] = v` |
| `PyDict_DelItem` | `del d[k]` |
| `PyUnicode_GetLength` | `len(s)` |
| `PyUnicode_Find` | `s.find(sub)` |
| `PyUnicode_Substring` | `s[a:b]` |
| `PyUnicode_Format` | `%` formatting or `.format()` |
| `PyErr_*` | exception path |
| `PyGen_*` / `PyCoro_*` | generator/coroutine |
| `PyIter_*` | iteration |

## Forensics

`@FORENSICS` contains evidence for functions with no `@OPS` body. It normally
lists a qualname index, nearby constants, and strings that mention the function
name. Use it only when it plainly supports behavior. Otherwise emit an
uncertain stub.

## Do Not Emit Without Evidence

- `exec`, `eval`, dynamic `__import__`
- dynamic `getattr`/`setattr`
- decorators
- metaclasses
- broad `try/except`
- async/generator syntax
- cryptographic signing, verification, encryption, or hashing logic
- network retries, proxy handling, timeouts, or logging not present in evidence

When tempted to add one of these, add `# UNCERTAIN` instead.
