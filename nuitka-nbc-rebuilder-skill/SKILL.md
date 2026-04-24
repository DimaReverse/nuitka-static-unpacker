---
name: nuitka-nbc-rebuilder
description: Maximum-fidelity Python source reconstruction from Nuitka `.nbc` / `NBC/2` files produced by `nuitka_decompiler.py`. Use when the user pastes or references a `.nbc` file, an `AI_READY_NBC` bundle, sections such as `@MOD`, `@CONSTS`, `@RAW_CHUNK`, `@OPS`, `@ASM`, `@FORENSICS`, `module_code_*`, `mod_consts[N]`, or asks to rebuild Python source from a Nuitka C-compiled module. The goal is evidence-backed reconstruction, not guaranteed perfect 1:1 recovery; uncertain spans must be marked.
---

# Nuitka NBC -> Python Source

Rebuild Python source from a Nuitka `.nbc` file with maximum fidelity to the
original module. Treat the `.nbc` as forensic evidence, not as a normal Python
bytecode listing. Nuitka may have removed comments, formatting, some local
names, and may have inlined or optimized logic; never promise exact 1:1 output
when the evidence is incomplete.

## Output Contract

Emit one Python code block per module:

```python
# MODULE: <module.dotted.name>
# CONFIDENCE: <percent>% evidence-backed reconstruction
# UNCERTAIN SPANS: <count>

<imports>
<globals>
<classes>
<functions>
```

No prose outside the code block unless the user explicitly asks for
explanation. If a required `.nbc` section is missing, ask for the missing data
instead of fabricating code.

## Non-Negotiable Rules

1. Do not invent logic. Every emitted statement must be supported by `@OPS`,
   `@ASM`, `@CONSTS`, `@IMPORTS`, `@CODE_OBJECTS`, or `@FORENSICS`.
2. Preserve every literal exactly as shown in `@CONSTS`: strings, URLs,
   numbers, dict keys, format strings, escapes, and casing.
3. Preserve imported names exactly when they are evidenced. Do not add imports
   for convenience.
4. Mark uncertain code with `# UNCERTAIN: <specific reason>`.
5. Prefer a short uncertain body over a plausible but unsupported body.
6. Do not add comments, docstrings, logging, exception handling, async, crypto
   primitives, decorators, or helper functions unless the `.nbc` supports them.

## NBC/2 Sections

- `@NBC 2`: format marker.
- `@MOD`: module name.
- `@VER`: CPython target version.
- `@ENTRY`: native VA of the module entry function.
- `@MODULE_TABLE`: loader-table metadata; `func_ptr` confirms the module entry.
- `@RAW_CHUNK`: base64 of the original Nuitka constants chunk. Use it only to
  verify or re-parse evidence; do not decode it by hand unless necessary.
- `@CONSTS <count> mode=full_repr`: authoritative `mod_consts` table.
- `@IMPORTS`: analyzer-suggested import statements.
- `@FUNCS_DETECTED`: inferred function signatures.
- `@CODE_OBJECTS`: code-object metadata where Nuitka preserved it.
- `@BLOCKS`: summary of disassembled native blocks.
- `@OPS <va> # <qualname>`: virtual operations derived from native code.
- `@ASM <va>`: annotated native assembly. Use this to resolve ambiguous `@OPS`.
- `@FORENSICS` and `@NO_OPS <qualname>`: evidence for functions without a
  reachable `@OPS` body.
- Bare `@NO_OPS`: the whole module lacks disassembly; emit only signatures and
  constants-backed globals with uncertainty markers.

## Translation Workflow

1. Parse `@MOD`, `@VER`, `@ENTRY`, `@MODULE_TABLE`, and `@CONSTS`.
2. Build a literal map from every `@CONSTS` row: `c[N] -> exact repr`.
3. Build function declarations from `@FUNCS_DETECTED` and `@CODE_OBJECTS`.
4. Build a block map from every `@OPS <va>` and matching `@ASM <va>`.
5. Map `@OPS` blocks to functions using the `# qualname` annotation first.
   If no annotation exists, use nearby string constants that look like
   qualnames. If still ambiguous, mark the body uncertain.
6. Translate the `@ENTRY` block into imports, global assignments, class/function
   registration, and top-level calls only when the sequence is clear.
7. Translate each function block. Use `@ASM` comments to confirm attribute
   names, C-API calls, call targets, and constants.
8. For functions listed in `@FUNCS_DETECTED` but missing `@OPS`, inspect the
   matching `@FORENSICS` block. Emit logic only when adjacent constants or
   mentions plainly support it; otherwise emit `...` with an uncertainty reason.
9. Run the anti-hallucination checklist before final output.

## Virtual Ops

- `L c[N]`: load `mod_consts[N]`.
- `C r#N`: call a ranked Nuitka runtime helper.
- `C helper_*`: call a less common runtime helper.
- `C fn@0xVA`: call another native block in this same module; resolve to
  `@OPS 0xVA` when present.
- `C module_code_<name>`: call another module entry. Usually import/init logic.
- `C capi:<name>`: call a Python C-API function.
- `J_EQ c[N] Lx` / `J_NE c[N] Lx`: conditional branch against a constant.
- `J_EQ ? Lx`: conditional branch with unresolved comparator.
- `J Lx`: unconditional branch.
- `:Lx`: label.
- `RET`: return.

## Runtime Helper Hints

Treat ranks as build-local hints, not universal truth. Use
`AI_READY_NBC/context/NUITKA_RUNTIME_HELPERS.txt` when available.

Common rank meanings:

- `r#0`: attribute lookup (`obj.attr`)
- `r#1`: no-arg call (`f()`)
- `r#2`: one-arg call (`f(a)`)
- `r#3`: two-arg call (`f(a, b)`)
- `r#4`: three-arg call (`f(a, b, c)`)
- `r#5`: positional/variadic call
- `r#6` to `r#8`: globals or string-dict lookup/update
- `r#9` to `r#13`: imports or method calls
- `r#14` and above: function creation, class creation, globals update, or
  helper-specific operations depending on the build

## C-API Hints

- `PyImport_ImportModule`: `import X`
- `PyImport_ImportModuleLevel*`: relative/from import logic
- `PyObject_GetAttrString`: `obj.name`
- `PyObject_SetAttrString`: `obj.name = value`
- `PyObject_Call*`: `obj(...)`
- `PyObject_IsTrue`: truthiness check
- `PyDict_GetItem`, `PyDict_SetItem`, `PyDict_DelItem`: dict access/update
- `PyUnicode_GetLength`, `PyUnicode_Find`, `PyUnicode_Substring`: string ops
- `PyErr_*`: exception path evidence
- `PyGen_*`, `PyCoro_*`: generator/coroutine evidence

## Anti-Hallucination Checklist

Before emitting code, verify:

- Every string literal appears verbatim in `@CONSTS`.
- Every numeric literal above 10 appears in `@CONSTS`.
- Every import is supported by `@IMPORTS`, `@OPS`, or `@ASM`.
- Every call target is supported by `@OPS`, `@ASM`, or a known C-API pattern.
- No exception handling appears without `PyErr_*` or branch evidence.
- No crypto logic appears without visible crypto imports, attributes, constants,
  or C-API evidence.
- No async/generator syntax appears without coroutine/generator evidence.

If a line fails, replace that line with `# UNCERTAIN: <failed check>`.

## Confidence

Compute confidence qualitatively:

- 90-100%: almost every nontrivial line comes from `@OPS`/`@ASM`.
- 70-89%: core control flow is evidenced, with small uncertain spans.
- 40-69%: signatures and literals are strong, bodies partly inferred.
- Below 40%: emit mostly signatures/globals with uncertainty markers.

Use the header value to communicate evidence quality, not optimism.
