# Installing `nuitka-nbc-rebuilder`

This folder contains instructions for using `.nbc` / `NBC/2` files to rebuild
Python source with maximum fidelity. It does not guarantee perfect 1:1 recovery
when Nuitka or the C compiler removed evidence.

## Recommended Input

Generate an AI-ready bundle with the unpacker:

```powershell
python nuitka_decompiler.py --source target.exe --output OUT --only myapp,myapp.* --nbc-only
```

Use `--nbc-only` when you only need the LLM handoff bundle. It keeps `.nbc`
generation and skips slower report/source/decompilation phases.

Use files from:

```text
OUT\AI_READY_NBC\nbc\
OUT\AI_READY_NBC\context\
```

Prefer modules whose `NBC_MANIFEST.json` entry has:

```json
"has_ops": true,
"has_no_ops": false
```

## Claude Code / Codex Skill

Copy the folder into your skills directory:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills" | Out-Null
Copy-Item -Recurse -Force ".\nuitka-nbc-rebuilder-skill" `
  "$env:USERPROFILE\.codex\skills\nuitka-nbc-rebuilder"
```

Claude Code-style installs can use:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse -Force ".\nuitka-nbc-rebuilder-skill" `
  "$env:USERPROFILE\.claude\skills\nuitka-nbc-rebuilder"
```

On Linux/macOS:

```bash
mkdir -p ~/.codex/skills ~/.claude/skills
cp -r nuitka-nbc-rebuilder ~/.codex/skills/
cp -r nuitka-nbc-rebuilder ~/.claude/skills/
```

The skill should trigger when a request references `.nbc`, `AI_READY_NBC`,
`@MOD`, `@CONSTS`, `@OPS`, `@ASM`, or Nuitka source reconstruction.

## Single Chat Usage

For ChatGPT, Claude, Gemini, or a local LLM:

1. Open `PROMPT.md`.
2. Copy everything between `<<<PROMPT>>>` and `<<<END PROMPT>>>`.
3. Paste it as the first message.
4. Paste one `.nbc` file in a fenced code block.
5. Ask for maximum-fidelity reconstruction with uncertainty markers.

## Batch Workflow

1. Use `NBC_MANIFEST.json` to identify relevant modules.
2. Rebuild one `.nbc` at a time.
3. Keep `AI_READY_NBC/context/NUITKA_RUNTIME_HELPERS.txt` available for helper
   rank interpretation.
4. Merge rebuilt modules manually, preserving every `# UNCERTAIN` marker until
   a human reviewer verifies it.
