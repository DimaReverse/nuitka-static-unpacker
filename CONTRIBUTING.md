# Contributing

Thanks for taking the time to look at this project.

## What's most useful right now

- **Bug reports** with reproduction steps (target Nuitka version, Python version, error output)
- **New Nuitka version support** — the blob format shifts between releases; PRs with format notes are very welcome
- **Decompiler backend improvements** — better fallback logic, new backends, coverage for edge cases
- **Test fixtures** — sanitized or synthetic binaries that exercise specific code paths
- **Documentation** — clearer architecture notes, usage examples, explanations of the blob format

## Before opening a PR

1. Describe the problem you're solving or the feature you're adding
2. Keep changes focused — one thing per PR makes review much faster
3. If you're changing parsing logic, explain which Nuitka version or format variant it targets

## Reporting bugs

Please include:

- Operating system and Python version
- Nuitka version of the target binary (if known)
- Whether the target is open-source or commercial build
- Full command you ran
- Full console output or traceback

## Code style

- PEP 8 where reasonable
- Descriptive variable names in parsing code — magic numbers need comments
- No external dependencies added without discussion

## Discussions

Open an issue for anything you're unsure about. Questions are welcome.
