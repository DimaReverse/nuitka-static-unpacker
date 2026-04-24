# Roadmap

This is a rough plan — not a promise. Priority shifts based on what people actually run into.

## Near term

- [ ] Split monolithic script into proper Python package structure (see `docs/architecture.md`)
- [ ] Add unit tests for blob parsing and commercial data-hiding handling
- [ ] Add synthetic test fixtures (no real proprietary binaries)
- [ ] Improve CLI output formatting and progress reporting
- [ ] Publish first tagged release (`v7.2.0`)

## Medium term

- [ ] Formal plugin interface for decompiler backends
- [ ] Better support for Nuitka 2.x format variations
- [ ] Cross-platform dynamic mode (Linux `ptrace`-based alternative to DLL injection)
- [ ] CI pipeline for linting and basic sanity checks
- [ ] Detailed documentation of the constant tag format

## Longer term

- [ ] Clean library API (importable, not just CLI)
- [ ] Regression test suite with version-pinned fixtures
- [ ] Support for more Nuitka versions and edge cases
- [ ] Possibly: GUI / web interface for non-CLI users

## Known gaps

- Dynamic mode is Windows-only (requires `hook64.dll`)
- Some Nuitka 0.x format variants are not covered
- `pylingual` backend requires network access
- `.pyc` decompilation quality depends heavily on which backend is available and the Python version of the target
