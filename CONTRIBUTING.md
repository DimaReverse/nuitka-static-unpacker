# Contributing

Thanks for taking the time to improve this project.

This repository is for legitimate analysis of Nuitka-compiled software. Before
opening an issue or pull request, please read [ETHICS.md](ETHICS.md).

## Useful Contributions

- Bug reports with reproducible steps and sanitized logs
- Support for new Nuitka versions using synthetic or open-source fixtures
- Parser correctness improvements
- Safer error handling and clearer diagnostics
- Documentation that helps authorized analysts avoid misuse
- Tests built from small fixtures generated specifically for this repo

## Contribution Rules

- Do not upload proprietary binaries, recovered source, credentials, customer
  data, private keys, tokens, or malware payloads.
- Do not submit changes whose primary purpose is license circumvention, DRM
  bypass, unauthorized source recovery, or evasion.
- Keep pull requests focused. One behavioral change per PR is easiest to review.
- If a parsing change targets a specific Nuitka version, document the version,
  platform, Python version, and build flags when possible.
- Prefer synthetic fixtures over real-world samples.

## Reporting Bugs

Please include:

- Operating system and Python version
- Nuitka version and Python version used to build the test target, if known
- Whether the sample is synthetic, open-source, owned by you, or covered by an
  engagement authorization
- Full command line
- Redacted console output or traceback
- Expected behavior and actual behavior

Do not attach binaries or extracted files unless they are clearly redistributable
and safe to share.

## Pull Request Checklist

- The change has a legitimate research, defensive, interoperability, testing, or
  documentation purpose.
- No unauthorized third-party files are included.
- Sensitive output has been redacted from examples and tests.
- New fixtures are synthetic, minimal, and documented.
- User-facing text does not encourage misuse.

## Code Style

- PEP 8 where reasonable
- Descriptive variable names in parsing code
- Comments for non-obvious format assumptions or magic constants
- No new external dependencies unless they are necessary and documented

## Security-Sensitive Issues

If you found a vulnerability in this repository itself, report it privately.
See [SECURITY.md](SECURITY.md).
