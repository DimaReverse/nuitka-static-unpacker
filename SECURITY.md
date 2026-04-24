# Security Policy

## Reporting a Vulnerability

If you find a security issue in this repository, please report it privately
before opening a public issue.

Use GitHub's "Report a vulnerability" flow on the Security tab when available.
If that is not available, open a minimal public issue asking for a private
contact path without posting exploit details.

## Scope

In scope:

- vulnerabilities in this tool or its helper scripts
- unsafe handling of crafted inputs
- accidental disclosure of analysis output caused by this project
- dependency or packaging issues that affect users of this repository

Out of scope:

- requests to analyze, decompile, unpack, or bypass protections on third-party
  software without authorization
- recovered proprietary source, customer data, credentials, or private samples
- vulnerabilities in a target binary that are unrelated to this repository

## What to Include

Please provide:

- affected commit or version
- operating system and Python version
- minimal reproduction steps
- sanitized logs or traceback
- a synthetic fixture when possible

Do not attach proprietary binaries, recovered source, secrets, tokens, or private
customer data.

## Supported Versions

The latest version in `main` is the only actively maintained version.

## Responsible Use

This tool is designed for static and optional dynamic analysis of software you
are authorized to inspect. The maintainer does not authorize or support misuse.
See [ETHICS.md](ETHICS.md).
