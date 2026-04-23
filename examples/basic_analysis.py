#!/usr/bin/env python3
"""
Basic usage example for nuitka-decompiler.

This shows how to invoke the tool programmatically instead of via CLI.
For most use cases, the CLI is simpler:

    python nuitka_decompiler.py --source target.exe --output ./out

This example is for cases where you want to embed the analysis in a larger script.
"""

import sys
import os

# Add parent directory to path if running from examples/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nuitka_decompiler import NuitkalizatorPro


def analyze(target_path: str, output_dir: str = "./output", include_all: bool = False):
    """
    Run static analysis on a Nuitka-compiled binary.

    Args:
        target_path:  Path to the .exe or .dll to analyze.
        output_dir:   Directory where artifacts will be written.
        include_all:  If True, include library/stdlib modules too.
                      If False (default), only the main application modules.

    Returns:
        True on success, False on failure.
    """
    engine = NuitkalizatorPro(
        target_path=target_path,
        output_dir=output_dir,
        main_only=not include_all,
    )
    return engine.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python basic_analysis.py <target.exe> [output_dir]")
        sys.exit(1)

    target = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "./output"

    success = analyze(target, out)
    sys.exit(0 if success else 1)
