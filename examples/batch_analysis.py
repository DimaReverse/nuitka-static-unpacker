#!/usr/bin/env python3
"""
Batch analysis example.

Analyzes all .exe files in a directory and writes a combined summary.

Usage:
    python batch_analysis.py ./samples ./results
"""

import sys
import os
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nuitka_decompiler import NuitkalizatorPro


def batch_analyze(samples_dir: str, output_base: str):
    samples = list(Path(samples_dir).glob("*.exe")) + list(Path(samples_dir).glob("*.dll"))

    if not samples:
        print(f"No .exe or .dll files found in {samples_dir}")
        return

    print(f"Found {len(samples)} target(s)")
    combined_reports = []

    for target in samples:
        out_dir = os.path.join(output_base, target.stem)
        print(f"\n--- Analyzing: {target.name} ---")

        engine = NuitkalizatorPro(
            target_path=str(target),
            output_dir=out_dir,
            main_only=True,
        )
        success = engine.run()

        report_path = os.path.join(out_dir, "REPORT.json")
        if os.path.isfile(report_path):
            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)
            report["_success"] = success
            combined_reports.append(report)

    # Write combined summary
    summary_path = os.path.join(output_base, "BATCH_SUMMARY.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(combined_reports, f, indent=2)

    print(f"\n\nBatch complete. Summary written to {summary_path}")
    print(f"Successful: {sum(1 for r in combined_reports if r.get('_success'))}/{len(combined_reports)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python batch_analysis.py <samples_dir> <output_dir>")
        sys.exit(1)

    batch_analyze(sys.argv[1], sys.argv[2])
