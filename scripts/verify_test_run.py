#!/usr/bin/env python3
"""Reject empty/ignored executable coverage; retain only numeric, secret-free CI summaries."""
import argparse
import json
from pathlib import Path
import re


def summarize(output, minimum_e2e=3, completed=True):
    totals = {"passed": 0, "failed": 0, "ignored": 0}
    end_to_end = []
    in_end_to_end = False
    for line in output.splitlines():
        if "Running tests/end_to_end.rs" in line:
            in_end_to_end = True
        result = re.search(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", line)
        if result:
            counts = {key: int(value) for key, value in zip(totals, result.groups()[1:])}
            for key in totals:
                totals[key] += counts[key]
            if in_end_to_end:
                end_to_end.append(counts)
                in_end_to_end = False
    e2e = end_to_end[0] if len(end_to_end) == 1 else {"passed": 0, "failed": 0, "ignored": 0}
    ok = (completed and totals["passed"] > 0 and totals["failed"] == 0 and len(end_to_end) == 1
          and e2e["passed"] >= minimum_e2e and e2e["failed"] == 0 and e2e["ignored"] == 0)
    return {"guard_ok": ok, "cargo_completed_successfully": completed, "workspace": totals, "end_to_end": e2e}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--exit-code", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--minimum-e2e", type=int, default=3)
    args = parser.parse_args()
    completed = args.exit_code.exists() and args.exit_code.read_text().strip() == "0"
    result = summarize(args.output.read_text() if args.output.exists() else "", args.minimum_e2e, completed)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(result) + "\n")
    print(json.dumps(result))
    if not result["guard_ok"]:
        parser.exit(1, "Behavioral test guard rejected missing, empty, ignored or failed end-to-end coverage.\n")


if __name__ == "__main__":
    main()
