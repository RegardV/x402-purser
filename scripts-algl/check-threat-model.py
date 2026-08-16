#!/usr/bin/env python3
"""Gate for the threat model document.

A prose gate is easy to make decorative, so this checks structure a plausible-but-empty
document would fail: every adversary must carry an explicit loss bound, and no absolute
safety claim may appear anywhere in the file.
"""
import re
import sys

PATH = "docs/superpowers/specs/2026-08-16-threat-model.md"
REQUIRED_SECTIONS = [
    "## The invariant",
    "## Trust boundaries",
    "## Adversaries",
    "## What bounds the loss",
    "## Residual risk",
    "## What we do not defend against",
]
# Claims that cannot be true of any software control on this rail.
FORBIDDEN = [
    "cannot drain the wallet",
    "cannot be drained",
    "guarantees that no",
    "impossible to drain",
]
MIN_ADVERSARIES = 5

def main() -> int:
    try:
        text = open(PATH, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"FAIL: {PATH} does not exist")
        return 1

    problems = []

    for section in REQUIRED_SECTIONS:
        if section not in text:
            problems.append(f"missing required section: {section}")

    lowered = text.lower()
    for phrase in FORBIDDEN:
        if phrase in lowered:
            problems.append(f"contains an absolute claim we cannot make: {phrase!r}")

    # Every adversary row in the adversaries table must state a bound.
    # Match adversary IDs specifically. "| A" alone also matched the trust boundary row
    # "| Agent to daemon", which made the gate fail for the wrong reason.
    rows = [
        line for line in text.splitlines()
        if re.match(r"^\|\s*A\d+\s", line.strip()) and line.count("|") >= 4
    ]
    if len(rows) < MIN_ADVERSARIES:
        problems.append(f"only {len(rows)} adversaries enumerated, expected at least {MIN_ADVERSARIES}")
    for row in rows:
        if "bounded by" not in row.lower():
            problems.append(f"adversary row states no loss bound: {row.strip()[:70]}")

    # The em-dash rule applies to every document in this repo.
    if "—" in text:
        problems.append("contains an em-dash")

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1

    print(f"OK: {len(rows)} adversaries, each with a stated loss bound")
    return 0

if __name__ == "__main__":
    sys.exit(main())
