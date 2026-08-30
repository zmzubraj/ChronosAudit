#!/usr/bin/env python3
"""Pilot-only Solidity lexical normalizer for clone-family reproducibility checks.

This deliberately removes comments and whitespace outside quoted strings. It does
not claim semantic equivalence and must not be used as the definitive benchmark
clone detector without an independently reviewed specification.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path


def normalize(source: str) -> str:
    output: list[str] = []
    index = 0
    state = "normal"

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char in "\r\n":
                state = "normal"
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                state = "normal"
                index += 2
            else:
                index += 1
            continue

        if state in {"single_quote", "double_quote"}:
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                index += 2
                continue
            if (state == "single_quote" and char == "'") or (
                state == "double_quote" and char == '"'
            ):
                state = "normal"
            index += 1
            continue

        if char == "/" and next_char == "/":
            state = "line_comment"
            index += 2
        elif char == "/" and next_char == "*":
            state = "block_comment"
            index += 2
        elif char == "'":
            state = "single_quote"
            output.append(char)
            index += 1
        elif char == '"':
            state = "double_quote"
            output.append(char)
            index += 1
        elif char.isspace():
            index += 1
        else:
            output.append(char)
            index += 1

    if state == "block_comment":
        raise ValueError("unterminated block comment")
    if state in {"single_quote", "double_quote"}:
        raise ValueError("unterminated quoted string")
    return "".join(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(["normalized_sha256", "normalized_bytes", "path"])
    for path in args.files:
        normalized = normalize(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        writer.writerow([digest, len(normalized.encode("utf-8")), str(path)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
