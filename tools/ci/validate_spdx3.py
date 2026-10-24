#!/usr/bin/env python3
"""Validate an SPDX 3 document and fail closed on reported findings.

spdx3-validate 0.0.7's module API returns a ValidationResult whose truth value
indicates validity. The wrapper is used instead of its CLI because that CLI
version can print schema errors while returning exit status zero.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SPDX_VERSION = "3.0.1"


def validate_document(path: Path) -> tuple[bool, str]:
    # Import lazily so the repository's dependency-free unit tests can exercise
    # the wrapper contract without requiring the validator package to be installed.
    import spdx3_validate

    result = spdx3_validate.validate(str(path), version=SPDX_VERSION)
    if result:
        return True, ""
    return False, str(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", nargs="?", default="sbom.spdx3.json")
    args = parser.parse_args(argv)
    path = Path(args.document)
    try:
        valid, details = validate_document(path)
    except Exception as exc:
        print(f"SPDX 3.0.1 validation failed: {exc}", file=sys.stderr)
        return 1
    if not valid:
        print(f"SPDX 3.0.1 validation failed for {path}:\n{details}", file=sys.stderr)
        return 1
    print(f"SPDX 3.0.1 validation passed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
