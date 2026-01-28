#!/usr/bin/env python3
"""
EndpointHarvester
A safe, regex-based endpoint and URL extraction tool
for offensive security and reconnaissance.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Set


# -----------------------------
# REGEX DEFINITIONS (VERBOSE-SAFE)
# -----------------------------

# Full URLs: https://example.com/path
FULL_URL_REGEX = re.compile(
    r"""
    \b
    (?:https?|ftp)://
    (?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}
    (?::\d{1,5})?
    (?:/[^\s"'<>]*)?
    """,
    re.VERBOSE | re.IGNORECASE
)

# Protocol-relative URLs: //example.com/path
PROTO_RELATIVE_REGEX = re.compile(
    r"""
    (?<!:)
    //
    (?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}
    (?::\d{1,5})?
    (?:/[^\s"'<>]*)?
    """,
    re.VERBOSE | re.IGNORECASE
)

# Absolute paths: /path, /path?x=1, /path#frag
ABSOLUTE_PATH_REGEX = re.compile(
    r"""
    (?<!\w)
    /
    [A-Za-z0-9._~!$&'()+,;=:@/%\-]*
    (?:\?[A-Za-z0-9._~!$&'()+,;=:@/%\-]*)?
    (?:\#[A-Za-z0-9._~!$&'()+,;=:@/%\-]*)?
    """,
    re.VERBOSE
)


# -----------------------------
# CORE LOGIC
# -----------------------------

def extract_endpoints(file_path: Path) -> Set[str]:
    results: Set[str] = set()

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                results.update(FULL_URL_REGEX.findall(line))
                results.update(PROTO_RELATIVE_REGEX.findall(line))
                results.update(ABSOLUTE_PATH_REGEX.findall(line))
    except OSError as e:
        print(f"[!] File error: {e}", file=sys.stderr)
        sys.exit(1)

    return results


# -----------------------------
# CLI
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="EndpointHarvester - Extract URLs and endpoints from files",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python endpointharvest.py app.js
  python endpointharvest.py app.js -o endpoints.txt
"""
    )

    parser.add_argument(
        "file",
        type=Path,
        help="Input file to analyze"
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Save output to a file instead of stdout"
    )

    args = parser.parse_args()

    if not args.file.is_file():
        print("[!] Input file does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    endpoints = sorted(extract_endpoints(args.file))

    if args.output:
        try:
            args.output.write_text("\n".join(endpoints) + "\n", encoding="utf-8")
            print(f"[+] Extracted {len(endpoints)} endpoints → {args.output}")
        except OSError as e:
            print(f"[!] Output error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        for endpoint in endpoints:
            print(endpoint)


if __name__ == "__main__":
    main()
