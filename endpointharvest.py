#!/usr/bin/env python3
"""
URL / Path Extraction Tool
Author: Security-focused implementation
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Set

# -----------------------------
# SAFE & BOUNDED REGEX PATTERNS
# -----------------------------

# 1. Full URLs with protocol
FULL_URL_REGEX = re.compile(
    r"""
    \b
    (?:https?|ftp)://
    (?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}
    (?::\d{1,5})?
    (?:/[^\s"'<>]*)?
    """,
    re.VERBOSE | re.IGNORECASE
)

# 2. Protocol-relative URLs (//example.com/path)
PROTO_RELATIVE_REGEX = re.compile(
    r"""
    (?<!:)
    //
    (?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}
    (?::\d{1,5})?
    (?:/[^\s"'<>]*)?
    """,
    re.VERBOSE | re.IGNORECASE
)

# 3. Absolute paths with optional query & fragment
ABSOLUTE_PATH_REGEX = re.compile(
    r"""
    (?<![\w-])
    /
    [a-zA-Z0-9._~!$&'()*+,;=:@/%-]*
    (?:\?[a-zA-Z0-9._~!$&'()*+,;=:@/%-]*)?
    (?:#[a-zA-Z0-9._~!$&'()*+,;=:@/%-]*)?
    """,
    re.VERBOSE
)

# -----------------------------
# CORE LOGIC
# -----------------------------

def extract_links(file_path: Path) -> Set[str]:
    results: Set[str] = set()

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                results.update(FULL_URL_REGEX.findall(line))
                results.update(PROTO_RELATIVE_REGEX.findall(line))
                results.update(ABSOLUTE_PATH_REGEX.findall(line))
    except OSError as exc:
        print(f"[!] File error: {exc}", file=sys.stderr)
        sys.exit(1)

    return results


# -----------------------------
# CLI INTERFACE
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely extract potential URLs and paths from a file using regex",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 url_extractor.py input.txt
  python3 url_extractor.py input.txt -o results.txt
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
        help="Write results to a file instead of stdout"
    )

    args = parser.parse_args()

    if not args.file.is_file():
        print("[!] Input file does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    links = sorted(extract_links(args.file))

    if args.output:
        try:
            args.output.write_text("\n".join(links) + "\n", encoding="utf-8")
            print(f"[+] Extracted {len(links)} unique entries → {args.output}")
        except OSError as exc:
            print(f"[!] Failed to write output: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        for link in links:
            print(link)


if __name__ == "__main__":
    main()
