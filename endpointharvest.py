#!/usr/bin/env python3
"""
EndpointHarvest
Extract endpoints and URLs (including commented and parameterized ones)
for offensive security and reconnaissance.
"""

import argparse
import re
import sys
from pathlib import Path

# =========================
# Regex Patterns
# =========================

FULL_URL_REGEX = re.compile(
    r"""
    (?:https?|ftp)://
    [a-zA-Z0-9.-]+
    (?::\d{1,5})?
    (?:/[a-zA-Z0-9\-._~%!$&'()*+,;=:@/]*)?
    (?:\?[a-zA-Z0-9\-._~%!$&'()*+,;=:@/?]*)?
    """,
    re.VERBOSE | re.IGNORECASE
)

RELATIVE_ENDPOINT_REGEX = re.compile(
    r"""
    (?<![a-zA-Z0-9])
    /
    (?:[a-zA-Z0-9_\-]+/)*        # folders
    [a-zA-Z0-9_\-\.]+            # endpoint or file
    (?:\?[a-zA-Z0-9_\-&=%+']*)?  # query (allow partial / concat)
    """,
    re.VERBOSE
)

# =========================
# Noise Filters
# =========================

BLACKLIST_EXACT = {
    "/", "/g", "/gi", "/i", "/div", "/span", "/h3", "/iframe",
    "/alert", "/debugger"
}

JS_KEYWORDS = {
    "var", "let", "const", "function", "return",
    "else", "if", "for", "while", "switch", "new"
}

STATIC_EXTENSIONS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".eot"
)

# =========================
# Validation
# =========================

def is_valid_endpoint(value: str) -> bool:
    value = value.strip()

    if len(value) < 3:
        return False

    if value in BLACKLIST_EXACT:
        return False

    # Remove JS keywords used as paths
    if value.strip("/").lower() in JS_KEYWORDS:
        return False

    # Ignore pure static assets (keep HTML/HTM)
    for ext in STATIC_EXTENSIONS:
        if value.lower().endswith(ext):
            return False

    return True


def normalize(endpoint: str) -> str:
    # Remove only hard syntax noise
    return endpoint.rstrip(");,")


# =========================
# Extraction Logic
# =========================

def extract_endpoints(content: str) -> set[str]:
    results = set()

    # Full URLs (even inside comments)
    for match in FULL_URL_REGEX.findall(content):
        results.add(match)

    # Relative endpoints
    for match in RELATIVE_ENDPOINT_REGEX.findall(content):
        cleaned = normalize(match)
        if is_valid_endpoint(cleaned):
            results.add(cleaned)

    return results


# =========================
# CLI
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="EndpointHarvest - Extract endpoints and URLs from files"
    )
    parser.add_argument("-i", "--input", required=True, help="Input file")
    parser.add_argument("-o", "--output", help="Save output to file")

    args = parser.parse_args()
    path = Path(args.input)

    if not path.exists():
        print("[-] Input file not found")
        sys.exit(1)

    content = path.read_text(errors="ignore")
    endpoints = sorted(extract_endpoints(content))

    if args.output:
        Path(args.output).write_text("\n".join(endpoints))
        print(f"[+] Saved {len(endpoints)} endpoints → {args.output}")
    else:
        for ep in endpoints:
            print(ep)


if __name__ == "__main__":
    main()
