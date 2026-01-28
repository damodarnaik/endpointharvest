#!/usr/bin/env python3
"""
EndpointHarvest (Production Ready)
Advanced endpoint extractor targeting high-precision results for offensive security.
"""

import argparse
import re
import sys
import json
import html
from pathlib import Path
from urllib.parse import unquote

# =========================
# Configuration & Constants
# =========================

# High-Precision Regex (LinkFinder Logic)
# 1. Matches full URLs (http/s, ws, ftp)
# 2. Matches absolute paths inside quotes starting with /
# 3. Matches relative paths with known extensions or "folder/file" structure inside quotes
REGEX_QUOTED = re.compile(
    r"""
    (?:"|'|`)                                   # Start Quote
    (
        (?:https?|ftp|wss?|file)://[^"'\s`]+    # Scheme-based URLs
        |
        (?:/|\.\./|\./)                         # Paths starting with /, ./, ../
        [^"'\s`><]+
        |
        [a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|do) # Filenames without leading /
    )
    (?:"|'|`)                                   # End Quote
    """,
    re.VERBOSE | re.IGNORECASE
)

# Fallback for unquoted full URLs (e.g., in comments)
REGEX_UNQUOTED_FULL = re.compile(
    r"""
    (?<!["'`])                                  # Lookbehind: Not preceded by quote
    (https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s<>"']*)?)
    """,
    re.VERBOSE | re.IGNORECASE
)

# Common Garbage that mimics paths
FALSE_POSITIVES = {
    "text/html", "text/plain", "application/json", "application/xml",
    "application/x-www-form-urlencoded", "multipart/form-data",
    "text/javascript", "image/png", "image/jpeg", "image/gif",
    "text/css", "gzip", "br", "keep-alive", "use strict",
    "/", "//", "undefined", "null", "true", "false",
    "w3.org", "xml", "html", "svg", "soap",
    "%s", "%d", "%f", # C-style formatters
}

# Static assets to ignore if strict mode is on (optional, but good for pure API hunting)
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", 
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3"
)

# =========================
# Core Logic
# =========================

class EndpointExtractor:
    def __init__(self, ignore_static=False):
        self.ignore_static = ignore_static

    def is_garbage(self, text: str) -> bool:
        """
        Heuristic analysis to determine if a string is garbage.
        """
        text = text.lower().strip()
        
        # 1. Length Check
        if len(text) < 4: 
            return True
        
        # 2. Exact Blacklist (MIME types, etc)
        if text in FALSE_POSITIVES:
            return True
        
        # 3. Structure Check
        # Discard if it looks like a variable concatenation (e.g., /api/ + id)
        if text.endswith(" +") or text.startswith("+ "):
            return True
            
        # Discard if it contains whitespace (URLs rarely do, unless encoded)
        if " " in text:
            return True

        # Discard if strictly a date format (YYYY/MM/DD)
        if re.match(r"^\d{4}/\d{2}/\d{2}", text):
            return True
            
        # 4. Character Validity
        # Reject strings with non-printable characters or excessive weird symbols
        if re.search(r"[^\x20-\x7E]", text):
            return True
            
        # 5. Static File Check (Optional)
        if self.ignore_static and any(text.endswith(ext) for ext in STATIC_EXTENSIONS):
            return True

        return False

    def clean_url(self, url: str) -> str:
        """
        Normalizes and cleans the extracted URL.
        """
        url = url.strip()
        
        # Remove trailing slashes or weird punctuation often caught in regex
        url = url.rstrip(",.;)>]\"'")
        
        # Decode HTML entities (e.g., &amp; -> &)
        try:
            url = html.unescape(url)
        except:
            pass
            
        # Handle escaped forward slashes common in JSON (e.g., \/api\/v1)
        url = url.replace(r"\/", "/")
        
        return url

    def extract(self, content: str) -> set[str]:
        results = set()
        
        # Pass 1: Quoted Paths (High Confidence)
        for match in REGEX_QUOTED.findall(content):
            clean = self.clean_url(match)
            if not self.is_garbage(clean):
                results.add(clean)

        # Pass 2: Unquoted Full URLs (Medium Confidence - Comments/Docs)
        for match in REGEX_UNQUOTED_FULL.findall(content):
            clean = self.clean_url(match)
            if not self.is_garbage(clean):
                results.add(clean)

        return results

# =========================
# File Handling
# =========================

def process_file(file_path: Path, extractor: EndpointExtractor) -> set[str]:
    try:
        # Try UTF-8 first, fallback to Latin-1 to avoid crashing on binaries
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return extractor.extract(content)
    except Exception as e:
        sys.stderr.write(f"[!] Error reading {file_path}: {e}\n")
        return set()

def get_files(input_path: Path):
    if input_path.is_file():
        yield input_path
    elif input_path.is_dir():
        for p in input_path.rglob("*"):
            if p.is_file() and p.stat().st_size < 10 * 1024 * 1024: # Skip files > 10MB
                yield p

# =========================
# Main Execution
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="EndpointHarvest - Production Ready JS Endpoint Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--input", required=True, help="Input file or directory")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--ignore-static", action="store_true", help="Ignore images, css, fonts")
    parser.add_argument("--plain", action="store_true", help="Print only URLs (no banners)")

    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print("[-] Input path not found")
        sys.exit(1)

    extractor = EndpointExtractor(ignore_static=args.ignore_static)
    all_endpoints = set()
    
    # Process
    if not args.plain and not args.json:
        print(f"[*] Scanning: {input_path}")

    for f in get_files(input_path):
        eps = process_file(f, extractor)
        all_endpoints.update(eps)

    sorted_endpoints = sorted(list(all_endpoints))

    # Output Handling
    if args.json:
        output_data = {"count": len(sorted_endpoints), "endpoints": sorted_endpoints}
        print(json.dumps(output_data, indent=4))
        if args.output:
            Path(args.output).write_text(json.dumps(output_data, indent=4))
    else:
        # Console Output
        if not args.plain:
            print(f"[*] Found {len(sorted_endpoints)} unique endpoints:\n")
        
        output_text = "\n".join(sorted_endpoints)
        print(output_text)

        # File Write
        if args.output:
            Path(args.output).write_text(output_text)
            if not args.plain:
                print(f"\n[+] Results saved to -> {args.output}")

if __name__ == "__main__":
    main()
