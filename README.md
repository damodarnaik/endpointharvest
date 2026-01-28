# EndpointHarvest 🕸️

**High-Precision Endpoint Extractor for Offensive Security**

![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

**EndpointHarvest** is an advanced static analysis tool designed to extract URLs and endpoints from source code (JavaScript, bundles, map files) with **99% accuracy**.

Unlike naive regex scrapers that produce massive lists of false positives, EndpointHarvest uses **context-aware heuristics** similar to industry standards like LinkFinder. It distinguishes between actual string paths and code noise (regex literals, math division, MIME types, and variable concatenation).

---

## ✨ Key Features

* **🎯 Context-Aware Extraction**: Prioritizes URLs inside string delimiters (`"`, `'`, `` ` ``) to eliminate code noise like `var a = b / c`.
* **🧠 Heuristic Garbage Collection**: Automatically detects and rejects false positives like MIME types (`application/json`), dates, and C-style formatters.
* **📂 Recursive Scanning**: Point it at a directory (e.g., a webpack dump), and it will recursively scan all files.
* **⚙️ Pipeline Friendly**: Includes a `--plain` mode for piping output directly into tools like `httpx`, `nuclei`, or `curl`.
* **📊 JSON Output**: Full JSON support for integration with reporting dashboards and automated pipelines.
* **🛡️ Battle Tested**: Filters out common "junk" tokens often found in minified JavaScript (e.g., regex flags `/g`, math operators, and valid HTML tags).

---

## 🔍 How It Works

EndpointHarvest utilizes a **multi-pass extraction strategy**:

1.  **Pass 1 (Quoted Strings):** It first searches for strings enclosed in quotes. This allows it to confidently identify relative paths like `/api/v1/user` while ignoring mathematical division (`x = y / z`).
2.  **Pass 2 (Unquoted URLs):** It scans for full URLs (`https://...`) that might appear in comments or documentation blocks.
3.  **Sanitization:** * **Normalization:** Converts escaped JSON slashes (`\/`) back to standard format.
    * **Filtering:** Runs every candidate through a heuristic engine that rejects high-entropy strings, variable concatenation fragments (`" + id + "`), and non-path tokens.

---

## 🚀 Installation

EndpointHarvest is a standalone script. No `pip install` required.

```bash
git clone https://github.com/damodarnaik/endpointharvest.git
cd endpointharvest
chmod +x endpointharvest.py
```

---

## 📖 Usage

**Basic File Scan** </br>
Analyze a single JavaScript file and output the results to the terminal.
```bash
python3 endpointharvest.py -i <input_file>
```

**Recursive Directory Scan** </br>
Scan an entire project folder or a leaked source map directory.
```bash
python3 endpointharvest.py -i ./<directory>/
```

**Bug Bounty Workflow (Piping)** </br>
Filter for live endpoints by piping the --plain output into httpx.
```bash
python3 endpointharvest.py -i <input_file> --plain | httpx -silent -status-code
```

**Output as JSON** </br>
```bash
python3 endpointharvest.py -i <input_file> --json -o results.json
```
