# 🌾 EndpointHarvester

**EndpointHarvester** is a lightweight, security-focused URL and endpoint extraction tool built for **offensive security**, **penetration testing**, **bug bounty**, and **reconnaissance** workflows.

It statically analyzes files and harvests potentially interesting **URLs, endpoints, and paths** using carefully designed, bounded regular expressions.

---

## 🚀 Features

- Extracts high-signal attack surface:
  - Full URLs (`https://example.com/api`)
  - Protocol-relative URLs (`//cdn.example.com/app.js`)
  - Absolute paths (`/login`, `/api/v1/users`)
  - Paths with parameters (`/search?q=test`)
- Regex patterns optimized for real-world web & API targets
- Deduplicated output
- Handles large files safely (line-by-line processing)
- CLI interface with `--help`
- Output to stdout or file
- Python standard library only (no external dependencies)

---

## 📦 Installation

### Clone the Repository

```bash
git clone https://github.com/damodarnaik/endpointharvest.git
cd endpointharvest
