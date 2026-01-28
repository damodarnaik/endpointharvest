# EndpointHarvest 🕸️

**EndpointHarvest** is a lightweight, offensive-security–focused Python tool that extracts potential endpoints and URLs from files using carefully designed regular expressions.

Unlike naive URL extractors, EndpointHarvest is built for **real-world pentesting and bug bounty workflows**:
- ✔ Extracts endpoints from **comments and dead code**
- ✔ Preserves **parameterized and partial URLs**
- ✔ Handles **JavaScript string concatenation**
- ✔ Filters out common **noise and garbage tokens**
- ✔ Works reliably on **Python 3.9 – 3.14**

---

## ✨ Features

- Extracts:
  - Full URLs (`https://example.com/api`)
  - Relative endpoints (`/api/v1/users`)
  - Parameterized URLs (`/search?q=`, `/item?id=' + id`)
  - URLs hidden inside `//` and `/* */` comments
- Ignores:
  - Regex flags (`/g`, `/gi`)
  - HTML tags (`/div`, `/span`)
  - JavaScript keywords (`/if`, `/var`)
  - Low-value static assets (`.css`, `.png`, `.woff`, etc.)
- Safe by default:
  - No `eval`
  - No shell execution
  - Read-only file access

---

## 📦 Requirements

- Python **3.9 or newer**
- No external dependencies

> Standard library only — nothing to install via pip.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/damodarnaik/endpointharvest.git
cd endpointharvest
python3 endpointharvest.py -i <input_file>
