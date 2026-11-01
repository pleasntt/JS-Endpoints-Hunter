<div align="center">

# 🔍 JS-Endpoints-Hunter

**Extract hidden API endpoints & secrets from JavaScript files — fast, offline-friendly, beautiful.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/)
[![Made with ❤️](https://img.shields.io/badge/made%20with-%E2%9D%A4-red)]()

*Recon tool for bug hunters & pentesters. One command — all paths and tokens.*

</div>

---

## ✨ Features

- 🎯 **Three input modes**: remote URL, single local file, or a whole directory (recursive).
- 🧠 **Endpoint extraction**: `fetch()`, `axios.get()`, `$.ajax()`, `new URL()`, `.open()`, quoted `/api/...` literals, full `http(s)://` URLs.
- 🔐 **Secret detection**: AWS Access Keys, JWT, Google API Keys, Bearer tokens, Slack tokens, Stripe live keys, GitHub tokens, PEM private keys.
- 🎨 **Beautiful CLI output** powered by [`rich`](https://github.com/Textualize/rich) — colored tables, spinners, summary panels.
- 💾 **Export** results to `.json` (structured) or `.txt` (human-readable).
- 🛡️ **Safety first**: size limits, binary sniffing, SSL toggle for bug-bounty scopes, graceful error handling.
- 🧩 **Modular & typed**: PEP8, `type hints`, docstrings, `logging`.

---

## 📦 Installation

```bash
# 1. Clone
git clone https://github.com/<your-username>/JS-Endpoints-Hunter.git
cd JS-Endpoints-Hunter

# 2. Virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Dependencies
pip install -r requirements.txt
```

**Windows (PowerShell) gotcha** — if activation is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## 🚀 Usage

```bash
python main.py -u https://example.com/static/js/main.js
```

### Flags

| Flag | Description |
|------|-------------|
| `-u, --url URL` | Remote JS file URL. Can be repeated. |
| `-f, --file PATH` | Local JS file. Can be repeated. |
| `-d, --dir DIR` | Directory with JS files (recursive). |
| `-o, --output FILE` | Save report to `.json` or `.txt`. |
| `-v, --verbose` | Debug logging. |
| `--no-color` | Disable colored output. |
| `--timeout SEC` | HTTP timeout (default `15`). |
| `--no-ssl-verify` | Skip SSL verification (bug bounty scopes). |

### Examples

```bash
# Single remote file
python main.py -u https://target.com/app.js

# Several remote files, export to JSON
python main.py -u https://target.com/app.js -u https://target.com/vendor.js -o recon.json

# Local directory with bundled JS
python main.py -d ./dist -o report.txt

# Skip SSL verification on self-signed target
python main.py -u https://target.local/main.js --no-ssl-verify
```

---

## 🖼️ Demo

```
╔═══════════════════════════════════════════════╗
║        JS-Endpoints-Hunter  v1.0.0            ║
║   extract endpoints & secrets from JavaScript  ║
╚═══════════════════════════════════════════════╝

         Loaded sources (1)
 ──────────────────────────────────
 #   Source                        Size
 1   https://target.com/app.js    142,311

 Endpoints  (7 unique)
 ╭────┬───────────────────────────────╮
 │ #  │ Endpoint                      │
 ├────┼───────────────────────────────┤
 │ 1  │ /api/v1/login                 │
 │ 2  │ /api/v1/users/me              │
 │ 3  │ /api/v2/orders?status=active  │
 │ …  │ …                             │
 ╰────┴───────────────────────────────╯

 Secrets  (2 total)
 ╭──────────────────┬──────────────────────────╮
 │ Type             │ Value                    │
 ├──────────────────┼──────────────────────────┤
 │ AWS Access Key   │ AKIA…                    │
 │ Bearer Token     │ eyJhbGciOi…              │
 ╰──────────────────┴──────────────────────────╯

 ╭── Summary ─────────────────────────────╮
 │ Endpoints : 7                          │
 │ Secrets   : 2                          │
 │ Saved to  : recon.json                 │
 ╰────────────────────────────────────────╯
```

*(Замените блок выше на реальный скриншот / GIF после запуска: запишите терминал через [asciinema](https://asciinema.org/) или [ScreenToGif](https://www.screentogif.com/) — и вставьте сюда.)*

---

## 🗂️ Project structure

```
JS-Endpoints-Hunter/
├── main.py                  # CLI entry-point (argparse + rich)
├── requirements.txt         # requests, rich
├── README.md
└── hunter/
    ├── __init__.py
    ├── fetcher.py           # JSFetcher — HTTP & filesystem loader
    └── extractor.py         # EndpointExtractor — regex-based parser
```

---

## 🔬 What it finds

**Endpoints**

- Full URLs: `https://api.example.com/v1`, `wss://...`
- Paths in calls: `fetch('/api/users')`, `axios.get("/v1/me")`, `$.ajax('/x')`
- Quoted literals: `"/api/orders"`, `'/v1/checkout'`
- Config-style paths: `{ baseUrl: "/api/v1" }`

**Secrets**

| Type | Pattern |
|------|---------|
| AWS Access Key | `AKIA…` / `ASIA…` / `AGPA…` (20 chars) |
| JWT | `eyJ….….…` |
| Google API Key | `AIza…` (39 chars) |
| Bearer token | `Bearer <20+ chars>` |
| Slack token | `xox[abprs]-…` |
| Stripe live key | `sk_live_…` |
| GitHub token | `gh[pousr]_…` |
| PEM private key | `-----BEGIN … PRIVATE KEY-----` |

> ⚠️ Regex-based detection ≠ 100% accuracy. **Always verify findings manually** before reporting.

---

## 🛣️ Roadmap

- [ ] `--threads N` — parallel downloads
- [ ] Sourcemap support (`.js.map` deobfuscation)
- [ ] Entropy-based secret detection (Shannon)
- [ ] Integration with `waybackurls` / `gau` output
- [ ] Markdown report generator

---

## ⚖️ Disclaimer

This tool is intended **only for authorized security testing**, educational purposes, and reconnaissance on systems you **own or have explicit written permission to test**. The author is not responsible for any misuse or damage caused by this program. Respect [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) and the target's bug-bounty policy.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 🙌 Contributing

PRs, issues, and stars are welcome ⭐. If you find a bug or want a new feature — open an issue.

<div align="center">

**Made with ❤️ for the bug-bounty community**

</div>