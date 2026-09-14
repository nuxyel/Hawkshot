# 🦅 HAWKSHOT

```
   ▄█    █▄       ▄████████  ▄█     █▄     ▄█   ▄█▄    ▄████████    ▄█    █▄     ▄██████▄      ███     
  ███    ███     ███    ███ ███     ███   ███ ▄███▀   ███    ███   ███    ███   ███    ███ ▀█████████▄ 
  ███    ███     ███    ███ ███     ███   ███▐██▀     ███    █▀    ███    ███   ███    ███    ▀███▀▀██ 
 ▄███▄▄▄▄███▄▄   ███    ███ ███     ███  ▄█████▀      ███         ▄███▄▄▄▄███▄▄ ███    ███     ███   ▀ 
▀▀███▀▀▀▀███▀  ▀███████████ ███     ███ ▀▀█████▄    ▀███████████ ▀▀███▀▀▀▀███▀  ███    ███     ███     
  ███    ███     ███    ███ ███     ███   ███▐██▄            ███   ███    ███   ███    ███     ███     
  ███    ███     ███    ███ ███ ▄█▄ ███   ███ ▀███▄    ▄█    ███   ███    ███   ███    ███     ███     
  ███    █▀      ███    █▀   ▀███▀███▀    ███   ▀█▀  ▄████████▀    ███    █▀     ▀██████▀     ▄████▀   
                                          ▀                                                            
                            v4.0 - by nuxyel
```

<div align="center">
  <img alt="Language" src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img alt="Pentesting" src="https://img.shields.io/badge/Usage-Pentesting%20%7C%20Recon-red?style=for-the-badge">
  <img alt="Version" src="https://img.shields.io/badge/Version-4.0.0-purple?style=for-the-badge">
</div>

**HAWKSHOT** is a personal Python project, built to practice Python and networking concepts (inspired by Solyd's cybersecurity coursework) by writing a small modular reconnaissance toolkit. It's not a maintained or professionally released security tool — treat it as a learning project with working code, not a production-grade product.

## ✨ Features

| Module | Description |
|--------|-------------|
| **`enum`** | DNS subdomain enumeration with multi-record type support |
| **`dir`** | Web directory and file brute-force scanning |
| **`vhost`** | Virtual host enumeration via Host header manipulation |
| **`tech`** | Technology and framework fingerprinting |

### Core Capabilities

- 🚀 **High Performance:** Multi-threaded worker/queue architecture
- 📊 **Progress Tracking:** Real-time progress bars for all scans
- 💾 **Multiple Output Formats:** Plain text and JSON export
- 🔄 **Resume Capability:** Continue interrupted scans with `--resume`
- 🛡️ **Robust Error Handling:** Verbose mode for debugging
- ⏱️ **Rate Limiting:** Configurable delay to avoid detection
- 🌐 **Cross-Platform:** Works on Linux, macOS, and Windows

## ⚙️ Installation

### Quick Install (pip)

```bash
git clone https://github.com/nuxyel/hawkshot.git
cd hawkshot
pip install -e .
```

### Manual Install

```bash
git clone https://github.com/nuxyel/hawkshot.git
cd hawkshot
pip install -r requirements.txt
python hawkshot.py --help
```

## 🚀 Usage

### DNS Subdomain Enumeration

```bash
# Basic enumeration
hawkshot enum example.com wordlist.txt

# With multiple record types and output
hawkshot enum example.com wordlist.txt -t 100 -T A AAAA CNAME MX -o results.txt

# JSON output with verbose mode
hawkshot enum example.com wordlist.txt --json -v -o results.json
```

### Web Directory Scanning

```bash
# Basic scan
hawkshot dir http://example.com wordlist.txt

# With extensions and rate limiting
hawkshot dir http://example.com wordlist.txt -x php,html,txt --delay 0.1

# Filter specific status codes
hawkshot dir http://example.com wordlist.txt -s 200,301,403 --no-verify
```

### Virtual Host Enumeration

```bash
# Enumerate vhosts on IP
hawkshot vhost http://10.10.10.10 wordlist.txt --host example.com

# With custom user-agent
hawkshot vhost http://10.10.10.10 wordlist.txt --host target.htb -ua "CustomBot/1.0"
```

### Technology Detection

```bash
# Detect technologies on single target
hawkshot tech http://example.com

# Scan multiple URLs from file
hawkshot tech http://example.com -l urls.txt -o techs.json --json
```

## 📋 Command Reference

### Common Options (all modules)

| Flag | Description |
|------|-------------|
| `-t, --threads` | Number of threads (1-500, default: 20) |
| `-o, --output` | Save results to file |
| `--json` | Output in JSON format |
| `-v, --verbose` | Enable debug output |
| `--delay` | Delay between requests (seconds) |
| `--resume` | Resume interrupted scan |
| `--timeout` | Request timeout (seconds) |

### DNS Enumeration (`enum`)

| Flag | Description |
|------|-------------|
| `-T, --types` | Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA |

### Directory Scanning (`dir`)

| Flag | Description |
|------|-------------|
| `-ua, --user-agent` | Custom User-Agent header |
| `--no-verify` | Disable SSL verification |
| `-x, --extensions` | Append file extensions (e.g., php,html) |
| `-s, --status-codes` | Filter by status codes (e.g., 200,301) |
| `--no-redirect` | Don't follow redirects |

### VHost Enumeration (`vhost`)

| Flag | Description |
|------|-------------|
| `--host` | Base domain for vhost generation (required) |
| `-ua, --user-agent` | Custom User-Agent header |
| `--no-verify` | Disable SSL verification |

## 📁 Project Structure

```
hawkshot/
├── hawkshot.py          # Legacy single-file entry point
├── setup.py             # PyPI installation script
├── requirements.txt     # Dependencies
├── hawkshot/
│   ├── __init__.py
│   ├── __main__.py      # python -m hawkshot entry
│   ├── cli.py           # Argument parsing
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py    # Configuration & state
│   │   ├── output.py    # Logger, progress bar
│   │   └── validators.py # Input validation
│   └── modules/
│       ├── __init__.py
│       ├── dns_enum.py  # DNS enumeration
│       ├── web_dir.py   # Directory scanning
│       ├── vhost_enum.py # VHost enumeration
│       └── tech_detect.py # Technology detection
```

## 📄 Output Formats

### Text Output (default)

```
# HAWKSHOT Scan Results
# Date: 2024-01-15 14:30:22
# module: dns_enum
# target: example.com
# Total results: 42
#============================================================

[A    ] api.example.com                          -> 192.168.1.1
[CNAME] cdn.example.com                          -> cloudfront.net
```

### JSON Output (`--json`)

```json
{
  "metadata": {
    "tool": "hawkshot",
    "version": "4.0.0",
    "timestamp": "2024-01-15T14:30:22",
    "module": "dns_enum",
    "target": "example.com"
  },
  "results": [
    {"subdomain": "api.example.com", "type": "A", "value": "192.168.1.1"}
  ],
  "total_count": 42
}
```

## 🔄 Resume Capability

Scans can be resumed after interruption:

```bash
# Start scan (interrupt with Ctrl+C)
hawkshot enum example.com large_wordlist.txt -o results.txt
# [!] Scan interrupted. State saved to .hawkshot_state_example_com.json

# Resume from where it left off
hawkshot enum example.com large_wordlist.txt -o results.txt --resume
# [*] Resuming scan: 15000 completed, 85000 remaining
```

## 🛡️ Technology Detection

HAWKSHOT can identify 50+ technologies including:

- **Web Servers:** Apache, Nginx, IIS, LiteSpeed
- **Languages:** PHP, ASP.NET, Python, Java
- **Frameworks:** React, Vue.js, Angular, Django, Laravel, Express
- **CMS:** WordPress, Drupal, Joomla, Shopify
- **CDN/Proxy:** Cloudflare, Akamai, CloudFront, Varnish
- **Analytics:** Google Analytics, Tag Manager, Hotjar

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **Solyd** for the foundational cybersecurity knowledge
- The open-source security community

## 🚧 Ideas for later

No active development right now. Things that could be fun to add if I come back to it:

- [ ] Port scanning module
- [ ] Async DNS with aiodns
- [ ] YAML/TOML config file support
- [ ] Plugin system for custom modules

---

**Made with ❤️ by nuxyel**
