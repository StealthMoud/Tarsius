# Tarsius - Web Vulnerability Scanner
**University Project (2025)**
**Author:** stealthmoud

## Description
Tarsius is a black box web vulnerability scanner built with Node.js. It crawls websites, discovers pages and forms, then tests them for security flaws like SQL Injection, XSS, command execution, and more.

## Requirements
- **Node.js** 18.0.0 or higher
- **npm** (comes with Node.js)

## Installation

```bash
git clone https://github.com/StealthMoud/Tarsius.git
cd Tarsius
npm install
```

## Usage

```bash
node bin/tarsius -u <target_url> [options]
```

### Quick Examples

```bash
# basic scan with default modules
node bin/tarsius -u http://testphp.vulnweb.com

# scan with specific modules only
node bin/tarsius -u http://target.com -m xss,sql,exec

# scan with a proxy
node bin/tarsius -u http://target.com -p http://127.0.0.1:8080

# scan with a cookie
node bin/tarsius -u http://target.com -C "session=abc123"

# output json report
node bin/tarsius -u http://target.com -f json -o ./report.json

# list all available attack modules
node bin/tarsius --list-modules
```

### Options

| Option | Description |
|--------|-------------|
| `-u, --url <url>` | Target URL to scan |
| `-m, --module <list>` | Comma-separated modules to run |
| `-l, --level <1\|2>` | Attack level (2 = more aggressive) |
| `-d, --depth <n>` | Max crawl depth (default: 40) |
| `-t, --timeout <sec>` | Request timeout in seconds (default: 10) |
| `-p, --proxy <url>` | HTTP/SOCKS proxy URL |
| `-f, --format <fmt>` | Report format: html, json, csv, txt |
| `-o, --output <path>` | Output file or directory |
| `-v, --verbose <0-2>` | Verbosity level |
| `--scope <scope>` | Scan scope: url, folder, domain |
| `--skip-crawl` | Skip crawling, attack found URLs only |
| `-s, --start <urls>` | Extra URLs to crawl |
| `-x, --exclude <urls>` | URLs to exclude |
| `--skip <params>` | Parameters to skip attacking |
| `-H, --header <h>` | Custom header (repeatable) |
| `-A, --user-agent <a>` | Custom user agent |
| `--verify-ssl` | Enable SSL certificate verification |
| `-C, --cookie-value <c>` | Cookie string for every request |
| `-c, --cookie <file>` | JSON cookie file path |
| `--auth-user <user>` | HTTP basic auth username |
| `--auth-password <pw>` | HTTP basic auth password |
| `--form-user <user>` | Login form username |
| `--form-password <pw>` | Login form password |
| `--form-url <url>` | Login form URL |
| `--tasks <n>` | Concurrent crawl tasks (default: 32) |
| `--max-links-per-page <n>` | Max links per page (default: 100) |
| `--max-scan-time <sec>` | Max total scan time |
| `--max-attack-time <sec>` | Max time per attack module |

Run `node bin/tarsius --help` for the full list.

### Authentication

```bash
# http basic auth
node bin/tarsius -u http://target.com --auth-user admin --auth-password secret

# form login
node bin/tarsius -u http://target.com --form-user admin --form-password pass --form-url http://target.com/login

# cookie-based
node bin/tarsius -u http://target.com -C "PHPSESSID=abc123"
```

## Attack Modules

| Module | Description | Default |
|--------|-------------|---------|
| `xss` | Reflected cross-site scripting | ✅ |
| `permanentxss` | Stored cross-site scripting | ✅ |
| `sql` | SQL injection (error-based) | ✅ |
| `timesql` | Blind time-based SQL injection | |
| `exec` | OS command injection | ✅ |
| `file` | Path traversal / file inclusion | ✅ |
| `ssrf` | Server-side request forgery | ✅ |
| `redirect` | Open redirect | ✅ |
| `upload` | Unrestricted file upload | ✅ |
| `ssl` | SSL/TLS certificate issues | ✅ |
| `csrf` | Cross-site request forgery | |
| `crlf` | CRLF header injection | |
| `xxe` | XML external entity injection | |
| `backup` | Backup file discovery | |
| `shellshock` | Shellshock (CVE-2014-6271) | |
| `log4shell` | Log4Shell (CVE-2021-44228) | |
| `spring4shell` | Spring4Shell (CVE-2022-22965) | |
| `nikto` | Known dangerous files and scripts | |
| `buster` | Directory brute force | |
| `brute_login_form` | Weak credential testing | |
| `htaccess` | Access control bypass | |
| `methods` | Uncommon HTTP methods | |
| `ldap` | LDAP injection | |
| `takeover` | Subdomain takeover | |

## Project Structure

```
tarsius/
├── bin/tarsius              # cli entry point
├── package.json
├── docs/                    # technical docs
├── report_template/         # html report assets
└── src/
    ├── index.js             # version constants
    ├── cli.js               # command line interface
    ├── core/tarsius.js      # main scan controller
    ├── network/             # http, crawling, persistence
    ├── attacks/             # attack modules
    ├── parsers/             # html, ini, txt parsers
    ├── definitions/         # vulnerability definitions
    ├── reports/             # report generators
    ├── utils/               # logging, banners
    └── data/attacks/        # payload files
```

## Report Formats
- **HTML** — visual report for the browser
- **JSON** — structured data for automation
- **CSV** — importable into spreadsheets
- **TXT** — plain text summary

## Documentation
- [Test Targets](docs/test_targets.md) — vulnerable websites for testing
- [Technical Documentation](docs/technical_documentation.md) — architecture details

## License
Released under the GPLv2 license for educational use.
