# Tarsius - Web Vulnerability Scanner
**University Project (2025)**
**Author:** stealthmoud

## Description
Tarsius is a black box web vulnerability scanner built with Node.js. It crawls websites, discovers pages and forms, then tests them for security flaws like SQL Injection, XSS, command execution, and more. Recently updated with advanced double-verification heuristics to actively reduce false positives from dynamic content and WAFs.

## Requirements
- **Node.js** 18.0.0 or higher
- **npm** (comes with Node.js)

## Installation & Usage (Recommended)

The easiest and most reliable way to run Tarsius is via Docker. This ensures all external dependencies (like ProjectDiscovery's Nuclei) are built-in and ready to augment your scans.

```bash
# Pull the latest image (or build it locally)
docker build -t stealthmoud/tarsius .

# Run a scan against a target
docker run --rm -it ghcr.io/stealthmoud/tarsius -u http://target.com
```

### Manual Installation (Node.js)
If you prefer to run Tarsius directly on your host machine without Docker:

```bash
git clone https://github.com/stealthmoud/tarsius.git
cd tarsius
npm install --omit=dev  # Install only production dependencies
node bin/tarsius -u http://target.com
```
*(Note: If you run Tarsius manually, the external engine orchestration flag `--external` requires `nuclei` to be installed in your system PATH).*

### Local Testing Environment (VulnApp)
Tarsius comes with a modern, deliberately vulnerable Node.js application called **VulnApp** explicitly designed to exercise all detection modules.

1. Start the VulnApp locally (requires Docker):
   ```bash
   docker compose -f tests/vulnapp/docker-compose.yml up -d
   ```
2. Scan the VulnApp:
   ```bash
   node bin/tarsius -u http://127.0.0.1:3000
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

All modules are run by default unless you explicitly restrict them using the `-m` flag.

| Module | Description | Default |
|--------|-------------|---------|
| `xss` | Reflected cross-site scripting | yes |
| `permanentxss` | Stored cross-site scripting | yes |
| `sql` | SQL injection (error-based) | yes |
| `timesql` | Blind time-based SQL injection | yes |
| `exec` | OS command injection | yes |
| `file` | Path traversal / file inclusion | yes |
| `ssrf` | Server-side request forgery | yes |
| `redirect` | Open redirect | yes |
| `upload` | Unrestricted file upload | yes |
| `ssl` | SSL/TLS certificate issues | yes |
| `csrf` | Cross-site request forgery | yes |
| `crlf` | CRLF header injection | yes |
| `xxe` | XML external entity injection | yes |
| `backup` | Backup file discovery | yes |
| `shellshock` | Shellshock (CVE-2014-6271) | yes |
| `log4shell` | Log4Shell (CVE-2021-44228) | yes |
| `spring4shell` | Spring4Shell (CVE-2022-22965) | yes |
| `nikto` | Known dangerous files and scripts | yes |
| `buster` | Directory brute force | yes |
| `brute_login_form` | Weak credential testing | yes |
| `htaccess` | Access control bypass | yes |
| `methods` | Uncommon HTTP methods | yes |
| `ldap` | LDAP injection | yes |
| `takeover` | Subdomain takeover | yes |

### External Tool Orchestration (Opt-In)

If you run Tarsius via its Docker image, it comes pre-packaged with external security tools that can dramatically expand vulnerability coverage. To enable them, simply attach the `--external` flag.

```bash
docker run --rm -it ghcr.io/stealthmoud/tarsius -u http://target.com --external
```

**Currently Supported External Engines:**
- **Nuclei**: Automatically executes the built-in `nuclei` binary against the scraped host data and seamlessly merges its CVE findings directly into the finalized Tarsius report.

## Project Structure

```
tarsius/
├── bin/tarsius              # cli entry point
├── package.json
├── data/attacks/            # payload files
├── docs/                    # technical docs
├── report_template/         # html report assets
└── src/
    ├── index.js             # version constants
    ├── cli.js               # command line interface
    ├── scanner.js           # main scan controller
    ├── http/                # request, response, http client
    ├── crawler/             # crawler, explorer, scope
    ├── auth/                # authentication, cookies
    ├── db/                  # sqlite persistence
    ├── modules/             # attack modules
    ├── parsers/             # html, ini, txt parsers
    ├── definitions/         # vulnerability definitions
    ├── reports/             # report generators
    └── utils/               # logging, banners
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
