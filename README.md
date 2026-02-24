# Tarsius - Web Vulnerability Scanner
**University Project (2025)**
**Author:** stealthmoud

## Description
Tarsius is a black box web vulnerability scanner built with Node.js. It crawls websites, discovers pages and forms, then tests them for security flaws like SQL Injection, XSS, command execution, and more. Originally written in Python, it was rewritten in JavaScript for better performance and modern tooling.

## Requirements
- **Node.js** 18.0.0 or higher
- **npm** (comes with Node.js)

## Installation

```bash
git clone https://github.com/StealthMoud/Tarsius.git
cd Tarsius
npm install
```

> [!NOTE]
> If you plan to use headless browser scanning, you also need to install Playwright browsers:
> ```bash
> npx playwright install firefox
> ```

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

# scan with proxy and custom timeout
node bin/tarsius -u http://target.com -p http://127.0.0.1:8080 -t 15

# scan through tor
node bin/tarsius -u http://target.com --tor

# output json report to a specific folder
node bin/tarsius -u http://target.com -f json -o ./my_reports

# authenticated scan with cookies
node bin/tarsius -u http://target.com -C "session=abc123; token=xyz"

# list all available attack modules
node bin/tarsius --list-modules
```

### Common Options

| Option | Description |
|--------|-------------|
| `-u, --url <url>` | Target URL to scan |
| `-m, --module <list>` | Comma-separated list of modules to run |
| `-l, --level <1\|2>` | Attack level (2 = more aggressive) |
| `-d, --depth <n>` | Max crawl depth (default: 40) |
| `-t, --timeout <sec>` | Request timeout in seconds (default: 10) |
| `-p, --proxy <url>` | HTTP/SOCKS proxy URL |
| `--tor` | Use Tor (127.0.0.1:9050) |
| `-f, --format <fmt>` | Report format: html, json, csv, txt |
| `-o, --output <path>` | Output file or directory |
| `-v, --verbose <0-2>` | Verbosity level |
| `--scope <scope>` | Scan scope: url, page, folder, subdomain, domain, punk |
| `-S, --scan-force <f>` | Intensity: paranoid, sneaky, polite, normal, aggressive, insane |
| `--headless <mode>` | Headless browser: no, hidden, visible |
| `--skip-crawl` | Skip crawling, attack previously found URLs |
| `--flush-session` | Clear all stored data for this target |
| `-H, --header <h>` | Custom header (repeatable) |
| `-A, --user-agent <a>` | Custom user agent |
| `--verify-ssl` | Enable SSL certificate verification |
| `-C, --cookie-value <c>` | Cookie string for every request |
| `--jwt <token>` | JWT token for authenticated scans |

Run `node bin/tarsius --help` for the full list of options.

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
| `nikto` | Known dangerous paths | |
| `buster` | Directory brute force | |
| `brute_login_form` | Weak credential testing | |
| `htaccess` | Access control bypass | |
| `methods` | Uncommon HTTP methods | |
| `takeover` | Subdomain takeover | |
| `wapp` | Technology fingerprinting (Wappalyzer) | |
| `htp` | Technology fingerprinting (HashThePlanet) | |

## Project Structure

```
tarsius/
├── bin/tarsius              # entry point
├── package.json
├── config/                  # default scanner config
├── docs/                    # diagrams and technical docs
├── report_template/         # html report css/js/assets
└── src/
    ├── index.js             # version constants
    ├── cli.js               # command line interface
    ├── core/tarsius.js      # main scan controller
    ├── network/             # http, crawling, persistence
    ├── attacks/             # attack modules and scanners
    ├── parsers/             # html, ini, txt parsers
    ├── definitions/         # vulnerability type definitions
    ├── reports/             # report generators
    ├── utils/               # logging, banners
    └── data/attacks/        # payload files
```

## Report Formats
- **HTML** — interactive report you can open in a browser
- **JSON** — structured data for automation and CI/CD
- **CSV** — importable into spreadsheets
- **TXT** — plain text for quick reading

Reports are saved to `~/.tarsius/generated_report/` by default, or use `-o` to specify a path.

## Documentation
- [Test Targets](docs/test_targets.md) — vulnerable websites for testing
- [Technical Documentation](docs/technical_documentation.md) — architecture and internals

## License
Released under the GPLv2 license for educational use.
