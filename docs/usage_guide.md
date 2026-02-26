# Tarsius Usage Guide

## Full CLI Options

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
