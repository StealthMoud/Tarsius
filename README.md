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

For a full list of all Tarsius attack modules, advanced scanning configurations, authentication examples, and project structure, please read the [Tarsius Usage Guide](docs/usage_guide.md).

## Report Formats
- **HTML** — visual report for the browser
- **JSON** — structured data for automation
- **CSV** — importable into spreadsheets
- **TXT** — plain text summary

## Architecture & Workflows

Curious about how Tarsius discovers and exploits vulnerabilities under the hood?

### Detailed Scanning Flow
A step-by-step sequence diagram charting the exact lifecycle of a scan, from the `AsyncCrawler` discovering internal links and identifying CMS platforms, down to the concurrent orchestration of native attacks alongside Nuclei, WPScan, and JoomScan.

![Detailed Scanning Flow](docs/diagrams/scanning_flow.puml)

### High-Level Architecture
View the component interplay between the Node.js engine, the persistent DB, and the external Docker wrappers.

![High-Level Architecture](docs/diagrams/architecture.puml)

## Documentation
- [Test Targets](docs/test_targets.md) — vulnerable websites for testing
- [Technical Documentation](docs/technical_documentation.md) — architecture details
- [Tarsius Usage Guide](docs/usage_guide.md) — Advanced configurations, modules, and full CLI references.
Released under the GPLv2 license for educational use.
