# Tarsius - Web Vulnerability Scanner
**University Project - 2025**
**Author:** stealthmoud

## Abstract
Tarsius is a lightweight, black-box web vulnerability scanner developed as part of a university independent study in cybersecurity. The tool is designed to identify common web application security flaws, including SQL Injection, Cross-Site Scripting (XSS), and Server-Side Request Forgery (SSRF).

This project demonstrates the practical application of automated security testing methodologies and includes 38 distinct attack modules.

## Features
The scanner supports active and passive analysis of web applications:
- **Injection Attacks**: Detection of SQL injection, XSS, XXE, and Command Injection.
- **Misconfiguration Detection**: Identification of missing security headers, sensitive file exposure, and directory listing.
- **Crawling Capabilities**: Automated discovery of endpoints and parameters.
- **Reporting**: Generation of detailed reports in HTML, JSON, and CSV formats.

## Architecture
The project is structured into modular components to facilitate extensibility:
- `src/tarsius/core`: Central logic and controller.
- `src/tarsius/attacks`: Individual vulnerability detection modules.
- `src/tarsius/network`: Networking primitives and crawler implementation.
- `src/tarsius/reports`: Report generation logic.

## Usage
To execute the scanner against a target URL:

```bash
tarsius <target_url> [options]
```

**Example:**
```bash
tarsius http://testphp.vulnweb.com
```

## Disclaimer
This tool is for educational purposes only. It should only be used on systems you own or have explicit permission to test. The author is not responsible for any misuse.

## License
This project is released under the GPLv2 license for educational use.
