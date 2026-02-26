# Tarsius - Technical Documentation & Assessment Guide

This document provides an in-depth look at the architecture, logic, and operational boundaries of Tarsius. It is intended for academic evaluation and technical review.

## 1. System Overview
Tarsius is a **DAST (Dynamic Application Security Testing)** tool. Unlike Static Analysis (SAST) which looks at source code, Tarsius interacts with a running web application over HTTP to discover vulnerabilities from the perspective of an external attacker.

### Core Architecture
Tarsius follows a modular architecture built on Node.js.

> [!NOTE]
> See [architecture.puml](diagrams/architecture.puml) for a visual overview of the system components.

- **CLI Layer (`cli.js`)**: Handles user input and argument validation using Commander.js.
- **Engine Layer (`core/tarsius.js`)**: The "brain" of the scanner. Orchestrates the crawler and the attack modules.
- **Crawler (`network/crawler.js`, `network/explorer.js`)**: A web spider that discovers URLs and forms using BFS traversal. Parses HTML with Cheerio.
- **Attack Layer (`attacks/`)**: Contains the vulnerability detection logic.
  - **ActiveScanner**: Loads modules that inject payloads into discovered targets.
  - **ExternalOrchestrator**: Integrates containerized Go/Ruby/Perl scanners (Nuclei, WPScan, JoomScan).
  - **PassiveScanner**: Analyzes server responses (headers, cookies, body) without modifying requests.
- **Reporting Layer (`reports/`)**: Generates reports in HTML, JSON, CSV, and plain text formats.

---

## 2. Scanning Logic: How it Works

### Operational Flow
The following sequence diagram illustrates the lifecycle of a typical scan.

> [!NOTE]
> See [scanning_flow.puml](diagrams/scanning_flow.puml) for the step-by-step scanning logic.

### Phase 1: Exploration (Crawling)
The scanner visits the target URL and extracts all links (`<a>`), forms (`<form>`), and scripts. It builds a map of the application's attack surface using breadth-first search with configurable depth limits.

### Phase 2: Mutation & Injection
For every parameter found (GET, POST), Tarsius uses the **`Mutator`** class to generate attack requests:
1. **Payload Selection**: Based on the module type, it selects specialized payloads from `data/attacks/`.
2. **Injection**: Each parameter is tested individually with each payload.
3. **Verification**: It analyzes the server's response code, headers, and body to confirm if the injection was successful.

### Phase 2.5: External Integration (Opt-In)
If launched with `--external` via Docker, Tarsius concurrently executes embedded vulnerability engines:
- Generates targeted Nuclei templates on the fly.
- Monitors site signatures for WordPress/Joomla to selectively fire WPScan/JoomScan.
- Parses disparate JSON/NDJSON outputs back into the unified Tarsius reporting engine.

### Phase 3: Reporting
Findings are persisted in a local SQLite database during the scan. Once complete, the reporting engine transforms these findings into a structured document.

---

## 3. False Positive Mitigation Heuristics
A major focus of Tarsius is reducing "noise" or false positives common in classic scanners:
1. **SSRF Padding Verification**: To avoid mistaking reflected input for SSRF (e.g., search functions), Tarsius generates an invalid domain (`http://a.invalid/`) and pads it to the exact length of the attack payload. If both payloads produce a highly similar response, it's flagged as a reflection anomaly, not a true SSRF.
2. **SQLi Logical Double-Check**: Boolean-based blind SQLi detection is notoriously noisy. Tarsius implements a two-stage verification: if `AND 1=1` / `AND 1=2` triggers an anomaly, it immediately verifies the finding with `AND 2=2` / `AND 2=3`. A finding is only logged if both logical sets yield consistent anomalies.
3. **Status Code Drift Prevention**: Any vulnerability inferred via response similarity (like blind SQLi or time-based SQLi) is strictly discarded if the "True" case response returns a different HTTP status code than the original baseline request (indicating a generic server error rather than true injection).

---

## 4. Scope of Detection (Capabilities)

Tarsius is equipped with **24 attack modules**, including:

- **Injection Flaws**:
  - **SQL Injection**: Error-based and time-based detection.
  - **Cross-Site Scripting (XSS)**: Reflected and stored XSS detection.
  - **Command Execution**: OS command injection via shell metacharacters.
  - **XXE**: XML External Entity injection.
  - **LDAP Injection**: LDAP query manipulation.

- **Configuration & Logic**:
  - **Unrestricted File Upload**: Detection and live verification of dangerous file uploads.
  - **CRLF Injection**: HTTP response splitting.
  - **File Disclosure**: Path traversal and backup file discovery.
  - **SSRF**: Server-side request forgery.
  - **Open Redirect**: Unvalidated redirects.
  - **CSRF**: Missing anti-CSRF tokens.
  - **Insecure Headers**: Missing HSTS, CSP, X-Frame-Options, etc.
  - **SSL/TLS**: Certificate expiry, self-signed certs.
  - **Shellshock / Log4Shell / Spring4Shell**: High-impact CVE detection.
  - **CMS Scanners**: Integrated WPScan and JoomScan (WordPress/Joomla) via Docker container.

---

## 4. What Tarsius is NOT (Limitations)

- **Not an Exploitation Tool**: Tarsius **reports** vulnerabilities; it does not **exploit** them.
- **No Persistence**: It does not install backdoors or maintain persistence on a target.
- **No Lateral Movement**: It scans the web application layer only.
- **Vulnerability-Focus**: It is a "point-in-time" auditor. It identifies flaws that exist at the moment of the scan.

---

## 5. Academic Relevance
Tarsius was designed to demonstrate:
1. **Asynchronous Networking**: High-performance HTTP interaction using Axios.
2. **Modular Software Design**: Easy extension of security logic through a plug-and-play module system.
3. **Security Research**: Implementation of industry-standard testing methodologies (OWASP WSTG).

---
**Author:** stealthmoud
**Version:** 3.2.10 (2025 University Edition)
