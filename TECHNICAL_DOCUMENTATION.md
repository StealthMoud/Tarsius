# Tarsius - Technical Documentation & Assessment Guide

This document provides an in-depth look at the architecture, logic, and operational boundaries of Tarsius. It is intended for academic evaluation and technical review.

## 1. System Overview
Tarsius is a **DAST (Dynamic Application Security Testing)** tool. Unlike Static Analysis (SAST) which looks at source code, Tarsius interacts with a running web application over HTTP to discover vulnerabilities from the perspective of an external attacker.

### Core Architecture
Tarsius follows a modular, asynchronous architecture built on Python's `asyncio` framework.

> [!NOTE]
> See [architecture.puml](docs/diagrams/architecture.puml) for a visual overview of the system components.

- **CLI Layer (`cli.py`, `parsers/`)**: Handles user input, argument validation, and session management.
- **Engine Layer (`core/controller/tarsius.py`)**: The "brain" of the scanner. Orchestrates the crawler and the attack modules.
- **Crawler (`network/crawler.py`)**: An asynchronous web spider that discovers URLs and forms. It supports both standard HTTP requests and **Headless Firefox** (via Playwright) for JavaScript rendering.
- **Attack Layer (`attacks/`)**: Contains the vulnerability detection logic.
  - **ActiveScanner**: Loads modules that inject payloads into discovered targets.
  - **PassiveScanner**: Analyzes server responses (headers, cookies, body) without modifying requests.
- **Reporting Layer (`reports/`)**: Uses the **Mako Template Engine** to generate professional HTML, JSON, and CSV reports.

---

## 2. Scanning Logic: How it Works

### Operational Flow
The following sequence diagram illustrates the lifecycle of a typical scan.

> [!NOTE]
> See [scanning_flow.puml](docs/diagrams/scanning_flow.puml) for the step-by-step scanning logic.


### Phase 1: Exploration (Crawling)
The scanner visits the target URL and extracts all links (`<a>`), forms (`<form>`), and scripts. It builds a map of the application's attack surface. If headless mode is enabled, it waits for JavaScript to execute, ensuring modern SPAs (Single Page Applications) are fully covered.

### Phase 2: Mutation & Injection
For every parameter found (GET, POST, JSON, Multipart), Tarsius uses the **`Mutator`** class to generate "Evil Requests":
1. **Tainting**: It first sends a harmless unique string (e.g., `wujmzlev3j`) to see if and where the input is reflected in the response.
2. **Payload Selection**: Based on the reflection context (e.g., inside an HTML tag, inside a `<script>`, or in a SQL query), it selects specialized payloads from `data/attacks/`.
3. **Verification**: It analyzes the server's response code, headers, and body to confirm if the injection was successful.

### Phase 3: Reporting
Findings are persisted in a local SQLite database during the scan. Once complete, the reporting engine transforms these findings into a structured document, highlighting severity levels (Critical, High, Medium, Low, Info).

---

## 3. Scope of Detection (Capabilities)

Tarsius is equipped with **37+ attack modules**, including:

- **Injection Flaws**:
  - **SQL Injection**: Error-based, Blind, and Time-based detection for MySQL, PostgreSQL, Oracle, and MSSQL.
  - **Cross-Site Scripting (XSS)**: Identification of Reflected and Permanent (Stored) XSS.
  - **Command Execution**: Detecting OS command injection via shell metacharacters.
  - **XXE**: XML External Entity injection via file upload modules.

- **Configuration & Logic**:
  - **CRLF Injection**: Testing for HTTP response splitting.
  - **File Disclosure**: Searching for sensitive files like `.htaccess`, `config.php`, or backup files.
  - **Insecure Headers**: Flagging missing HSTS, CSP, X-Frame-Options, etc.
  - **Heartbleed / Shellshock**: Detection of classic high-impact server vulnerabilities.

---

## 4. What Tarsius is NOT (Limitations)

It is important to distinguish Tarsius from "exploitation frameworks" used for offensive operations:

- **Not an Exploitation Tool**: Tarsius **reports** vulnerabilities; it does not **leverage** them. It will tell you a database is vulnerable to SQLi, but it will not dump the tables or user passwords.
- **No Persistence**: It does not install backdoors, web shells, or maintain persistence on a target.
- **No lateral movement**: It scans the web application layer only. It does not attempt to pivot into the internal network or exploit the underlying Operating System's kernel.
- **Vulnerability-Focus**: It is a "point-in-time" auditor. It identifies flaws that exist at the moment of the scan.

---

## 5. Academic Relevance
Tarsius was designed to demonstrate:
1.  **Asynchronous Networking**: High-performance HTTP interaction using `httpx`.
2.  **Modular Software Design**: Easy extension of security logic through a plug-and-play module system.
3.  **Security Research**: Implementation of industry-standard testing methodologies (OWASP WSTG).

---
**Author:** stealthmoud  
**Version:** 3.2.10 (2025 University Edition)
