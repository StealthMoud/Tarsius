# Tarsius - Web Vulnerability Scanner
**University Project (2025)**
**Author:** stealthmoud

## Description
Tarsius is a web vulnerability scanner written in Python. It detects security flaws like SQL Injection, XSS, and command execution vulnerabilities. This tool was developed as part of an independent study in cybersecurity.

## Installation

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/StealthMoud/Tarsius.git
cd Tarsius

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

You can run the scanner directly using Python:

```bash
python3 bin/tarsius <target_url> [options]
```

### Example
Scanning a test application:

```bash
python3 bin/tarsius http://testphp.vulnweb.com
```

## Features
- **SQL Injection** detection (Blind and Time-based)
- **Cross-Site Scripting (XSS)** scanning
- **Misconfiguration checks** (Security Headers, File Disclosure)
- **Command Execution** and **File Handling** vulnerabilities
- Generates reports in HTML and JSON formats.

## License
Released under the GPLv2 license for educational use.
