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

# Install Playwright browsers (required for headless scanning)
playwright install
```

> [!NOTE]
> Ensure you are using Python 3.9+ and have a virtual environment activated.

## Usage

You can run the scanner using the following syntax:

```bash
python3 bin/tarsius -u <target_url> [options]
```

### Example
Scanning a test application with default modules:

```bash
python3 bin/tarsius -u http://testphp.vulnweb.com
```

To list all available modules:
```bash
python3 bin/tarsius --list-modules
```

For more vulnerable websites and recommended test commands, see [test_targets.md](docs/test_targets.md).

For a detailed explanation of how Tarsius works, its architecture, and its limitations, please refer to [TECHNICAL_DOCUMENTATION.md](docs/technical_documentation.md).

## Features
- **SQL Injection** detection (Blind and Time-based)
- **Cross-Site Scripting (XSS)** scanning (Reflected and Permanent)
- **Misconfiguration checks** (Security Headers, File Disclosure, CRLF)
- **Advanced Scanning**: Supports headless Firefox for JavaScript-heavy sites.
- **CMS Porting**: Specialized modules for WordPress, Joomla, and Drupal.
- **Reporting**: Generates comprehensive reports in HTML, JSON, and other formats.

## License
Released under the GPLv2 license for educational use.
