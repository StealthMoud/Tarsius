# Tarsius - Recommended Test Targets

This document provides a collection of public websites that are intentionally designed with security vulnerabilities. These are safe and legal targets for testing the scanning capabilities of Tarsius.

## 1. Local VulnApp (Recommended)
Tarsius bundles a modern, deliberately vulnerable Node.js application explicitly designed to test its detection modules, including Upload, SSRF, XSS, and SQLi.

1. Start the VulnApp locally (requires Docker):
   ```bash
   docker compose -f tests/vulnapp/docker-compose.yml up -d
   ```
2. Scan the VulnApp:
   ```bash
   tarsius -u http://127.0.0.1:3000 -o reports/vulnapp.html
   ```

---

## 2. Acunetix Vulnerable Apps
Maintained by Acunetix (now Invicti), these are classic targets for testing web scanners.

- **PHP Lab (XSS, SQLi, etc.)**: [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
- **ASP.NET Lab**: [http://testaspnet.vulnweb.com](http://testaspnet.vulnweb.com)
- **ASP Lab**: [http://testasp.vulnweb.com](http://testasp.vulnweb.com)

**Recommended Command:**
```bash
tarsius -u http://testphp.vulnweb.com -o reports/testphp.html
```

---

## 3. Altoro Mutual (Testfire)
A simulated online banking site created by IBM to demonstrate web application vulnerabilities.

- **URL**: [http://demo.testfire.net](http://demo.testfire.net)

**Recommended Command:**
```bash
tarsius -u http://demo.testfire.net -m sql,xss -o reports/testfire.html
```

---

## 4. OWASP Juice Shop
Probably the most modern and sophisticated "vulnerable by design" web application.

- **URL (Public Demo)**: [https://demo.owasp-juice.shop](https://demo.owasp-juice.shop)

**Recommended Command:**
```bash
tarsius -u https://demo.owasp-juice.shop -o reports/juiceshop.html
```

---

## 5. Hack Yourself First
A target developed by Troy Hunt (creator of Have I Been Pwned) showing common real-world vulnerabilities.

- **URL**: [https://hack-yourself-first.com](https://hack-yourself-first.com)

**Recommended Command:**
```bash
tarsius -u https://hack-yourself-first.com -m xss,sql -o reports/hackyourself.html
```

---

## 6. Google Gruyere
An educational tool from Google created to teach web application security.

- **URL**: [https://google-gruyere.appspot.com](https://google-gruyere.appspot.com)

**Note:** This site requires you to start a personal "instance" (a unique ID in the URL).

---

## Tips for Testing

1. **Output**: Use `-o` to specify where the report goes.
2. **Verbosity**: Add `-v 1` for live feedback during the scan.
3. **Module Selection**: Use `-m xss,sql` to pick specific modules or omit for defaults.
4. **Timeout**: Increase with `-t 15` if the target is slow.
5. **CMS / Advanced Scanning**: Always run via Docker with `--external` to ensure WPScan, JoomScan, and Nuclei are actively involved in the penetration test.
