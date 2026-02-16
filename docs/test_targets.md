# Tarsius - Recommended Test Targets

This document provides a collection of public websites that are intentionally designed with security vulnerabilities. These are safe and legal targets for testing the scanning and detection capabilities of Tarsius.

## 1. Acunetix Vulnerable Apps
Maintained by Acunetix (now Invicti), these are classic targets for testing web scanners.

- **PHP Lab (XSS, SQLi, etc.)**: [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
- **ASP.NET Lab**: [http://testaspnet.vulnweb.com](http://testaspnet.vulnweb.com)
- **ASP Lab**: [http://testasp.vulnweb.com](http://testasp.vulnweb.com)

**Recommended Command:**
```bash
python3 bin/tarsius -u http://testphp.vulnweb.com -m common -o reports/testphp_report.html
```

---

## 2. Altoro Mutual (Testfire)
A simulated online banking site created by IBM to demonstrate web application vulnerabilities.

- **URL**: [http://demo.testfire.net](http://demo.testfire.net)

**Recommended Command:**
```bash
python3 bin/tarsius -u http://demo.testfire.net -m sql,xss,http_headers -o reports/testfire_report.html
```

---

## 3. OWASP Juice Shop
Probably the most modern and sophisticated "vulnerable by design" web application.

- **URL (Public Demo)**: [https://demo.owasp-juice.shop](https://demo.owasp-juice.shop)

**Note:** Since this is a modern SPA (Single Page Application), using the `--headless` flag is recommended to ensure all links are discovered.

**Recommended Command:**
```bash
python3 bin/tarsius -u https://demo.owasp-juice.shop --headless visible -m common -o reports/juiceshop_report.html
```

---

## 4. Hack Yourself First
A target developed by Troy Hunt (creator of Have I Been Pwned) showing common real-world vulnerabilities.

- **URL**: [https://hack-yourself-first.com](https://hack-yourself-first.com)

**Recommended Command:**
```bash
python3 bin/tarsius -u https://hack-yourself-first.com -m xss,sql -o reports/hackyourself_report.html
```

---

## 5. Google Gruyere
An educational tool from Google created to teach web application security.

- **URL**: [https://google-gruyere.appspot.com](https://google-gruyere.appspot.com)

**Note:** This site is slightly different as it often requires you to start a personal "instance" (a unique ID in the URL).

---

## Summary of Usage Tips for Testing

1. **Output Directory**: Use the `-o` flag to specify a report name. Tarsius will create a folder with that name containing the HTML report.
2. **Verbosity**: For detailed live feedback during the scan, add `-v 1`.
3. **Headless Mode**: For modern websites (React, Angular, Vue), use `--headless visible` to allow the scanner to "see" the page as a real user would.
4. **Module Selection**: Use `-m common` for a balanced scan or `-m all` for a deep, comprehensive audit.
