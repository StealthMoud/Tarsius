// checks headers and cookies for issues

import { logYellow, logVerbose } from '../utils/log.js';

export class PassiveScanner {
    constructor() {
        this._anomalies = [];
    }

    // check all crawled pages using their already-fetched responses
    async run(crawledPages) {
        console.log('[*] Running passive checks...');
        const total = crawledPages.length;

        for (let i = 0; i < total; i++) {
            const { request, response } = crawledPages[i];

            const shortUrl = request.url.length > 60 ? request.url.substring(0, 57) + '...' : request.url;
            process.stdout.write(`\r    [${i + 1}/${total}] ${shortUrl}`.padEnd(100));

            try {
                this._checkHeaders(request, response);
                this._checkCookies(request, response);
                this._checkContent(request, response);
            } catch (error) {
                logVerbose(`passive check error on ${request.url}: ${error.message}`);
            }
        }
        process.stdout.write('\r' + ' '.repeat(100) + '\r');
    }

    // check for missing securty headers
    _checkHeaders(request, response) {
        const headers = response.headers;

        const securityHeaders = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy',
        ];

        for (const header of securityHeaders) {
            if (!headers[header]) {
                this._addAnomaly(
                    'HTTP Security Header Missing',
                    request,
                    `Missing ${header} header`,
                    'WSTG-CONF-07'
                );
            }
        }

        // check server header for version leakng
        if (headers.server && /[\d.]+/.test(headers.server)) {
            this._addAnomaly(
                'Web Server Fingerprint',
                request,
                `Server header reveals version: ${headers.server}`,
                'WSTG-INFO-02'
            );
        }
    }

    // check cookie securty flags
    _checkCookies(request, response) {
        const setCookies = response.cookies;

        for (const cookieStr of setCookies) {
            const lower = cookieStr.toLowerCase();
            const name = cookieStr.split('=')[0].trim();

            if (!lower.includes('secure')) {
                this._addAnomaly(
                    'Cookie Without Secure Flag',
                    request,
                    `Cookie "${name}" missing Secure flag`,
                    'WSTG-SESS-02'
                );
            }

            if (!lower.includes('httponly')) {
                this._addAnomaly(
                    'Cookie Without HttpOnly Flag',
                    request,
                    `Cookie "${name}" missing HttpOnly flag`,
                    'WSTG-SESS-02'
                );
            }
        }
    }

    // check page content for senstive info
    _checkContent(request, response) {
        const content = response.content;
        if (!content) return;

        if (request.scheme === 'http' && content.includes('type="password"')) {
            this._addAnomaly(
                'Cleartext Password Submission',
                request,
                'Login form over unencrypted HTTP',
                'WSTG-CRYP-03'
            );
        }
    }

    _addAnomaly(category, request, info, wstg) {
        logYellow(`[*] Anomaly: ${info}`);
        this._anomalies.push({ category, url: request.url, info, wstg });
    }

    get anomalies() { return this._anomalies; }
}
