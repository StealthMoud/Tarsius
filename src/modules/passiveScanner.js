// checks headers and cookies for issues

import { logYellow, logVerbose } from '../utils/log.js';
import { Attack } from './attack.js';

export class PassiveScanner extends Attack {
    constructor(crawler, persister, attackOptions, crawlerConfig) {
        super(crawler, persister, attackOptions, crawlerConfig);
        this.moduleName = 'passive';
    }

    // check all discovery pages for passive issues
    async launch(requests) {
        console.log('[*] Running passive checks...');
        const total = requests.length;

        for (let i = 0; i < total; i++) {
            const request = requests[i];
            const shortUrl = request.url.length > 60 ? request.url.substring(0, 57) + '...' : request.url;
            process.stdout.write(`\r    [${i + 1}/${total}] ${shortUrl}`.padEnd(100));

            try {
                const response = await this.crawler.get(request);
                if (!response) continue;

                await this._checkHeaders(request, response);
                await this._checkCookies(request, response);
                await this._checkContent(request, response);
            } catch (error) {
                logVerbose(`passive check error on ${request.url}: ${error.message}`);
            }
        }
        process.stdout.write('\r' + ' '.repeat(100) + '\r');
    }

    // check for missing securty headers
    async _checkHeaders(request, response) {
        const headers = response.headers;

        // check for missing securty headers
        const securityHeaders = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy',
        ];

        for (const header of securityHeaders) {
            if (!headers[header]) {
                this.logAnomaly(
                    'HTTP Security Header Missing',
                    request,
                    `Missing ${header} header`,
                    '',
                    'WSTG-CONF-07'
                );
            }
        }

        // check server header for version leakng
        if (headers.server && /[\d.]+/.test(headers.server)) {
            this.logAnomaly(
                'Web Server Fingerprint',
                request,
                `Server header reveals version: ${headers.server}`,
                '',
                'WSTG-INFO-02'
            );
        }
    }

    // check cookie securty flags
    async _checkCookies(request, response) {
        const setCookies = response.cookies;

        for (const cookieStr of setCookies) {
            const lower = cookieStr.toLowerCase();

            if (!lower.includes('secure')) {
                const name = cookieStr.split('=')[0].trim();
                this.logAnomaly(
                    'Cookie Without Secure Flag',
                    request,
                    `Cookie "${name}" missing Secure flag`,
                    name,
                    'WSTG-SESS-02'
                );
            }

            if (!lower.includes('httponly')) {
                const name = cookieStr.split('=')[0].trim();
                this.logAnomaly(
                    'Cookie Without HttpOnly Flag',
                    request,
                    `Cookie "${name}" missing HttpOnly flag`,
                    name,
                    'WSTG-SESS-02'
                );
            }
        }
    }

    // check page content for senstive info
    async _checkContent(request, response) {
        const content = response.content;
        if (!content) return;

        // check for passwrd fields over http
        if (request.scheme === 'http' && content.includes('type="password"')) {
            this.logAnomaly(
                'Cleartext Password Submission',
                request,
                'Login form over unencrypted HTTP',
                '',
                'WSTG-CRYP-03'
            );
        }
    }
}
