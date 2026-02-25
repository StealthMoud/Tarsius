// server side request forgry with similarity detection

import { Attack, Mutator } from './attack.js';

export default class ModSsrf extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'ssrf';
    }

    async attack(request) {
        const payloads = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'http://127.0.0.1:22/',
            'http://127.0.0.1:3306/',
            'http://127.0.0.1:3000/', // internal web application port
            'http://127.0.0.1:8080/',
            'http://169.254.169.254/latest/meta-data/',  // aws metadata
            'http://metadata.google.internal/',           // gcp metadata
            'http://169.254.169.254/metadata/instance',   // azure metadata
            'http://127.0.0.1:6379/',                     // redis default port
            'file:///etc/passwd',
            'file:///etc/hostname',
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        // get normal respnse first for baseline comparison
        let normalResponse;
        try {
            normalResponse = await this.crawler.send(request);
        } catch {
            return;
        }
        if (!normalResponse || !normalResponse.content) return;

        const baseContent = normalResponse.content;

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // 1. Check for specific success markers (High Confidence)
                if (this._hasExplicitSSRFMarker(response.content)) {
                    this.logVulnerability(
                        'Server Side Request Forgery',
                        mutation.request,
                        `SSRF confirmed via explicit marker in parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-19'
                    );
                    break;
                }

                // 2. Check for significant response change (Similarity Analysis)
                // If the response is significantly different from the baseline, it may indicate SSRF
                if (!this.isResponseSimilar(baseContent, response.content, 0.15)) { // 15% threshold for SSRF
                    this.logVulnerability(
                        'Server Side Request Forgery',
                        mutation.request,
                        `Potential SSRF found via response anomaly in parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-19'
                    );
                    break;
                }
            } catch {
                // skip errors
            }
        }
    }

    // check for unambiguous indicators of successful SSRF
    _hasExplicitSSRFMarker(content) {
        const markers = [
            'ami-id', 'instance-id', 'local-hostname', // AWS
            'computeMetadata/v1',                      // GCP
            'SSH-2.0-',                                // SSH banner
            'root:x:0:0:', 'root:*:0:0:',              // Unix passwd
            '+PONG', '$6\r\nSELECT',                  // Redis
            'mysql_native_password',                   // MySQL
            '[boot loader]',                           // Windows win.ini
        ];

        for (const marker of markers) {
            if (content.includes(marker)) return true;
        }

        return false;
    }
}
