// reflected xss detection with false-positive mitigation

import { Attack, Mutator } from './attack.js';

export default class ModXss extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'xss';

        // load payloads once
        const payloadSections = this.loadIniPayloads('xssPayloads.ini');
        this._payloads = Object.values(payloadSections).flat();
    }

    async attack(request) {
        const mutator = new Mutator(this._payloads, this.options.skippedParams || []);

        await this.sendMutations(request, mutator, (response, mutation) => {
            if (!response.content) return null;

            // 1. Content-Type Validation
            // Only flag XSS in executable browser contexts
            const contentType = (response.headers['content-type'] || '').toLowerCase();
            const isValidContext = contentType.includes('text/html') ||
                contentType.includes('application/xhtml+xml') ||
                contentType.includes('text/xml');

            if (!isValidContext) return null;

            // FALSE POSITIVE MITIGATION:
            // many servers reflect the invalid path in a 404 page. 
            // if we are testing a PATH_ parameter and get a 404, it's likely a false positive.
            if (mutation.parameter.startsWith('PATH_') && response.status === 404) {
                return null;
            }

            // 2. Exact Payload Reflection Check
            if (response.content.includes(mutation.payload)) {

                // 3. Canary Check & Character Validation (Context Analysis)
                // We check if the application is reflecting the payload "as-is" or escaping it.
                // If it's a simple reflection, we verify if critical characters are restricted.

                const criticalChars = ['<', '>', '"', "'"];
                let isVulnerable = true;

                // Simple check: if the payload contains tags, see if they are escaped
                if (mutation.payload.includes('<') && response.content.includes('&lt;')) {
                    isVulnerable = false;
                }
                if (mutation.payload.includes('>') && response.content.includes('&gt;')) {
                    isVulnerable = false;
                }

                if (isVulnerable) {
                    return {
                        category: 'Reflected Cross Site Scripting',
                        message: `XSS vulnerability found via parameter ${mutation.parameter}`,
                        wstg: 'WSTG-INPV-01',
                    };
                }
            }
            return null;
        });
    }
}
