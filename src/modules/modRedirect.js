// open redirect detection with host validation

import { Attack, Mutator } from './attack.js';

export default class ModRedirect extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'redirect';
    }

    async attack(request) {
        // payloads that try to redirect to external sites
        const payloads = [
            'https://evil.com',
            '//evil.com',
            'https://evil.com/',
            '/\\evil.com',
            'https://evil%2Ecom',
            '///evil.com',
            '////evil.com',
            'https://evil.com%23',
            'https://evil.com%2F%2F',
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response) continue;

                // 1. Check if we got an actual redirect status code
                if (response.isRedirect) {
                    const location = response.redirectionUrl || '';

                    // 2. Stricter Validation: Check if the redirect is actually going to evil.com
                    // We parse the URL to ensure evil.com is the actual hostname
                    try {
                        let targetUrl;
                        if (location.startsWith('//')) {
                            targetUrl = new URL('http:' + location);
                        } else if (location.startsWith('/')) {
                            // Local redirect, not an open redirect unless it's a bypass like /\ or //
                            continue;
                        } else {
                            targetUrl = new URL(location);
                        }

                        if (targetUrl.hostname === 'evil.com' || targetUrl.hostname.endsWith('.evil.com')) {
                            this.logVulnerability(
                                'Open Redirect',
                                mutation.request,
                                `Open redirect confirmed to ${targetUrl.hostname} via parameter ${mutation.parameter}`,
                                mutation.parameter,
                                'WSTG-CLNT-04'
                            );
                            break;
                        }
                    } catch {
                        // If it's not a valid URL, fallback to partial check but with defensive boundaries
                        if (location.includes('://evil.com') || location.startsWith('//evil.com')) {
                            this.logVulnerability(
                                'Open Redirect',
                                mutation.request,
                                `Open redirect potential via parameter ${mutation.parameter} (malformed location: ${location})`,
                                mutation.parameter,
                                'WSTG-CLNT-04'
                            );
                            break;
                        }
                    }
                }
            } catch {
                // skip errors
            }
        }
    }
}
