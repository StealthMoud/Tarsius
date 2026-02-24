// redirect module - finds open redirect vulnerabilitys
// checks if url paramters can redirect users to external sites

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

                // check if we got redirected to our evil domain
                if (response.isRedirect) {
                    const location = response.redirectionUrl || '';
                    if (location.includes('evil.com')) {
                        this.logVulnerability(
                            'Open Redirect',
                            mutation.request,
                            `Open redirect via parameter ${mutation.parameter}`,
                            mutation.parameter,
                            'WSTG-CLNT-04'
                        );
                        break;
                    }
                }
            } catch {
                // skip errors
            }
        }
    }
}
