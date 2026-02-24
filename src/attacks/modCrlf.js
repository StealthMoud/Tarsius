// crlf module - detects carriage return line feed injecton in headers

import { Attack, Mutator } from './attack.js';

export default class ModCrlf extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'crlf';
    }

    async attack(request) {
        const payloads = [
            '%0D%0ASet-Cookie:tarsius=crlf',
            '%0d%0aX-Injected:tarsius',
            '\\r\\nSet-Cookie:tarsius=crlf',
            '%E5%98%8A%E5%98%8DSet-Cookie:tarsius=crlf',
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response) continue;

                // check if our injectd header apears in the response headers
                const headers = response.headers;
                if (headers['x-injected'] === 'tarsius' ||
                    (headers['set-cookie'] && headers['set-cookie'].includes('tarsius=crlf'))) {
                    this.logVulnerability(
                        'CRLF Injection',
                        mutation.request,
                        `CRLF injection via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-15'
                    );
                    break;
                }
            } catch {
                // skip
            }
        }
    }
}
