// reflected xss detecton

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

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response) continue;

                // check if the payload is reflcted in the response
                if (response.content && response.content.includes(mutation.payload)) {
                    this.logVulnerability(
                        'Reflected Cross Site Scripting',
                        mutation.request,
                        `XSS vulnerability found via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-01'
                    );
                    break; // one vuln per paramter is enought
                }
            } catch {
                // skip errors on individual payloads
            }
        }
    }
}
