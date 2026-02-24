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

        await this.sendMutations(request, mutator, (response, mutation) => {
            if (response.content && response.content.includes(mutation.payload)) {
                return {
                    category: 'Reflected Cross Site Scripting',
                    message: `XSS vulnerability found via parameter ${mutation.parameter}`,
                    wstg: 'WSTG-INPV-01',
                };
            }
            return null;
        });
    }
}
