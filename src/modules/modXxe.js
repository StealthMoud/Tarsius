// xml external entiy injecton

import { Attack, Mutator } from './attack.js';

export default class ModXxe extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'xxe';
    }

    async attack(request) {
        const payloadSections = this.loadIniPayloads('xxePayloads.ini');
        const allPayloads = Object.values(payloadSections).flat();

        const mutator = new Mutator(allPayloads, this.options.skippedParams || []);

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // check for xxe markers
                if (response.content.includes('root:x:0:0:') ||
                    response.content.includes('ENTITY')) {
                    this.logVulnerability(
                        'XML External Entity',
                        mutation.request,
                        `XXE vulnerability via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-07'
                    );
                    break;
                }
            } catch {
                // skip
            }
        }
    }
}
