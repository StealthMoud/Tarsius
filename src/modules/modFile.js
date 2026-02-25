// path traversal and file incluson

import { Attack, Mutator } from './attack.js';

export default class ModFile extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'file';

        // load payloads once
        const payloadSections = this.loadIniPayloads('fileHandlingPayloads.ini');
        this._payloads = Object.values(payloadSections).flat();
    }

    async attack(request) {
        const mutator = new Mutator(this._payloads, this.options.skippedParams || []);

        await this.sendMutations(request, mutator, (response, mutation) => {
            if (response.content && this._hasFileMarker(response.content)) {
                return {
                    category: 'File Inclusion',
                    message: `Path traversal found via parameter ${mutation.parameter}`,
                    wstg: 'WSTG-INPV-11',
                };
            }
            return null;
        });
    }

    _hasFileMarker(content) {
        if (content.includes('root:x:0:0:')) return true;  // linux passwd
        if (content.includes('root:*:0:0:')) return true;  // macos / bsd passwd
        if (content.includes('[boot loader]')) return true;
        if (content.includes('[extensions]')) return true;
        if (content.includes('<?php')) return true;
        if (content.includes('<configuration>') && content.includes('connectionString')) return true;
        return false;
    }
}
