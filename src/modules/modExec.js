// os comand injecton checks

import { Attack, Mutator } from './attack.js';

export default class ModExec extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'exec';

        // load payloads once
        const payloadSections = this.loadIniPayloads('execPayloads.ini');
        this._payloads = Object.values(payloadSections).flat();
    }

    async attack(request) {
        const mutator = new Mutator(this._payloads, this.options.skippedParams || []);

        await this.sendMutations(request, mutator, (response, mutation) => {
            if (response.content && this._hasExecutionMarker(response.content)) {
                return {
                    category: 'Command Execution',
                    message: `Command injection found via parameter ${mutation.parameter}`,
                    wstg: 'WSTG-INPV-12',
                };
            }
            return null;
        });
    }

    _hasExecutionMarker(content) {
        if (content.includes('root:x:0:0:')) return true;
        if (content.includes('uid=') && content.includes('gid=')) return true;
        if (content.includes('Windows IP Configuration')) return true;
        if (content.includes('Volume Serial Number')) return true;
        return false;
    }
}
