// os comand injecton checks

import { Attack, Mutator } from './attack.js';

export default class ModExec extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'exec';
    }

    async attack(request) {
        const payloadSections = this.loadIniPayloads('execPayloads.ini');
        const allPayloads = Object.values(payloadSections).flat();

        const mutator = new Mutator(allPayloads, this.options.skippedParams || []);

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // check for comand execution indicators
                // these strings would only apear if the comand ran
                if (this._hasExecutionMarker(response.content, mutation.payload)) {
                    this.logVulnerability(
                        'Command Execution',
                        mutation.request,
                        `Command injection found via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-12'
                    );
                    break;
                }
            } catch {
                // skip errors
            }
        }
    }

    // check if the respnse shows signs of comand execution
    _hasExecutionMarker(content, payload) {
        // look for unix/linux markers
        if (content.includes('root:x:0:0:')) return true;    // /etc/passwd
        if (content.includes('uid=') && content.includes('gid=')) return true;  // id command
        if (content.includes('Windows IP Configuration')) return true;  // ipconfig
        if (content.includes('Volume Serial Number')) return true;  // dir command

        return false;
    }
}
