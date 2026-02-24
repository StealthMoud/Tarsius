// file inclusion module - finds path traversal and file inclusion vulns
// tests paramters with ../ and file paths to see if we can read local files

import { Attack, Mutator } from './attack.js';

export default class ModFile extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'file';
    }

    async attack(request) {
        const payloadSections = this.loadIniPayloads('fileHandlingPayloads.ini');
        const allPayloads = Object.values(payloadSections).flat();

        const mutator = new Mutator(allPayloads, this.options.skippedParams || []);

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // check for file incluison indicators
                if (this._hasFileMarker(response.content)) {
                    this.logVulnerability(
                        'File Inclusion',
                        mutation.request,
                        `Path traversal found via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-11'
                    );
                    break;
                }
            } catch {
                // skip errors
            }
        }
    }

    // check if the respnse contains file content markers
    _hasFileMarker(content) {
        // unix file markers
        if (content.includes('root:x:0:0:')) return true;       // /etc/passwd
        if (content.includes('[boot loader]')) return true;      // boot.ini
        if (content.includes('[extensions]')) return true;       // win.ini

        // php source code leaking
        if (content.includes('<?php')) return true;

        // web config files
        if (content.includes('<configuration>') && content.includes('connectionString')) return true;

        return false;
    }
}
