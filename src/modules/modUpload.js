// file upload detecton

import { Attack } from './attack.js';

export default class ModUpload extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'upload';
    }

    async launch(requests) {
        const hasUpload = requests.some(r => r.fileParams && r.fileParams.length > 0);
        if (!hasUpload) {
            const { logBlue } = await import('../utils/log.js');
            logBlue(`[*] [${this.moduleName}] No file upload forms discovered. Skipping.`);
            return;
        }
        await super.launch(requests);
    }

    async attack(request) {
        // only check forms with file inputs
        if (!request.fileParams || request.fileParams.length === 0) return;

        // check each file paramter
        for (const [paramName] of request.fileParams) {
            // todo: actually try uploading dangerus files
            // for now just flag that there's a file upload
            this.logAnomaly(
                'Unrestricted File Upload',
                request,
                `File upload found via parameter "${paramName}"`,
                paramName,
                'WSTG-BUSL-08'
            );
        }
    }
}
