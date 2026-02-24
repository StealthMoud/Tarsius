// file upload detecton

import { Attack } from './attack.js';

export default class ModUpload extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'upload';
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
