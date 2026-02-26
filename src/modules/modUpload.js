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
            // Benign test upload to verify if it's actually unrestricted
            // We use a small text file with a "safe" message
            try {
                const response = await this.crawler.send(request);

                // If the server responds with a success message indicating the file was saved,
                // we elevate this from "Anomaly" to "Vulnerability"
                const successMarkers = [
                    'uploaded successfully',
                    'file saved',
                    'success',
                    '/uploads/'
                ];

                let isVulnerable = false;
                for (const marker of successMarkers) {
                    if (response.content.toLowerCase().includes(marker)) {
                        isVulnerable = true;
                        break;
                    }
                }

                if (isVulnerable) {
                    this.logVulnerability(
                        'Unrestricted File Upload',
                        request,
                        `Unrestricted file upload confirmed via parameter "${paramName}"`,
                        paramName,
                        'WSTG-BUSL-08'
                    );
                } else {
                    this.logAnomaly(
                        'Potential File Upload',
                        request,
                        `File upload form found via parameter "${paramName}" but upload verification was inconclusive`,
                        paramName,
                        'WSTG-BUSL-08'
                    );
                }
            } catch (error) {
                // if the upload failed, we still log the anomaly that a form exists
                this.logAnomaly(
                    'Potential File Upload',
                    request,
                    `File upload discovery failed for "${paramName}": ${error.message}`,
                    paramName,
                    'WSTG-BUSL-08'
                );
            }
        }
    }
}
