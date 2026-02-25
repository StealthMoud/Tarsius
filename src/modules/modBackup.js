// finds backup files on the server

import { Attack } from './attack.js';
import { Request } from '../http/request.js';

export default class ModBackup extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'backup';
    }

    async attack(request) {
        // 1. get the original content as a baseline to avoid false positives 
        // (if "backup" returns exactly the same content as the original page, it's likely a catch-all route)
        const originalRes = await this.crawler.get(request);
        const originalContent = originalRes ? originalRes.content : '';

        // load backup payloads
        const payloads = this.loadTxtPayloads('backupPayloads.txt');
        const fileName = request.fileName || '';
        const fileNoExt = fileName.includes('.') ? fileName.split('.').slice(0, -1).join('.') : fileName;

        // get the directory part of the path
        const basePath = request.path;
        const dirPath = basePath.substring(0, basePath.lastIndexOf('/') + 1);

        const testedUrls = new Set();

        for (const rawPayload of payloads) {
            if (this._isTimeUp()) break;

            let probePath = '';

            // handle placeholders or static names
            if (rawPayload.includes('[FILE_NAME]')) {
                if (!fileName) continue;
                probePath = dirPath + rawPayload.replace('[FILE_NAME]', fileName);
            } else if (rawPayload.includes('[FILE_NOEXT]')) {
                if (!fileNoExt) continue;
                probePath = dirPath + rawPayload.replace('[FILE_NOEXT]', fileNoExt);
            } else {
                // assume its a static file in the same directory (e.g. backup.zip)
                probePath = dirPath + rawPayload;
            }

            if (!probePath || testedUrls.has(probePath)) continue;
            testedUrls.add(probePath);

            try {
                const backupReq = new Request(probePath, { referer: request.url });
                const response = await this.crawler.get(backupReq);

                if (!response) continue;

                // verification logic:
                // - status 200
                // - has content
                // - content is DIFFERENT from original (very important to stop false positives)
                if (response.status === 200 && response.content && response.content.length > 0) {
                    if (response.content === originalContent) {
                        continue;
                    }

                    this.logVulnerability(
                        'Backup File',
                        backupReq,
                        `Backup file found at ${probePath}`,
                        '',
                        'WSTG-CONF-04'
                    );
                }
            } catch {
                // skip
            }
        }
    }
}
