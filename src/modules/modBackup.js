// finds backup files on the server

import { Attack } from './attack.js';
import { Request } from '../http/request.js';
import { pMap } from '../utils/concurrency.js';

export default class ModBackup extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'backup';
    }

    async attack(request) {
        // 1. get the original content as a baseline to avoid false positives 
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
        const numThreads = this.options.threads || 16;

        // map payloads to probe paths
        const probePaths = payloads.map(rawPayload => {
            if (rawPayload.includes('[FILE_NAME]')) {
                if (!fileName) return null;
                return dirPath + rawPayload.replace('[FILE_NAME]', fileName);
            } else if (rawPayload.includes('[FILE_NOEXT]')) {
                if (!fileNoExt) return null;
                return dirPath + rawPayload.replace('[FILE_NOEXT]', fileNoExt);
            } else {
                return dirPath + rawPayload;
            }
        }).filter(p => p !== null);

        // run probes concurrently
        await pMap(probePaths, async (probePath) => {
            if (this._isTimeUp()) return;
            if (testedUrls.has(probePath)) return;
            testedUrls.add(probePath);

            try {
                const backupReq = new Request(probePath, { referer: request.url });
                const response = await this.crawler.get(backupReq);

                if (!response) return;

                // verification logic: 200 OK + content + different from original
                if (response.status === 200 && response.content && response.content.length > 0) {
                    if (response.content === originalContent) {
                        return;
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
        }, numThreads);
    }
}
