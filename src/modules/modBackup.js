// backup module - finds backup files left on the web server
// tries comn backup file extentions and paths

import { Attack } from './attack.js';
import { Request } from '../http/request.js';

export default class ModBackup extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'backup';
    }

    async attack(request) {
        // load backup payloads
        const payloads = this.loadTxtPayloads('backupPayloads.txt');

        for (const suffix of payloads) {
            if (this._isTimeUp()) break;

            try {
                // try adding the backup suffix to the url
                const backupUrl = request.url + suffix;
                const backupReq = new Request(backupUrl, { referer: request.url });
                const response = await this.crawler.get(backupReq);

                if (!response) continue;

                // if we get a 200 with content, its probly a backup file
                if (response.status === 200 && response.content && response.content.length > 0) {
                    this.logVulnerability(
                        'Backup File',
                        backupReq,
                        `Backup file found: ${backupUrl}`,
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
