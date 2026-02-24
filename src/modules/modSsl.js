// ssl cert checks

import https from 'https';
import tls from 'tls';
import { Attack } from './attack.js';
import { logVerbose } from '../utils/log.js';

export default class ModSsl extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'ssl';
    }

    async attack(request) {
        // only check https urls
        if (!request.url.startsWith('https://')) return;

        try {
            const urlObj = new URL(request.url);
            const certInfo = await this._getCertInfo(urlObj.hostname, parseInt(urlObj.port) || 443);

            if (!certInfo) return;

            // check if cert is expird
            if (certInfo.validTo) {
                const expiryDate = new Date(certInfo.validTo);
                if (expiryDate < new Date()) {
                    this.logVulnerability(
                        'SSL/TLS Issue',
                        request,
                        `SSL certificate expird on ${certInfo.validTo}`,
                        '',
                        'WSTG-CRYP-01'
                    );
                }
            }

            // check for self-signed cert
            if (certInfo.issuer && certInfo.subject &&
                JSON.stringify(certInfo.issuer) === JSON.stringify(certInfo.subject)) {
                this.logAnomaly(
                    'SSL/TLS Issue',
                    request,
                    'Self-signed SSL certifcate detected',
                    '',
                    'WSTG-CRYP-01'
                );
            }

        } catch (error) {
            logVerbose(`ssl check failed for ${request.url}: ${error.message}`);
        }
    }

    // get certificte info from the server
    _getCertInfo(hostname, port) {
        return new Promise((resolve, reject) => {
            const socket = tls.connect({
                host: hostname,
                port: port,
                rejectUnauthorized: false,
                servername: hostname,
            }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert);
            });

            socket.on('error', (err) => {
                reject(err);
            });

            socket.setTimeout(5000, () => {
                socket.destroy();
                reject(new Error('timeout'));
            });
        });
    }
}
