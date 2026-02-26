import { spawn } from 'child_process';
import { logYellow, logVerbose, logBlue } from '../utils/log.js';
import { Attack } from './attack.js';

export default class ModNuclei extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'nuclei';
    }

    static get name() { return 'nuclei'; }

    // Nuclei maps its own severities; we map them to Tarsius numeric levels
    // Tarsius convention: 1 (anomaly), 2 (low), 3 (medium), 4 (high), 5 (critical)
    _mapSeverity(nucleiSeverity) {
        const sev = (nucleiSeverity || '').toLowerCase();
        if (sev === 'critical') return 5;
        if (sev === 'high') return 4;
        if (sev === 'medium') return 3;
        if (sev === 'low') return 2;
        return 1; // info/unknown -> anomaly
    }

    // Since Nuclei scans whole hosts/templates, we don't need to run it per request path.
    // Instead, we extract unique target hosts from the request lists, run docker, and parse the output.
    async launch(requests) {
        this._startTime = Date.now();

        // extract strictly unique root URLs (e.g. scheme://host:port)
        const uniqueTargets = new Set();
        for (const req of requests) {
            if (req.scheme && req.netloc) {
                uniqueTargets.add(`${req.scheme}://${req.netloc}`);
            }
        }

        logBlue(`[*] [${this.moduleName}] Initiating Docker container for ${uniqueTargets.size} target(s).`);

        for (const target of uniqueTargets) {
            if (this._isTimeUp()) break;
            await this._runNucleiNative(target, requests[0]); // pass the first request object just for tracking context
        }
    }

    _runNucleiNative(targetUrl, contextRequest) {
        return new Promise((resolve) => {
            logVerbose(`Running native Nuclei against ${targetUrl}...`);

            // `nuclei -u <target> -jsonl -silent`
            const args = [
                '-u', targetUrl,
                '-jsonl',    // JSON Lines output for easy streaming parse
                '-silent'    // Only output findings, no banners
            ];

            const child = spawn('nuclei', args);

            let buffer = '';

            child.stdout.on('data', (data) => {
                buffer += data.toString();
                // Process NDJSON line by line
                let n = buffer.indexOf('\n');
                while (n !== -1) {
                    const line = buffer.substring(0, n);
                    buffer = buffer.substring(n + 1);
                    this._processFinding(line, contextRequest);
                    n = buffer.indexOf('\n');
                }
            });

            child.stderr.on('data', (data) => {
                logVerbose(`Nuclei STDERR: ${data.toString().trim()}`);
            });

            child.on('close', (code) => {
                if (buffer.trim().length > 0) {
                    this._processFinding(buffer.trim(), contextRequest);
                }
                if (code !== 0) {
                    logYellow(`[*] [${this.moduleName}] Nuclei exited with code ${code}.`);
                }
                resolve();
            });

            child.on('error', (err) => {
                logYellow(`[*] [${this.moduleName}] Failed to spawn Nuclei: ${err.message}. Is it installed? (Run Tarsius via Docker for built-in support)`);
                resolve();
            });
        });
    }

    _processFinding(jsonString, contextRequest) {
        try {
            if (!jsonString.trim()) return;
            const finding = JSON.parse(jsonString);

            // Nuclei JSON structure usually contains:
            // "template-id", "info": { "name", "severity" }, "matched-at", "extracted-results"

            const templateId = finding['template-id'] || 'unknown';
            const name = (finding.info && finding.info.name) ? finding.info.name : templateId;
            const severityStr = (finding.info && finding.info.severity) ? finding.info.severity : 'info';
            const matchedAt = finding['matched-at'] || contextRequest.url;

            const severityLevel = this._mapSeverity(severityStr);
            const message = `[Nuclei] ${name} (Severity: ${severityStr})`;

            // If it's just 'info', we treat it as an anomaly, otherwise a full vulnerability
            if (severityLevel <= 1) {
                this.logAnomaly(templateId, contextRequest, message, '', `URL: ${matchedAt}`);
            } else {
                this.logVulnerability(templateId, contextRequest, message, '', `URL: ${matchedAt}`);
            }
        } catch (e) {
            logVerbose(`Failed to parse Nuclei JSON line: ${jsonString}`);
        }
    }
}
