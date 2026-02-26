import { spawn } from 'child_process';
import { logYellow, logVerbose, logBlue, logRed } from '../utils/log.js';
import { Attack } from './attack.js';

export default class ModJoomscan extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'joomscan';
    }

    static get name() { return 'joomscan'; }

    // Check if the target is likely Joomla
    _isJoomla(requests) {
        for (const req of requests) {
            const body = req.responseBody || '';
            const path = req.path || '';

            // 1. Look for typical Joomla admin paths
            if (path.includes('/administrator/index.php')) {
                return true;
            }

            // 2. Look for generator meta tag
            if (body.toLowerCase().includes('<meta name="generator" content="joomla')) {
                return true;
            }

            // 3. Look for Joomla specific directories
            if (path.includes('/components/com_') || path.includes('/media/system/js/')) {
                return true;
            }
        }
        return false;
    }

    async launch(requests) {
        this._startTime = Date.now();

        // 1. Heuristic Check: Only run JoomScan if Joomla is detected
        const isJoomla = this._isJoomla(requests);
        if (!isJoomla) {
            logVerbose(`[*] [${this.moduleName}] Target does not appear to be Joomla. Skipping JoomScan.`);
            return;
        }

        // 2. Identify unique root targets
        const uniqueTargets = new Set();
        for (const req of requests) {
            if (req.scheme && req.netloc) {
                uniqueTargets.add(`${req.scheme}://${req.netloc}`);
            }
        }

        logBlue(`[*] [${this.moduleName}] Joomla detected! Initiating JoomScan for ${uniqueTargets.size} target(s).`);

        for (const target of uniqueTargets) {
            if (this._isTimeUp()) break;
            await this._runJoomscan(target, requests[0]);
        }
    }

    _runJoomscan(targetUrl, contextRequest) {
        return new Promise((resolve) => {
            logVerbose(`Running native JoomScan against ${targetUrl}...`);

            // JoomScan is a perl script located at /opt/joomscan/joomscan.pl
            // `perl /opt/joomscan/joomscan.pl --url <target>`
            const args = [
                '/opt/joomscan/joomscan.pl',
                '--url', targetUrl
            ];

            const child = spawn('perl', args);

            let buffer = '';

            child.stdout.on('data', (data) => {
                buffer += data.toString();
            });

            child.stderr.on('data', (data) => {
                logVerbose(`JoomScan progress/error: ${data.toString().trim()}`);
            });

            child.on('close', (code) => {
                this._processFindings(buffer, contextRequest);
                if (code !== 0) {
                    logYellow(`[*] [${this.moduleName}] JoomScan exited with code ${code}.`);
                }
                resolve();
            });

            child.on('error', (err) => {
                logYellow(`[*] [${this.moduleName}] Failed to spawn JoomScan: ${err.message}. Is it installed? (Run Tarsius via Docker for built-in support)`);
                resolve();
            });
        });
    }

    _processFindings(rawOutput, contextRequest) {
        // JoomScan does not output clean JSON. It outputs ASCII text.
        // We must parse it using regex heuristics to find the vulnerabilities block.

        try {
            if (!rawOutput) return;

            const lines = rawOutput.split('\n');
            let parsingVulns = false;
            let currentVuln = '';

            for (const line of lines) {
                const cleanLine = line.trim();

                // Look for vulnerability blocks
                if (cleanLine.includes('[+] Vulnerability found:')) {
                    if (currentVuln) {
                        this.logVulnerability('Joomla_Vuln', contextRequest, currentVuln, '', 'CVE/JoomScan');
                    }
                    currentVuln = cleanLine.replace('[+] Vulnerability found:', '').trim();
                    continue;
                }

                // Append details to the current vulnerability
                if (currentVuln && cleanLine.startsWith('CVE :')) {
                    currentVuln += ` - ${cleanLine}`;
                } else if (currentVuln && cleanLine.startsWith('Exploit :')) {
                    currentVuln += ` (Exploit: ${cleanLine.replace('Exploit :', '').trim()})`;
                }

                // End of vulnerability block usually denoted by blank lines or new sections
                if (currentVuln && cleanLine === '' && currentVuln.length > 20) {
                    this.logVulnerability('Joomla_Vuln', contextRequest, currentVuln, '', 'CVE/JoomScan');
                    currentVuln = '';
                }
            }

            // Catch any trailing vulnerability
            if (currentVuln) {
                this.logVulnerability('Joomla_Vuln', contextRequest, currentVuln, '', 'CVE/JoomScan');
            }

            // Parse basic info as anomalies
            const versionMatch = rawOutput.match(/\[\+\] Joomla version: (.*)/);
            if (versionMatch) {
                this.logAnomaly('Joomla_Version', contextRequest, `Joomla Version Detected: ${versionMatch[1]}`, '', '');
            }

        } catch (e) {
            logVerbose(`Failed to parse JoomScan output: ${e.message}`);
        }
    }
}
