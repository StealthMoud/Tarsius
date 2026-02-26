import { spawn } from 'child_process';
import { logYellow, logVerbose, logBlue, logRed } from '../utils/log.js';
import { Attack } from './attack.js';

export default class ModWpscan extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'wpscan';
    }

    static get name() { return 'wpscan'; }

    // Check if the target is likely WordPress
    _isWordPress(requests) {
        for (const req of requests) {
            const body = req.responseBody || '';
            const path = req.path || '';

            // 1. Look for wp-content or wp-includes in URLs
            if (path.includes('/wp-content/') || path.includes('/wp-includes/')) {
                return true;
            }

            // 2. Look for generator meta tag
            if (body.toLowerCase().includes('<meta name="generator" content="wordpress')) {
                return true;
            }

            // 3. Look for typical wp- login paths in the crawled requests
            if (path.endsWith('/wp-login.php') || path.endsWith('/xmlrpc.php')) {
                return true;
            }
        }
        return false;
    }

    async launch(requests) {
        this._startTime = Date.now();

        // 1. Heuristic Check: Only run WPScan if WordPress is detected
        const isWp = this._isWordPress(requests);
        if (!isWp) {
            logVerbose(`[*] [${this.moduleName}] Target does not appear to be WordPress. Skipping WPScan.`);
            return;
        }

        // 2. Identify unique root targets
        const uniqueTargets = new Set();
        for (const req of requests) {
            if (req.scheme && req.netloc) {
                uniqueTargets.add(`${req.scheme}://${req.netloc}`);
            }
        }

        logBlue(`[*] [${this.moduleName}] WordPress detected! Initiating WPScan for ${uniqueTargets.size} target(s).`);

        for (const target of uniqueTargets) {
            if (this._isTimeUp()) break;
            await this._runWpscan(target, requests[0]);
        }
    }

    _runWpscan(targetUrl, contextRequest) {
        return new Promise((resolve) => {
            logVerbose(`Running native WPScan against ${targetUrl}...`);

            // `wpscan --url <target> --format json --no-banner --no-update`
            const args = [
                '--url', targetUrl,
                '--format', 'json',
                '--no-banner',
                '--no-update', // avoid slow updates during active scans
                '--random-user-agent'
            ];

            const child = spawn('wpscan', args);

            let buffer = '';

            child.stdout.on('data', (data) => {
                buffer += data.toString();
            });

            child.stderr.on('data', (data) => {
                // WPScan outputs some progress to stderr
                logVerbose(`WPScan progress: ${data.toString().trim()}`);
            });

            child.on('close', (code) => {
                this._processFindings(buffer.trim(), contextRequest);
                if (code !== 0 && code !== 5) { // 5 usually means vulnerabilities found
                    logYellow(`[*] [${this.moduleName}] WPScan exited with code ${code}.`);
                }
                resolve();
            });

            child.on('error', (err) => {
                logYellow(`[*] [${this.moduleName}] Failed to spawn WPScan: ${err.message}. Is it installed? (Run Tarsius via Docker for built-in support)`);
                resolve();
            });
        });
    }

    _processFindings(jsonString, contextRequest) {
        try {
            if (!jsonString) return;
            const output = JSON.parse(jsonString);

            // WPScan JSON usually has "interesting_findings", "version", and "plugins"

            // 1. Parse Interesting Findings (usually Anomalies/Low info)
            if (output.interesting_findings && output.interesting_findings.length > 0) {
                for (const finding of output.interesting_findings) {
                    this.logAnomaly('WP_Finding', contextRequest, finding.to_s, '', finding.type);
                }
            }

            // 2. Parse Version Vulnerabilities
            if (output.version && output.version.vulnerabilities) {
                for (const vuln of output.version.vulnerabilities) {
                    this.logVulnerability('WP_Core_Vuln', contextRequest, vuln.title, '', 'CVE/WPScan');
                }
            }

            // 3. Parse Plugin Vulnerabilities
            if (output.plugins) {
                for (const [pluginName, pluginData] of Object.entries(output.plugins)) {
                    if (pluginData.vulnerabilities) {
                        for (const vuln of pluginData.vulnerabilities) {
                            this.logVulnerability(`WP_Plugin_${pluginName}`, contextRequest, vuln.title, '', 'CVE/WPScan');
                        }
                    } else if (pluginData.outdated) {
                        this.logAnomaly('WP_Plugin_Outdated', contextRequest, `Plugin '${pluginName}' is outdated.`, '', '');
                    }
                }
            }

            // 4. Parse Theme Vulnerabilities
            if (output.themes) {
                for (const [themeName, themeData] of Object.entries(output.themes)) {
                    if (themeData.vulnerabilities) {
                        for (const vuln of themeData.vulnerabilities) {
                            this.logVulnerability(`WP_Theme_${themeName}`, contextRequest, vuln.title, '', 'CVE/WPScan');
                        }
                    }
                }
            }
        } catch (e) {
            logVerbose(`Failed to parse WPScan JSON output. This usually happens if the site blocked WPScan completely.`);
        }
    }
}
