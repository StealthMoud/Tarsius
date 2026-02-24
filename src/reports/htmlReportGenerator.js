// html report genertor

import fs from 'fs';
import path from 'path';
import { ReportGenerator } from './reportGenerator.js';
import { TARSIUS_VERSION } from '../index.js';
import { DEFINITIONS } from '../definitions/index.js';

export class HtmlReportGenerator extends ReportGenerator {
    generate(outputPath) {
        this._ensureDir(outputPath);

        // check if outputPath is a directry or a file
        let outputDir, reportFile;
        if (outputPath.endsWith('.html')) {
            outputDir = path.dirname(outputPath);
            reportFile = outputPath;
        } else {
            outputDir = outputPath;
            reportFile = path.join(outputDir, 'report.html');
        }

        // copy template files
        const templateDir = path.join(
            path.dirname(new URL(import.meta.url).pathname),
            '..', '..', 'report_template'
        );

        this._copyTemplate(templateDir, outputDir);

        // generate the report html
        const html = this._buildHtml();
        fs.writeFileSync(reportFile, html);

        return reportFile;
    }

    // copy css, js, and images from the templte
    _copyTemplate(srcDir, destDir) {
        if (!fs.existsSync(srcDir)) return;

        for (const item of ['css', 'js']) {
            const srcSub = path.join(srcDir, item);
            const destSub = path.join(destDir, item);
            if (fs.existsSync(srcSub)) {
                if (!fs.existsSync(destSub)) fs.mkdirSync(destSub, { recursive: true });
                for (const file of fs.readdirSync(srcSub)) {
                    fs.copyFileSync(path.join(srcSub, file), path.join(destSub, file));
                }
            }
        }

        // copy logo
        const logo = path.join(srcDir, 'logo_clear.png');
        if (fs.existsSync(logo)) {
            fs.copyFileSync(logo, path.join(destDir, 'logo_clear.png'));
        }
    }

    // helper to map vulnerability categories to explicit severity scores for badges
    _getSeverity(category) {
        const critical = ['Command Execution', 'SQL Injection', 'Shellshock', 'Spring4Shell', 'Log4Shell', 'XML External Entity', 'Server Side Request Forgery', 'Local File Inclusion', 'File Inclusion'];
        const high = ['Reflected Cross Site Scripting', 'Stored Cross Site Scripting', 'LDAP Injection', 'XPath Injection', 'Unrestricted File Upload', 'Htaccess Bypass', 'Subdomain Takeover', 'NS Subdomain Takeover', 'Weak Credentials'];
        const medium = ['Open Redirect', 'Cross Site Request Forgery', 'CRLF Injection', 'SSL/TLS Issue', 'HTML Injection', 'Stored HTML Injection'];
        const low = ['Backup File', 'Hidden Resource', 'Potentially Dangerous Resource'];
        // all 'anomalies' and info disclosures default to Info or Low

        if (critical.includes(category)) return 'critical';
        if (high.includes(category)) return 'high';
        if (medium.includes(category)) return 'medium';
        if (low.includes(category)) return 'low';
        return 'info';
    }

    // build the actual html content
    _buildHtml() {
        const vulnCount = Object.values(this.vulnerabilities).reduce((s, a) => s + a.length, 0);
        const anomalyCount = Object.values(this.anomalies).reduce((s, a) => s + a.length, 0);

        let tocLinks = '';
        let vulnSections = '';

        // build vulnerabilities
        for (const [category, items] of Object.entries(this.vulnerabilities)) {
            const def = DEFINITIONS[category];
            const desc = def ? def.description() : '';
            const solution = def ? def.solution() : '';
            const severity = this._getSeverity(category);
            const anchorId = `vuln-${category.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

            tocLinks += `<a href="#${anchorId}" class="toc-link">${this._escape(category)} <span class="badge-count">${items.length}</span></a>`;

            vulnSections += `
                <div id="${anchorId}" class="issue-section">
                    <div class="issue-header">
                        <span class="severity-badge sev-${severity}">${severity}</span>
                        <h3>${this._escape(category)}</h3>
                    </div>
                    <div class="issue-meta">
                        <p class="desc">${this._escape(desc)}</p>
                        <div class="sol"><strong>Solution:</strong> ${this._escape(solution)}</div>
                    </div>
                    <table>
                        <tr><th>URL</th><th>Parameter</th><th>Target Info</th><th>Verify (CURL)</th></tr>
                        ${items.map(item => {
                const escapedUrl = this._escape(item.url || '');
                const escapedParam = this._escape(item.parameter || '');
                const escapedInfo = this._escape(item.info || '');
                const escapedCurl = this._escape(item.curl || '');
                return `
                            <tr>
                                <td><a href="${escapedUrl}" target="_blank">${escapedUrl}</a></td>
                                <td><strong>${escapedParam}</strong></td>
                                <td>${escapedInfo}</td>
                                <td>${escapedCurl ? `<code>${escapedCurl}</code>` : '-'}</td>
                            </tr>
                            `;
            }).join('')}
                    </table>
                </div>
            `;
        }

        let anomalySections = '';
        // build anomalies
        for (const [category, items] of Object.entries(this.anomalies)) {
            const severity = 'info';
            const anchorId = `anom-${category.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

            tocLinks += `<a href="#${anchorId}" class="toc-link">${this._escape(category)} <span class="badge-count">${items.length}</span></a>`;

            anomalySections += `
                <div id="${anchorId}" class="issue-section">
                    <div class="issue-header">
                        <span class="severity-badge sev-${severity}">${severity}</span>
                        <h3>${this._escape(category)}</h3>
                    </div>
                    <table>
                        <tr><th>URL</th><th>Info</th><th>Verify (CURL)</th></tr>
                        ${items.map(item => {
                const escapedUrl = this._escape(item.url || '');
                const escapedInfo = this._escape(item.info || '');
                const escapedCurl = this._escape(item.curl || '');
                return `
                            <tr>
                                <td><a href="${escapedUrl}" target="_blank">${escapedUrl}</a></td>
                                <td>${escapedInfo}</td>
                                <td>${escapedCurl ? `<code>${escapedCurl}</code>` : '-'}</td>
                            </tr>
                            `;
            }).join('')}
                    </table>
                </div>
            `;
        }

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tarsius ${TARSIUS_VERSION} - Scan Report</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>Tarsius</h2>
            <p>Scan Report v${TARSIUS_VERSION}</p>
        </div>
        <div class="toc-group">
            <div class="toc-title">Findings Navigation</div>
            ${tocLinks || '<div class="toc-link" style="color:#64748b;">No findings</div>'}
        </div>
    </div>

    <div class="main-content">
        <div class="dashboard">
            <div class="dash-header">
                <div class="dash-title">
                    <h1>Executive Summary</h1>
                    <p>Target: <a href="${this._escape(this.infos.target || '')}" target="_blank">${this._escape(this.infos.target || '')}</a></p>
                </div>
                <div class="dash-meta">
                    <p>Generated: ${new Date().toLocaleString()}</p>
                </div>
            </div>
            
            <div class="dash-stats">
                <div class="stat-box vulns">
                    <h3>Vulnerabilities</h3>
                    <div class="num">${vulnCount}</div>
                </div>
                <div class="stat-box">
                    <h3>Anomalies</h3>
                    <div class="num">${anomalyCount}</div>
                </div>
                <div class="stat-box">
                    <h3>Risk Level</h3>
                    <div class="num">${vulnCount > 0 ? 'CRITICAL' : (anomalyCount > 0 ? 'LOW' : 'SAFE')}</div>
                </div>
            </div>
        </div>

        ${vulnCount > 0 ? vulnSections : ''}
        ${anomalyCount > 0 ? anomalySections : ''}
        ${(vulnCount === 0 && anomalyCount === 0) ? '<div class="no-issues">No vulnerabilities or anomalies were detected during the scan.</div>' : ''}
    </div>
    <script src="js/app.js"></script>
</body>
</html>`;
    }

    // escape html to prevent xss in our own report lol
    _escape(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}
