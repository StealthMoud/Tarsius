// html report genertor - makes a nice html report you can open in a browser
// uses the report_template files for styling

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

    // build the actual html content
    _buildHtml() {
        const vulnCount = Object.values(this.vulnerabilities).reduce((s, a) => s + a.length, 0);
        const anomalyCount = Object.values(this.anomalies).reduce((s, a) => s + a.length, 0);

        let vulnSections = '';
        for (const [category, items] of Object.entries(this.vulnerabilities)) {
            const def = DEFINITIONS[category];
            const desc = def ? def.description() : '';
            const solution = def ? def.solution() : '';

            vulnSections += `
                <div class="vulnerability-section">
                    <h3>${this._escape(category)} (${items.length})</h3>
                    <p class="description">${this._escape(desc)}</p>
                    <p class="solution"><strong>Solution:</strong> ${this._escape(solution)}</p>
                    <table>
                        <tr><th>URL</th><th>Parameter</th><th>Info</th></tr>
                        ${items.map(item => `
                            <tr>
                                <td>${this._escape(item.url || '')}</td>
                                <td>${this._escape(item.parameter || '')}</td>
                                <td>${this._escape(item.info || '')}</td>
                            </tr>
                        `).join('')}
                    </table>
                </div>
            `;
        }

        let anomalySections = '';
        for (const [category, items] of Object.entries(this.anomalies)) {
            anomalySections += `
                <div class="anomaly-section">
                    <h3>${this._escape(category)} (${items.length})</h3>
                    <table>
                        <tr><th>URL</th><th>Info</th></tr>
                        ${items.map(item => `
                            <tr>
                                <td>${this._escape(item.url || '')}</td>
                                <td>${this._escape(item.info || '')}</td>
                            </tr>
                        `).join('')}
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
    <div class="container">
        <header>
            <h1>Tarsius Scan Report</h1>
            <p>Version ${TARSIUS_VERSION} | Generated ${new Date().toISOString()}</p>
            <p>Target: ${this._escape(this.infos.target || '')}</p>
        </header>

        <section class="summary">
            <h2>Summary</h2>
            <div class="stats">
                <div class="stat vuln">${vulnCount} Vulnerabilities</div>
                <div class="stat anomaly">${anomalyCount} Anomalies</div>
            </div>
        </section>

        <section class="vulnerabilities">
            <h2>Vulnerabilities</h2>
            ${vulnSections || '<p>No vulnerabilities found.</p>'}
        </section>

        <section class="anomalies">
            <h2>Anomalies</h2>
            ${anomalySections || '<p>No anomalies found.</p>'}
        </section>
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
