// txt report genertor - outputs scan results as plain text
// readable by humans without any special sofware

import fs from 'fs';
import { ReportGenerator } from './reportGenerator.js';
import { TARSIUS_VERSION } from '../index.js';

export class TxtReportGenerator extends ReportGenerator {
    generate(outputPath) {
        this._ensureDir(outputPath);

        let output = '';
        output += `Tarsius ${TARSIUS_VERSION} - Scan Report\n`;
        output += `${'='.repeat(50)}\n`;
        output += `Date: ${new Date().toISOString()}\n`;
        output += `Target: ${this.infos.target || ''}\n\n`;

        // vulnerabilities
        const vulnCount = Object.values(this.vulnerabilities).reduce((s, a) => s + a.length, 0);
        output += `Vulnerabilities (${vulnCount})\n`;
        output += `${'-'.repeat(30)}\n`;

        for (const [category, items] of Object.entries(this.vulnerabilities)) {
            output += `\n[${category}] (${items.length} found)\n`;
            for (const item of items) {
                output += `  URL: ${item.url || ''}\n`;
                if (item.parameter) output += `  Parameter: ${item.parameter}\n`;
                output += `  Info: ${item.info || ''}\n`;
                output += '\n';
            }
        }

        // anomalies
        const anomalyCount = Object.values(this.anomalies).reduce((s, a) => s + a.length, 0);
        output += `\nAnomalies (${anomalyCount})\n`;
        output += `${'-'.repeat(30)}\n`;

        for (const [category, items] of Object.entries(this.anomalies)) {
            output += `\n[${category}] (${items.length} found)\n`;
            for (const item of items) {
                output += `  URL: ${item.url || ''}\n`;
                output += `  Info: ${item.info || ''}\n`;
                output += '\n';
            }
        }

        fs.writeFileSync(outputPath, output);
        return outputPath;
    }
}
