// csv report genertor

import fs from 'fs';
import { ReportGenerator } from './reportGenerator.js';

export class CsvReportGenerator extends ReportGenerator {
    generate(outputPath) {
        this._ensureDir(outputPath);

        const rows = ['Type,Category,URL,Parameter,Info'];

        // add vulnerabilties
        for (const [category, items] of Object.entries(this.vulnerabilities)) {
            for (const item of items) {
                rows.push(this._csvRow('vulnerability', category, item));
            }
        }

        // add anomalys
        for (const [category, items] of Object.entries(this.anomalies)) {
            for (const item of items) {
                rows.push(this._csvRow('anomaly', category, item));
            }
        }

        fs.writeFileSync(outputPath, rows.join('\n'));
        return outputPath;
    }

    // escape and format a csv row
    _csvRow(type, category, item) {
        const fields = [
            type,
            category,
            item.url || '',
            item.parameter || '',
            item.info || '',
        ];
        return fields.map(f => `"${String(f).replace(/"/g, '""')}"`).join(',');
    }
}
