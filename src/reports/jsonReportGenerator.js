// json report genertor - outputs scan results as structured json
// this is the simplest report formt and good for automaton

import fs from 'fs';
import { ReportGenerator } from './reportGenerator.js';
import { TARSIUS_VERSION } from '../index.js';

export class JsonReportGenerator extends ReportGenerator {
    generate(outputPath) {
        this._ensureDir(outputPath);

        const report = {
            version: TARSIUS_VERSION,
            date: new Date().toISOString(),
            infos: this.infos,
            vulnerabilities: this.vulnerabilities,
            anomalies: this.anomalies,
            additionals: this.additionals,
            summary: {
                totalVulnerabilities: Object.values(this.vulnerabilities).reduce((sum, arr) => sum + arr.length, 0),
                totalAnomalies: Object.values(this.anomalies).reduce((sum, arr) => sum + arr.length, 0),
                totalAdditionals: Object.values(this.additionals).reduce((sum, arr) => sum + arr.length, 0),
            },
        };

        fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
        return outputPath;
    }
}
