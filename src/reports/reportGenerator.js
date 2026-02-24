// base report genertor class

import fs from 'fs';
import path from 'path';

export class ReportGenerator {
    constructor() {
        this.vulnerabilities = {};
        this.anomalies = {};
        this.additionals = {};
        this.infos = {};
    }

    // add a vulnerabilty to the report
    addVulnerability(category, info) {
        if (!this.vulnerabilities[category]) {
            this.vulnerabilities[category] = [];
        }
        this.vulnerabilities[category].push(info);
    }

    // add an anomly to the report
    addAnomaly(category, info) {
        if (!this.anomalies[category]) {
            this.anomalies[category] = [];
        }
        this.anomalies[category].push(info);
    }

    // add addiitonal info (fingerprints etc)
    addAdditional(category, info) {
        if (!this.additionals[category]) {
            this.additionals[category] = [];
        }
        this.additionals[category].push(info);
    }

    // add scan metadata
    setInfo(key, value) {
        this.infos[key] = value;
    }

    // overide in subclases - write the report to disk
    generate(outputPath) {
        throw new Error('subclases must implement generate()');
    }

    // helper to ensure the output directry exists
    _ensureDir(outputPath) {
        const dir = path.dirname(outputPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }
}
