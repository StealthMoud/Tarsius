// report format registy

import { HtmlReportGenerator } from './htmlReportGenerator.js';
import { JsonReportGenerator } from './jsonReportGenerator.js';
import { CsvReportGenerator } from './csvReportGenerator.js';
import { TxtReportGenerator } from './txtReportGenerator.js';

// map of format name -> genertor class
export const GENERATORS = {
    html: HtmlReportGenerator,
    json: JsonReportGenerator,
    csv: CsvReportGenerator,
    txt: TxtReportGenerator,
};

// get a report genertor by format name
export function getReportGenerator(format) {
    const GeneratorClass = GENERATORS[format];
    if (!GeneratorClass) {
        throw new Error(`unsupported report format: ${format}`);
    }
    return new GeneratorClass();
}
