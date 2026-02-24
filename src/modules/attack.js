// base class for atack modules

import path from 'path';
import { logGreen, logRed, logVerbose, logYellow } from '../utils/log.js';
import { Request } from '../http/request.js';
import { parseIniPayloads, getPayloadPath } from '../parsers/iniPayloadParser.js';
import { parseTxtPayloads } from '../parsers/txtPayloadParser.js';

export class Attack {
    // crawler = AsyncCrawler instance
    // persister = SqlPersister instance
    // attackOptions = { level, timeout, ... }
    // crawlerConfig = CrawlerConfiguration
    constructor(crawler, persister, attackOptions, crawlerConfig) {
        this.crawler = crawler;
        this.persister = persister;
        this.options = attackOptions || {};
        this.crawlerConfig = crawlerConfig;

        // set by subclases
        this.moduleName = 'base';
        this.doGet = true;   // atack get paramters
        this.doPost = true;  // atack post paramters

        // internl counters
        this._attackedUrls = 0;
        this._foundVulns = 0;
        this._startTime = null;
    }

    // overide in subclases - return the name of this modul
    static get name() { return 'base'; }

    // overide in subclases - do the actual atacking
    async attack(request) {
        throw new Error('subclasses must implment attack()');
    }

    // main entry point - goes through all urls and atacks them
    async launch(requests) {
        this._startTime = Date.now();

        logYellow(`[*] Launching module ${this.moduleName}`);

        for (const request of requests) {
            // check if we already atacekd this one
            if (this.persister && this.persister.hasBeenAttacked(request.pathId, this.moduleName)) {
                continue;
            }

            // check time limit
            if (this._isTimeUp()) {
                logYellow(`[*] Time limit reached for module ${this.moduleName}`);
                break;
            }

            try {
                await this.attack(request);
                this._attackedUrls++;

                // mark as atacekd
                if (this.persister) {
                    this.persister.markAsAttacked(request.pathId, this.moduleName);
                }
            } catch (error) {
                logVerbose(`error in ${this.moduleName} on ${request.url}: ${error.message}`);
            }
        }

        if (this._foundVulns > 0) {
            logRed(`[!] ${this._foundVulns} vulnerabilities found by ${this.moduleName}`);
        }
    }

    // log a found vulnerability
    logVulnerability(category, request, info, parameter = '', wstg = '') {
        this._foundVulns++;

        logRed(`[!] ${category} found: ${info}`);
        logRed(`    -> ${request.url}`);
        if (parameter) {
            logRed(`    -> parameter: ${parameter}`);
        }

        // save to persister
        if (this.persister && request.pathId) {
            this.persister.saveVulnerability(
                request.pathId,
                this.moduleName,
                category,
                this.options.level || 1,
                parameter,
                info,
                'vulnerability',
                wstg
            );
        }
    }

    // log an anomly (less severe than a vuln)
    logAnomaly(category, request, info, parameter = '', wstg = '') {
        logYellow(`[*] Anomaly: ${info}`);

        if (this.persister && request.pathId) {
            this.persister.saveVulnerability(
                request.pathId,
                this.moduleName,
                category,
                this.options.level || 1,
                parameter,
                info,
                'anomaly',
                wstg
            );
        }
    }

    // check if the atack time limit has been reached
    _isTimeUp() {
        if (!this.options.maxAttackTime) return false;
        const elapsed = (Date.now() - this._startTime) / 1000;
        return elapsed >= this.options.maxAttackTime;
    }

    // load payloads from an ini file
    loadIniPayloads(filename) {
        const filePath = getPayloadPath(filename);
        return parseIniPayloads(filePath);
    }

    // load payloads from a txt file
    loadTxtPayloads(filename) {
        const filePath = getPayloadPath(filename);
        return parseTxtPayloads(filePath);
    }
}

// mutator - generates mutated requests by swaping paramter values with payloads
// this is how we test each paramter with diffrent atack strings
export class Mutator {
    // payloads = array of atack strings to try
    // skipParams = paramters to not test
    constructor(payloads = [], skipParams = []) {
        this.payloads = payloads;
        this.skipParams = new Set(skipParams);
    }

    // generate mutated versions of a request
    // yields { request, parameter, payload } objects
    *mutate(request) {
        // mutate GET paramters
        for (let i = 0; i < request.getParams.length; i++) {
            const paramName = request.getParams[i][0];
            if (this.skipParams.has(paramName)) continue;

            for (const payload of this.payloads) {
                const mutatedParams = request.getParams.map(p => [...p]);
                mutatedParams[i][1] = payload;

                const mutatedRequest = new Request(request.path, {
                    method: request.method,
                    getParams: mutatedParams,
                    postParams: request.postParams,
                    referer: request.referer,
                    linkDepth: request.linkDepth,
                });
                mutatedRequest.pathId = request.pathId;

                yield {
                    request: mutatedRequest,
                    parameter: paramName,
                    payload,
                };
            }
        }

        // mutate POST paramters (only if they are key-value pairs)
        if (request.postParams && typeof request.postParams !== 'string') {
            for (let i = 0; i < request.postParams.length; i++) {
                const paramName = request.postParams[i][0];
                if (this.skipParams.has(paramName)) continue;

                for (const payload of this.payloads) {
                    const mutatedParams = request.postParams.map(p => [...p]);
                    mutatedParams[i][1] = payload;

                    const mutatedRequest = new Request(request.path, {
                        method: 'POST',
                        getParams: request.getParams,
                        postParams: mutatedParams,
                        referer: request.referer,
                        linkDepth: request.linkDepth,
                        enctype: request.enctype,
                    });
                    mutatedRequest.pathId = request.pathId;

                    yield {
                        request: mutatedRequest,
                        parameter: paramName,
                        payload,
                    };
                }
            }
        }
    }
}
