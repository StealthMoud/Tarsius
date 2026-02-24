// base class for atack modules

import path from 'path';
import { logGreen, logRed, logVerbose, logYellow } from '../utils/log.js';
import { Request } from '../http/request.js';
import { parseIniPayloads, getPayloadPath } from '../parsers/iniPayloadParser.js';
import { parseTxtPayloads } from '../parsers/txtPayloadParser.js';

// how many payloads to send at once per url
const PAYLOAD_CONCURRENCY = 20;

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
        const total = requests.length;

        for (let i = 0; i < total; i++) {
            const request = requests[i];

            // show progress
            const shortUrl = request.url.length > 60 ? request.url.substring(0, 57) + '...' : request.url;
            process.stdout.write(`\r    [${i + 1}/${total}] ${shortUrl}`.padEnd(100));

            // check if we already atacekd this one
            if (this.persister && this.persister.hasBeenAttacked(request.pathId, this.moduleName)) {
                continue;
            }

            // check time limit
            if (this._isTimeUp()) {
                logYellow(`\n[*] Time limit reached for ${this.moduleName}`);
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

    // send all mutatins concurently and check each respons
    // checkFn = (response, mutation) => vuln info string or null
    // stops early when a vuln is found for a paramter
    async sendMutations(request, mutator, checkFn) {
        const mutations = [...mutator.mutate(request)];
        if (mutations.length === 0) return;

        const foundParams = new Set();
        let i = 0;

        while (i < mutations.length && !this._isTimeUp()) {
            // grab a batch
            const batch = mutations.slice(i, i + PAYLOAD_CONCURRENCY);
            i += PAYLOAD_CONCURRENCY;

            const results = await Promise.allSettled(
                batch.map(async (mutation) => {
                    if (foundParams.has(mutation.parameter)) return null;
                    try {
                        const response = await this.crawler.send(mutation.request);
                        if (!response) return null;
                        const vulnInfo = checkFn(response, mutation);
                        if (vulnInfo) return { mutation, info: vulnInfo };
                    } catch {
                        // skip
                    }
                    return null;
                })
            );

            for (const result of results) {
                if (result.status !== 'fulfilled' || !result.value) continue;
                const { mutation, info } = result.value;
                if (!foundParams.has(mutation.parameter)) {
                    foundParams.add(mutation.parameter);
                    this.logVulnerability(info.category, mutation.request, info.message, mutation.parameter, info.wstg || '');
                }
            }
        }
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
