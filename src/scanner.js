// main scan orchestrtor

import path from 'path';
import os from 'os';
import fs from 'fs';
import { logGreen, logRed, logYellow, logVerbose } from './utils/log.js';
import { TARSIUS_VERSION } from './index.js';
import { sendRequest, fetchWithRedirects } from './http/client.js';
import { Request } from './http/request.js';
import { AsyncCrawler } from './crawler/crawler.js';
import { ActiveScanner } from './modules/activeScanner.js';
import { PassiveScanner } from './modules/passiveScanner.js';
import { getReportGenerator } from './reports/index.js';

// scan force presets - controls how agresive the scan is
const SCAN_FORCE_VALUES = {
    paranoid: { maxLinks: 2, maxFiles: 1 },
    sneaky: { maxLinks: 5, maxFiles: 2 },
    polite: { maxLinks: 10, maxFiles: 5 },
    normal: { maxLinks: 100, maxFiles: 0 },
    aggressive: { maxLinks: 500, maxFiles: 0 },
    insane: { maxLinks: 0, maxFiles: 0 },
};

export class Tarsius {
    constructor(crawlerConfig, scope) {
        this.crawlerConfig = crawlerConfig;
        this.scope = scope;

        // atack settings
        this.attackLevel = 1;
        this.reportFormat = 'html';
        this.maxDepth = 10;
        this.maxLinksPerPage = 100;
        this.maxFilesPerDir = 0;
        this.concurrentTasks = 16;
        this.maxScanTime = null;
        this.maxAttackTime = null;
        this.maxParameters = 0;
        this.detailedReportLevel = 0;

        // output and storage
        this.outputFile = null;
        this.logFile = null;
        this.sessionDir = null;
        this.configDir = null;

        // internl state
        this._modules = null;
        this._startUrls = [];
        this._excludedUrls = [];
        this._excludedParams = [];
        this._skippedParams = [];
        this._formCredential = null;
        this._rawCredential = null;
        this._cookieValue = null;
        this._jwtToken = null;
        this._cms = null;
        this._headlessMode = null;
        this._headlessWait = 2;

        // crawl contrl flags
        this.skipCrawl = false;
        this.resumeCrawl = false;
        this.flushAttacks = false;
        this.flushSession = false;

        // scan results
        this._vulnerabilities = {};
        this._anomalies = {};
        this._additionals = {};
        this._crawledUrls = [];
        this._attackedUrls = new Set();
    }

    // set which modules to load - comma seprated string
    setModules(moduleStr) {
        this._modules = moduleStr.split(',').map(m => m.trim()).filter(Boolean);
    }

    // add extra urls to start crawlng from
    addStartUrls(urls) {
        this._startUrls.push(...urls);
    }

    // add urls to skip durring crawling
    addExcludedUrls(urls) {
        this._excludedUrls.push(...urls);
    }

    // paramters to remove from all urls
    setExcludedParameters(params) {
        this._excludedParams = params;
    }

    // paramters to skip when atacking
    setSkippedParameters(params) {
        this._skippedParams = params;
    }

    // set scan intesity level
    setScanForce(force) {
        const preset = SCAN_FORCE_VALUES[force];
        if (preset) {
            if (preset.maxLinks > 0) this.maxLinksPerPage = preset.maxLinks;
            if (preset.maxFiles > 0) this.maxFilesPerDir = preset.maxFiles;
        }
    }

    // form login credentails
    setFormCredentials(cred) {
        this._formCredential = cred;
    }

    // raw post body credentails
    setRawCredentials(cred) {
        this._rawCredential = cred;
    }

    // set a cookie string for all requets
    setCookieValue(value) {
        this._cookieValue = value;
    }

    // set jwt tokn for authed scans
    setJwtToken(token) {
        this._jwtToken = token;
    }

    // load cookies from a file or browser
    async loadCookies(source) {
        // todo: implement cookie loading from file/browser
        logVerbose(`loading cookies from: ${source}`);
    }

    // enable headles browser mode
    setHeadless(mode, waitTime) {
        this._headlessMode = mode;
        this._headlessWait = waitTime;
    }

    // set cms for specfic scanning
    setCms(cms) {
        this._cms = cms;
    }

    // get the default output directry
    _getOutputDir() {
        if (this.outputFile) return this.outputFile;
        const homeDir = os.homedir();
        const outputDir = path.join(homeDir, '.tarsius', 'generated_report');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        return outputDir;
    }

    // the main scan loop - this is where evrything happns
    async run() {
        const startTime = Date.now();

        logYellow(`[*] Scanning ${this.crawlerConfig.baseRequest.url}`);

        // step 1: crawl the website to find all pages
        if (!this.skipCrawl) {
            await this._crawl();
            process.stdout.write('\r' + ' '.repeat(120) + '\r');
        }

        const pageCount = this._crawledUrls.length;
        const crawlTime = ((Date.now() - startTime) / 1000).toFixed(1);
        logGreen(`[*] Found ${pageCount} URLs in ${crawlTime}s`);
        console.log('');

        // step 2: run atack modules against found pages
        await this._attack();

        // step 3: genrate the report
        await this._generateReport();

        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        logGreen(`[*] Scan completed in ${elapsed} seconds`);
    }

    // crawl the target websit to discover pages and forms
    async _crawl() {
        logYellow('[*] Crawling target...');

        // start with the base url
        const urlsToVisit = [this.crawlerConfig.baseRequest.url];
        urlsToVisit.push(...this._startUrls);

        const visited = new Set();
        const crawlStart = Date.now();
        let pathIdCounter = 0;

        // concurent bfs crawlr
        while (urlsToVisit.length > 0) {
            // grab a batch of unvisited urls
            const batch = [];
            while (batch.length < this.concurrentTasks && urlsToVisit.length > 0) {
                const url = urlsToVisit.shift();
                if (visited.has(url)) continue;
                if (!this.scope.check(url)) continue;
                if (this._excludedUrls.some(ex => url.includes(ex))) continue;
                if (visited.size >= this.maxDepth * this.maxLinksPerPage) break;
                visited.add(url);
                batch.push(url);
            }

            if (batch.length === 0) break;

            // show progress
            process.stdout.write(`\r[*] Crawled: ${this._crawledUrls.length} | Queued: ${urlsToVisit.length + batch.length} | Batch: ${batch.length}`.padEnd(120));

            // fetch all urls in this batch concurently
            const results = await Promise.allSettled(
                batch.map(async (url) => {
                    try {
                        const request = new Request(url);
                        const response = await fetchWithRedirects(request, this.crawlerConfig);
                        if (!response) return null;
                        return { request, response };
                    } catch (err) {
                        logVerbose(`error crawling ${url}: ${err.message}`);
                        return null;
                    }
                })
            );

            // collect results and extract new links
            for (const result of results) {
                if (result.status !== 'fulfilled' || !result.value) continue;
                const { request, response } = result.value;

                request.pathId = ++pathIdCounter;
                this._crawledUrls.push({ request, response });

                // extract links from the page
                const links = this._extractLinks(response.content, request.url);
                for (const link of links) {
                    if (!visited.has(link) && this.scope.check(link)) {
                        urlsToVisit.push(link);
                    }
                }
            }

            // check time limit
            if (this.maxScanTime) {
                const elapsed = (Date.now() - crawlStart) / 1000;
                if (elapsed >= this.maxScanTime) {
                    logYellow('\n[*] Crawl time limit reached');
                    break;
                }
            }
        }
    }

    // basic link extracton from html - todo: replace with cherio parser
    _extractLinks(html, baseUrl) {
        const links = new Set();
        if (!html) return links;

        // find href atributes
        const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
        let match;
        while ((match = hrefRegex.exec(html)) !== null) {
            try {
                const absUrl = new URL(match[1], baseUrl).href;
                // only keep http/https links
                if (absUrl.startsWith('http://') || absUrl.startsWith('https://')) {
                    links.add(absUrl.split('#')[0]); // remove fragments
                }
            } catch {
                // bad url, skip it
            }
        }

        return links;
    }

    // run all the atack modules
    async _attack() {
        if (this._crawledUrls.length === 0) {
            logYellow('[*] No pages to atack');
            return;
        }

        // run passive checks on already-crawled respons (no extra requests)
        try {
            const passiveScanner = new PassiveScanner();
            await passiveScanner.run(this._crawledUrls);
        } catch (err) {
            logVerbose(`passive scanner error: ${err.message}`);
        }

        // create a crawlr for sending atack requests
        const crawler = new AsyncCrawler(this.crawlerConfig);

        // pull out just the request objects for the modules
        const requests = this._crawledUrls.map(u => u.request);

        const attackOptions = {
            level: this.attackLevel,
            maxAttackTime: this.maxAttackTime || 30, // default 30s per module
            skippedParams: this._skippedParams,
            timeout: this.crawlerConfig.timeout,
        };

        // run active atack modules
        const activeScanner = new ActiveScanner(crawler, null, attackOptions, this.crawlerConfig);
        await activeScanner.run(requests, this._modules);

        // collect vulns from the active scanner
        // the modules log vulns directly so we grab them from the module output

        await crawler.close();
    }

    // generate the scan report
    async _generateReport() {
        console.log('[*] Generating report...');

        const outputDir = this._getOutputDir();
        const hostname = this.crawlerConfig.baseRequest.hostname;
        const now = new Date();
        const dateStr = `${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}${now.getFullYear()}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
        const fileName = `${hostname}_${dateStr}.${this.reportFormat}`;
        const outputPath = path.join(outputDir, fileName);

        try {
            const generator = getReportGenerator(this.reportFormat);

            // feed scan metadata
            generator.setInfo('version', TARSIUS_VERSION);
            generator.setInfo('target', this.crawlerConfig.baseRequest.url);
            generator.setInfo('date', now.toISOString());
            generator.setInfo('crawled_urls', this._crawledUrls.length);

            // feed vulns and anomalies
            for (const [cat, items] of Object.entries(this._vulnerabilities)) {
                for (const item of (Array.isArray(items) ? items : [items])) {
                    generator.addVulnerability(cat, item);
                }
            }
            for (const [cat, items] of Object.entries(this._anomalies)) {
                for (const item of (Array.isArray(items) ? items : [items])) {
                    generator.addAnomaly(cat, item);
                }
            }
            for (const [cat, items] of Object.entries(this._additionals)) {
                for (const item of (Array.isArray(items) ? items : [items])) {
                    generator.addAdditional(cat, item);
                }
            }

            generator.generate(outputPath);
        } catch (err) {
            // fallback to basic json if report genertor fails
            logVerbose(`report genertor error: ${err.message}, falling back to json`);
            const reportData = {
                version: TARSIUS_VERSION,
                target: this.crawlerConfig.baseRequest.url,
                date: now.toISOString(),
                crawled_urls: this._crawledUrls.length,
                vulnerabilities: this._vulnerabilities,
                anomalies: this._anomalies,
                additionals: this._additionals,
            };
            fs.writeFileSync(outputPath, JSON.stringify(reportData, null, 2));
        }

        console.log(`A report has been generated in the file ${outputDir}`);
        console.log(`Open ${outputPath} with a browser to see this report.`);
    }
}
