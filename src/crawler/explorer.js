// bfs crawlr that finds pages and forms

import { Request, makeAbsolute } from '../http/request.js';
import { AsyncCrawler } from './crawler.js';
import { Scope } from './scope.js';
import { Html } from '../parsers/htmlParser.js';
import { logVerbose, logGreen, logYellow } from '../utils/log.js';

export class Explorer {
    // crawlerConfig = CrawlerConfiguration
    // scope = Scope object
    // persister = SqlPersister for saving discoverd urls
    constructor(crawlerConfig, scope, persister) {
        this._config = crawlerConfig;
        this._scope = scope;
        this._persister = persister;

        // crawl setings
        this.maxDepth = 40;
        this.maxLinksPerPage = 100;
        this.maxFilesPerDir = 0;
        this.threads = 32;
        this.maxScanTime = null;
        this.excludedUrls = [];
        this.excludedParams = [];

        // internl state
        this._visited = new Set();
        this._queue = [];
        this._startTime = null;
    }

    // start the crawl from the base url and any extra starting urls
    async explore(startUrls = []) {
        this._startTime = Date.now();
        const crawler = new AsyncCrawler(this._config);

        // add the base url and any extra start urls to the queu
        this._queue.push(this._config.baseRequest);
        for (const url of startUrls) {
            this._queue.push(new Request(url));
        }

        logYellow(`[*] Crawling from ${this._config.baseRequest.url}`);

        try {
            await this._crawlLoop(crawler);
        } finally {
            await crawler.close();
        }

        logGreen(`[*] Crawler found ${this._visited.size} pages`);
        return this._visited.size;
    }

    // main crawl loop - processs the queu until empty or time runs out
    async _crawlLoop(crawler) {
        while (this._queue.length > 0) {
            // check time limit
            if (this._isTimeUp()) {
                logYellow('[*] Scan time limit reached, stoping crawl');
                break;
            }

            // process a batch of urls concurently
            const batch = this._queue.splice(0, this.threads);
            const promises = batch.map(req => this._processUrl(crawler, req));
            await Promise.allSettled(promises);
        }
    }

    // proces a single url - fetch it and extract links
    async _processUrl(crawler, request) {
        const url = request.url;

        // skip if already visitd
        if (this._visited.has(url)) return;

        // skip if out of scope
        if (!this._scope.check(url)) return;

        // skip if excluded
        if (this._isExcluded(url)) return;

        // skip if too deep
        if (request.linkDepth > this.maxDepth) return;

        this._visited.add(url);

        try {
            const response = await crawler.send(request, true);
            if (!response) return;

            // save to persister
            if (this._persister) {
                this._persister.addUrl(request, response);
            }

            logVerbose(`[+] ${response.status} ${url}`);

            // extract links from the page if its html
            if (response.type.includes('text/html') || response.type.includes('application/xhtml')) {
                const newLinks = this._extractLinks(response.content, url);
                let addedCount = 0;

                for (const link of newLinks) {
                    if (addedCount >= this.maxLinksPerPage && this.maxLinksPerPage > 0) break;
                    if (!this._visited.has(link) && this._scope.check(link) && !this._isExcluded(link)) {
                        this._queue.push(new Request(link, {
                            referer: url,
                            linkDepth: request.linkDepth + 1,
                        }));
                        addedCount++;
                    }
                }

                // extract forms too
                const html = new Html(url, response.content);
                const forms = html.getForms();
                for (const form of forms) {
                    const req = new Request(form.action, {
                        method: form.method,
                        postParams: form.method === 'POST' ? form.inputs.filter(i => i.type !== 'file').map(i => [i.name, i.value]) : null,
                        getParams: form.method === 'GET' ? form.inputs.map(i => [i.name, i.value]) : null,
                        fileParams: form.inputs.filter(i => i.type === 'file').map(i => [i.name, 'tarsius_test.txt']),
                        enctype: form.enctype,
                        referer: url,
                    });
                    if (!this._visited.has(req.url)) {
                        this._queue.push(req);
                    }
                }
            }
        } catch (error) {
            logVerbose(`error crawling ${url}: ${error.message}`);
        }
    }

    // URL extraction via regex for speed (complemented by form extraction)
    _extractLinks(html, baseUrl) {
        const links = new Set();
        if (!html) return links;

        // find href atributes
        const hrefRegex = /href\s*=\s*["']([^"'#]+)/gi;
        let match;
        while ((match = hrefRegex.exec(html)) !== null) {
            const absUrl = makeAbsolute(baseUrl, match[1]);
            if (absUrl && (absUrl.startsWith('http://') || absUrl.startsWith('https://'))) {
                // remove fragmnts and clean up
                links.add(absUrl.split('#')[0]);
            }
        }

        // find src atributes too (for scripts, images)
        const srcRegex = /src\s*=\s*["']([^"'#]+)/gi;
        while ((match = srcRegex.exec(html)) !== null) {
            const absUrl = makeAbsolute(baseUrl, match[1]);
            if (absUrl && (absUrl.startsWith('http://') || absUrl.startsWith('https://'))) {
                links.add(absUrl.split('#')[0]);
            }
        }

        return links;
    }

    // check if a url is in our excuded list
    _isExcluded(url) {
        return this.excludedUrls.some(ex => url.includes(ex));
    }

    // check if we've run out of time
    _isTimeUp() {
        if (!this.maxScanTime) return false;
        const elapsed = (Date.now() - this._startTime) / 1000;
        return elapsed >= this.maxScanTime;
    }
}
