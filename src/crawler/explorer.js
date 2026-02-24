// bfs crawlr that finds pages and forms

import { Request, makeAbsolute } from '../http/request.js';
import { AsyncCrawler } from './crawler.js';
import { Scope } from './scope.js';
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
                const forms = this._extractForms(response.content, url);
                for (const form of forms) {
                    if (!this._visited.has(form.url)) {
                        this._queue.push(form);
                    }
                }
            }
        } catch (error) {
            logVerbose(`error crawling ${url}: ${error.message}`);
        }
    }

    // extract links from html content usng regex
    // todo: replace with cherio for beter accuracy
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

    // extract forms from html
    // todo: replace with cherio parser for much beter accuracy
    _extractForms(html, baseUrl) {
        const forms = [];
        if (!html) return forms;

        // simple regex to find form actins
        const formRegex = /<form[^>]*action\s*=\s*["']([^"']*)["'][^>]*>/gi;
        const methodRegex = /method\s*=\s*["']([^"']*)["']/i;

        let match;
        while ((match = formRegex.exec(html)) !== null) {
            const action = makeAbsolute(baseUrl, match[1]);
            if (!action) continue;

            const methodMatch = match[0].match(methodRegex);
            const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

            // extract input fields
            // this is a rough extraction, the real parser will do much beter
            const postParams = [];
            const inputRegex = /<input[^>]*name\s*=\s*["']([^"']*)["'][^>]*>/gi;
            let inputMatch;

            // search for inputs between this form and the next form or end of html
            const formEndIdx = html.indexOf('</form>', match.index);
            const formHtml = html.substring(match.index, formEndIdx > 0 ? formEndIdx : undefined);

            while ((inputMatch = inputRegex.exec(formHtml)) !== null) {
                const valueMatch = inputMatch[0].match(/value\s*=\s*["']([^"']*)["']/i);
                postParams.push([inputMatch[1], valueMatch ? valueMatch[1] : '']);
            }

            forms.push(new Request(action, {
                method,
                postParams: method === 'POST' ? postParams : null,
                getParams: method === 'GET' ? postParams : null,
                referer: baseUrl,
            }));
        }

        return forms;
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
