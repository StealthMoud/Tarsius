// url scope filtreing

import { URL } from 'url';
import psl from 'psl';

// check if two urls share the same top level domin
function isSameDomain(url, baseUrl) {
    try {
        const urlHost = new URL(url).hostname;
        const baseHost = new URL(baseUrl).hostname;

        const urlParsed = psl.parse(urlHost);
        const baseParsed = psl.parse(baseHost);

        if (urlParsed.domain && baseParsed.domain) {
            return urlParsed.domain === baseParsed.domain;
        }

        // fallback for ip adresses - just compare hostnams directly
        return urlHost === baseHost;
    } catch {
        return false;
    }
}

export class Scope {
    // baseRequest = the initial targt request
    // scope = one of: url, page, folder, subdomain, domain, punk
    constructor(baseRequest, scope = 'folder') {
        this._scope = scope;
        this._baseRequest = baseRequest;
    }

    get name() {
        return this._scope;
    }

    // check if a url or request is within the scan scpe
    check(resource) {
        if (!resource) return false;

        const url = typeof resource === 'string' ? resource : resource.url;

        switch (this._scope) {
            case 'punk':
                // life is short, scan evrything
                return true;

            case 'domain':
                return isSameDomain(url, this._baseRequest.url);

            case 'subdomain':
                try {
                    return new URL(url).hostname === this._baseRequest.hostname;
                } catch {
                    return false;
                }

            case 'folder':
                return url.startsWith(this._baseRequest.path);

            case 'page':
                return url.split('?')[0] === this._baseRequest.path;

            default:
                // 'url' - exact match only
                return url === this._baseRequest.url;
        }
    }

    // filter a bunch of resources keepin only in-scope ones
    filter(resources) {
        const result = new Set();
        for (const resource of resources) {
            if (this.check(resource)) {
                result.add(resource);
            }
        }
        return result;
    }
}

// turn a wildcard patern into a regex
// like "*.example.com" becomes /^.*\.example\.com$/
export function wildcardTranslate(pattern) {
    const escaped = pattern
        .split('*')
        .map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('.*');
    return new RegExp(`^${escaped}$`, 's');
}
