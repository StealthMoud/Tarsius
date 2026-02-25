// http requst wrapper

import { URL } from 'url';
import { createHash } from 'crypto';

export class Request {
    // path = target url
    // method = GET/POST/etc
    // getParams = query string stuff as [[key,val],...]
    // postParams = post body paramters
    // fileParams = file upload stuff
    // referer = where we came from
    // linkDepth = how deep in the crawl tre
    // enctype = content type for post requsts
    constructor(
        path,
        {
            method = 'GET',
            getParams = null,
            postParams = null,
            fileParams = null,
            referer = '',
            linkDepth = 0,
            enctype = 'application/x-www-form-urlencoded',
        } = {}
    ) {
        this._path = path;
        this._method = method.toUpperCase();
        this._enctype = enctype;
        this._referer = referer;
        this._linkDepth = linkDepth;
        this._pathId = null;

        // try to break apart the url into its peices
        try {
            const urlObj = new URL(path);
            this._scheme = urlObj.protocol.replace(':', '');
            this._hostname = urlObj.hostname;
            this._port = urlObj.port;
            this._netloc = urlObj.host;
            this._basePath = urlObj.pathname;
            this._fragment = urlObj.hash.replace('#', '');

            // grab get params from url if not given explictly
            if (getParams === null) {
                this._getParams = [];
                for (const [key, value] of urlObj.searchParams) {
                    this._getParams.push([key, value]);
                }
            } else if (typeof getParams === 'string') {
                this._getParams = Request.parseQueryString(getParams);
            } else {
                this._getParams = getParams.map(p => [...p]);
            }
        } catch {
            this._scheme = '';
            this._hostname = '';
            this._port = '';
            this._netloc = '';
            this._basePath = path;
            this._fragment = '';
            this._getParams = getParams ? (typeof getParams === 'string' ? Request.parseQueryString(getParams) : getParams.map(p => [...p])) : [];
        }

        // post params - could be a json string or [[key,val],...] pairs
        if (postParams === null) {
            this._postParams = [];
        } else if (typeof postParams === 'string') {
            this._postParams = postParams; // json body stays as string
        } else {
            this._postParams = postParams.map(p => [...p]);
        }

        // file upload paramaters
        this._fileParams = fileParams ? fileParams.map(p => [...p]) : [];
    }

    // parse a query string into [[key,val],...] pairs
    static parseQueryString(qs) {
        if (!qs) return [];
        const params = [];
        const pairs = qs.split('&');
        for (const pair of pairs) {
            if (!pair) continue;
            const eqIndex = pair.indexOf('=');
            if (eqIndex === -1) {
                params.push([decodeURIComponent(pair.replace(/\+/g, ' ')), null]);
            } else {
                const key = decodeURIComponent(pair.substring(0, eqIndex).replace(/\+/g, ' '));
                const value = decodeURIComponent(pair.substring(eqIndex + 1).replace(/\+/g, ' '));
                params.push([key, value]);
            }
        }
        return params;
    }

    get url() {
        if (this._getParams.length === 0) {
            return this.path;
        }
        return `${this.path}?${this.encodedParams}`;
    }

    get path() {
        if (this._scheme && this._netloc) {
            return `${this._scheme}://${this._netloc}${this._basePath}`;
        }
        return this._basePath;
    }

    get method() { return this._method; }
    set method(val) { this._method = val.toUpperCase(); }

    get hostname() { return this._hostname; }
    get netloc() { return this._netloc; }
    get scheme() { return this._scheme; }
    get referer() { return this._referer; }
    set referer(val) { this._referer = val; }

    get linkDepth() { return this._linkDepth; }
    set linkDepth(val) { this._linkDepth = val; }

    get pathId() { return this._pathId; }
    set pathId(val) { this._pathId = val; }

    get enctype() { return this._enctype; }
    set enctype(val) { this._enctype = val; }

    get getParams() { return this._getParams; }
    set getParams(val) { this._getParams = val; }

    get postParams() { return this._postParams; }
    set postParams(val) { this._postParams = val; }

    get fileParams() { return this._fileParams; }
    set fileParams(val) { this._fileParams = val; }

    // check if the body is json insted of form data
    get isJson() {
        return typeof this._postParams === 'string';
    }

    // get numeric parts of the path that could be RESTful IDs (e.g. /products/123)
    // returns [[index_in_path_split, current_value], ...]
    get pathParams() {
        const parts = this._basePath.split('/');
        const params = [];
        for (let i = 0; i < parts.length; i++) {
            if (/^\d+$/.test(parts[i])) {
                params.push([i, parts[i]]);
            }
        }
        return params;
    }

    get encodedParams() {
        return Request.encodeParams(this._getParams);
    }

    get encodedData() {
        if (typeof this._postParams === 'string') return this._postParams;
        return Request.encodeParams(this._postParams);
    }

    // get the filename part of the path like "index.php"
    get fileName() {
        const parts = this._basePath.split('/');
        const last = parts[parts.length - 1];
        return last || '';
    }

    // encode [[key,val],...] to a qurey string
    static encodeParams(params) {
        if (!params || typeof params === 'string') return params || '';
        return params
            .map(([k, v]) => {
                if (v === null || v === undefined) return encodeURIComponent(k);
                return `${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
            })
            .join('&');
    }

    // hash for deduplicaton so we dont scan the same thing twice
    hash() {
        const data = `${this._method}|${this.path}|${this.encodedParams}|${this.encodedData}`;
        return createHash('md5').update(data).digest('hex');
    }

    // path with numbers replaced by placeholders to group similar endpoints
    get normalizedPath() {
        const parts = this._basePath.split('/');
        const normalized = parts.map(p => {
            if (/^\d+$/.test(p)) return '{id}';
            return p;
        });
        return normalized.join('/');
    }

    // hash for logical deduplication (same method, same path structure, same parameter keys)
    logicalHash() {
        // sort parameters by key to ensure order doesnt change the hash
        const getKeys = (this._getParams || []).map(p => p[0]).sort().join(',');
        const postKeys = (typeof this._postParams === 'string') ? 'JSON' : (this._postParams || []).map(p => p[0]).sort().join(',');

        const data = `${this._method}|${this.normalizedPath}|${getKeys}|${postKeys}`;
        return createHash('md5').update(data).digest('hex');
    }

    toString() {
        return `${this._method} ${this.url}`;
    }
}

// convert a relative url to absolute usign a base url
export function makeAbsolute(base, url) {
    if (!url || !url.trim()) return '';

    try {
        return new URL(url, base).href;
    } catch {
        return '';
    }
}

// escape special chars for shell comands
export function shellEscape(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\$/g, '\\$')
        .replace(/!/g, '\\!')
        .replace(/`/g, '\\`');
}

// generate a curl comand string for a request
export function httpRepr(request) {
    let cmd = `curl "${shellEscape(request.url)}"`;

    if (request.method === 'POST') {
        if (request.isJson) {
            cmd += ` -H "Content-Type: application/json" -d "${shellEscape(request.postParams)}"`;
        } else {
            cmd += ` -d "${shellEscape(request.encodedData)}"`;
        }
    }

    if (request.referer) {
        cmd += ` -e "${shellEscape(request.referer)}"`;
    }

    return cmd;
}
