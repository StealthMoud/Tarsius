// response class - wraps the raw http respons from axios
// gives us nice properies for status, headers, body, redirectons etc

import { createHash } from 'crypto';
import { makeAbsolute } from './request.js';

export class Response {
    // response = the raw axios respnse object
    // url = overide url (usefull for redirects)
    constructor(response, url = null) {
        this._response = response;
        this._url = url || response.config?.url || '';
        this._elapsed = response._elapsed || 0;
    }

    // the url of this respnose
    get url() {
        return this._url;
    }

    // http status code like 200, 404, 500 etc
    get status() {
        return this._response.status;
    }

    // respone headers as a plain object
    get headers() {
        return this._response.headers || {};
    }

    // grab cookis from set-cookie headers
    get cookies() {
        const setCookieHeaders = this.headers['set-cookie'];
        if (!setCookieHeaders) return [];
        return Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    }

    // web server banner from the Server heaer
    get server() {
        return this.headers.server || '';
    }

    // content type lowercased
    get type() {
        return (this.headers['content-type'] || '').toLowerCase();
    }

    // wether the body is uncompresed
    get isPlain() {
        return (this.headers['content-encoding'] || 'identity') === 'identity';
    }

    // size of the reponse body in bytes
    get size() {
        const contentLength = this.headers['content-length'];
        if (contentLength && this.isPlain) {
            return parseInt(contentLength, 10) || this.bytes.length;
        }
        return this.bytes.length;
    }

    // time in secnds it took to fetch the page
    get delay() {
        return this._elapsed;
    }

    // the html/text contnt of the response body
    get content() {
        if (typeof this._response.data === 'string') {
            return this._response.data;
        }
        if (Buffer.isBuffer(this._response.data)) {
            return this._response.data.toString('utf-8');
        }
        if (typeof this._response.data === 'object') {
            return JSON.stringify(this._response.data);
        }
        return String(this._response.data || '');
    }

    // response body as raw bytes buffer
    get bytes() {
        if (Buffer.isBuffer(this._response.data)) {
            return this._response.data;
        }
        return Buffer.from(this.content, 'utf-8');
    }

    // try to parse json from the body
    get json() {
        try {
            if (typeof this._response.data === 'object') return this._response.data;
            return JSON.parse(this.content);
        } catch {
            return null;
        }
    }

    // md5 hash of the body for comparisons
    get md5() {
        return createHash('md5').update(this.bytes).digest('hex');
    }

    // where does this redirect go to
    get redirectionUrl() {
        if (this.isRedirect && this.headers.location) {
            return makeAbsolute(this._url, this.headers.location);
        }
        return '';
    }

    // check if this is just a "add trailing slash" redirct
    get isDirectoryRedirection() {
        if (!this.redirectionUrl) return false;
        const base = this._url.endsWith('/') ? this._url : this._url + '/';
        return base === this.redirectionUrl;
    }

    // true for 2xx statuses - everthing is fine
    get isSuccess() {
        return this._response.status >= 200 && this._response.status < 300;
    }

    // true for 3xx - your page is somwhere else
    get isRedirect() {
        return this._response.status >= 300 && this._response.status < 400;
    }

    // true for 4xx/5xx - somthing went wrong
    get isError() {
        return this._response.status >= 400;
    }
}

// make a detail object from a response for the report
export function detailResponse(response) {
    if (!response) return null;
    return {
        status_code: response.status,
        headers: Object.entries(response.headers),
        body: response.content.substring(0, 4096),
    };
}
