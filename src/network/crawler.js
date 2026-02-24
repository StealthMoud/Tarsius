// async crawler - sends http reqests with retry logic
// wraps axios and handles timeouts, errors, ssl, proxys etc
// this is the low level "go fetch this page" worker

import https from 'https';
import axios from 'axios';
import { Response } from './response.js';
import { logVerbose, logRed } from '../utils/log.js';

// status codes for crawl results
export const CrawlStatus = {
    SUCCESS: 0,
    TIMEOUT: 1,
    HTTP_ERROR: 2,
    INVALID_URL: 3,
    CONNECT_ERROR: 4,
    SSL_ERROR: 5,
    UNKNOWN_ERROR: 6,
};

// reusable agent for skiping ssl checks
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

export class AsyncCrawler {
    // config = CrawlerConfiguration object
    constructor(config) {
        this._config = config;
        this._client = null;
        this.isLoggedIn = false;
        this.authUrl = config.baseRequest.url;
        this._buildClient();
    }

    // create the axios client from our config
    _buildClient() {
        const headers = {
            'User-Agent': this._config.userAgent,
            'Accept-Language': 'en-US',
            'Accept-Encoding': this._config.compression ? 'gzip, deflate, br' : 'identity',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        };

        // add any custm headers
        if (this._config.headers) {
            Object.assign(headers, this._config.headers);
        }

        const axiosConfig = {
            headers,
            timeout: this._config.timeout * 1000,
            maxRedirects: 0, // we handle redirects manualy
            validateStatus: () => true,
        };

        // proxy setup
        if (this._config.proxy) {
            try {
                const proxyUrl = new URL(this._config.proxy);
                axiosConfig.proxy = {
                    host: proxyUrl.hostname,
                    port: parseInt(proxyUrl.port, 10),
                    protocol: proxyUrl.protocol,
                };
            } catch {
                // bad proxy url
            }
        }

        // http auth
        if (this._config.httpCredential) {
            axiosConfig.auth = {
                username: this._config.httpCredential.username,
                password: this._config.httpCredential.password,
            };
        }

        // ssl
        if (!this._config.secure) {
            axiosConfig.httpsAgent = insecureAgent;
        }

        this._client = axios.create(axiosConfig);
    }

    // send a GET requst with retry logic
    async get(request, followRedirects = false) {
        return this._sendWithRetry(request, 'GET', followRedirects);
    }

    // send a POST requst with retry logic
    async post(request, followRedirects = false) {
        return this._sendWithRetry(request, 'POST', followRedirects);
    }

    // send any request with the right methd
    async send(request, followRedirects = false) {
        return this._sendWithRetry(request, request.method, followRedirects);
    }

    // the actual send with retry wraped around it
    async _sendWithRetry(request, method, followRedirects, retries = 3, delay = 1000) {
        let lastError = null;

        for (let attempt = 0; attempt < retries; attempt++) {
            if (attempt > 0) {
                await new Promise(r => setTimeout(r, delay));
            }

            try {
                return await this._doRequest(request, method, followRedirects);
            } catch (error) {
                lastError = error;

                // dont retry on network erors
                if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
                    throw error;
                }

                // only retry on timeouts
                if (error.code !== 'ECONNABORTED') {
                    throw error;
                }

                logVerbose(`retry ${attempt + 1}/${retries} for ${request.url}`);
            }
        }

        throw lastError;
    }

    // actually do the http requst
    async _doRequest(request, method, followRedirects) {
        const startTime = Date.now();

        const config = {
            method: method.toLowerCase(),
            url: request.url,
        };

        // add referer
        if (request.referer) {
            config.headers = { Referer: request.referer };
        }

        // add post body
        if (method === 'POST') {
            if (request.isJson) {
                config.data = request.postParams;
                config.headers = { ...(config.headers || {}), 'Content-Type': 'application/json' };
            } else if (request.postParams && request.postParams.length > 0) {
                config.data = request.encodedData;
                config.headers = { ...(config.headers || {}), 'Content-Type': request.enctype };
            }
        }

        const rawResponse = await this._client(config);
        rawResponse._elapsed = (Date.now() - startTime) / 1000;

        let response = new Response(rawResponse, request.url);

        // follow redirects if asked
        if (followRedirects && response.isRedirect && response.redirectionUrl) {
            const { Request } = await import('./request.js');
            const redirectReq = new Request(response.redirectionUrl, {
                method: 'GET',
                referer: request.url,
            });
            return this._doRequest(redirectReq, 'GET', true);
        }

        return response;
    }

    // close the crawler (cleanup)
    async close() {
        // axios doesnt need explict closing
    }
}
