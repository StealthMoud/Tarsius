// web.js - the main http helper for tarsius
// this is where all the actual reqests get sent and recieved
// wraps axios with our cusotm config, retries, and stuff

import axios from 'axios';
import { Request, makeAbsolute, shellEscape } from './request.js';
import { Response, detailResponse } from './response.js';
import { logRed, logVerbose } from '../utils/log.js';

// create an axios instanc with the right settings from crawler config
function createHttpClient(crawlerConfig) {
    const config = {
        timeout: crawlerConfig.timeout * 1000, // axios uses miliseconds
        maxRedirects: 0, // we handle redirects ourselfs
        validateStatus: () => true, // dont throw on 4xx/5xx
        headers: {
            'User-Agent': crawlerConfig.userAgent,
        },
        decompress: crawlerConfig.compression,
    };

    // setup proxy if we have one
    if (crawlerConfig.proxy) {
        const proxyUrl = new URL(crawlerConfig.proxy);
        config.proxy = {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port, 10),
            protocol: proxyUrl.protocol,
        };
    }

    // add any extra hedaers the user specifed
    if (crawlerConfig.headers) {
        Object.assign(config.headers, crawlerConfig.headers);
    }

    // setup basic auth if we have credentails
    if (crawlerConfig.httpCredential) {
        config.auth = {
            username: crawlerConfig.httpCredential.username,
            password: crawlerConfig.httpCredential.password,
        };
    }

    // disable ssl verificaton if not in secure mode
    if (!crawlerConfig.secure) {
        config.httpsAgent = new (await import('https')).Agent({
            rejectUnauthorized: false,
        });
    }

    return axios.create(config);
}

// send a request and get back a nice Response objct
// handles timeing and basic eror handling
export async function sendRequest(request, crawlerConfig) {
    const startTime = Date.now();

    try {
        const client = await createAxiosConfig(crawlerConfig);

        const axiosConfig = {
            method: request.method.toLowerCase(),
            url: request.url,
            ...client,
        };

        // add referer heaer if we have one
        if (request.referer) {
            axiosConfig.headers = axiosConfig.headers || {};
            axiosConfig.headers['Referer'] = request.referer;
        }

        // add post body if this is a post requst
        if (request.method === 'POST') {
            if (request.isJson) {
                axiosConfig.data = request.postParams;
                axiosConfig.headers = axiosConfig.headers || {};
                axiosConfig.headers['Content-Type'] = 'application/json';
            } else {
                axiosConfig.data = request.encodedData;
                axiosConfig.headers = axiosConfig.headers || {};
                axiosConfig.headers['Content-Type'] = request.enctype;
            }
        }

        const rawResponse = await axios(axiosConfig);

        // calculate how long it took
        rawResponse._elapsed = (Date.now() - startTime) / 1000;

        return new Response(rawResponse, request.url);
    } catch (error) {
        if (error.code === 'ECONNABORTED') {
            logVerbose(`timeout on ${request.url}`);
        } else if (error.code === 'ECONNREFUSED') {
            logRed(`[!] connection refused to ${request.url}`);
        } else {
            logVerbose(`error requesting ${request.url}: ${error.message}`);
        }
        return null;
    }
}

// build axios config from crawler configuraton
// seprated out so we can reuse it
async function createAxiosConfig(crawlerConfig) {
    const config = {
        timeout: crawlerConfig.timeout * 1000,
        maxRedirects: 0,
        validateStatus: () => true,
        headers: {
            'User-Agent': crawlerConfig.userAgent,
        },
    };

    if (crawlerConfig.proxy) {
        try {
            const proxyUrl = new URL(crawlerConfig.proxy);
            config.proxy = {
                host: proxyUrl.hostname,
                port: parseInt(proxyUrl.port, 10),
                protocol: proxyUrl.protocol,
            };
        } catch {
            // bad proxy url, skip it
        }
    }

    if (crawlerConfig.headers) {
        Object.assign(config.headers, crawlerConfig.headers);
    }

    if (crawlerConfig.httpCredential) {
        config.auth = {
            username: crawlerConfig.httpCredential.username,
            password: crawlerConfig.httpCredential.password,
        };
    }

    if (!crawlerConfig.secure) {
        const https = await import('https');
        config.httpsAgent = new https.Agent({
            rejectUnauthorized: false,
        });
    }

    return config;
}

// follow redirects manualy so we can track the chain
export async function fetchWithRedirects(request, crawlerConfig, maxRedirects = 5) {
    let currentUrl = request.url;
    const redirectChain = [];

    for (let i = 0; i < maxRedirects; i++) {
        const req = new Request(currentUrl, { method: 'GET', referer: request.referer });
        const response = await sendRequest(req, crawlerConfig);

        if (!response) return null;

        redirectChain.push(response);

        if (response.isRedirect && response.redirectionUrl) {
            currentUrl = response.redirectionUrl;
        } else {
            // final respnse - attach the redirect history
            response._redirectChain = redirectChain.slice(0, -1);
            return response;
        }
    }

    // too many redircts
    logVerbose(`too many redirects for ${request.url}`);
    return redirectChain[redirectChain.length - 1] || null;
}

// re-export stuff that other moduls need
export { Request, Response, makeAbsolute, shellEscape, detailResponse };
