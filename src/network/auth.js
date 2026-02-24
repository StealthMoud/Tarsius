// auth - handles authenticaton for the scanner
// supports http basic/digest, form login, and headless browser login

import { Request } from './request.js';
import { AsyncCrawler } from './crawler.js';
import { logGreen, logRed, logVerbose } from '../utils/log.js';

// check if http auth credentails work
export async function checkHttpAuth(crawlerConfig) {
    const crawler = new AsyncCrawler(crawlerConfig);
    try {
        const response = await crawler.get(crawlerConfig.baseRequest);
        if (response && response.status !== 401 && response.status !== 403) {
            return true;
        }
        return false;
    } catch {
        return false;
    } finally {
        await crawler.close();
    }
}

// try to login using a form
// posts the credentails to the form url and checks if we got in
export async function formLogin(crawlerConfig, formCredential) {
    const crawler = new AsyncCrawler(crawlerConfig);

    try {
        // first fetch the login page to get any csrf tokns
        const loginPage = await crawler.get(
            new Request(formCredential.url, { method: 'GET' })
        );

        if (!loginPage) {
            logRed('[!] Could not fetch login page');
            return false;
        }

        logVerbose(`[*] Login page fetched: ${loginPage.status}`);

        // build the login requst
        // todo: detect form fields automaticly instead of assuming usrname/password
        const loginRequest = new Request(formCredential.url, {
            method: 'POST',
            postParams: [
                ['username', formCredential.username],
                ['password', formCredential.password],
            ],
            referer: formCredential.url,
        });

        const response = await crawler.post(loginRequest, true);

        if (response && response.isSuccess) {
            logGreen('[+] Form login successfull');
            crawler.isLoggedIn = true;
            return true;
        }

        logRed('[-] Form login failed');
        return false;
    } catch (error) {
        logRed(`[!] Login error: ${error.message}`);
        return false;
    } finally {
        await crawler.close();
    }
}

// try to login using raw post data
export async function rawLogin(crawlerConfig, rawCredential) {
    const crawler = new AsyncCrawler(crawlerConfig);

    try {
        const loginRequest = new Request(rawCredential.url, {
            method: 'POST',
            postParams: rawCredential.data,
            enctype: rawCredential.enctype || 'application/x-www-form-urlencoded',
        });

        const response = await crawler.post(loginRequest, true);

        if (response && response.isSuccess) {
            logGreen('[+] Raw login successfull');
            return true;
        }

        logRed('[-] Raw login failed');
        return false;
    } catch (error) {
        logRed(`[!] Login error: ${error.message}`);
        return false;
    } finally {
        await crawler.close();
    }
}

// login using a headless browser (playwight)
// this is the most relible method for modern web apps
export async function headlessLogin(crawlerConfig, formCredential, mode = 'hidden') {
    // todo: implement playwright based login
    logVerbose('[*] Headless login not yet implementd in JS version');
    return false;
}
