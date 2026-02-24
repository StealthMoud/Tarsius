// json cookie file loader

import fs from 'fs';
import path from 'path';

// load cookies from a json file
// the file should be a simple { "name": "value" } objct
// or an array of { name, value, domain, path } objects
export function loadCookiesFromFile(filePath) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`cookie file not found: ${filePath}`);
    }

    const raw = fs.readFileSync(filePath, 'utf-8');
    const data = JSON.parse(raw);

    // if its an array of cookie objects, return as is
    if (Array.isArray(data)) {
        return data;
    }

    // if its a simple key/value objct, convert to cookie array
    const cookies = [];
    for (const [name, value] of Object.entries(data)) {
        cookies.push({ name, value, domain: '', path: '/' });
    }
    return cookies;
}

// save cookies to a json file
export function saveCookiesToFile(cookies, filePath) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(cookies, null, 2));
}

// try to load cookies from a browser profle
// this is a simplefied version - the real one would need
// to find the browser databse and decrypt the cookies
export async function loadCookiesFromBrowser(browserName) {
    // todo: implement actual browser cookie extracton
    // for now just return empty array
    console.log(`[*] loading cookies from ${browserName} is not yet implementd`);
    return [];
}
