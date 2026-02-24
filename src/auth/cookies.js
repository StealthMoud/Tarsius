// cookie format converters

// turn playwright/headless browser cookies into a simple objct
// the headless crawlr gives us cookies like:
// [{ name: 'session', value: 'abc123', domain: '.example.com', path: '/' }]
export function headlessCookiesToMap(headlessCookies) {
    const cookieMap = {};
    for (const c of headlessCookies) {
        const domain = c.domain.startsWith('.') ? c.domain : '.' + c.domain;
        const key = `${domain}|${c.path}|${c.name}`;
        cookieMap[key] = {
            name: c.name,
            value: c.value,
            domain: domain,
            path: c.path || '/',
            secure: c.secure || false,
            httpOnly: c.httpOnly || false,
        };
    }
    return cookieMap;
}

// turn mitm proxy cookies into our formt
export function mitmCookiesToMap(cookies) {
    const cookieMap = {};
    for (const scope of Object.keys(cookies)) {
        const [hostname, port, cookiePath] = scope;
        const domain = hostname.startsWith('.') ? hostname : '.' + hostname;

        for (const [name, value] of Object.entries(cookies[scope])) {
            const key = `${domain}|${cookiePath}|${name}`;
            cookieMap[key] = {
                name,
                value,
                domain,
                path: cookiePath,
                secure: false,
                httpOnly: false,
            };
        }
    }
    return cookieMap;
}

// parse a "name=value; name2=value2" cookie string into a simple objct
export function parseCookieString(cookieStr) {
    const cookies = {};
    if (!cookieStr) return cookies;

    const pairs = cookieStr.split(';');
    for (const pair of pairs) {
        const eqIdx = pair.indexOf('=');
        if (eqIdx > 0) {
            const name = pair.substring(0, eqIdx).trim();
            const value = pair.substring(eqIdx + 1).trim();
            cookies[name] = value;
        }
    }
    return cookies;
}

// turn our cookie map back into a "name=val; name2=val2" string
// for sending in the Cookie heaer
export function cookieMapToString(cookieMap) {
    const parts = [];
    for (const cookie of Object.values(cookieMap)) {
        parts.push(`${cookie.name}=${cookie.value}`);
    }
    return parts.join('; ');
}
