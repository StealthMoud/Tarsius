// configration classes for the crawlr and authentication

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0';

// http basic/digest/ntlm credentail
export class HttpCredential {
    constructor(username, password, method = 'basic') {
        this.username = username;
        this.password = password;
        this.method = method;
    }
}

// form based credentails (usrname + password + form url)
export class FormCredential {
    constructor(username, password, url) {
        this.username = username;
        this.password = password;
        this.url = url;
    }
}

// raw credentail data for custm post bodies
export class RawCredential {
    constructor(data, url, enctype = null) {
        this.data = data;
        this.url = url;
        this.enctype = enctype;
    }
}

// main crawlr config - holds all setings for sending http reqeusts
export class CrawlerConfiguration {
    constructor(baseRequest) {
        this.baseRequest = baseRequest;
        this.timeout = 10.0;
        this.secure = false;
        this.compression = true;
        this.userAgent = DEFAULT_UA;
        this.proxy = null;
        this.httpCredential = null;
        this.cookies = null;
        this.stream = false;
        this.headers = null;
        this.dropCookies = false;
    }

    // make a shallow copy of this config
    clone() {
        const copy = new CrawlerConfiguration(this.baseRequest);
        Object.assign(copy, this);
        return copy;
    }
}
