// cli argument parsng and main entry

import { Command } from 'commander';
import { TARSIUS_VERSION } from './index.js';
import { printBanner } from './utils/banners.js';
import { setVerbosity, logRed, logYellow, logGreen } from './utils/log.js';
import { Request } from './http/request.js';
import { CrawlerConfiguration, HttpCredential, FormCredential } from './http/config.js';
import { Scope } from './crawler/scope.js';
import { Tarsius } from './scanner.js';

// the report formts we suport
const REPORT_FORMATS = ['html', 'json', 'csv', 'txt'];

// setup all the comand line arguments using commander
function createProgram() {
    const program = new Command();

    program
        .name('tarsius')
        .description(`Tarsius ${TARSIUS_VERSION}: Web application vulnerabilty scanner`)
        .version(TARSIUS_VERSION)

        // target - the only requird option
        .requiredOption('-u, --url <url>', 'target url to scan')
        .option('--data <data>', 'urlencoded data for post requsts')
        .option('--scope <scope>', 'scan scope (url, page, folder, domain)', 'domain')

        // modules
        .option('-m, --module <modules>', 'comma-separated list of moduls to run')
        .option('--list-modules', 'list tarsius attack moduls and exit')

        // atack level
        .option('-l, --level <level>', 'set atack level (1 or 2)', '1')

        // proxy
        .option('-p, --proxy <proxy>', 'http/socks proxy url')

        // auth options
        .option('--auth-user <username>', 'http basic auth usrname')
        .option('--auth-password <password>', 'http basic auth pasword')

        // form login
        .option('--form-user <username>', 'login form usrname')
        .option('--form-password <password>', 'login form pasword')
        .option('--form-url <url>', 'login form url')

        // cookies and tokens
        .option('-c, --cookie <file>', 'json cookie file path')
        .option('-C, --cookie-value <value>', 'cookie string for every requst')

        // crawl control
        .option('--skip-crawl', 'skip crawlig, just attack prevously found urls')

        // url maniuplation
        .option('-s, --start <urls...>', 'extra urls to start scaning with')
        .option('-x, --exclude <urls...>', 'urls to exclde from scan')
        .option('--skip <params...>', 'skip atacking these paramters')

        // limits
        .option('-d, --depth <depth>', 'max crawl depth', '10')
        .option('--max-links-per-page <max>', 'max links to extract per page', '100')
        .option('--max-scan-time <seconds>', 'max total scan time in seconds')
        .option('--max-attack-time <seconds>', 'max time per atack module')

        // concurency
        .option('-T, --threads <n>', 'concurrent threads for crawling and attacking', '16')

        // request setings
        .option('-t, --timeout <seconds>', 'request timout in seconds', '5')
        .option('-H, --header <headers...>', 'custm headers (e.g. "X-Api-Key: abc")')
        .option('-A, --user-agent <agent>', 'custm user agent string')
        .option('--verify-ssl', 'enable ssl certifcate checking')

        // output
        .option('-v, --verbose <level>', 'verbosity level (0-2)', '0')
        .option('-f, --format <format>', 'report formt (html, json, csv, txt)', 'html')
        .option('-o, --output <path>', 'output file or folder for report');

    return program;
}

// the main entry point - this is what bin/tarsius cals
export async function tarsiusMain() {
    const program = createProgram();
    program.parse(process.argv);
    const opts = program.opts();

    printBanner();

    // set verbostiy level
    setVerbosity(parseInt(opts.verbose, 10));

    // if they just want the modul list, show it and bail
    if (opts.listModules) {
        await listModules();
        return;
    }

    // the url is requird, commmander handles this with requiredOption

    try {
        // build the initial requst from the target url
        const baseRequest = new Request(opts.url, {
            method: opts.data ? 'POST' : 'GET',
            postParams: opts.data || null,
        });

        // setup the crawler configration
        const crawlerConfig = new CrawlerConfiguration(baseRequest);
        crawlerConfig.timeout = parseFloat(opts.timeout);

        if (opts.proxy) {
            crawlerConfig.proxy = opts.proxy;
        }

        if (opts.userAgent) {
            crawlerConfig.userAgent = opts.userAgent;
        }

        if (opts.verifySsl) {
            crawlerConfig.secure = true;
        }

        // parse custm headers
        if (opts.header && opts.header.length > 0) {
            crawlerConfig.headers = {};
            for (const h of opts.header) {
                const colonIdx = h.indexOf(':');
                if (colonIdx > 0) {
                    const key = h.substring(0, colonIdx).trim();
                    const val = h.substring(colonIdx + 1).trim();
                    crawlerConfig.headers[key] = val;
                }
            }
        }

        // setup http authenticaton
        if (opts.authUser && opts.authPassword) {
            crawlerConfig.httpCredential = new HttpCredential(
                opts.authUser,
                opts.authPassword,
                'basic'
            );
        }

        // create the scope
        const scope = new Scope(baseRequest, opts.scope);

        // create the main tarsius instanc and configure it
        const tarsius = new Tarsius(crawlerConfig, scope);

        // set attack opptions
        tarsius.attackLevel = parseInt(opts.level, 10);
        tarsius.reportFormat = opts.format;
        tarsius.maxDepth = parseInt(opts.depth, 10);
        tarsius.maxLinksPerPage = parseInt(opts.maxLinksPerPage, 10);
        tarsius.threads = parseInt(opts.threads, 10);

        if (opts.maxScanTime) tarsius.maxScanTime = parseFloat(opts.maxScanTime);
        if (opts.maxAttackTime) tarsius.maxAttackTime = parseFloat(opts.maxAttackTime);
        if (opts.output) tarsius.outputFile = opts.output;

        // modules to run
        if (opts.module) {
            tarsius.setModules(opts.module);
        }

        // extra starting urls
        if (opts.start && opts.start.length > 0) {
            tarsius.addStartUrls(opts.start);
        }

        // excluded urls
        if (opts.exclude && opts.exclude.length > 0) {
            tarsius.addExcludedUrls(opts.exclude);
        }

        // paramters to skip
        if (opts.skip && opts.skip.length > 0) {
            tarsius.setSkippedParameters(opts.skip);
        }

        // form login credentails
        if (opts.formUser && opts.formPassword && opts.formUrl) {
            tarsius.setFormCredentials(new FormCredential(
                opts.formUser,
                opts.formPassword,
                opts.formUrl
            ));
        }

        // cookie setings
        if (opts.cookie) {
            await tarsius.loadCookies(opts.cookie);
        }
        if (opts.cookieValue) {
            tarsius.setCookieValue(opts.cookieValue);
        }

        // crawl control
        tarsius.skipCrawl = !!opts.skipCrawl;

        // run the actual scan! this is where it all hapens
        await tarsius.run();

    } catch (error) {
        logRed(`[!] Error: ${error.message}`);
        if (parseInt(opts.verbose, 10) >= 2) {
            console.error(error);
        }
        process.exit(1);
    }
}

// list all availble attack modles
async function listModules() {
    const modules = [
        { name: 'backup', desc: 'find backup files left on the web server.' },
        { name: 'brute_login_form', desc: 'try common weak credentails on login forms.' },
        { name: 'buster', desc: 'brute force paths to find hidden files.' },
        { name: 'crlf', desc: 'detect carriage return line feed injecton.' },
        { name: 'csrf', desc: 'detect forms missing csrf protectons.' },
        { name: 'exec', desc: 'detect comand injection vulnerabiltys.' },
        { name: 'file', desc: 'detect path traversal and file incluson.' },
        { name: 'htaccess', desc: 'attempt to bypass htaccess restrictons.' },
        { name: 'ldap', desc: 'detect ldap injecton vulnerabiltys.' },
        { name: 'log4shell', desc: 'detect the log4shell vulnerabilty (CVE-2021-44228).' },
        { name: 'methods', desc: 'detect uncomon http methods enabled.' },
        { name: 'nikto', desc: 'test for known dangerus files and scripts.' },
        { name: 'permanentxss', desc: 'detect stored xss vulnerabiltys.' },
        { name: 'redirect', desc: 'detect open redirect vulnerabiltys.' },
        { name: 'shellshock', desc: 'detect shellshock vulnerabilty (CVE-2014-6271).' },
        { name: 'spring4shell', desc: 'detect spring4shell vulnerabilty (CVE-2022-22965).' },
        { name: 'sql', desc: 'find sql injecton using error-based detecton.' },
        { name: 'ssl', desc: 'evaluate ssl/tls certifcate security.' },
        { name: 'ssrf', desc: 'detect server side request forgry.' },
        { name: 'takeover', desc: 'detect subdomin takeover vulnerabiltys.' },
        { name: 'timesql', desc: 'detect blind time-based sql injecton.' },
        { name: 'upload', desc: 'detect unresticted file upload.' },
        { name: 'xss', desc: 'detect reflected xss vulnerabiltys.' },
        { name: 'xxe', desc: 'detect xml external entity injecton.' },
    ];

    console.log('[*] Available modules (all modules are run by default unless specified with -m):');
    for (const mod of modules) {
        console.log(`\t${mod.name}`);
        console.log(`\t\t${mod.desc}\n`);
    }
}
