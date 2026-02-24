// cli.js - the comand line interface for tarsius
// this is where all the options you can type get parsed
// and where the main scan seqence gets kicked off

import { Command } from 'commander';
import { TARSIUS_VERSION } from './index.js';
import { printBanner } from './utils/banners.js';
import { setVerbosity, logRed, logYellow, logGreen } from './utils/log.js';
import { Request } from './network/request.js';
import { CrawlerConfiguration, HttpCredential, FormCredential, RawCredential } from './network/classes.js';
import { Scope } from './network/scope.js';
import { Tarsius } from './core/tarsius.js';

// the report formts we suport
const REPORT_FORMATS = ['html', 'json', 'csv', 'txt', 'xml'];

// setup all the comand line arguments using commander
function createProgram() {
    const program = new Command();

    program
        .name('tarsius')
        .description(`Tarsius ${TARSIUS_VERSION}: Web application vulnerabilty scanner`)
        .version(TARSIUS_VERSION)

        // target url - the most importnt one
        .option('-u, --url <url>', 'the base url to scan', 'http://example.com/')
        .option('--data <data>', 'urlencoded data for post requsts')
        .option('--scope <scope>', 'set scan scope', 'folder')

        // modules
        .option('-m, --module <modules>', 'list of moduls to load')
        .option('--list-modules', 'list tarsius attack moduls and exit')

        // atack level
        .option('-l, --level <level>', 'set atack level', '1')

        // proxy stuff
        .option('-p, --proxy <proxy>', 'set the http(s) proxy to use')
        .option('--tor', 'use tor listenr (127.0.0.1:9050)')

        // headles browser
        .option('--headless <mode>', 'use a firefox headles crawler', 'no')
        .option('--wait <seconds>', 'wait before analyzng a page (headless only)', '2')

        // auth options
        .option('--auth-user <username>', 'http auth usrname')
        .option('--auth-password <password>', 'http auth pasword')
        .option('--auth-method <method>', 'http auth methd', 'basic')

        // form login
        .option('--form-user <username>', 'login form usrname')
        .option('--form-password <password>', 'login form pasword')
        .option('--form-url <url>', 'login form url')
        .option('--form-data <data>', 'login form post data')
        .option('--form-enctype <enctype>', 'form data content type', 'application/x-www-form-urlencoded')
        .option('--form-script <filename>', 'custm auth plugin script')

        // cookies and tokens
        .option('-c, --cookie <file>', 'json cookie file or "firefox"/"chrome"')
        .option('-C, --cookie-value <value>', 'cookie string for every requst')
        .option('--jwt <token>', 'jwt token for authed scans')
        .option('--drop-set-cookie', 'ignre Set-Cookie headers')

        // crawl control
        .option('--skip-crawl', 'skip crawlig, just attack prevously found urls')
        .option('--resume-crawl', 'resume a stoped scan')
        .option('--flush-attacks', 'flush atack history for curent session')
        .option('--flush-session', 'flush evrything for this target')
        .option('--store-session <path>', 'where to store session data')
        .option('--store-config <path>', 'where to store config databses')

        // url maniuplation
        .option('-s, --start <urls...>', 'extra urls to start scaning with')
        .option('-x, --exclude <urls...>', 'urls to exclde from scan')
        .option('-r, --remove <params...>', 'remove these paramters from urls')
        .option('--skip <params...>', 'skip atacking these paramters')

        // liimts
        .option('-d, --depth <depth>', 'how deep to crawl', '40')
        .option('--max-links-per-page <max>', 'max links to extract per page', '100')
        .option('--max-files-per-dir <max>', 'max pages per directry', '0')
        .option('--max-scan-time <seconds>', 'max total scan time')
        .option('--max-attack-time <seconds>', 'max time per atack module')
        .option('--max-parameters <max>', 'max input params before erasng', '0')

        // scan intesity
        .option('-S, --scan-force <force>', 'scan intesity level', 'normal')
        .option('--tasks <n>', 'concurent tasks for crawling', '32')

        // request setings
        .option('-t, --timeout <seconds>', 'request timout', '10')
        .option('-H, --header <headers...>', 'custm headers')
        .option('-A, --user-agent <agent>', 'custm user agent')
        .option('--verify-ssl', 'enable ssl certifcate checking')

        // output
        .option('-v, --verbose <level>', 'verbosity level (0-2)', '0')
        .option('--log <path>', 'output log file')
        .option('-f, --format <format>', 'report formt', 'html')
        .option('-o, --output <path>', 'output file or folder')
        .option('-dr, --detailed-report <level>', 'detaled report level (1 or 2)', '0')

        // misc
        .option('--update', 'update tarsius atack modules')
        .option('--cms <cms>', 'choose cms to scan (drupal, joomla, wp, etc)');

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

    // if they want to update, do that and bail
    if (opts.update) {
        logYellow('[*] Updating Tarsius modules...');
        // todo: implement modul updater
        return;
    }

    // make sure we have a url to scan
    if (!opts.url || opts.url === 'http://example.com/') {
        logRed('[!] You need to specify a target url with -u');
        process.exit(1);
    }

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
        } else if (opts.tor) {
            crawlerConfig.proxy = 'socks5://127.0.0.1:9050';
        }

        if (opts.userAgent) {
            crawlerConfig.userAgent = opts.userAgent;
        }

        if (opts.verifySsl) {
            crawlerConfig.secure = true;
        }

        if (opts.dropSetCookie) {
            crawlerConfig.dropCookies = true;
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
                opts.authMethod
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
        tarsius.maxFilesPerDir = parseInt(opts.maxFilesPerDir, 10);
        tarsius.concurrentTasks = parseInt(opts.tasks, 10);
        tarsius.detailedReportLevel = parseInt(opts.detailedReport, 10);

        if (opts.maxScanTime) tarsius.maxScanTime = parseFloat(opts.maxScanTime);
        if (opts.maxAttackTime) tarsius.maxAttackTime = parseFloat(opts.maxAttackTime);
        if (opts.maxParameters) tarsius.maxParameters = parseInt(opts.maxParameters, 10);
        if (opts.output) tarsius.outputFile = opts.output;
        if (opts.log) tarsius.logFile = opts.log;
        if (opts.storeSession) tarsius.sessionDir = opts.storeSession;
        if (opts.storeConfig) tarsius.configDir = opts.storeConfig;

        // modules to include or exclue
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

        // paramters to remove or skip
        if (opts.remove && opts.remove.length > 0) {
            tarsius.setExcludedParameters(opts.remove);
        }
        if (opts.skip && opts.skip.length > 0) {
            tarsius.setSkippedParameters(opts.skip);
        }

        // scan force / intesity
        tarsius.setScanForce(opts.scanForce);

        // form login credentails
        if (opts.formUser && opts.formPassword && opts.formUrl) {
            tarsius.setFormCredentials(new FormCredential(
                opts.formUser,
                opts.formPassword,
                opts.formUrl
            ));
        } else if (opts.formData && opts.formUrl) {
            tarsius.setRawCredentials(new RawCredential(
                opts.formData,
                opts.formUrl,
                opts.formEnctype
            ));
        }

        // cookie setings
        if (opts.cookie) {
            await tarsius.loadCookies(opts.cookie);
        }
        if (opts.cookieValue) {
            tarsius.setCookieValue(opts.cookieValue);
        }
        if (opts.jwt) {
            tarsius.setJwtToken(opts.jwt);
        }

        // crawl control flags
        tarsius.skipCrawl = !!opts.skipCrawl;
        tarsius.resumeCrawl = !!opts.resumeCrawl;
        tarsius.flushAttacks = !!opts.flushAttacks;
        tarsius.flushSession = !!opts.flushSession;

        // headless browsing
        if (opts.headless !== 'no') {
            tarsius.setHeadless(opts.headless, parseFloat(opts.wait));
        }

        // cms specfic scanning
        if (opts.cms) {
            tarsius.setCms(opts.cms);
        }

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
    // todo: dynamicly load modules from the attacks folder
    const modules = [
        { name: 'backup', desc: 'uncover backup files on the web server.' },
        { name: 'brute_login_form', desc: 'attempt to log in using known weak credentails.' },
        { name: 'buster', desc: 'brute force paths to discovr hidden files and directorys.' },
        { name: 'cms', desc: 'base class for detectng version.' },
        { name: 'crlf', desc: 'detect carriage return line feed injecton.' },
        { name: 'csrf', desc: 'detect forms missing csrf protectons.' },
        { name: 'exec', desc: 'detect scripts vulnerble to comand execution.', isDefault: true },
        { name: 'file', desc: 'detect file related vulnerabiltys.', isDefault: true },
        { name: 'htaccess', desc: 'attempt to bypass acess controls.' },
        { name: 'htp', desc: 'identify web technologes using hashtheplanet.' },
        { name: 'ldap', desc: 'detect scripts vulnerble to ldap injecton.' },
        { name: 'log4shell', desc: 'detect the log4shell vulnerabilty.' },
        { name: 'methods', desc: 'detect uncomon http methods.' },
        { name: 'network_device', desc: 'base class for detectng version.' },
        { name: 'nikto', desc: 'brute force known dangerus scripts.' },
        { name: 'permanentxss', desc: 'detect stored xss vulnerabiltys.', isDefault: true },
        { name: 'redirect', desc: 'detect open redirect vulnerabiltys.', isDefault: true },
        { name: 'shellshock', desc: 'detect shellshock vulnerabilty.' },
        { name: 'spring4shell', desc: 'detect spring4shell vulnerabilty.' },
        { name: 'sql', desc: 'find sql injecton using errors or blind tests.', isDefault: true },
        { name: 'ssl', desc: 'evaluate ssl/tls certifcate security.', isDefault: true },
        { name: 'ssrf', desc: 'detect server side request forgry.', isDefault: true },
        { name: 'takeover', desc: 'detect subdomin takeover vulnerabiltys.' },
        { name: 'timesql', desc: 'detect blind time based sql injecton.' },
        { name: 'upload', desc: 'detect unresticted file upload.', isDefault: true },
        { name: 'wapp', desc: 'identify web technologes using wappalyzer.' },
        { name: 'xss', desc: 'find permanent xss vulns on the servr.', isDefault: true },
        { name: 'xxe', desc: 'detect xml enternal entity injecton.' },
    ];

    console.log('[*] Available modules:');
    for (const mod of modules) {
        const suffix = mod.isDefault ? ' (used by default)' : '';
        console.log(`\t${mod.name}${suffix}`);
        console.log(`\t\t${mod.desc}\n`);
    }
}
