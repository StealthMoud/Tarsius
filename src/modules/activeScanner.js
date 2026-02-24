// loads and runs atack modules

import path from 'path';
import { logYellow, logGreen, logVerbose } from '../utils/log.js';

// all availble active atack modules
// each modul is lazy loaded when needed
const MODULE_MAP = {
    'xss': () => import('./modXss.js'),
    'sql': () => import('./modSql.js'),
    'exec': () => import('./modExec.js'),
    'file': () => import('./modFile.js'),
    'redirect': () => import('./modRedirect.js'),
    'ssrf': () => import('./modSsrf.js'),
    'crlf': () => import('./modCrlf.js'),
    'csrf': () => import('./modCsrf.js'),
    'xxe': () => import('./modXxe.js'),
    'ldap': () => import('./modLdap.js'),
    'timesql': () => import('./modTimesql.js'),
    'backup': () => import('./modBackup.js'),
    'buster': () => import('./modBuster.js'),
    'brute_login_form': () => import('./modBruteLoginForm.js'),
    'shellshock': () => import('./modShellshock.js'),
    'spring4shell': () => import('./modSpring4shell.js'),
    'log4shell': () => import('./modLog4shell.js'),
    'ssl': () => import('./modSsl.js'),
    'htaccess': () => import('./modHtaccess.js'),
    'methods': () => import('./modMethods.js'),
    'nikto': () => import('./modNikto.js'),
    'wapp': () => import('./modWapp.js'),
    'htp': () => import('./modHtp.js'),
    'upload': () => import('./modUpload.js'),
    'permanentxss': () => import('./modPermanentxss.js'),
    'takeover': () => import('./modTakeover.js'),
};

// default modul list - used when no specifc modules are requestd
const DEFAULT_MODULES = [
    'exec', 'file', 'sql', 'xss', 'ssrf', 'redirect',
    'permanentxss', 'upload', 'ssl',
];

export class ActiveScanner {
    // crawler = AsyncCrawler
    // persister = SqlPersister
    // attackOptions = { level, maxAttackTime, skippedParams, ... }
    // crawlerConfig = CrawlerConfiguration
    constructor(crawler, persister, attackOptions, crawlerConfig) {
        this.crawler = crawler;
        this.persister = persister;
        this.options = attackOptions;
        this.crawlerConfig = crawlerConfig;
    }

    // run all the atack modules
    async run(requests, moduleNames = null) {
        const modulesToRun = moduleNames || DEFAULT_MODULES;

        for (let i = 0; i < modulesToRun.length; i++) {
            const modName = modulesToRun[i];
            console.log(`[*] [Module ${i + 1}/${modulesToRun.length}] Launching ${modName}...`);

            try {
                const loader = MODULE_MAP[modName];
                if (!loader) {
                    logVerbose(`module "${modName}" not found, skipping`);
                    continue;
                }

                const mod = await loader();
                const ModClass = mod.default || mod[Object.keys(mod)[0]];

                if (!ModClass) {
                    logVerbose(`module "${modName}" has no export, skipping`);
                    continue;
                }

                const instance = new ModClass(
                    this.crawler,
                    this.persister,
                    this.options,
                    this.crawlerConfig
                );

                await instance.launch(requests);
            } catch (error) {
                // modul not found yet - thats ok, we'll add them gradully
                if (error.code === 'ERR_MODULE_NOT_FOUND') {
                    logVerbose(`module "${modName}" not implementd yet`);
                } else {
                    logVerbose(`error in module "${modName}": ${error.message}`);
                }
            }

            console.log('');
        }
    }

    // list all availble modules
    static listModules() {
        return Object.keys(MODULE_MAP);
    }
}
