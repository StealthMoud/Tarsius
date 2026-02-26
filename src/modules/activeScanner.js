// loads and runs atack modules

import path from 'path';
import { logYellow, logRed, logGreen, logVerbose } from '../utils/log.js';

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
    'nuclei': () => import('./modNuclei.js'), // External Docker Tool
};

// default modul list - used when no specifc modules are requestd
// we explicitly exclude 'nuclei' from the default list so it only runs when enabled
const DEFAULT_MODULES = Object.keys(MODULE_MAP).filter(mod => mod !== 'nuclei');

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

    // run all the atack modules - now with inter-modul concurency!
    async run(requests, moduleNames = null) {
        const { pMap } = await import('../utils/concurrency.js');
        let modulesToRun = moduleNames || DEFAULT_MODULES;

        // If external tools are enabled, safely add nuclei if it isn't already requested
        if (this.options.enableExternalTools && !modulesToRun.includes('nuclei')) {
            modulesToRun = [...modulesToRun, 'nuclei'];
        }
        let totalVulns = 0;

        logYellow(`[*] Attacking ${requests.length} URLs with ${modulesToRun.length} modules (parallel execution)`);
        console.log('');

        // run up to 3 modules at a time
        await pMap(modulesToRun, async (modName, i) => {
            const modStart = Date.now();
            const modIndex = i + 1;

            try {
                const loader = MODULE_MAP[modName];
                if (!loader) return;

                const mod = await loader();
                const ModClass = mod.default || mod[Object.keys(mod)[0]];
                if (!ModClass) return;

                const instance = new ModClass(
                    this.crawler,
                    this.persister,
                    { ...this.options, silentProgress: true },
                    this.crawlerConfig
                );

                console.log(`[*] [${modIndex}/${modulesToRun.length}] Starting ${modName}...`);

                // each module handles its own internal concurency
                await instance.launch(requests);

                const elapsed = ((Date.now() - modStart) / 1000).toFixed(1);
                if (instance._foundVulns > 0) {
                    totalVulns += instance._foundVulns;
                    logRed(`[!] [${modIndex}/${modulesToRun.length}] ${modName}: ${instance._foundVulns} issue(s) (${elapsed}s)`);
                } else {
                    console.log(`[*] [${modIndex}/${modulesToRun.length}] ${modName}: clean (${elapsed}s)`);
                }
            } catch (error) {
                if (error.code === 'ERR_MODULE_NOT_FOUND') {
                    console.log(`[*] [${modIndex}/${modulesToRun.length}] ${modName}: skipped (not implemented)`);
                } else {
                    logVerbose(`[*] [${modIndex}/${modulesToRun.length}] ${modName}: error - ${error.message}`);
                }
            }
        }, 3);

        console.log('');
        return totalVulns;
    }

    // list all availble modules
    static listModules() {
        return Object.keys(MODULE_MAP);
    }
}
