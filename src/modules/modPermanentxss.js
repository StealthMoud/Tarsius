// placeholder for permanent (stored) xss detecton

import { Attack } from './attack.js';

export default class ModPermanentxss extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'permanentxss';
    }

    async launch(requests) {
        const { logBlue } = await import('../utils/log.js');
        logBlue(`[*] [${this.moduleName}] Stored XSS detection requires deeply interlinked state tracking. Using placeholder implementation.`);
        // For now, we simply skip processing further as it's not fully implemented
        return;
    }

    async attack(request) {
        // intentionally empty
    }
}
