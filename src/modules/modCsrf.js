// csrf token detecton

import { Attack } from './attack.js';

export default class ModCsrf extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'csrf';
    }

    async attack(request) {
        // only check POST forms
        if (request.method !== 'POST') return;
        if (!request.postParams || request.postParams.length === 0) return;

        // check if any paramter looks like a csrf token
        const csrfNames = ['csrf', 'token', '_token', 'csrftoken', 'csrf_token',
            'xsrf', '_csrf', 'authenticity_token', 'anti-csrf', '__requestverificationtoken'];

        const hasToken = request.postParams.some(([name]) =>
            csrfNames.some(csrfName => name.toLowerCase().includes(csrfName))
        );

        if (!hasToken) {
            this.logVulnerability(
                'Cross Site Request Forgery',
                request,
                `Form at ${request.url} has no CSRF protecton`,
                '',
                'WSTG-SESS-05'
            );
        }
    }
}
