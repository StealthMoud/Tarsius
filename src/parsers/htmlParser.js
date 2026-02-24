// html parser - extracts links, forms, and other intresting stuff from html pages
// uses cherio (jquery-like) for parsing instead of regex

import * as cheerio from 'cheerio';
import { makeAbsolute } from '../http/request.js';

export class Html {
    // url = the page url (for makeing relative links absolute)
    // html = the raw html string
    constructor(url, html) {
        this._url = url;
        this._html = html || '';
        this._$ = cheerio.load(this._html);
    }

    // get all links from the page
    // returns a set of absolute urls
    getLinks() {
        const links = new Set();
        const $ = this._$;

        // regular links
        $('a[href]').each((_, el) => {
            const href = $(el).attr('href');
            if (href) {
                const abs = makeAbsolute(this._url, href);
                if (abs && (abs.startsWith('http://') || abs.startsWith('https://'))) {
                    links.add(abs.split('#')[0]);
                }
            }
        });

        // script sources
        $('script[src]').each((_, el) => {
            const src = $(el).attr('src');
            if (src) {
                const abs = makeAbsolute(this._url, src);
                if (abs) links.add(abs);
            }
        });

        // css links
        $('link[href]').each((_, el) => {
            const href = $(el).attr('href');
            if (href) {
                const abs = makeAbsolute(this._url, href);
                if (abs) links.add(abs);
            }
        });

        // iframes
        $('iframe[src]').each((_, el) => {
            const src = $(el).attr('src');
            if (src) {
                const abs = makeAbsolute(this._url, src);
                if (abs) links.add(abs);
            }
        });

        return links;
    }

    // get all forms from the page
    // returns array of form objects with action, method, inputs, enctype
    getForms() {
        const forms = [];
        const $ = this._$;

        $('form').each((_, formEl) => {
            const action = $(formEl).attr('action') || '';
            const method = ($(formEl).attr('method') || 'GET').toUpperCase();
            const enctype = $(formEl).attr('enctype') || 'application/x-www-form-urlencoded';
            const absAction = makeAbsolute(this._url, action) || this._url;

            const inputs = [];

            // get all input fields
            $(formEl).find('input, textarea, select').each((_, inputEl) => {
                const name = $(inputEl).attr('name');
                if (!name) return;

                const type = ($(inputEl).attr('type') || 'text').toLowerCase();
                let value = $(inputEl).attr('value') || '';

                // for select elements grab the first option
                if (inputEl.tagName === 'select') {
                    const firstOption = $(inputEl).find('option[selected]').first();
                    value = firstOption.attr('value') || firstOption.text() || '';
                }

                // for textareas grab the content
                if (inputEl.tagName === 'textarea') {
                    value = $(inputEl).text() || '';
                }

                inputs.push({
                    name,
                    value,
                    type,
                    tag: inputEl.tagName,
                });
            });

            forms.push({
                action: absAction,
                method,
                enctype,
                inputs,
                referer: this._url,
            });
        });

        return forms;
    }

    // get the page title
    getTitle() {
        return this._$('title').text().trim() || '';
    }

    // get meta tags
    getMetaTags() {
        const metas = {};
        this._$('meta').each((_, el) => {
            const name = this._$(el).attr('name') || this._$(el).attr('property') || '';
            const content = this._$(el).attr('content') || '';
            if (name) metas[name] = content;
        });
        return metas;
    }

    // check if the page has a base href tag
    getBaseHref() {
        const base = this._$('base').attr('href');
        return base ? makeAbsolute(this._url, base) : null;
    }

    // get all comments in the html
    getComments() {
        const comments = [];
        this._$('*').contents().each((_, node) => {
            if (node.type === 'comment') {
                comments.push(node.data.trim());
            }
        });
        return comments;
    }

    // find password fields in the page
    hasPasswordField() {
        return this._$('input[type="password"]').length > 0;
    }

    // check if the page looks like a login form
    isLoginPage() {
        return this.hasPasswordField() && this._$('form').length > 0;
    }
}
