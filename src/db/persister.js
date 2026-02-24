// sqlite storage for scan state

import Database from 'better-sqlite3';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { Request } from '../http/request.js';

const HOME_DIR = os.homedir();
const BASE_DIR = path.join(HOME_DIR, '.tarsius');
const CRAWLER_DATA_DIR = path.join(BASE_DIR, 'scans');
const CONFIG_DIR = path.join(BASE_DIR, 'config');

export class SqlPersister {
    // output_file = path to the sqlite databse file
    constructor(outputFile) {
        this.outputFile = outputFile;

        // make sure the directry exists
        const dir = path.dirname(outputFile);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        this.db = new Database(outputFile);
        this.db.pragma('journal_mode = WAL'); // faster writes
        this._createTables();
    }

    // setup the databse tables if they dont exist yet
    _createTables() {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scan_infos (
                key TEXT NOT NULL,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS paths (
                path_id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                enctype TEXT NOT NULL DEFAULT 'application/x-www-form-urlencoded',
                depth INTEGER NOT NULL DEFAULT 0,
                encoding TEXT,
                headers TEXT,
                referer TEXT,
                evil INTEGER NOT NULL DEFAULT 0,
                response_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS params (
                param_id INTEGER PRIMARY KEY,
                path_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                position INTEGER NOT NULL,
                name TEXT NOT NULL,
                value1 TEXT,
                value2 TEXT,
                meta TEXT,
                FOREIGN KEY (path_id) REFERENCES paths(path_id)
            );

            CREATE TABLE IF NOT EXISTS payloads (
                evil_path_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                category TEXT NOT NULL,
                level INTEGER NOT NULL DEFAULT 0,
                parameter TEXT,
                info TEXT,
                type TEXT,
                wstg TEXT,
                response_id INTEGER,
                FOREIGN KEY (evil_path_id) REFERENCES paths(path_id)
            );

            CREATE TABLE IF NOT EXISTS responses (
                response_id INTEGER PRIMARY KEY,
                status_code INTEGER,
                headers TEXT,
                body TEXT
            );

            CREATE TABLE IF NOT EXISTS attack_log (
                path_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                parameter TEXT,
                FOREIGN KEY (path_id) REFERENCES paths(path_id)
            );
        `);
    }

    // save a url we discoverd during crawling
    addUrl(request, response = null) {
        const stmt = this.db.prepare(`
            INSERT INTO paths (path, method, enctype, depth, referer, evil)
            VALUES (?, ?, ?, ?, ?, 0)
        `);

        const result = stmt.run(
            request.path,
            request.method,
            request.enctype,
            request.linkDepth,
            request.referer
        );

        const pathId = result.lastInsertRowid;

        // save get paramters
        this._saveParams(pathId, 'GET', request.getParams);

        // save post paramters
        if (request.postParams && typeof request.postParams !== 'string') {
            this._saveParams(pathId, 'POST', request.postParams);
        }

        // save file paramters
        if (request.fileParams) {
            this._saveParams(pathId, 'FILE', request.fileParams);
        }

        return pathId;
    }

    // save paramters for a path
    _saveParams(pathId, type, params) {
        if (!params || params.length === 0) return;

        const stmt = this.db.prepare(`
            INSERT INTO params (path_id, type, position, name, value1)
            VALUES (?, ?, ?, ?, ?)
        `);

        const insertMany = this.db.transaction((items) => {
            for (let i = 0; i < items.length; i++) {
                stmt.run(pathId, type, i, items[i][0], items[i][1]);
            }
        });

        insertMany(params);
    }

    // get all the urls we've craweld so far
    getCrawledUrls() {
        const rows = this.db.prepare(`
            SELECT path_id, path, method, enctype, depth, referer
            FROM paths WHERE evil = 0
        `).all();

        return rows.map(row => {
            const request = new Request(row.path, {
                method: row.method,
                enctype: row.enctype,
                linkDepth: row.depth,
                referer: row.referer || '',
            });
            request.pathId = row.path_id;

            // load paramters
            const params = this.db.prepare(`
                SELECT type, name, value1 FROM params
                WHERE path_id = ? ORDER BY position
            `).all(row.path_id);

            const getParams = [];
            const postParams = [];
            for (const p of params) {
                if (p.type === 'GET') getParams.push([p.name, p.value1]);
                else if (p.type === 'POST') postParams.push([p.name, p.value1]);
            }
            if (getParams.length) request.getParams = getParams;
            if (postParams.length) request.postParams = postParams;

            return request;
        });
    }

    // save a vulnerability finding
    saveVulnerability(pathId, module, category, level, parameter, info, type, wstg, responseId = null) {
        this.db.prepare(`
            INSERT INTO payloads (evil_path_id, module, category, level, parameter, info, type, wstg, response_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(pathId, module, category, level, parameter, info, type, wstg, responseId);
    }

    // check if we already atacked this url with this module
    hasBeenAttacked(pathId, module) {
        const row = this.db.prepare(`
            SELECT COUNT(*) as cnt FROM attack_log
            WHERE path_id = ? AND module = ?
        `).get(pathId, module);
        return row.cnt > 0;
    }

    // mark a url as atacked by a module
    markAsAttacked(pathId, module, parameter = null) {
        this.db.prepare(`
            INSERT INTO attack_log (path_id, module, parameter)
            VALUES (?, ?, ?)
        `).run(pathId, module, parameter);
    }

    // save a respnse for detailed reporting
    saveResponse(statusCode, headers, body) {
        const result = this.db.prepare(`
            INSERT INTO responses (status_code, headers, body)
            VALUES (?, ?, ?)
        `).run(statusCode, JSON.stringify(headers), body);
        return result.lastInsertRowid;
    }

    // get all vulns found durring the scan
    getVulnerabilities() {
        return this.db.prepare(`
            SELECT p.path, p.method, pl.module, pl.category, pl.level,
                   pl.parameter, pl.info, pl.type, pl.wstg
            FROM payloads pl
            JOIN paths p ON pl.evil_path_id = p.path_id
        `).all();
    }

    // set a scan info value like the root url
    setScanInfo(key, value) {
        // delete old one first
        this.db.prepare('DELETE FROM scan_infos WHERE key = ?').run(key);
        this.db.prepare('INSERT INTO scan_infos (key, value) VALUES (?, ?)').run(key, value);
    }

    // get a scan info value
    getScanInfo(key) {
        const row = this.db.prepare('SELECT value FROM scan_infos WHERE key = ?').get(key);
        return row ? row.value : null;
    }

    // flush all atack data but keep crawled urls
    flushAttacks() {
        this.db.exec('DELETE FROM payloads; DELETE FROM attack_log; DELETE FROM responses;');
    }

    // flush evrything - start fresh
    flushSession() {
        this.db.exec('DELETE FROM paths; DELETE FROM params; DELETE FROM payloads; DELETE FROM attack_log; DELETE FROM responses; DELETE FROM scan_infos;');
    }

    // count how many urls we have
    getUrlCount() {
        const row = this.db.prepare('SELECT COUNT(*) as cnt FROM paths WHERE evil = 0').get();
        return row.cnt;
    }

    // close the databse cleanly
    close() {
        this.db.close();
    }

    // get the default storage directry
    static getDefaultDir(subdirName = 'scans') {
        const dir = subdirName === 'config' ? CONFIG_DIR : CRAWLER_DATA_DIR;
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        return dir;
    }
}
