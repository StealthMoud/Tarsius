// reads payloads from .ini files

import fs from 'fs';
import path from 'path';

// parse an ini-style payload file
// returns { sectionName: [payload1, payload2, ...] }
export function parseIniPayloads(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const sections = {};
    let currentSection = 'default';

    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        // check for secton header like [xss_reflected]
        const sectionMatch = trimmed.match(/^\[(.+)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1];
            if (!sections[currentSection]) {
                sections[currentSection] = [];
            }
            continue;
        }

        // otherwise we only care about the actual payload values
        // wfuzz format uses:
        // payload = <the payload string>
        // rules = <matching rule>
        // we must ignore rules and messages
        if (trimmed.startsWith('payload = ')) {
            const payloadValue = trimmed.substring(10).trim();
            if (payloadValue === '__TARSIUS_IGNORE_VALUE__') continue;

            if (!sections[currentSection]) {
                sections[currentSection] = [];
            }
            sections[currentSection].push(payloadValue);
        }
    }

    return sections;
}

// get the path to a payload file in the data directry
export function getPayloadPath(filename) {
    return path.join(
        path.dirname(new URL(import.meta.url).pathname),
        '..', '..',
        'data',
        'attacks',
        filename
    );
}
