// ini payload parser - reads atack payloads from .ini files
// these files contain the actual strings we send to find vulnerabiltys
// format is like: [sectionName]\npayload\npayload\n

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

        // otherwise its a payload line
        if (!sections[currentSection]) {
            sections[currentSection] = [];
        }
        sections[currentSection].push(trimmed);
    }

    return sections;
}

// get the path to a payload file in the data directry
export function getPayloadPath(filename) {
    return path.join(
        path.dirname(new URL(import.meta.url).pathname),
        '..',
        'data',
        'attacks',
        filename
    );
}
