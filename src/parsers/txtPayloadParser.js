// txt payload parser - reads atack payloads from plain text files
// one payload per line, ignores comments and empty lines

import fs from 'fs';
import path from 'path';

// parse a txt payload file - returns array of strings
export function parseTxtPayloads(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const payloads = [];

    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            payloads.push(trimmed);
        }
    }

    return payloads;
}

// get the path to a payload file
export function getPayloadPath(filename) {
    return path.join(
        path.dirname(new URL(import.meta.url).pathname),
        '..', '..',
        'data',
        'attacks',
        filename
    );
}
