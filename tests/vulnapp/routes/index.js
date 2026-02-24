const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    res.render('index', {
        title: 'Welcome to VulnStore',
        message: 'The vulnerable e-commerce platform.'
    });
});

// mock backup file
router.get('/app.js.bak', (req, res) => {
    res.send('// backup source: const express = require("express");');
});

// open redirect profile action
router.get('/profile/redirect', (req, res) => {
    const target = req.query.url;
    if (target) {
        res.redirect(target);
    } else {
        res.status(400).send('Missing redirect URL parameter');
    }
});

// crlf injection on language set
router.get('/lang', (req, res) => {
    const lang = req.query.set || 'en';

    // simulate crlf vulnerability manually since express sanitizes by default
    if (lang.includes('%0d%0a') || lang.includes('\\r\\n')) {
        const decodedLang = decodeURIComponent(lang);
        const rawResponse =
            "HTTP/1.1 200 OK\\r\\n" +
            "Content-Type: text/html\\r\\n" +
            "Set-Cookie: language=" + decodedLang + "\\r\\n" +
            "Connection: close\\r\\n\\r\\n" +
            "<h1>Language Preference Saved</h1>";

        req.socket.write(rawResponse);
        req.socket.end();
    } else {
        res.cookie('language', lang);
        res.send(`<h1>Language selected: ${lang}</h1><a href="/">Go back</a>`);
    }
});

module.exports = router;
