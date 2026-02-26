const express = require('express');
const router = express.Router();
const http = require('http');
const db = require('../db/connection');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// configure multer for vulnerable unrestricted file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, '../public/uploads/');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath)
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname) // implicitly trusting user input
    }
});
const upload = multer({ storage: storage });

// idor endpoint (insecure direct object reference)
router.get('/messages/:id', async (req, res) => {
    // missing auth check! anyone can read any user's profile description
    const id = req.params.id;
    try {
        const query = 'SELECT username, profile_desc FROM users WHERE id = ?';
        const users = await db.executeQueryWithRetry(query, [id]);
        if (users.length === 0) return res.status(404).send('user not found');
        res.json(users[0]);
    } catch (e) {
        res.status(500).send('error retrieving message');
    }
});

// ssrf endpoint (fetching external avatar mapping)
router.get('/avatar/fetch', (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).send('missing url');

    try {
        http.get(targetUrl, (fetchRes) => {
            let data = '';
            fetchRes.on('data', chunk => data += chunk);
            fetchRes.on('end', () => res.send(data));
        }).on('error', err => res.status(500).send(err.message));
    } catch (e) {
        res.status(500).send('invalid url format');
    }
});

// unrestricted file upload (lfi to rce vector)
router.post('/upload', upload.single('profile_pic'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('no file uploaded.');
    }
    res.send(`file uploaded successfully to /uploads/${req.file.originalname}`);
});

// local file inclusion (lfi)
router.get('/file', (req, res) => {
    const page = req.query.page || 'about.txt';
    try {
        // very vulnerable! allows ../../../etc/passwd etc.
        const content = fs.readFileSync(path.join(__dirname, '../public/', page), 'utf8');
        res.send("<pre>" + content + "</pre>");
    } catch (err) {
        res.status(500).send(err.message);
    }
});

module.exports = router;
