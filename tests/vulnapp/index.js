const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));

// Setup an in-memory SQL database for injection tests
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'supersecret123')");
    db.run("INSERT INTO users VALUES (2, 'john', 'password')");
});

// --- INDEX PAGE (Discovery ground for the crawler) ---
app.get('/', (req, res) => {
    // Set an insecure cookie for the passive scanner to detect
    res.cookie('session_id', '1234567890');

    res.send(`
        <html>
        <head><title>Vulnerable App Demo</title></head>
        <body>
            <h1>Welcome to the deliberately Vulnerable Test App</h1>
            <p>This app is designed to be scanned by Tarsius.</p>
            
            <h2>1. Cross-Site Scripting (XSS)</h2>
            <form action="/xss" method="GET">
                <input type="text" name="q" placeholder="Search..." />
                <button type="submit">Search</button>
            </form>

            <h2>2. SQL Injection (SQLi)</h2>
            <p>View user: <a href="/sqli?id=1">User 1</a> | <a href="/sqli?id=2">User 2</a></p>

            <h2>3. Command Injection (Exec)</h2>
            <form action="/exec" method="POST">
                <input type="text" name="ip" placeholder="8.8.8.8" />
                <button type="submit">Ping IP</button>
            </form>

            <h2>4. Local File Inclusion (LFI)</h2>
            <p>Load content: <a href="/file?page=about.txt">About</a></p>

            <h2>5. Open Redirect</h2>
            <p><a href="/redirect?url=https://example.com">Leave Site</a></p>

            <h2>6. Server-Side Request Forgery (SSRF)</h2>
            <form action="/ssrf" method="GET">
                <input type="text" name="url" placeholder="http://example.com" value="http://example.com" />
                <button type="submit">Fetch URL</button>
            </form>
            
            <h2>7. Weak Login & CSRF</h2>
            <form action="/login" method="POST">
                Username: <input type="text" name="username" /><br/>
                Password: <input type="password" name="password" /><br/>
                <button type="submit">Login</button>
            </form>

            <h2>8. XML External Entity (XXE)</h2>
            <form action="/xxe" method="POST" enctype="application/xml">
                <textarea name="xmlData" rows="5" cols="40">&lt;xml&gt;&lt;test&gt;data&lt;/test&gt;&lt;/xml&gt;</textarea><br/>
                <button type="submit">Send XML</button>
            </form>

            <h2>9. Unrestricted File Upload</h2>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="uploaded_file" />
                <button type="submit">Upload</button>
            </form>

            <h2>10. CRLF Injection (HTTP Response Splitting)</h2>
            <p>Test CRLF: <a href="/crlf?lang=en">Language Selection</a></p>

            <h2>11. Backup Files</h2>
            <p>Source is running at <code>/index.js</code>. The scanner will look for <code>/index.js.bak</code></p>
        </body>
        </html>
    `);
});

// A mock backup file route
app.get('/index.js.bak', (req, res) => {
    res.send('// This is a backup of the source code\\nconst express = require("express");');
});

// --- VULNERABLE ENDPOINTS ---

// 1. Reflected XSS
app.get('/xss', (req, res) => {
    const query = req.query.q || '';
    // intentionally no escaping
    res.send("<h1>Search Results for: " + query + "</h1><p>Nothing found.</p>");
});

// 2. ERROR-BASED SQL INJECTION
app.get('/sqli', (req, res) => {
    const id = req.query.id;
    if (!id) return res.send('Missing ID');

    // intentionally vulnerable to SQL syntax errors
    const query = "SELECT * FROM users WHERE id = " + id;
    db.get(query, (err, row) => {
        if (err) {
            // Leak the SQLite error directly into the response
            return res.status(500).send("SQLite Error: " + err.message);
        }
        res.send(row ? "User: " + row.username : 'User not found');
    });
});

// 3. O/S COMMAND INJECTION
app.post('/exec', (req, res) => {
    const ip = req.body.ip || '127.0.0.1';
    // deliberately concatenate user input into a shell command
    exec("ping -c 1 " + ip, (error, stdout, stderr) => {
        let output = stdout || stderr;
        if (error) output += "\\nError: " + error.message;
        res.send("<pre>" + output + "</pre>");
    });
});

// 4. LOCAL FILE INCLUSION (LFI)
app.get('/file', (req, res) => {
    const page = req.query.page || 'about.txt';
    try {
        // Warning: Very vulnerable! allows ../../../etc/passwd etc.
        const content = fs.readFileSync(page, 'utf8');
        res.send("<pre>" + content + "</pre>");
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// 5. OPEN REDIRECT
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    if (url) {
        // Open Redirect vulnerability
        res.redirect(url);
    } else {
        res.send('Missing URL');
    }
});

// 6. SERVER-SIDE REQUEST FORGERY (SSRF)
app.get('/ssrf', (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.send('Missing URL');

    try {
        http.get(targetUrl, (fetchRes) => {
            let data = '';
            fetchRes.on('data', chunk => data += chunk);
            fetchRes.on('end', () => res.send(data));
        }).on('error', err => res.status(500).send(err.message));
    } catch (e) {
        res.status(500).send('Invalid URL format');
    }
});

// 7. WEAK LOGIN / SQLi in POST
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // intentionally vulnerable POST endpoint
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    db.get(query, (err, row) => {
        if (err) {
            return res.status(500).send("SQLite Error: " + err.message);
        }
        if (row) {
            res.send("Welcome " + row.username + "!");
        } else {
            res.send("Login Failed - Incorrect Username or Password");
        }
    });
});

// 8. XXE (XML External Entity) Mock
app.post('/xxe', (req, res) => {
    let xmlData = '';
    req.on('data', chunk => xmlData += chunk.toString());
    req.on('end', () => {
        // If the payload contains typical XXE markers, simulate a successful exploitation
        if (xmlData.includes('ENTITY') && xmlData.includes('SYSTEM')) {
            return res.send("Parsed XML Output: root:x:0:0:root:/root:/bin/bash");
        }
        res.send("Parsed XML Output: " + xmlData);
    });
});

// 9. UNRESTRICTED FILE UPLOAD Mock
app.post('/upload', (req, res) => {
    // We just need to accept the multipart form
    res.send("File uploaded successfully.");
});

// 10. CRLF INJECTION
app.get('/crlf', (req, res) => {
    const lang = req.query.lang || 'en';

    // Node.js normally blocks HTTP response splitting. 
    // To make this explicitly vulnerable and demonstrable for Tarsius,
    // we hijack the raw socket to respond with the injected headers.
    if (lang.includes('%0d%0a') || lang.includes('\\r\\n')) {
        const decodedLang = decodeURIComponent(lang);
        const rawResponse =
            "HTTP/1.1 200 OK\\r\\n" +
            "Content-Type: text/html\\r\\n" +
            "X-Language: " + decodedLang + "\\r\\n" +
            "Connection: close\\r\\n\\r\\n" +
            "<h1>Language selected</h1>";

        req.socket.write(rawResponse);
        req.socket.end();
    } else {
        res.set('X-Language', lang);
        res.send("<h1>Language selected: " + lang + "</h1>");
    }
});

app.listen(port, () => {
    console.log("Vulnerable Test App listening on port " + port);
});
