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
            
            <h2>7. Weak Login</h2>
            <form action="/login" method="POST">
                Username: <input type="text" name="username" /><br/>
                Password: <input type="password" name="password" /><br/>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    `);
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

app.listen(port, () => {
    console.log("Vulnerable Test App listening on port " + port);
});
