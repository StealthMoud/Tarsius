const express = require('express');
const router = express.Router();
const db = require('../db/connection');

// show login page
router.get('/login', (req, res) => {
    res.render('auth/login');
});

// login logic (sql injection in post - auth bypass)
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // intentionally vulnerable string interpolation for auth bypass using ' or 1=1--
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

    try {
        const users = await db.executeVulnerableQueryWithRetry(query);

        if (users.length > 0) {
            req.session.user = users[0];
            res.redirect('/');
        } else {
            res.render('auth/login', { error: 'invalid credentials' });
        }
    } catch (e) {
        // returning generic database error on login screen
        res.status(500).send(`database error: ${e.message}`);
    }
});

// logout
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

module.exports = router;
