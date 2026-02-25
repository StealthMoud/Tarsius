const express = require('express');
const router = express.Router();
const db = require('../db/connection');
const { exec } = require('child_process');

// catalog endpoint (union-based sql injection)
router.get('/', async (req, res) => {
    let search = req.query.search || '';

    // intentionally vulnerable string concatenation for union/error sqli
    const query = "SELECT * FROM products WHERE name LIKE '%" + search + "%'";

    try {
        const products = await db.executeVulnerableQueryWithRetry(query);
        res.render('products/index', { products, search });
    } catch (e) {
        // echo database error for error-based sqli detection
        res.status(500).send(`SQL Error: ${e.message}`);
    }
});

// product detail endpoint with blind sqli and reflected xss
router.get('/:id', async (req, res) => {
    const id = req.params.id;
    const preview = req.query.preview || '';

    // using simple interpolation to trigger time-based blind sqli if sleep() is injected
    const query = "SELECT * FROM products WHERE id = " + id;

    try {
        const products = await db.executeVulnerableQueryWithRetry(query);
        if (products.length === 0) return res.status(404).send('Product not found');

        res.render('products/detail', { product: products[0], preview });
    } catch (e) {
        // generic error catching for blind sqli
        res.status(500).send('An unexpected error occurred processing your request.');
    }
});

// command injection (mock product stock refresh)
router.post('/:id/refresh-stock', (req, res) => {
    const serverIp = req.body.ip || '127.0.0.1';

    // vulnerable os execution
    exec("ping -c 1 " + serverIp, (error, stdout, stderr) => {
        let output = stdout || stderr;
        if (error) output += "\\nProcess Error: " + error.message;
        res.send("<pre>Stock Server Ping:\\n" + output + "</pre>");
    });
});

module.exports = router;
