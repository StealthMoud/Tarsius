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

// product detail endpoint with blind sqli and stored comments (stored xss)
router.get('/:id', async (req, res) => {
    const id = req.params.id;

    // using simple interpolation to trigger time-based blind sqli if sleep() is injected
    const query = "SELECT * FROM products WHERE id = " + id;

    try {
        const products = await db.executeVulnerableQueryWithRetry(query);
        if (products.length === 0) return res.status(404).send('Product not found');

        // fetch comments for stored xss demonstration
        const commentsQuery = `SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.product_id = ? ORDER BY c.created_at DESC`;
        const comments = await db.executeQueryWithRetry(commentsQuery, [id]);

        res.render('products/detail', { product: products[0], comments });
    } catch (e) {
        // generic error catching for blind sqli
        res.status(500).send('An unexpected error occurred processing your request.');
    }
});

// stored xss endpoint (adding comments)
router.post('/:id/comments', async (req, res) => {
    const id = req.params.id;
    const { comment } = req.body;
    const userId = req.session.user ? req.session.user.id : 2; // default to 'john' if not logged in

    if (!comment) return res.redirect(`/products/${id}`);

    try {
        // intentionally missing html sanitization to allow stored xss
        await db.executeQueryWithRetry("INSERT INTO comments (product_id, user_id, comment) VALUES (?, ?, ?)", [id, userId, comment]);
        res.redirect(`/products/${id}`);
    } catch (e) {
        res.status(500).send(`Failed to add comment. Error: ${e.message}`);
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
