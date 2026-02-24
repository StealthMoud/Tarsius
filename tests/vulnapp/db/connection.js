const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'vulndbuser',
    password: process.env.DB_PASS || 'vulnpassword',
    database: process.env.DB_NAME || 'vulnstore',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: true // enabled to allow stacked sqli attacks
});

// a simple retry logic because the node app might start before mysql is fully ready
async function executeQueryWithRetry(query, params = [], retries = 5, delayMs = 3000) {
    for (let i = 0; i < retries; i++) {
        try {
            const [rows, fields] = await pool.execute(query, params);
            return rows;
        } catch (error) {
            console.error(`Database query failed (${error.code}). Retrying in ${delayMs / 1000}s...`);
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
}

// separate function for strictly deliberately vulnerable queries that need direct string interpolation
async function executeVulnerableQueryWithRetry(query, retries = 5, delayMs = 3000) {
    for (let i = 0; i < retries; i++) {
        try {
            // using query instead of execute to allow non-prepared statements for sql injection
            const [rows, fields] = await pool.query(query);
            return rows;
        } catch (error) {
            console.error(`Vulnerable database query failed (${error.code}). Retrying in ${delayMs / 1000}s...`);
            if (i === retries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
}


module.exports = {
    pool,
    executeQueryWithRetry,
    executeVulnerableQueryWithRetry
};
