const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const db = require('./db/connection');

const app = express();
const port = process.env.PORT || 3000;

// setup middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'super-secret-vuln-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // insecure cookie for tarsius anomalies check
}));

// setup templating engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// serve static files
app.use(express.static(path.join(__dirname, 'public')));

// global middleware to pass session info to views
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

// import routes
const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');
const apiRoutes = require('./routes/api');

// mount routes
app.use('/', indexRoutes);
app.use('/auth', authRoutes);
app.use('/products', productRoutes);
app.use('/api', apiRoutes);

// error handling middleware (missing error page, leaks stack trace)
app.use((err, req, res, next) => {
    res.status(500).send(`<pre>Internal Server Error: ${err.stack}</pre>`);
});

// start the server
app.listen(port, () => {
    console.log(`VulnStore (Dockerized) listening at http://localhost:${port}`);
});
