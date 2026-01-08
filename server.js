const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const axios = require('axios');
const nunjucks = require('nunjucks');
const { v4: uuidv4 } = require('uuid');

const app = express();
const ROOT = __dirname;
const STATIC_DIR = path.join(ROOT, 'static');
const UPLOAD_FOLDER = path.join(STATIC_DIR, 'uploads');
const PRODUCTS_FILE = path.join(ROOT, 'products.json');
const ORDERS_FILE = path.join(ROOT, 'orders.json');
const CALL_LOG = path.join(ROOT, 'call_log.txt');
const REQ_FILE = path.join(ROOT, 'requirements.txt');

fs.mkdirSync(UPLOAD_FOLDER, { recursive: true });

// Templates via Nunjucks (Jinja-like syntax) so existing templates mostly work
nunjucks.configure(path.join(ROOT, 'templates'), {
    autoescape: true,
    express: app
});

app.use(express.static(STATIC_DIR));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

const SESSION_SECRET = process.env.FLASK_SECRET || 'change-this-default-secret';
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));

// DB (better-sqlite3 synchronous for simplicity)
const dbPath = path.join(ROOT, 'users.db');
const db = new Database(dbPath);

function initDb() {
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    phone TEXT,
    password_hash TEXT NOT NULL,
    created_at TEXT,
    balance REAL DEFAULT 0
  )`).run();
}
initDb();

// Password helpers compatible with Werkzeug's PBKDF2 format
function generatePasswordHash(password) {
    const iterations = 260000;
    const salt = crypto.randomBytes(16).toString('hex');
    const keylen = 32;
    const derived = crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256');
    return `pbkdf2:sha256:${iterations}$${salt}$${derived.toString('hex')}`;
}

function verifyPasswordHash(password, stored) {
    if (!stored) return false;
    if (stored.startsWith('pbkdf2:')) {
        // format: pbkdf2:sha256:260000$<salt>$<hex>
        try {
            const parts = stored.split('$');
            const meta = parts[0];
            const salt = parts[1];
            const hash = parts[2];
            const metaParts = meta.split(':');
            const iterations = parseInt(metaParts[2], 10) || 260000;
            const keylen = Buffer.from(hash, 'hex').length;
            const derived = crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha256');
            return derived.toString('hex') === hash;
        } catch (e) {
            return false;
        }
    }
    // fallback: plain equality (not secure)
    return false;
}

// Utility functions
function loadProductsMap() {
    try {
        if (fs.existsSync(PRODUCTS_FILE)) {
            const arr = JSON.parse(fs.readFileSync(PRODUCTS_FILE, 'utf8')) || [];
            const map = {};
            arr.forEach(p => map[p.id] = p);
            return { arr, map };
        }
    } catch (e) { }
    return { arr: [], map: {} };
}

function saveProducts(arr) {
    try {
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
    } catch (e) { }
}

function loadOrders() {
    try {
        if (fs.existsSync(ORDERS_FILE)) {
            return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')) || [];
        }
    } catch (e) { }
    return [];
}

function saveOrders(orders) {
    try { fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2), 'utf8'); } catch (e) { }
}

// File upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_FOLDER),
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// Routes
app.get('/', (req, res) => {
    const { arr: products } = loadProductsMap();
    let user_balance = null;
    try {
        if (req.session.user_id) {
            const row = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.session.user_id);
            if (row) user_balance = Number(row.balance || 0);
        }
    } catch (e) { }
    res.render('index.html', { products, user_balance });
});

app.get('/home', (req, res) => res.render('home.html'));

app.get('/call', (req, res) => {
    try { fs.appendFileSync(CALL_LOG, `${new Date().toISOString()} - ${req.ip}\n`); } catch (e) { }
    const CALL_NUMBER = process.env.CALL_NUMBER || '254112402377';
    res.redirect(`tel:${CALL_NUMBER}`);
});

function checkAdminAuth(req, res) {
    if (req.session && req.session.admin_authenticated) return true;
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Basic ')) return false;
    const b = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const parts = b.split(':');
    const password = parts.slice(1).join(':');
    const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || (process.env.ADMIN_PASSWORD ? generatePasswordHash(process.env.ADMIN_PASSWORD) : generatePasswordHash('Peaceking'));
    if (verifyPasswordHash(password, ADMIN_PASSWORD_HASH)) return true;
    return false;
}

app.get('/admin', (req, res) => {
    if (!checkAdminAuth(req, res)) return res.status(401).set('WWW-Authenticate', 'Basic realm="Admin Area"').send('');
    const logs = fs.existsSync(CALL_LOG) ? fs.readFileSync(CALL_LOG, 'utf8').split('\n').filter(Boolean) : [];
    const { arr: products } = loadProductsMap();
    res.render('admin.html', { logs, products });
});

app.post('/admin/upload', upload.single('image'), (req, res) => {
    if (!checkAdminAuth(req, res)) return res.status(401).set('WWW-Authenticate', 'Basic realm="Admin Area"').send('');
    const name = (req.body.name || '').trim();
    const price = (req.body.price || '').trim();
    const stock = parseInt(req.body.stock || '0') || 0;
    const description = (req.body.description || '').trim();
    const image = req.file ? path.basename(req.file.path) : null;
    if (!name || !price) return res.redirect('/admin');
    const { arr: products } = loadProductsMap();
    const product = { id: uuidv4().replace(/-/g, ''), name, price: isNaN(Number(price)) ? price : Number(price), stock, description, image, created_at: new Date().toISOString() };
    products.unshift(product);
    saveProducts(products);
    res.redirect('/admin');
});

app.post('/admin/delete/:prod_id', (req, res) => {
    if (!checkAdminAuth(req, res)) return res.status(401).set('WWW-Authenticate', 'Basic realm="Admin Area"').send('');
    const prod_id = req.params.prod_id;
    const { arr: products } = loadProductsMap();
    const remaining = products.filter(p => p.id !== prod_id);
    const removed = products.find(p => p.id === prod_id);
    if (removed && removed.image) {
        try { fs.unlinkSync(path.join(UPLOAD_FOLDER, removed.image)); } catch (e) { }
    }
    saveProducts(remaining);
    res.redirect('/admin');
});

app.get('/cart', (req, res) => {
    const cart = req.session.cart || {};
    const { arr: products } = loadProductsMap();
    const productMap = {};
    products.forEach(p => productMap[p.id] = p);
    const items = [];
    let total = 0.0;
    for (const pid in cart) {
        const qty = cart[pid];
        const prod = productMap[pid];
        if (!prod) continue;
        const price = Number(prod.price || 0);
        const subtotal = price * qty;
        items.push({ product: prod, qty, subtotal });
        total += subtotal;
    }
    res.render('cart.html', { items, total });
});

app.post('/cart/add/:prod_id', (req, res) => {
    const prod_id = req.params.prod_id;
    let qty = parseInt(req.body.qty || '1') || 1;
    const { arr: products } = loadProductsMap();
    const productMap = {};
    products.forEach(p => productMap[p.id] = p);
    const prod = productMap[prod_id];
    if (!prod) return res.redirect('/');
    const stock = parseInt(prod.stock || 0) || 0;
    const cart = req.session.cart || {};
    const current = cart[prod_id] || 0;
    if (current + qty > stock) return res.redirect('/');
    cart[prod_id] = current + qty;
    req.session.cart = cart;
    res.redirect('/');
});

app.post('/cart/update/:prod_id', (req, res) => {
    const prod_id = req.params.prod_id;
    let qty = parseInt(req.body.qty || '0') || 0;
    const { arr: products } = loadProductsMap();
    const productMap = {};
    products.forEach(p => productMap[p.id] = p);
    const prod = productMap[prod_id];
    if (!prod) return res.redirect('/cart');
    const stock = parseInt(prod.stock || 0) || 0;
    if (qty < 0) qty = 0;
    if (qty > stock) qty = stock;
    const cart = req.session.cart || {};
    if (qty === 0) delete cart[prod_id]; else cart[prod_id] = qty;
    req.session.cart = cart;
    res.redirect('/cart');
});

app.post('/cart/remove/:prod_id', (req, res) => {
    const prod_id = req.params.prod_id;
    const cart = req.session.cart || {};
    delete cart[prod_id];
    req.session.cart = cart;
    res.redirect('/cart');
});

app.post('/cart/inc/:prod_id', (req, res) => {
    const prod_id = req.params.prod_id;
    const cart = req.session.cart || {};
    let qty = (cart[prod_id] || 0) + 1;
    const { arr: products } = loadProductsMap();
    const productMap = {};
    products.forEach(p => productMap[p.id] = p);
    const prod = productMap[prod_id];
    if (!prod) return res.redirect('/cart');
    const stock = parseInt(prod.stock || 0) || 0;
    if (qty > stock) qty = stock;
    cart[prod_id] = qty;
    req.session.cart = cart;
    res.redirect('/cart');
});

app.post('/cart/dec/:prod_id', (req, res) => {
    const prod_id = req.params.prod_id;
    const cart = req.session.cart || {};
    let qty = (cart[prod_id] || 0) - 1;
    if (qty <= 0) delete cart[prod_id]; else cart[prod_id] = qty;
    req.session.cart = cart;
    res.redirect('/cart');
});

app.get('/register', (req, res) => res.render('register.html'));
app.post('/register', (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const phone = (req.body.phone || '').trim();
    const password = req.body.password || '';
    if (!email || !password) return res.redirect('/register');
    const pw_hash = generatePasswordHash(password);
    try {
        db.prepare('INSERT INTO users (email, phone, password_hash, created_at, balance) VALUES (?, ?, ?, ?, ?)').run(email, phone, pw_hash, new Date().toISOString(), 0.0);
        return res.redirect('/');
    } catch (e) {
        return res.redirect('/register');
    }
});

app.post('/login', (req, res) => {
    const identifier = (req.body.identifier || '').trim();
    const password = req.body.password || '';
    if (!identifier || !password) return res.redirect('/');
    let row = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(identifier.toLowerCase());
    if (!row) row = db.prepare('SELECT * FROM users WHERE phone = ?').get(identifier);
    if (!row) return res.redirect('/');
    if (!verifyPasswordHash(password, row.password_hash)) return res.redirect('/');
    req.session.user_id = row.id;
    req.session.user_email = row.email;
    res.redirect('/');
});

app.get('/logout', (req, res) => { req.session.user_id = null; req.session.user_email = null; res.redirect('/'); });

app.get('/profile', (req, res) => {
    if (!req.session.user_id) return res.redirect('/');
    const uid = req.session.user_id;
    const user = db.prepare('SELECT id, email, phone, balance FROM users WHERE id = ?').get(uid) || { email: req.session.user_email };
    const orders = loadOrders().filter(o => String(o.user_id) === String(uid));
    res.render('profile.html', { user, orders });
});

app.post('/checkout', (req, res) => {
    const cart = req.session.cart || {};
    if (!Object.keys(cart).length) return res.redirect('/cart');
    if (!req.session.user_id) return res.redirect('/');
    const { arr: products } = loadProductsMap();
    const prodMap = {};
    products.forEach(p => prodMap[p.id] = p);
    for (const pid in cart) {
        const p = prodMap[pid];
        if (!p || cart[pid] > (p.stock || 0)) return res.redirect('/cart');
    }
    let total = 0.0; const order_items = [];
    for (const pid in cart) {
        const p = prodMap[pid];
        const qty = cart[pid];
        const price = Number(p.price || 0);
        const subtotal = price * qty; total += subtotal;
        const stock_before = Number(p.stock || 0);
        order_items.push({ id: pid, name: p.name, qty, price, subtotal, stock: stock_before });
        p.stock = stock_before - qty;
    }
    saveProducts(products);
    const orders = loadOrders();
    const order = { id: uuidv4().replace(/-/g, ''), created_at: new Date().toISOString(), items: order_items, total };
    orders.unshift(order);
    saveOrders(orders);
    req.session.cart = {};
    res.redirect('/');
});

// Simple MPESA STK push helpers (best-effort; uses env vars similar to Python app)
async function getMpesaToken() {
    const key = process.env.MPESA_CONSUMER_KEY;
    const secret = process.env.MPESA_CONSUMER_SECRET;
    if (!key || !secret) return null;
    const env = process.env.MPESA_ENV || 'sandbox';
    const url = env === 'production' ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials' : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';
    try {
        const resp = await axios.get(url, { auth: { username: key, password: secret }, timeout: 10000 });
        return resp.data && resp.data.access_token ? resp.data.access_token : null;
    } catch (e) { return null; }
}

async function sendStkPush(phone, amount, account_ref, description, callback_url) {
    const token = await getMpesaToken();
    if (!token) return null;
    const shortcode = process.env.MPESA_SHORTCODE || process.env.MPESA_PAYBILL;
    const passkey = process.env.MPESA_PASSKEY;
    if (!shortcode || !passkey) return null;
    const timestamp = new Date().toISOString().replace(/[-:T\.Z]/g, '').slice(0, 14);
    const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
    const payload = { BusinessShortCode: shortcode, Password: password, Timestamp: timestamp, TransactionType: 'CustomerPayBillOnline', Amount: Number(amount), PartyA: phone, PartyB: shortcode, PhoneNumber: phone, CallBackURL: callback_url, AccountReference: account_ref, TransactionDesc: description };
    const env = process.env.MPESA_ENV || 'sandbox';
    const url = env === 'production' ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest' : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';
    try {
        const resp = await axios.post(url, payload, { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 15000 });
        return resp.data;
    } catch (e) { return null; }
}

app.post('/mpesa/callback', (req, res) => {
    const payload = req.body || {};
    let checkout_request_id = null;
    try { checkout_request_id = payload.Body && payload.Body.stkCallback && payload.Body.stkCallback.CheckoutRequestID; } catch (e) { }
    if (!checkout_request_id) checkout_request_id = payload.CheckoutRequestID || payload.checkoutRequestID || null;
    if (!checkout_request_id) return res.status(200).send('');
    const orders = loadOrders();
    let updated = false;
    for (const o of orders) {
        const pay = o.payment || {};
        if (pay.checkout_request_id === checkout_request_id) {
            const result_code = (payload.Body && payload.Body.stkCallback && payload.Body.stkCallback.ResultCode) || payload.ResultCode;
            if (result_code === 0 || result_code === '0') { o.paid = true; o.payment.status = 'paid'; } else { o.payment.status = 'failed'; }
            o.payment.raw_callback = payload; updated = true; break;
        }
    }
    if (updated) saveOrders(orders);
    return res.status(200).send('');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Kuku Yetu (Express) listening on ${PORT}`));
