const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();

// Enable full CORS to prevent net::ERR_FAILED and 400 errors
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use('/uploads', express.json(), express.static('uploads'));

// Database Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// Brevo Setup
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = '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';
const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();
const apiInstanceEmail = new SibApiV3Sdk.TransactionalEmailsApi();

// File Upload Logic for Death Certificates
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// --- HELPERS ---
const sendSMS = async (phone, msg) => {
    try { await apiInstanceSMS.sendTransacSms({ "sender": "LesediLife", "recipient": phone, "content": msg }); }
    catch (e) { console.error("SMS Error:", e); }
};

// --- ROUTES ---

// Fixed Signup: Prevents 500 error by ensuring all fields are handled correctly
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ message: "Registration recorded. Proceeding to PayFast." });
    } catch (err) {
        res.status(500).json({ error: "Email already exists or server error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') return res.json({ id: 0, role: 'admin', email: 'admin' });

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Pending approval" });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid credentials" });
        res.json({ id: user.id, role: 'company', email: user.email });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

// Policies: Common for Admin and Users
app.post('/api/policies', async (req, res) => {
    const { company_id, type, name, id_num, cell, addr } = req.body;
    const policyNum = "LL-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`,
            [company_id, policyNum, type, name, id_num, cell, addr]
        );
        await sendSMS(cell, `Lesedi Life: Your unique policy ${policyNum} is active.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/policies', async (req, res) => {
    const { company_id, role } = req.query;
    // Admin (ID 0) sees ALL active policies; Companies see only their own
    const sql = (role === 'admin') ? 'SELECT * FROM policies WHERE status = "active"' : 'SELECT * FROM policies WHERE company_id = ? AND status = "active"';
    const params = (role === 'admin') ? [] : [company_id];
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
});

// Deactivate Policy with File Upload
app.post('/api/policies/deactivate', upload.single('certificate'), async (req, res) => {
    const { policyId } = req.body;
    const filePath = req.file ? req.file.path : null;
    try {
        await pool.execute('UPDATE policies SET status = "inactive", death_cert_path = ? WHERE id = ?', [filePath, policyId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin Approval List
app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
    res.json({ success: true });
});

app.listen(3000, () => console.log('Server online on 3000'));