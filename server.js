const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();

// 1. FIXED CORS (Solves net::ERR_CONNECTION_TIMED_OUT)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// 2. UPLOADS CONFIGURATION
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// 3. DATABASE CONNECTION
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});




// 4. BREVO SMS SETUP
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
// Use the variable from your .env/Render settings
apiKey.apiKey = process.env.BREVO_API_KEY; 
const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();

// --- ROUTES ---

// NEW DATABASE DOCTOR ROUTE (Added for troubleshooting)
app.get('/api/debug-db', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT 1 + 1 AS result');
        res.json({ 
            success: true, 
            message: "DATABASE IS CONNECTED!", 
            testResult: rows[0].result,
            config: {
                host: process.env.DB_HOST ? "Defined" : "MISSING",
                user: process.env.DB_USER ? "Defined" : "MISSING",
                db: process.env.DB_NAME ? "Defined" : "MISSING"
            }
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "DATABASE CONNECTION FAILED", 
            error: err.message,
            hint: "Check your Render Environment Variables and TiDB IP Whitelist." 
        });
    }
});

app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "User already exists or DB Error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Pending Admin approval." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid credentials" });
        res.json({ id: user.id, role: 'company', email: user.email });
    } catch (e) { res.status(500).json({ error: "Login error" }); }
});

app.post('/api/policies', async (req, res) => {
    const { company_id, type, name, id_num, cell, addr } = req.body;
    const policyNum = "LL-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`,
            [company_id, policyNum, type, name, id_num, cell, addr]
        );
        await apiInstanceSMS.sendTransacSms({ "sender": "LesediLife", "recipient": cell, "content": `Policy ${policyNum} is active.` });
        res.json({ success: true, policyNumber: policyNum });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/policies', async (req, res) => {
    const { company_id, role } = req.query;
    try {
        const sql = (role === 'admin') ? 'SELECT * FROM policies WHERE status = "active"' : 'SELECT * FROM policies WHERE company_id = ? AND status = "active"';
        const params = (role === 'admin') ? [] : [company_id];
        const [rows] = await pool.execute(sql, params);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: "Load failed" }); }
});

app.post('/api/policies/deactivate', upload.single('certificate'), async (req, res) => {
    const { policyId } = req.body;
    const filePath = req.file ? req.file.path : null;
    try {
        await pool.execute('UPDATE policies SET status = "inactive", death_cert_path = ? WHERE id = ?', [filePath, policyId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Deactivation failed" }); }
});

app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
    res.json({ success: true });
});

// ERROR HANDLERS
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Internal Server Error", message: err.message });
});

app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server live on ${PORT}`));