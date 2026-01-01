const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk'); // Brevo SDK
require('dotenv').config();

const app = express();

// FIX: Ensure CORS is fully open for Render/Netlify communication
app.use(cors());
app.use(express.json());

// Brevo Setup
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY; 
const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// Helper: Send SMS via Brevo
const sendSMS = async (phone, message) => {
    let sendTransacSms = {
        "sender": "LesediLife",
        "recipient": phone,
        "content": message
    };
    try {
        await apiInstanceSMS.sendTransacSms(sendTransacSms);
    } catch (error) { console.error('SMS Error:', error); }
};

// --- ROUTES ---

// 1. Signup: Fixed to include password in req.body
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body; // Added password
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ message: "Registration successful. Awaiting Admin Approval." });
    } catch (err) {
        res.status(500).json({ error: "User already exists or Database Error." });
    }
});

// 2. Login: Fixed Admin logic to prevent bcrypt crashes
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Check hardcoded admin first
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Account pending approval" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid credentials" });

        res.json({ id: user.id, role: 'insurance_company', email: user.email });
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. Admin: Approve Users (Missing in your previous version)
app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
        res.json({ message: "User approved" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/pending', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address } = req.body;
    const policyNum = "LL-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address]
        );
        await sendSMS(holder_cell, `Lesedi Life: Policy ${policyNum} created.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
    res.json(rows);
});

app.listen(3000, () => console.log('Server running on port 3000'));