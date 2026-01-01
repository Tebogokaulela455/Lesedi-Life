const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();

// --- Brevo Setup ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY; // Ensure this is in your Render Environment Variables

const apiInstanceEmail = new SibApiV3Sdk.TransactionalEmailsApi();
const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();

// Fix CORS
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

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
    let sendTransacSms = new SibApiV3Sdk.SendTransacSms();
    sendTransacSms = {
        "sender": "LesediLife",
        "recipient": phone,
        "content": message
    };
    try {
        await apiInstanceSMS.sendTransacSms(sendTransacSms);
        console.log(`SMS Sent to ${phone}`);
    } catch (error) { console.error('SMS Error:', error); }
};

// Routes
app.post('/api/signup', async (req, res) => {
    const { email, password, plan, hasLink } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, has_online_link, is_approved) VALUES (?, ?, ?, ?, 0)',
            [email, hashedPassword, plan, hasLink ? 1 : 0]
        );
        res.status(201).json({ message: "Success. Pending Admin Approval." });
    } catch (err) {
        res.status(500).json({ error: "Email already registered or Database error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 9999, role: 'admin', email: 'admin' });
    }
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "User not found" });
        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Account pending admin approval." });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid password" });
        res.json({ id: user.id, role: 'partner', email: user.email });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
    res.json({ message: "User approved successfully" });
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
        await sendSMS(holder_cell, `Lesedi Life: Your policy ${policyNum} is active. Welcome!`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
    res.json(rows);
});

app.listen(3000, () => console.log('Server running on port 3000'));