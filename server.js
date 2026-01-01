const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();

// FIX: Full CORS Implementation to stop "Access-Control-Allow-Origin" errors
// This allows requests from Netlify and local testing
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());

// Database Connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// --- Brevo (Sendinblue) Configuration ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
// Using the API key you provided
apiKey.apiKey = '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';

const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();
const apiInstanceEmail = new SibApiV3Sdk.TransactionalEmailsApi();

// SMS Sending Logic
const sendSMS = async (phone, message) => {
    let sendTransacSms = {
        "sender": "LesediLife",
        "recipient": phone,
        "content": message
    };
    try {
        await apiInstanceSMS.sendTransacSms(sendTransacSms);
        console.log(`SMS successfully sent to ${phone}`);
    } catch (error) { console.error('Brevo SMS Error:', error); }
};

// --- API ROUTES ---

// 1. Signup Route: Handles registration before PayFast redirect
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ message: "Registration captured. Pending approval." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Registration failed. Email may already exist." });
    }
});

// 2. Login Route: Supports 'admin' bypass and Partner login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "User not found." });

        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Account pending admin approval." });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Incorrect password." });

        res.json({ id: user.id, role: 'partner', email: user.email });
    } catch (err) {
        res.status(500).json({ error: "Database error during login." });
    }
});

// 3. Create Policy: Includes automatic SMS confirmation
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address } = req.body;
    const policyNum = "LL-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address]
        );
        
        await sendSMS(holder_cell, `Lesedi Life: Your policy ${policyNum} is active. Thank you!`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Admin View: Get Pending Users
app.get('/api/admin/pending', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. Admin Action: Approve Partner
app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
        res.json({ message: "Partner approved." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 6. Policy List: Fetch per Partner
app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    try {
        const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server live on port ${PORT}`));