const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();

// Fix CORS issues for cross-platform communication
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
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
const apiKey = defaultClient.authentications['API Key'];
apiKey.apiKey = process.env.BREVO_API_KEY; // Add your API key to Render Environment Variables

const apiInstanceSMS = new SibApiV3Sdk.TransactionalSMSApi();
const apiInstanceEmail = new SibApiV3Sdk.TransactionalEmailsApi();

const sendSMS = async (phone, message) => {
    let sendTransacSms = {
        "sender": "LesediLife",
        "recipient": phone,
        "content": message
    };
    try {
        await apiInstanceSMS.sendTransacSms(sendTransacSms);
        console.log(`SMS sent to ${phone}`);
    } catch (error) { console.error('SMS API Error:', error); }
};

// --- ROUTES ---

// 1. SIGNUP: Fixed to handle password hashing
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ message: "Registration successful. Pending approval." });
    } catch (err) {
        res.status(500).json({ error: "Email already exists or Database Error." });
    }
});

// 2. LOGIN: Fixed admin bypass and bcrypt check
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Admin Override
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

        res.json({ id: user.id, role: 'partner', email: user.email });
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. ADMIN: Get Pending Users
app.get('/api/admin/pending', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. ADMIN: Approve User
app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [userId]);
        res.json({ message: "User approved successfully" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. POLICIES: Create New
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address } = req.body;
    const policyNum = "LL-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address]
        );
        
        // SMS Confirmation via Brevo
        await sendSMS(holder_cell, `Lesedi Life: Your policy ${policyNum} is now active. Type: ${insurance_type}.`);
        
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. POLICIES: Get for specific user
app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    try {
        const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(3000, () => console.log('Server running on port 3000'));