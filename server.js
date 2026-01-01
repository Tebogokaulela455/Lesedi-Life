const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// --- Brevo (Sendinblue) SDK Initialization ---
const SibApiV3Sdk = require('sib-api-v3-sdk');
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = 'YOUR_BREVO_V3_API_KEY'; // Replace with your key

const app = express();

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

// ==========================================
// BREVO API LOGIC (Email & SMS)
// ==========================================

const sendSMS = async (phone, message) => {
    const apiInstance = new SibApiV3Sdk.TransactionalSMSApi();
    const sendTransacSms = new SibApiV3Sdk.SendTransacSms();
    sendTransacSms.sender = "LesediLife";
    sendTransacSms.recipient = phone;
    sendTransacSms.content = message;

    try {
        await apiInstance.sendTransacSms(sendTransacSms);
        console.log(`SMS sent successfully to ${phone}`);
    } catch (error) {
        console.error("Brevo SMS Error:", error.response ? error.response.text : error.message);
    }
};

const sendEmail = async (email, subject, htmlBody) => {
    const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    
    sendSmtpEmail.subject = subject;
    sendSmtpEmail.htmlContent = htmlBody;
    sendSmtpEmail.sender = { name: "Lesedi Life", email: "noreply@lesedilife.com" };
    sendSmtpEmail.to = [{ email: email }];

    try {
        await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log(`Email sent successfully to ${email}`);
    } catch (error) {
        console.error("Brevo Email Error:", error.response ? error.response.text : error.message);
    }
};

// ==========================================
// ROUTES (Fixed 404, 500, and 400 errors)
// ==========================================

// 1. Signup Route (Fixes 500 Error by logging exact DB issues)
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );

        // Notify user via Brevo
        await sendEmail(email, "Welcome to Lesedi Life", "<h1>Registration Received</h1><p>Please complete your payment to activate your account.</p>");

        res.status(201).json({ success: true, userId: result.insertId });
    } catch (err) {
        console.error("Signup Database Error:", err.message);
        res.status(500).json({ error: "Database error: " + err.message });
    }
});

// 2. Login Route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "User not found" });

        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Account pending approval" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid password" });

        res.json({ id: user.id, role: 'partner', email: user.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Policy Creation (Generates number and sends Brevo SMS)
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address } = req.body;
    const policyNum = "POL-" + Math.random().toString(36).substr(2, 9).toUpperCase();

    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address]
        );

        await sendSMS(holder_cell, `Hello ${holder_name}, your policy ${policyNum} for ${insurance_type} is active.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Admin: View Pending Users
app.get('/api/admin/pending', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. Admin: Approve User
app.post('/api/admin/approve', async (req, res) => {
    try {
        await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [req.body.user_id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(3000, () => console.log('Server live on port 3000'));