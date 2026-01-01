const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// 1. FULL CORS (Fixes all connection errors)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// 2. BREVO (SMS & EMAIL) SETUP
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = 'YOUR_BREVO_V3_KEY'; // REPLACE THIS

const sendSMS = async (phone, message) => {
    const apiInstance = new SibApiV3Sdk.TransactionalSMSApi();
    const sendTransacSms = new SibApiV3Sdk.SendTransacSms();
    sendTransacSms.sender = "LesediLife";
    sendTransacSms.recipient = phone;
    sendTransacSms.content = message;
    try { await apiInstance.sendTransacSms(sendTransacSms); } catch (e) { console.error("SMS Error"); }
};

const sendEmail = async (to, subject, content) => {
    const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = subject;
    sendSmtpEmail.htmlContent = content;
    sendSmtpEmail.sender = { name: "Lesedi Life", email: "admin@lesedilife.com" };
    sendSmtpEmail.to = [{ email: to }];
    try { await apiInstance.sendTransacEmail(sendSmtpEmail); } catch (e) { console.error("Email Error"); }
};

// 3. DATABASE CONNECTION
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// ==========================================
// ALL ROUTES (LEAVING NOTHING OUT)
// ==========================================

// SIGNUP: Save user and notify admin
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        await sendEmail("admin@lesedilife.com", "New FSP Signup", `User ${email} signed up for plan R${plan}`);
        res.status(201).json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LOGIN: Handle Admin and Partners + Generate unique links
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') return res.json({ id: 0, role: 'admin' });

    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    if (!user.is_approved) return res.status(403).json({ error: "Awaiting Admin Approval" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    // Unique link for this client's customers
    const uniqueLink = `https://monumental-malasada-0ba635.netlify.app/public-signup?ref=${user.id}`;
    res.json({ id: user.id, role: 'partner', uniqueLink });
});

// ADMIN: GET PENDING USERS
app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

// ADMIN: APPROVE USER
app.post('/api/admin/approve', async (req, res) => {
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [req.body.user_id]);
    res.json({ success: true });
});

// POLICIES: CREATE (With SMS trigger)
app.post('/api/policies', async (req, res) => {
    const { company_id, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type } = req.body;
    const policyNum = "LP-" + Math.floor(100000 + Math.random() * 900000);
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, beneficiary_relation, insurance_type, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active')`,
            [company_id, policyNum, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type || 'Funeral Cover']
        );
        await sendSMS(h_cell, `Lesedi Life: Your policy ${policyNum} is active.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// POLICIES: GET ALL FOR COMPANY
app.get('/api/policies', async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [req.query.company_id]);
    res.json(rows);
});

// POLICIES: STATUS UPDATE (Deactivate/Reactivate)
app.put('/api/policies/:id/status', async (req, res) => {
    await pool.execute('UPDATE policies SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
    res.json({ success: true });
});

// POLICIES: DELETE
app.delete('/api/policies/:id', async (req, res) => {
    await pool.execute('DELETE FROM policies WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

// PAY@ PLACEHOLDER (Premium Payments)
app.post('/api/payat-callback', async (req, res) => {
    console.log("Pay@ Payment Received", req.body);
    res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));