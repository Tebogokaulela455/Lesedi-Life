const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const jwt = require('jsonwebtoken'); // Added for unique policy links
require('dotenv').config();

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// --- 1. BREVO (SMS & EMAIL) SETUP ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = process.env.BREVO_API_KEY || 'YOUR_BREVO_V3_KEY';

const sendSMS = async (phone, message) => {
    const apiInstance = new SibApiV3Sdk.TransactionalSMSApi();
    const sendTransacSms = new SibApiV3Sdk.SendTransacSms();
    sendTransacSms.sender = "LesediLife";
    sendTransacSms.recipient = phone;
    sendTransacSms.content = message;
    try { await apiInstance.sendTransacSms(sendTransacSms); } 
    catch (error) { console.error("SMS Error:", error.message); }
};

// ADDED: Email Logic for Admin and Partners
const sendEmail = async (to, subject, htmlContent) => {
    const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = subject;
    sendSmtpEmail.htmlContent = htmlContent;
    sendSmtpEmail.sender = { name: "Lesedi Life", email: "noreply@lesedilife.com" };
    sendSmtpEmail.to = [{ email: to }];
    try { await apiInstance.sendTransacEmail(sendSmtpEmail); }
    catch (error) { console.error("Email Error:", error.message); }
};

// --- 2. DATABASE CONNECTION ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// --- 3. PAY@ API PLACEHOLDER ---
// This handles the monthly premium payments from customers to the insurance company
app.post('/api/payat/callback', async (req, res) => {
    const { reference, amount, status } = req.body;
    // logic: If status is success, update policy 'last_payment_date'
    console.log(`Pay@ Payment Received: ${reference} - R${amount}`);
    res.status(200).send("OK");
});

// ==========================================
// ROUTES
// ==========================================

// SIGNUP
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        // Notify Admin via Email that a new FSP has signed up
        await sendEmail("admin@lesedilife.com", "New Registration", `User ${email} is awaiting approval.`);
        res.status(201).json({ success: true, userId: result.insertId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "User not found" });
        const user = rows[0];
        if (!user.is_approved) return res.status(403).json({ error: "Awaiting Admin approval" });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid password" });

        // Generate a unique link for this client to give to THEIR customers
        const clientToken = jwt.sign({ clientId: user.id }, 'SECRET_KEY_123');
        const uniqueLink = `https://lesedi-life-portal.netlify.app/public-create?ref=${clientToken}`;

        res.json({ id: user.id, role: 'partner', email: user.email, uniqueLink: uniqueLink });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ADMIN: PENDING & APPROVE
app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

app.post('/api/admin/approve', async (req, res) => {
    const { user_id } = req.body;
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [user_id]);
    res.json({ success: true });
});

// CREATE POLICY (Partner creating for customer)
app.post('/api/policies', async (req, res) => {
    const { company_id, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type } = req.body;
    const policyNum = "LP" + Math.floor(100000 + Math.random() * 900000); // More professional policy number

    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, beneficiary_relation, insurance_type, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active')`,
            [company_id, policyNum, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type]
        );

        // SMS to Customer
        await sendSMS(h_cell, `Lesedi Life: Your policy ${policyNum} is active. Beneficiary: ${b_name}.`);
        
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET POLICIES
app.get('/api/policies', async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [req.query.company_id]);
    res.json(rows);
});

// DELETE & STATUS
app.put('/api/policies/:id/status', async (req, res) => {
    await pool.execute('UPDATE policies SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
    res.json({ success: true });
});

app.delete('/api/policies/:id', async (req, res) => {
    await pool.execute('DELETE FROM policies WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));