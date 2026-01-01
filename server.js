const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- 1. CONFIGURATION ---
const JWT_SECRET = 'MHftdpyYxx4lpuSSAfuDB6qi14n2lFa3pwaL4wQNTi8'; // Your specific secret
const BREVO_KEY = 'YOUR_API_V3_KEY'; // REPLACE with your real Brevo Key

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json());

// --- 2. BREVO SETUP (SMS & EMAIL) ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = BREVO_KEY;

const sendSMS = async (phone, message) => {
    try {
        const apiInstance = new SibApiV3Sdk.TransactionalSMSApi();
        const sendTransacSms = new SibApiV3Sdk.SendTransacSms();
        sendTransacSms.sender = "LesediLife";
        sendTransacSms.recipient = phone;
        sendTransacSms.content = message;
        await apiInstance.sendTransacSms(sendTransacSms);
        console.log(`SMS sent to ${phone}`);
    } catch (error) {
        console.error("SMS Failed (Check Brevo Credit/Key):", error.message);
    }
};

const sendEmail = async (toEmail, subject, htmlContent) => {
    try {
        const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
        const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
        sendSmtpEmail.subject = subject;
        sendSmtpEmail.htmlContent = htmlContent;
        sendSmtpEmail.sender = { "name": "Lesedi Life System", "email": "no-reply@lesedilife.com" };
        sendSmtpEmail.to = [{ "email": toEmail }];
        await apiInstance.sendTransacEmail(sendSmtpEmail);
    } catch (error) {
        console.error("Email Failed:", error.message);
    }
};

// --- 3. DATABASE CONNECTION ---
const pool = mysql.createPool({
    host: process.env.HOST || 'gateway01.eu-central-1.prod.aws.tidbcloud.com',
    user: process.env.USERNAME || 'nyBG8ksgN124vtf.root',
    password: process.env.PASSWORD || '0O5mu3c1yLgKBvLH',
    database: process.env.DATABASE || 'test',
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// --- 4. ROUTES ---

// SIGNUP: Registers user, sends Email to Admin
app.post('/api/signup', async (req, res) => {
    const { email, password, plan, includeLink } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert into DB
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, plan_type, has_online_link, is_approved) VALUES (?, ?, ?, ?, 0)',
            [email, hashedPassword, plan, includeLink ? 1 : 0]
        );
        
        // Notify Admin (You)
        await sendEmail('admin@lesedilife.com', 'New Partner Signup', `<p>User ${email} has registered and paid via PayFast. Please approve them in dashboard.</p>`);
        
        res.status(201).json({ success: true, id: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Email likely already exists." });
    }
});

// LOGIN: Handles Admin & Partners
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // A. Admin Logic
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', token: 'admin-token' });
    }

    // B. Partner Logic
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "User not found." });

        const user = rows[0];
        
        // Check Approval
        if (!user.is_approved) {
            return res.status(403).json({ error: "Account awaiting Admin Approval." });
        }

        // Check Password
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid password." });

        // Generate Unique Client Link if they paid for it
        let uniqueLink = null;
        if (user.has_online_link) {
            // Encode their ID into a token so their customers are linked to them
            const linkToken = jwt.sign({ companyId: user.id }, JWT_SECRET);
            uniqueLink = `https://monumental-malasada-0ba635.netlify.app/?ref=${linkToken}`;
        }

        res.json({ id: user.id, role: 'partner', email: user.email, uniqueLink });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CREATE POLICY (Used by Partners & Online Link)
app.post('/api/policies', async (req, res) => {
    const { company_id, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type } = req.body;
    
    // Generate Unique Policy Number (e.g., LSD-849201)
    const policyNum = "LSD-" + Math.floor(100000 + Math.random() * 900000);

    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, beneficiary_relation, insurance_type) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel, insurance_type || 'Funeral']
        );

        // SMS Notification to Policy Holder
        await sendSMS(h_cell, `Welcome to Lesedi Life. Your policy ${policyNum} has been created successfully.`);

        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET POLICIES (For Dashboard)
app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    try {
        // If company_id is 0 or missing, it might be admin, but let's stick to specific company fetching
        const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// UPDATE STATUS (Deactivate/Reactivate)
app.put('/api/policies/:id/status', async (req, res) => {
    const { status } = req.body; // 'Active' or 'Deactivated'
    try {
        await pool.execute('UPDATE policies SET status = ? WHERE id = ?', [status, req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE POLICY
app.delete('/api/policies/:id', async (req, res) => {
    try {
        await pool.execute('DELETE FROM policies WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ADMIN ROUTES ---

// Get Pending Users
app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM users WHERE is_approved = 0');
    res.json(rows);
});

// Approve User
app.post('/api/admin/approve', async (req, res) => {
    const { user_id } = req.body;
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [user_id]);
    
    // Fetch email to notify them
    const [rows] = await pool.execute('SELECT email FROM users WHERE id = ?', [user_id]);
    if(rows.length > 0) {
        await sendEmail(rows[0].email, 'Account Approved', 'Your Lesedi Life account is now active. You may login.');
    }
    
    res.json({ success: true });
});

// --- PAY@ INTEGRATION (Placeholder) ---
app.post('/api/payat/webhook', (req, res) => {
    // 1. Receive payment notification from Pay@
    const paymentData = req.body;
    console.log("Pay@ Notification Received:", paymentData);
    
    // 2. Logic to update 'last_payment_date' in 'policies' table would go here
    
    res.status(200).send("Ack");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));