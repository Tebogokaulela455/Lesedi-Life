const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(express.json());

// Database Connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// ==========================================
// SPACE FOR EXTERNAL APIs (INSERT CODE HERE)
// ==========================================

const sendSMS = async (phone, message) => {
    // --- INSERT YOUR SMS API CODE HERE (e.g. BulkSMS or Twilio) ---
    console.log(`Sending SMS to ${phone}: ${message}`);
};

const sendEmail = async (email, subject, body) => {
    // --- INSERT YOUR EMAIL API CODE HERE (e.g. Nodemailer) ---
    console.log(`Sending Email to ${email}`);
};

const processPayAtPayment = async (amount, reference) => {
    // --- INSERT YOUR PAY@ API CODE HERE ---
};

// ==========================================
// ROUTES
// ==========================================

// 1. SIGNUP: With Tier selection and R50 add-on
app.post('/api/signup', async (req, res) => {
    const { email, password, plan, activateSelfService } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        await pool.execute(
            'INSERT INTO users (email, password, plan_type, has_self_service_link) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, plan, activateSelfService]
        );
        res.status(201).json({ message: "Registration successful. Awaiting admin approval." });
    } catch (err) {
        res.status(500).json({ error: "Email already exists or server error." });
    }
});

// 2. LOGIN: Including hardcoded Admin check
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Admin Override Logic
    if (email === 'admin' && password === 'admin') {
        const token = jwt.sign({ id: 0, role: 'admin' }, process.env.JWT_SECRET);
        return res.json({ token, role: 'admin' });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });

    const user = rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    
    if (!validPass) return res.status(401).json({ error: "Invalid password" });
    if (!user.is_approved) return res.status(401).json({ error: "Account pending admin approval" });

    const token = jwt.sign({ id: user.id, role: user.role, is_blocked: user.is_blocked }, process.env.JWT_SECRET);
    res.json({ token, role: user.role, is_blocked: user.is_blocked });
});

// 3. CREATE POLICY: Generates unique ID and sends SMS
app.post('/api/policies', async (req, res) => {
    const { company_id, name, email, phone, is_admin } = req.body;
    
    // Check if account is blocked (Allow access but warn if needed)
    const [user] = await pool.execute('SELECT is_blocked FROM users WHERE id = ?', [company_id]);
    if (user[0] && user[0].is_blocked && !is_admin) {
        return res.status(403).json({ error: "Access blocked due to non-payment. Please settle your account." });
    }

    // Generate Unique Policy Number
    const policyNum = "POL-" + Math.floor(100000 + Math.random() * 900000) + Date.now().toString().slice(-4);

    try {
        await pool.execute(
            'INSERT INTO policies (company_id, policy_number, holder_name, holder_email, holder_phone, is_admin_private) VALUES (?, ?, ?, ?, ?, ?)',
            [company_id, policyNum, name, email, phone, is_admin || false]
        );

        // Send confirmation SMS
        await sendSMS(phone, `Your policy has been captured. Your unique Policy Number is: ${policyNum}`);

        res.json({ message: "Policy created successfully", policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. GET POLICIES: Separates Admin-only policies
app.get('/api/policies/:company_id', async (req, res) => {
    const { company_id } = req.params;
    const { role } = req.query; // Send 'admin' or 'client' from frontend

    let query = 'SELECT * FROM policies WHERE company_id = ?';
    if (role !== 'admin') {
        query += ' AND is_admin_private = FALSE';
    }

    const [rows] = await pool.execute(query, [company_id]);
    res.json(rows);
});

// 5. ADMIN ACTION: Approve User
app.put('/api/admin/approve/:userId', async (req, res) => {
    await pool.execute('UPDATE users SET is_approved = TRUE WHERE id = ?', [req.params.userId]);
    res.json({ message: "User approved successfully" });
});

app.listen(3000, () => console.log('Server is running on port 3000'));