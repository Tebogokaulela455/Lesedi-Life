const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// FIX: Full CORS Implementation to stop "Access-Control-Allow-Origin" errors
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
// API PLACEHOLDERS (Original Logic Preserved)
// ==========================================

const sendSMS = async (phone, message) => {
    // --- INSERT SMS API CODE HERE ---
    console.log(`[SMS API] To ${phone}: ${message}`);
};

const sendEmail = async (email, subject, body) => {
    // --- INSERT EMAIL API CODE HERE ---
    console.log(`[Email API] To ${email}`);
};

const processPayAt = async (amount, reference) => {
    // --- INSERT Pay@ API CODE HERE ---
};

// ==========================================
// ROUTES
// ==========================================

// 1. Signup Route (ADDED: Fixes the 404 error from your 1st screenshot)
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
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

// 2. Login Route (Original Admin hardcoded logic + DB check)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (email === 'admin' && password === 'admin') {
        return res.json({ id: 0, role: 'admin', email: 'admin' });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    if (!user.is_approved) return res.status(403).json({ error: "Account pending approval" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ id: user.id, role: 'insurance_company', email: user.email });
});

// 3. Create Policy (Original Logic + SMS trigger)
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address, ben_name, ben_id, is_admin } = req.body;
    
    const policyNum = "POL-" + Math.random().toString(36).substr(2, 9).toUpperCase();

    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, is_admin_private) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address, ben_name || "N/A", ben_id || "N/A", is_admin || false]
        );

        await sendSMS(holder_cell, `Policy ${policyNum} for ${insurance_type} has been captured.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Get Policies (ADDED: Fixes the 404/Empty table error from your 3rd screenshot)
app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    try {
        const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Admin: Pending Users (ADDED: Fixes the 404 error from your 4th screenshot)
app.get('/api/admin/pending', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));