const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// FIX: CORS Implementation to allow your frontend to connect
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
// API PLACEHOLDERS (INSERT YOUR CODES HERE)
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

// Login Route (with Admin hardcoded logic)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (email === 'admin' && password === 'admin') {
        const token = jwt.sign({ id: 0, role: 'admin' }, process.env.JWT_SECRET);
        return res.json({ token, role: 'admin' });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = rows[0];
    if (!user.is_approved) return res.status(403).json({ error: "Account pending approval" });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token, role: user.role });
});

// Create Policy (Generates unique number and sends SMS)
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, holder_name, holder_id, holder_cell, holder_address, ben_name, ben_id, is_admin } = req.body;
    
    const policyNum = "POL-" + Math.random().toString(36).substr(2, 9).toUpperCase();

    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, is_admin_private) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address, ben_name, ben_id, is_admin || false]
        );

        // Send SMS Confirmation
        await sendSMS(holder_cell, `Policy ${policyNum} for ${insurance_type} has been captured.`);

        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));