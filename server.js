const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); // FIX: Added CORS
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// FIX: Enable CORS for your Render URL and Local testing
app.use(cors()); 
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// --- API PLACEHOLDERS ---
const sendSMS = async (phone, msg) => console.log(`SMS to ${phone}: ${msg}`);
const sendEmail = async (email, subject, msg) => console.log(`Email to ${email}`);

// LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') {
        const token = jwt.sign({ id: 0, role: 'admin' }, process.env.JWT_SECRET);
        return res.json({ token, role: 'admin' });
    }
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    const user = rows[0];
    if (!user.is_approved) return res.status(401).json({ error: "Pending Admin Approval" });
    
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token, role: user.role, id: user.id });
});

// CREATE POLICY (Updated with detailed info)
app.post('/api/policies', async (req, res) => {
    const { 
        company_id, insurance_type, holder_name, holder_id, 
        holder_cell, holder_address, ben_name, ben_id, is_admin 
    } = req.body;

    const policyNum = "POL-" + Date.now().toString().slice(-8);

    try {
        await pool.execute(
            `INSERT INTO policies 
            (company_id, policy_number, insurance_type, holder_full_name, holder_id_number, holder_cell, holder_address, beneficiary_name, beneficiary_id_number, is_admin_private) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, holder_name, holder_id, holder_cell, holder_address, ben_name, ben_id, is_admin || false]
        );

        await sendSMS(holder_cell, `Lesedi Life: Policy ${policyNum} for ${insurance_type} is captured.`);
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(process.env.PORT || 3000, () => console.log('Server Active'));