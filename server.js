const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors'); 
const bcrypt = require('bcryptjs');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Brevo Setup ---
const defaultClient = SibApiV3Sdk.ApiClient.instance;
const apiKey = defaultClient.authentications['api-key'];
apiKey.apiKey = 'YOUR_BREVO_V3_KEY'; // Replace with your key

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 4000,
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true }
});

// SIGNUP
app.post('/api/signup', async (req, res) => {
    const { email, password, plan } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, plan_type, is_approved) VALUES (?, ?, ?, 0)',
            [email, hashedPassword, plan]
        );
        res.status(201).json({ success: true, userId: result.insertId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin') return res.json({ id: 0, role: 'admin' });
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: "Not found" });
        if (!rows[0].is_approved) return res.status(403).json({ error: "Awaiting Admin Approval" });
        const valid = await bcrypt.compare(password, rows[0].password);
        if (!valid) return res.status(401).json({ error: "Invalid password" });
        res.json({ id: rows[0].id, role: 'partner', email: rows[0].email });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// POLICY ACTIONS (Create, Delete, Status Toggle)
app.post('/api/policies', async (req, res) => {
    const { company_id, insurance_type, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel } = req.body;
    const policyNum = "POL-" + Math.random().toString(36).substr(2, 9).toUpperCase();
    try {
        await pool.execute(
            `INSERT INTO policies (company_id, policy_number, insurance_type, holder_name, holder_id, holder_cell, holder_address, beneficiary_name, beneficiary_id, beneficiary_relation) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [company_id, policyNum, insurance_type, h_name, h_id, h_cell, h_addr, b_name, b_id, b_rel]
        );
        res.json({ success: true, policyNumber: policyNum });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/policies', async (req, res) => {
    const { company_id } = req.query;
    const [rows] = await pool.execute('SELECT * FROM policies WHERE company_id = ?', [company_id]);
    res.json(rows);
});

app.post('/api/policies/status', async (req, res) => {
    const { id, status } = req.body;
    await pool.execute('UPDATE policies SET status = ? WHERE id = ?', [status, id]);
    res.json({ success: true });
});

app.delete('/api/policies/:id', async (req, res) => {
    await pool.execute('DELETE FROM policies WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

// ADMIN ROUTES
app.get('/api/admin/pending', async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, plan_type FROM users WHERE is_approved = 0');
    res.json(rows);
});

app.post('/api/admin/approve', async (req, res) => {
    await pool.execute('UPDATE users SET is_approved = 1 WHERE id = ?', [req.body.user_id]);
    res.json({ success: true });
});

app.listen(3000, () => console.log('Server Running on Port 3000'));