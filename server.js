const express   = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── KONFIGURASI ──
const JWT_SECRET      = process.env.JWT_SECRET      || 'SiVerifRHL_DefaultSecret_2025!';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DATABASE_URL    = process.env.DATABASE_URL;

// Inisialisasi Pool Koneksi
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper agar support PostgreSQL ($1, $2, dst)
const dbAll = async (sql, params = []) => {
  const res = await pool.query(sql.replace(/\?/g, (v, i) => `$${i + 1}`), params);
  return res.rows;
};
const dbGet = async (sql, params = []) => (await dbAll(sql, params))[0] || null;
const dbRun = async (sql, params = []) => await pool.query(sql.replace(/\?/g, (v, i) => `$${i + 1}`), params);

// Middleware
app.use(cors());
app.use(express.json());

// Auth Middleware
function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token missing' });
  try {
    const p = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.admin = p;
    next();
  } catch (e) { res.status(401).json({ error: 'Token invalid' }); }
}

// ── ENDPOINTS ──

// Dashboard (Diperbaiki agar detail)
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const total   = (await dbGet(`SELECT COUNT(*) as n FROM licenses`))?.n || 0;
    const active  = (await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`))?.n || 0;
    const pending = (await dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`))?.n || 0;
    const logs    = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);
    
    res.json({ 
      success: true,
      licenses: { total: parseInt(total), active: parseInt(active) },
      pending: parseInt(pending),
      recent_logs: logs,
      server_info: { uptime: process.uptime(), version: 'v3.0-PG' }
    });
  } catch (e) {
    res.status(500).json({ error: 'Database Error: ' + e.message });
  }
});

// Agency Admins (Daftar Akun Admin)
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  try {
    const rows = await dbAll(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
    res.json({ success: true, admins: rows, admin_users: rows, data: { admins: rows } });
  } catch (e) {
    res.status(500).json({ error: 'Database Error: ' + e.message });
  }
});

// Tambah Admin
app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
  try {
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1,$2,$3,$4)`, 
      [name, username, hash, instansi || agency || '']);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: 'Gagal: ' + e.message }); }
});

// Login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
  const target = crypto.createHash('sha256').update(SUPERADMIN_PASS + JWT_SECRET).digest('hex');
  if (hash === target) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password Admin Salah' });
});

// Root check
app.get('/', (req, res) => res.json({ status: 'ok', db: 'connected', msg: 'SiVerif Server Ready' }));

// Tabel Auto-Init
dbRun(`
  CREATE TABLE IF NOT EXISTS agency_admins (id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, password TEXT, instansi TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS licenses (id SERIAL PRIMARY KEY, license_key TEXT UNIQUE, user_name TEXT, instansi TEXT, status TEXT DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS activity_log (id SERIAL PRIMARY KEY, license_key TEXT, action TEXT, info TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS pending_registrations (id SERIAL PRIMARY KEY, user_name TEXT, instansi TEXT, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
`).catch(err => console.error('Init Error:', err));

module.exports = app;
