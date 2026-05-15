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

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000
});

// Helper Database Robust
const dbQuery = async (sql, params = []) => {
  const formattedSql = sql.replace(/\?/g, (val, i) => `$${i + 1}`);
  return await pool.query(formattedSql, params);
};

// Fungsi Auto-Create Tables jika belum ada
async function ensureTables() {
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS agency_admins (
      id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, password TEXT, instansi TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY, license_key TEXT UNIQUE, user_name TEXT, instansi TEXT, status TEXT DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id SERIAL PRIMARY KEY, license_key TEXT, action TEXT, info TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS pending_registrations (
      id SERIAL PRIMARY KEY, user_name TEXT, instansi TEXT, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

app.use(cors());
app.use(express.json());

// Auth Middleware
function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const p = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.admin = p;
    next();
  } catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

// ── ENDPOINTS ──

app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  try {
    await ensureTables(); // Pastikan tabel ada dulu
    const r = await dbQuery(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
    res.json({ success: true, admins: r.rows, admin_users: r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
  try {
    await ensureTables();
    await dbQuery(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1,$2,$3,$4)`, 
      [name, username, hash, instansi || agency || '']);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: 'Username sudah ada atau error DB' }); }
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
  const target = crypto.createHash('sha256').update(SUPERADMIN_PASS + JWT_SECRET).digest('hex');
  if (hash === target) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Salah' });
});

app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    await ensureTables();
    const lic = await dbQuery(`SELECT COUNT(*) FROM licenses`);
    const pending = await dbQuery(`SELECT COUNT(*) FROM pending_registrations WHERE status='pending'`);
    res.json({ licenses: { total: parseInt(lic.rows[0].count) }, pending: parseInt(pending.rows[0].count), recent_logs: [] });
  } catch (e) { res.json({ licenses: { total: 0 }, pending: 0, recent_logs: [] }); }
});

// Endpoint lainnya... (tambahkan jika diperlukan)
app.get('/', (req, res) => res.send('SiVerif Server Ready'));

module.exports = app;
