const express   = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;
const START_TIME = Date.now();

// ── KONFIGURASI ──
const JWT_SECRET      = process.env.JWT_SECRET      || 'SiVerifRHL_DefaultSecret_2025!';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DATABASE_URL    = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper PostgreSQL ($1, $2, dst)
const dbAll = async (sql, params = []) => {
  const res = await pool.query(sql.replace(/\?/g, (v, i) => `$${i + 1}`), params);
  return res.rows;
};
const dbGet = async (sql, params = []) => (await dbAll(sql, params))[0] || null;
const dbRun = async (sql, params = []) => await pool.query(sql.replace(/\?/g, (v, i) => `$${i + 1}`), params);

app.use(cors());
app.use(express.json({ limit: '5mb' }));

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

function hashPass(p) { return crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex'); }

// ── ENDPOINTS ──

app.get('/', (req, res) => res.json({ status: 'ok', msg: 'SiVerif RHL PostgreSQL Server Ready' }));

// Login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password Salah' });
});

// DASHBOARD LENGKAP
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const total = await dbGet(`SELECT COUNT(*) as n FROM licenses`);
    const active = await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`);
    const expired = await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='expired'`);
    const pending = await dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`);
    const logs = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 15`);
    
    res.json({
      success: true,
      licenses: { total: parseInt(total?.n||0), active: parseInt(active?.n||0), expired: parseInt(expired?.n||0) },
      pending: parseInt(pending?.n||0),
      recent_logs: logs,
      server_info: { 
        uptime: Math.floor((Date.now()-START_TIME)/1000),
        version: 'v12-Ultimate-PG'
      }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// INSTANSI & ADMIN (Menu yang tadi error)
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  try {
    const admins = await dbAll(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
    res.json({ 
      success: true, 
      agency_name: 'Kementerian Lingkungan Hidup dan Kehutanan', 
      admins: admins,
      admin_users: admins 
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  try {
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1,$2,$3,$4)`, 
      [name, username, hashPass(password), instansi || agency || '']);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: 'Username sudah ada' }); }
});

// MANAJEMEN LISENSI (Lengkap)
app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { q, status } = req.query;
  let sql = `SELECT * FROM licenses WHERE 1=1`;
  let params = [];
  if (q) { sql += ` AND (license_key ILIKE $1 OR user_name ILIKE $1 OR instansi ILIKE $1)`; params.push(`%${q}%`); }
  if (status) { sql += ` AND status = $${params.length+1}`; params.push(status); }
  sql += ` ORDER BY created_at DESC LIMIT 200`;
  const list = await dbAll(sql, params);
  res.json({ success: true, data: list, total: list.length });
});

app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, tier, valid_until, max_photos } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, tier, status, valid_until, max_photos) VALUES ($1,$2,$3,$4,'active',$5,$6)`,
    [key, user_name, instansi, tier || 'full', valid_until || null, max_photos || 0]);
  res.json({ success: true, license_key: key });
});

// VALIDASI (Untuk Aplikasi Desktop)
app.post('/api/validate', async (req, res) => {
  const { license_key, device_id } = req.body;
  const lic = await dbGet(`SELECT * FROM licenses WHERE license_key = $1`, [license_key?.toUpperCase()]);
  if (!lic) return res.json({ valid: false, error: 'Key tidak terdaftar' });
  if (lic.status !== 'active') return res.json({ valid: false, error: 'Lisensi ' + lic.status });
  
  await dbRun(`UPDATE licenses SET last_check=NOW(), check_count=check_count+1, device_id=$1 WHERE id=$2`, [device_id, lic.id]);
  res.json({ valid: true, user_name: lic.user_name, instansi: lic.instansi, tier: lic.tier });
});

// Pendaftaran Mandiri
app.post('/api/register', async (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  await dbRun(`INSERT INTO pending_registrations (user_name, instansi, email, whatsapp, device_id) VALUES ($1,$2,$3,$4,$5)`,
    [user_name, instansi, email, whatsapp, device_id]);
  res.json({ success: true });
});

// AUTO-INIT TABEL
async function init() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS agency_admins (id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, password TEXT, instansi TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS licenses (id SERIAL PRIMARY KEY, license_key TEXT UNIQUE, user_name TEXT, instansi TEXT, email TEXT, whatsapp TEXT, tier TEXT DEFAULT 'full', status TEXT DEFAULT 'active', max_photos INTEGER DEFAULT 0, valid_until TIMESTAMP, device_id TEXT, last_check TIMESTAMP, check_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS activity_log (id SERIAL PRIMARY KEY, license_key TEXT, action TEXT, ip TEXT, info TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS pending_registrations (id SERIAL PRIMARY KEY, user_name TEXT, instansi TEXT, email TEXT, whatsapp TEXT, device_id TEXT, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  `);
}
init().catch(console.error);

module.exports = app;
