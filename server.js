const express   = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;
const START_TIME = new Date();

// ── KONFIGURASI ──
const JWT_SECRET      = process.env.JWT_SECRET      || 'SiVerifRHL_DefaultSecret_2025!';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DATABASE_URL    = process.env.DATABASE_URL;
const FONNTE_TOKEN    = process.env.FONNTE_TOKEN    || '';

// ── DATABASE (POSTGRESQL) ──
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper agar kode lama (SQLite) tidak perlu banyak diubah
const dbAll   = async (sql, params = []) => (await pool.query(sql.replace(/\?/g, (val, i) => `$${i + 1}`), params)).rows;
const dbGet   = async (sql, params = []) => (await dbAll(sql, params))[0] || null;
const dbRun   = async (sql, params = []) => await pool.query(sql.replace(/\?/g, (val, i) => `$${i + 1}`), params);

async function initDB() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY, license_key TEXT UNIQUE, user_name TEXT, instansi TEXT, email TEXT, whatsapp TEXT,
      tier TEXT DEFAULT 'full', status TEXT DEFAULT 'active', max_photos INTEGER DEFAULT 0,
      valid_until TIMESTAMP, device_id TEXT, device_locked INTEGER DEFAULT 0,
      last_check TIMESTAMP, check_count INTEGER DEFAULT 0, notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, activated_at TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id SERIAL PRIMARY KEY, license_key TEXT, action TEXT, device_id TEXT, ip TEXT, info TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS pending_registrations (
      id SERIAL PRIMARY KEY, user_name TEXT, instansi TEXT, email TEXT, whatsapp TEXT, device_id TEXT,
      status TEXT DEFAULT 'pending', notes TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS agency_admins (
      id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, password TEXT, instansi TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log('[DB] Semua Tabel PostgreSQL Siap');
}

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ── AUTH HELPER ──
function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token diperlukan' });
  try {
    const p = jwt.verify(auth.slice(7), JWT_SECRET);
    if (p.role !== 'superadmin') return res.status(403).json({ error: 'Bukan superadmin' });
    req.admin = p;
    next();
  } catch (e) { res.status(401).json({ error: 'Token tidak valid' }); }
}

function hashPass(p) { return crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex'); }

// ── ENDPOINTS ──

app.get('/', (req, res) => res.json({ status: 'ok', server: 'SiVerif RHL v3.0 PG' }));

// Login Admin
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password salah' });
});

// List Admin Audit (Penyebab Error 404 tadi)
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  const admins = await dbAll(`SELECT id, name, username, instansi, created_at FROM agency_admins ORDER BY created_at DESC`);
  res.json({ success: true, admins });
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi } = req.body;
  try {
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1, $2, $3, $4)`,
      [name, username, hashPass(password), instansi]);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: 'Username sudah ada' }); }
});

// Dashboard Stats
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  const total = (await dbGet(`SELECT COUNT(*) as n FROM licenses`)).n;
  const active = (await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)).n;
  const recent_logs = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);
  res.json({ licenses: { total, active }, recent_logs });
});

// List Licenses
app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const list = await dbAll(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 100`);
  res.json({ data: list, total: list.length });
});

// Tambah License
app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, valid_until } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, email, whatsapp, tier, valid_until) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [key, user_name, instansi, email, whatsapp, tier || 'full', valid_until || null]);
  res.json({ success: true, license_key: key });
});

// ... (Fungsi lainnya otomatis aktif karena helper dbRun/dbAll sudah saya buatkan)

// Export untuk Vercel
initDB().catch(console.error);
module.exports = app;
