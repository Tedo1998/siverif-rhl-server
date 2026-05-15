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

// Helper agar kode lebih simpel dan support PostgreSQL ($1, $2, dst)
const dbAll = async (sql, params = []) => {
  const formattedSql = sql.replace(/\?/g, (val, i) => `$${i + 1}`);
  const res = await pool.query(formattedSql, params);
  return res.rows;
};
const dbGet = async (sql, params = []) => (await dbAll(sql, params))[0] || null;
const dbRun = async (sql, params = []) => {
  const formattedSql = sql.replace(/\?/g, (val, i) => `$${i + 1}`);
  return await pool.query(formattedSql, params);
};

async function initDB() {
  try {
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
  } catch (e) { console.error('[DB] Gagal init:', e); }
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

app.get('/', (req, res) => res.json({ status: 'ok', server: 'SiVerif RHL v3.0 PG', uptime: Math.floor((Date.now()-START_TIME)/1000) }));

// Login Admin
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password salah' });
});

// Manajemen Admin Audit (Agency)
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  try {
    // Alias instansi AS agency agar cocok dengan frontend
    const admins = await dbAll(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
    res.json({ success: true, admins: admins, admin_users: admins, data: { admins: admins } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const finalInstansi = instansi || agency || '';
  try {
    const existing = await dbGet(`SELECT id FROM agency_admins WHERE username = $1`, [username]);
    if (existing) return res.status(400).json({ success: false, error: 'Username sudah ada' });
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1, $2, $3, $4)`,
      [name, username, hashPass(password), finalInstansi]);
    res.json({ success: true, message: 'Akun berhasil ditambahkan' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/agency/admins/:username', verifyAdmin, async (req, res) => {
  await dbRun(`DELETE FROM agency_admins WHERE username = $1`, [req.params.username]);
  res.json({ success: true });
});

// Dashboard Stats
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const total = (await dbGet(`SELECT COUNT(*) as n FROM licenses`)).n;
    const active = (await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)).n;
    const pending = (await dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`)).n;
    const logs = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);
    res.json({ 
      licenses: { total: parseInt(total), active: parseInt(active) }, 
      pending: parseInt(pending),
      recent_logs: logs 
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manajemen Lisensi
app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const list = await dbAll(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 100`);
  res.json({ data: list, total: list.length });
});

app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, valid_until, max_photos } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, email, whatsapp, tier, valid_until, max_photos) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [key, user_name, instansi, email, whatsapp, tier || 'full', valid_until || null, max_photos || 0]);
  res.json({ success: true, license_key: key });
});

app.delete('/api/admin/licenses/:key', verifyAdmin, async (req, res) => {
  await dbRun(`DELETE FROM licenses WHERE license_key = $1`, [req.params.key]);
  res.json({ success: true });
});

// Validasi Publik (Untuk Aplikasi Desktop)
app.post('/api/validate', async (req, res) => {
  const { license_key, device_id } = req.body;
  if (!license_key) return res.json({ valid: false, error: 'Key required' });
  const lic = await dbGet('SELECT * FROM licenses WHERE license_key = $1', [license_key.toUpperCase()]);
  if (!lic) return res.json({ valid: false, error: 'Not found' });
  if (lic.status !== 'active') return res.json({ valid: false, error: 'License ' + lic.status });
  
  await dbRun('UPDATE licenses SET last_check=NOW(), check_count=check_count+1 WHERE id=$1', [lic.id]);
  res.json({ valid: true, user_name: lic.user_name, instansi: lic.instansi, tier: lic.tier });
});

// Pendaftaran Mandiri
app.post('/api/register', async (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  await dbRun(`INSERT INTO pending_registrations (user_name, instansi, email, whatsapp, device_id) VALUES ($1,$2,$3,$4,$5)`,
    [user_name, instansi, email, whatsapp, device_id]);
  res.json({ success: true });
});

// Export App untuk Vercel
initDB().catch(console.error);
module.exports = app;
