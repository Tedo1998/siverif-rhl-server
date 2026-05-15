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

// Auth Middleware
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

function logActivity(license_key, action, req, info = '') {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
  const device_id = req.body?.device_id || '';
  dbRun(`INSERT INTO activity_log (license_key, action, device_id, ip, info) VALUES ($1,$2,$3,$4,$5)`,
    [String(license_key), action, device_id, ip, info]).catch(console.error);
}

// ── ENDPOINTS ──

app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'SiVerif RHL Server', version: '3.0.0-PG', db: 'PostgreSQL/Supabase' });
});

// Login Admin
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin', ts: Date.now() }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password salah' });
});

// Dashboard
app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const total = (await dbGet(`SELECT COUNT(*) as n FROM licenses`)).n;
    const active = (await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)).n;
    const expired = (await dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='expired'`)).n;
    const pending = (await dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`)).n;
    const today = (await dbGet(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND created_at >= NOW() - INTERVAL '1 day'`)).n;
    
    const logs = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);
    const recentActive = await dbAll(`SELECT license_key, user_name, instansi, last_check, check_count FROM licenses WHERE last_check IS NOT NULL ORDER BY last_check DESC LIMIT 5`);

    res.json({
      licenses: { total: parseInt(total), active: parseInt(active), expired: parseInt(expired) },
      pending: parseInt(pending),
      activity: { validate_today: parseInt(today) },
      recent_active: recentActive,
      recent_logs: logs,
      server: { version: '3.0.0-PG', db: 'PostgreSQL' }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Agency Admins
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  const admins = await dbAll(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
  res.json({ success: true, admins, agency_name: 'Kementerian Lingkungan Hidup dan Kehutanan' });
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const finalInstansi = instansi || agency || '';
  try {
    const existing = await dbGet(`SELECT id FROM agency_admins WHERE username = $1`, [username]);
    if (existing) return res.status(400).json({ error: 'Username sudah ada' });
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1,$2,$3,$4)`,
      [name, username, hashPass(password), finalInstansi]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/agency/admins/:username', verifyAdmin, async (req, res) => {
  await dbRun(`DELETE FROM agency_admins WHERE username = $1`, [req.params.username]);
  res.json({ success: true });
});

// Licenses
app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { q, status } = req.query;
  let sql = `SELECT * FROM licenses WHERE 1=1`;
  const params = [];
  if (q) {
    sql += ` AND (license_key ILIKE $1 OR user_name ILIKE $1 OR instansi ILIKE $1)`;
    params.push(`%${q}%`);
  }
  if (status) {
    sql += ` AND status = $${params.length + 1}`;
    params.push(status);
  }
  sql += ` ORDER BY created_at DESC LIMIT 200`;
  const list = await dbAll(sql, params);
  res.json({ data: list, total: list.length });
});

app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, email, whatsapp, tier, status, max_photos, valid_until, device_locked) 
    VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9)`,
    [key, user_name, instansi, email, whatsapp, tier || 'full', max_photos || 0, valid_until || null, device_locked ? 1 : 0]);
  res.json({ success: true, license_key: key });
});

app.delete('/api/admin/licenses/:key', verifyAdmin, async (req, res) => {
  await dbRun(`DELETE FROM licenses WHERE license_key = $1`, [req.params.key]);
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/status', verifyAdmin, async (req, res) => {
  const { status } = req.body;
  await dbRun(`UPDATE licenses SET status = $1 WHERE license_key = $2`, [status, req.params.key]);
  res.json({ success: true });
});

// Pending Registrations
app.get('/api/admin/pending', verifyAdmin, async (req, res) => {
  const list = await dbAll(`SELECT * FROM pending_registrations WHERE status='pending' ORDER BY created_at DESC`);
  res.json(list);
});

app.post('/api/admin/pending/:id/approve', verifyAdmin, async (req, res) => {
  const p = await dbGet(`SELECT * FROM pending_registrations WHERE id = $1`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Tidak ditemukan' });
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const { tier, max_photos, valid_until, device_locked } = req.body;
  
  await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, email, whatsapp, tier, status, max_photos, valid_until, device_locked) 
    VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9)`,
    [key, p.user_name, p.instansi, p.email, p.whatsapp, tier || 'full', max_photos || 0, valid_until || null, device_locked ? 1 : 0]);
    
  await dbRun(`UPDATE pending_registrations SET status = 'approved' WHERE id = $1`, [req.params.id]);
  res.json({ success: true, license_key: key });
});

// Client API
app.post('/api/validate', async (req, res) => {
  const { license_key, device_id } = req.body;
  const lic = await dbGet(`SELECT * FROM licenses WHERE license_key = $1`, [license_key?.toUpperCase()]);
  if (!lic) return res.json({ valid: false, error: 'Key tidak terdaftar' });
  if (lic.status !== 'active') return res.json({ valid: false, error: 'Lisensi ' + lic.status });
  
  // Check valid_until if any
  if (lic.valid_until && new Date() > new Date(lic.valid_until)) {
    await dbRun(`UPDATE licenses SET status = 'expired' WHERE id = $1`, [lic.id]);
    return res.json({ valid: false, error: 'Lisensi expired' });
  }

  await dbRun(`UPDATE licenses SET last_check = NOW(), check_count = check_count + 1 WHERE id = $1`, [lic.id]);
  logActivity(license_key, 'VALIDATE_OK', req);
  res.json({ valid: true, user_name: lic.user_name, instansi: lic.instansi, tier: lic.tier });
});

app.post('/api/register', async (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  await dbRun(`INSERT INTO pending_registrations (user_name, instansi, email, whatsapp, device_id) VALUES ($1,$2,$3,$4,$5)`,
    [user_name, instansi, email, whatsapp, device_id]);
  res.json({ success: true });
});

// Initialize DB and Start
initDB().then(() => {
  if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  }
}).catch(console.error);

module.exports = app;
