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

// ── DATABASE (POSTGRESQL) ──
// Pastikan SSL diaktifkan untuk Supabase
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000, // 10 detik timeout
});

// Helper DB (Async/Await)
const dbAll   = async (sql, params = []) => {
  const client = await pool.connect();
  try {
    const res = await client.query(sql.replace(/\?/g, (val, i) => `$${i + 1}`), params);
    return res.rows;
  } finally { client.release(); }
};

const dbGet   = async (sql, params = []) => (await dbAll(sql, params))[0] || null;

const dbRun   = async (sql, params = []) => {
  const client = await pool.connect();
  try {
    return await client.query(sql.replace(/\?/g, (val, i) => `$${i + 1}`), params);
  } finally { client.release(); }
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
    console.log('[DB] PostgreSQL Tables Initialized Successfully');
  } catch (e) {
    console.error('[DB] Error initializing tables:', e.message);
  }
}

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json({ limit: '5mb' }));

function hashPass(p) { return crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex'); }

// Auth Middleware
function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token diperlukan' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (e) { res.status(401).json({ error: 'Sesi berakhir, silakan login kembali' }); }
}

// ── ENDPOINTS ──

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'SiVerif RHL Server Running', db: DATABASE_URL ? 'Connected' : 'Missing DATABASE_URL' });
});

// Diagnostic Endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await dbGet('SELECT NOW() as time');
    res.json({ success: true, db_time: result.time, url_used: DATABASE_URL ? DATABASE_URL.split('@')[1] : 'NOT_SET' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message, hint: 'Cek DATABASE_URL di Vercel Settings' });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password Admin Salah' });
});

app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const stats = await dbGet(`
      SELECT 
        (SELECT COUNT(*) FROM licenses) as total_lic,
        (SELECT COUNT(*) FROM licenses WHERE status='active') as active_lic,
        (SELECT COUNT(*) FROM pending_registrations WHERE status='pending') as pending_reg
    `);
    const logs = await dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);
    res.json({
      licenses: { total: parseInt(stats.total_lic), active: parseInt(stats.active_lic) },
      pending: parseInt(stats.pending_reg),
      recent_logs: logs
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Agency & Admins (Sangat Penting untuk Konsistensi Kolom)
app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  try {
    // Memberikan alias 'agency' agar kompatibel dengan frontend lama
    const admins = await dbAll(`SELECT id, name, username, instansi, instansi AS agency, created_at FROM agency_admins ORDER BY created_at DESC`);
    res.json({ success: true, admins, agency_name: 'Kementerian Lingkungan Hidup dan Kehutanan' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const finalInstansi = instansi || agency || 'Umum';
  try {
    await dbRun(`INSERT INTO agency_admins (name, username, password, instansi) VALUES ($1, $2, $3, $4)`, 
      [name, username, hashPass(password), finalInstansi]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Gagal menambah admin: ' + e.message }); }
});

app.delete('/api/admin/agency/admins/:username', verifyAdmin, async (req, res) => {
  try {
    await dbRun(`DELETE FROM agency_admins WHERE username = $1`, [req.params.username]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Management Lisensi
app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const list = await dbAll(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 500`);
  res.json({ data: list });
});

app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, tier, valid_until } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  try {
    await dbRun(`INSERT INTO licenses (license_key, user_name, instansi, tier, valid_until) VALUES ($1, $2, $3, $4, $5)`,
      [key, user_name, instansi, tier || 'full', valid_until || null]);
    res.json({ success: true, license_key: key });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Client Validation
app.post('/api/validate', async (req, res) => {
  const { license_key } = req.body;
  try {
    const lic = await dbGet(`SELECT * FROM licenses WHERE license_key = $1 AND status = 'active'`, [license_key?.toUpperCase()]);
    if (lic) {
      await dbRun(`UPDATE licenses SET last_check = NOW(), check_count = check_count + 1 WHERE id = $1`, [lic.id]);
      return res.json({ valid: true, user_name: lic.user_name, instansi: lic.instansi });
    }
    res.json({ valid: false, error: 'Lisensi Tidak Valid atau Nonaktif' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Init and Start
initDB().then(() => {
  if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`Server running locally on port ${PORT}`));
  }
});

module.exports = app;
