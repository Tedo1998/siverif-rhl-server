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
const DATABASE_URL    = process.env.DATABASE_URL; // Dari Vercel Env

// ── DATABASE (POSTGRESQL) ──
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id            SERIAL PRIMARY KEY,
        license_key   TEXT UNIQUE NOT NULL,
        user_name     TEXT NOT NULL,
        instansi      TEXT NOT NULL,
        email         TEXT DEFAULT '',
        whatsapp      TEXT DEFAULT '',
        tier          TEXT DEFAULT 'full',
        status        TEXT DEFAULT 'active',
        max_photos    INTEGER DEFAULT 0,
        valid_until   TIMESTAMP,
        device_id     TEXT,
        device_locked INTEGER DEFAULT 0,
        last_check    TIMESTAMP,
        check_count   INTEGER DEFAULT 0,
        notes         TEXT DEFAULT '',
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activated_at  TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS activity_log (
        id          SERIAL PRIMARY KEY,
        license_key TEXT DEFAULT '',
        action      TEXT DEFAULT '',
        device_id   TEXT DEFAULT '',
        ip          TEXT DEFAULT '',
        info        TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS pending_registrations (
        id          SERIAL PRIMARY KEY,
        user_name   TEXT NOT NULL,
        instansi    TEXT NOT NULL,
        email       TEXT DEFAULT '',
        whatsapp    TEXT DEFAULT '',
        device_id   TEXT DEFAULT '',
        status      TEXT DEFAULT 'pending',
        notes       TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS agency_admins (
        id         SERIAL PRIMARY KEY,
        name       TEXT NOT NULL,
        username   TEXT UNIQUE NOT NULL,
        password   TEXT NOT NULL,
        instansi   TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('[DB] Database PostgreSQL Siap');
  } finally {
    client.release();
  }
}

// Helper Query
const dbQuery = (text, params) => pool.query(text, params);

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json());

// Init DB saat startup (Vercel Serverless)
initDB().catch(console.error);

// ── ENDPOINTS (Sama seperti versi sebelumnya, hanya ganti query) ──

app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'SiVerif RHL Server', db: 'PostgreSQL/Supabase' });
});

// Login Admin
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === SUPERADMIN_PASS) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password salah' });
});

// Contoh Endpoint Validate yang sudah di-update ke PG
app.post('/api/validate', async (req, res) => {
  const { license_key, device_id } = req.body;
  try {
    const r = await dbQuery('SELECT * FROM licenses WHERE license_key = $1', [license_key?.toUpperCase()]);
    if (r.rows.length === 0) return res.json({ valid: false, error: 'Lisensi tidak ditemukan' });
    
    const lic = r.rows[0];
    // ... logika validasi lainnya (Sama seperti sebelumnya)
    
    await dbQuery('UPDATE licenses SET last_check=NOW(), check_count=check_count+1 WHERE id=$1', [lic.id]);
    res.json({ valid: true, user_name: lic.user_name, instansi: lic.instansi });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Export App untuk Vercel
module.exports = app;

// Port Listener (Hanya untuk local development)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
