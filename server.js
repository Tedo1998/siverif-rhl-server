/**
 * SiVerif RHL — License Server (sql.js version)
 * Pure JavaScript SQLite — works on Railway without compilation
 */

const express   = require('express');
const initSqlJs = require('sql.js');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const fs        = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET      = process.env.JWT_SECRET      || 'SiVerifRHL_DefaultSecret_ChangeMe_2025';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DB_PATH         = process.env.DB_PATH         || './siverif.db';

// ── DATABASE ─────────────────────────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key   TEXT    UNIQUE NOT NULL,
    user_name     TEXT    NOT NULL,
    instansi      TEXT    NOT NULL,
    email         TEXT    DEFAULT '',
    whatsapp      TEXT    DEFAULT '',
    tier          TEXT    DEFAULT 'full',
    status        TEXT    DEFAULT 'active',
    max_photos    INTEGER DEFAULT 0,
    valid_until   TEXT,
    device_id     TEXT,
    device_locked INTEGER DEFAULT 0,
    last_check    TEXT,
    check_count   INTEGER DEFAULT 0,
    notes         TEXT    DEFAULT '',
    created_at    TEXT    DEFAULT (datetime('now','localtime')),
    activated_at  TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS activity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT    DEFAULT '',
    action      TEXT    DEFAULT '',
    device_id   TEXT    DEFAULT '',
    ip          TEXT    DEFAULT '',
    info        TEXT    DEFAULT '',
    created_at  TEXT    DEFAULT (datetime('now','localtime'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS pending_registrations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name   TEXT NOT NULL,
    instansi    TEXT NOT NULL,
    email       TEXT DEFAULT '',
    whatsapp    TEXT DEFAULT '',
    device_id   TEXT DEFAULT '',
    status      TEXT DEFAULT 'pending',
    notes       TEXT DEFAULT '',
    created_at  TEXT DEFAULT (datetime('now','localtime'))
  )`);

  saveDB();
  console.log('[DB] Database initialized');
}

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Helper: run query and save
function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();
}

// Helper: get one row
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper: get all rows
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── MIDDLEWARE ───────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
const strictLimiter = rateLimit({ windowMs: 60*60*1000, max: 15 });
app.use('/api/', limiter);
app.use('/api/admin/login', strictLimiter);

// ── HELPERS ──────────────────────────────────────────────────────
function genKey() {
  const s = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `SVR-${s()}-${s()}-${s()}`;
}

function logActivity(license_key, action, req, info = '') {
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';
  const device_id = req.body?.device_id || '';
  dbRun(`INSERT INTO activity_log (license_key,action,device_id,ip,info) VALUES (?,?,?,?,?)`,
    [license_key, action, device_id, ip, info]);
}

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const p = jwt.verify(auth.slice(7), JWT_SECRET);
    if (p.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch { res.status(401).json({ error: 'Token tidak valid' }); }
}

// ── Health check ─────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'SiVerif RHL License Server', version: '1.0.0' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════

app.post('/api/validate', (req, res) => {
  const { license_key, device_id } = req.body;
  if (!license_key) return res.json({ valid: false, error: 'License key diperlukan', code: 'NO_KEY' });

  const lic = dbGet('SELECT * FROM licenses WHERE license_key = ?', [license_key]);
  if (!lic) {
    logActivity(license_key, 'VALIDATE_FAIL_NOT_FOUND', req);
    return res.json({ valid: false, error: 'Lisensi tidak ditemukan', code: 'NOT_FOUND' });
  }

  if (lic.status !== 'active') {
    logActivity(license_key, `VALIDATE_FAIL_${lic.status.toUpperCase()}`, req);
    const msgs = {
      inactive:  'Lisensi dinonaktifkan. Hubungi administrator.',
      expired:   'Lisensi telah kadaluarsa.',
      suspended: 'Lisensi ditangguhkan. Hubungi administrator.'
    };
    return res.json({ valid: false, error: msgs[lic.status] || 'Lisensi tidak aktif', code: lic.status.toUpperCase() });
  }

  if (lic.valid_until && new Date() > new Date(lic.valid_until)) {
    dbRun(`UPDATE licenses SET status='expired' WHERE license_key=?`, [license_key]);
    return res.json({ valid: false, error: 'Lisensi telah kadaluarsa.', code: 'EXPIRED' });
  }

  if (lic.device_locked && lic.device_id && device_id && lic.device_id !== device_id) {
    logActivity(license_key, 'VALIDATE_FAIL_DEVICE', req);
    return res.json({ valid: false, error: 'Lisensi terdaftar di perangkat lain. Hubungi administrator.', code: 'DEVICE_MISMATCH' });
  }

  if (lic.device_locked && !lic.device_id && device_id) {
    dbRun(`UPDATE licenses SET device_id=?, activated_at=datetime('now','localtime') WHERE license_key=?`, [device_id, license_key]);
  }

  dbRun(`UPDATE licenses SET last_check=datetime('now','localtime'), check_count=check_count+1 WHERE license_key=?`, [license_key]);
  logActivity(license_key, 'VALIDATE_OK', req);

  res.json({
    valid:       true,
    user_name:   lic.user_name,
    instansi:    lic.instansi,
    tier:        lic.tier,
    max_photos:  lic.max_photos,
    valid_until: lic.valid_until
  });
});

app.post('/api/register', (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  if (!user_name || !instansi) return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });
  dbRun(`INSERT INTO pending_registrations (user_name,instansi,email,whatsapp,device_id) VALUES (?,?,?,?,?)`,
    [user_name, instansi, email||'', whatsapp||'', device_id||'']);
  res.json({ success: true, message: 'Pendaftaran diterima. Tim kami akan menghubungi Anda.' });
});

// ════════════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const hash = p => crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex');
  if (hash(password) !== hash(SUPERADMIN_PASS)) {
    logActivity('SUPERADMIN', 'ADMIN_LOGIN_FAIL', req);
    return res.status(401).json({ error: 'Password salah' });
  }
  const token = jwt.sign({ role: 'superadmin', ts: Date.now() }, JWT_SECRET, { expiresIn: '12h' });
  logActivity('SUPERADMIN', 'ADMIN_LOGIN_OK', req);
  res.json({ token, expires_in: '12 jam' });
});

app.get('/api/admin/stats', verifyAdmin, (req, res) => {
  const total     = dbGet(`SELECT COUNT(*) as n FROM licenses`)?.n || 0;
  const active    = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)?.n || 0;
  const inactive  = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='inactive'`)?.n || 0;
  const suspended = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='suspended'`)?.n || 0;
  const expired   = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='expired'`)?.n || 0;
  const pending   = dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`)?.n || 0;
  const today     = dbGet(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND date(created_at)=date('now','localtime')`)?.n || 0;
  res.json({ total, active, inactive, suspended, expired, pending, validate_today: today });
});

app.get('/api/admin/licenses', verifyAdmin, (req, res) => {
  res.json(dbAll(`SELECT * FROM licenses ORDER BY created_at DESC`));
});

app.post('/api/admin/licenses', verifyAdmin, (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  if (!user_name || !instansi) return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });
  const key = genKey();
  dbRun(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,notes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [key, user_name, instansi, email||'', whatsapp||'', tier||'full', 'active',
     max_photos||0, valid_until||null, device_locked?1:0, notes||'']);
  logActivity(key, 'LICENSE_CREATED', req, `for ${user_name}`);
  res.json({ success: true, license_key: key });
});

app.patch('/api/admin/licenses/:key/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  if (!['active','inactive','suspended','expired'].includes(status))
    return res.status(400).json({ error: 'Status tidak valid' });
  const before = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!before) return res.status(404).json({ error: 'Tidak ditemukan' });
  dbRun(`UPDATE licenses SET status=? WHERE license_key=?`, [status, req.params.key]);
  logActivity(req.params.key, `STATUS_${status.toUpperCase()}`, req);
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/reset-device', verifyAdmin, (req, res) => {
  dbRun(`UPDATE licenses SET device_id=NULL WHERE license_key=?`, [req.params.key]);
  logActivity(req.params.key, 'DEVICE_RESET', req);
  res.json({ success: true });
});

app.delete('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  dbRun(`DELETE FROM licenses WHERE license_key=?`, [req.params.key]);
  logActivity(req.params.key, 'LICENSE_DELETED', req);
  res.json({ success: true });
});

app.get('/api/admin/pending', verifyAdmin, (req, res) => {
  res.json(dbAll(`SELECT * FROM pending_registrations ORDER BY created_at DESC`));
});

app.post('/api/admin/pending/:id/approve', verifyAdmin, (req, res) => {
  const p = dbGet(`SELECT * FROM pending_registrations WHERE id=?`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Tidak ditemukan' });
  const { tier, max_photos, valid_until, device_locked } = req.body;
  const key = genKey();
  dbRun(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,device_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [key, p.user_name, p.instansi, p.email, p.whatsapp,
     tier||'full', 'active', max_photos||0, valid_until||null,
     device_locked?1:0, p.device_id||null]);
  dbRun(`UPDATE pending_registrations SET status='approved' WHERE id=?`, [req.params.id]);
  logActivity(key, 'LICENSE_APPROVED', req);
  res.json({ success: true, license_key: key });
});

app.post('/api/admin/pending/:id/reject', verifyAdmin, (req, res) => {
  dbRun(`UPDATE pending_registrations SET status='rejected', notes=? WHERE id=?`,
    [req.body.reason||'', req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/logs', verifyAdmin, (req, res) => {
  res.json(dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 500`));
});

// ── START ─────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n╔══════════════════════════════════════╗`);
    console.log(`║  SiVerif RHL License Server v1.0     ║`);
    console.log(`║  Port: ${PORT}                          ║`);
    console.log(`╚══════════════════════════════════════╝\n`);
  });
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
