/**
 * SiVerif RHL — License Server
 * Backend API untuk validasi lisensi & manajemen user
 * Deploy ke: Railway / Render / VPS
 */

const express    = require('express');
const Database   = require('better-sqlite3');
const crypto     = require('crypto');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const fs         = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── ENV SECRETS (set di Railway/Render environment variables) ────
const JWT_SECRET      = process.env.JWT_SECRET      || 'GANTI_DENGAN_SECRET_PANJANG_ANDA';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DB_PATH         = process.env.DB_PATH         || './siverif.db';

// ── DATABASE SETUP ───────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key   TEXT    UNIQUE NOT NULL,
    user_name     TEXT    NOT NULL,
    instansi      TEXT    NOT NULL,
    email         TEXT,
    whatsapp      TEXT,
    tier          TEXT    DEFAULT 'full',   -- 'demo' | 'full'
    status        TEXT    DEFAULT 'active', -- 'active' | 'inactive' | 'expired' | 'suspended'
    max_photos    INTEGER DEFAULT 0,        -- 0 = unlimited
    valid_until   TEXT,                     -- NULL = lifetime
    device_id     TEXT,                     -- fingerprint perangkat terikat
    device_locked INTEGER DEFAULT 0,        -- 1 = terkunci ke 1 perangkat
    last_check    TEXT,
    check_count   INTEGER DEFAULT 0,
    notes         TEXT,
    created_at    TEXT    DEFAULT (datetime('now','localtime')),
    activated_at  TEXT
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    action      TEXT,
    device_id   TEXT,
    ip          TEXT,
    info        TEXT,
    created_at  TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS pending_registrations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name   TEXT NOT NULL,
    instansi    TEXT NOT NULL,
    email       TEXT,
    whatsapp    TEXT,
    device_id   TEXT,
    status      TEXT DEFAULT 'pending', -- 'pending' | 'approved' | 'rejected'
    notes       TEXT,
    created_at  TEXT DEFAULT (datetime('now','localtime'))
  );
`);

// ── MIDDLEWARE ───────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({ windowMs: 15*60*1000, max: 60, message: { error: 'Terlalu banyak permintaan' } });
const strictLimiter = rateLimit({ windowMs: 60*60*1000, max: 10, message: { error: 'Terlalu banyak percobaan' } });
app.use('/api/', limiter);
app.use('/api/admin/login', strictLimiter);

// ── HELPERS ──────────────────────────────────────────────────────
function hashPass(p) { return crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex'); }

function genLicenseKey() {
  const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `SVR-${seg()}-${seg()}-${seg()}`;
}

function log(license_key, action, req, info='') {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  const device_id = req.body?.device_id || '';
  db.prepare(`INSERT INTO activity_log (license_key,action,device_id,ip,info) VALUES (?,?,?,?,?)`)
    .run(license_key, action, device_id, ip, info);
}

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    if (payload.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch { res.status(401).json({ error: 'Token tidak valid atau expired' }); }
}

// ════════════════════════════════════════════════════════════════
// PUBLIC API (digunakan oleh aplikasi client)
// ════════════════════════════════════════════════════════════════

// POST /api/validate — validasi lisensi saat aplikasi dibuka
app.post('/api/validate', (req, res) => {
  const { license_key, device_id } = req.body;
  if (!license_key) return res.status(400).json({ valid: false, error: 'License key diperlukan' });

  const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(license_key);
  if (!lic) {
    log(license_key, 'VALIDATE_FAIL_NOT_FOUND', req);
    return res.json({ valid: false, error: 'Lisensi tidak ditemukan', code: 'NOT_FOUND' });
  }

  if (lic.status !== 'active') {
    log(license_key, `VALIDATE_FAIL_${lic.status.toUpperCase()}`, req);
    const msgs = { inactive: 'Lisensi dinonaktifkan. Hubungi administrator.', expired: 'Lisensi telah kadaluarsa.', suspended: 'Lisensi ditangguhkan. Hubungi administrator.' };
    return res.json({ valid: false, error: msgs[lic.status] || 'Lisensi tidak aktif', code: lic.status.toUpperCase() });
  }

  // Cek expired date
  if (lic.valid_until) {
    const now = new Date();
    const exp = new Date(lic.valid_until);
    if (now > exp) {
      db.prepare(`UPDATE licenses SET status='expired' WHERE license_key=?`).run(license_key);
      log(license_key, 'VALIDATE_FAIL_EXPIRED', req);
      return res.json({ valid: false, error: 'Lisensi telah kadaluarsa.', code: 'EXPIRED' });
    }
  }

  // Device lock: jika lisensi terkunci ke 1 perangkat
  if (lic.device_locked && lic.device_id) {
    if (device_id && lic.device_id !== device_id) {
      log(license_key, 'VALIDATE_FAIL_DEVICE', req, `expected:${lic.device_id} got:${device_id}`);
      return res.json({ valid: false, error: 'Lisensi ini terdaftar di perangkat lain. Hubungi administrator.', code: 'DEVICE_MISMATCH' });
    }
  }

  // Jika device belum terikat, ikat sekarang
  if (lic.device_locked && !lic.device_id && device_id) {
    db.prepare(`UPDATE licenses SET device_id=?, activated_at=datetime('now','localtime') WHERE license_key=?`).run(device_id, license_key);
  }

  // Update last check
  db.prepare(`UPDATE licenses SET last_check=datetime('now','localtime'), check_count=check_count+1 WHERE license_key=?`).run(license_key);
  log(license_key, 'VALIDATE_OK', req);

  res.json({
    valid: true,
    user_name:   lic.user_name,
    instansi:    lic.instansi,
    tier:        lic.tier,
    max_photos:  lic.max_photos,
    valid_until: lic.valid_until,
    check_count: lic.check_count + 1
  });
});

// POST /api/register — user daftar mandiri (pending approval)
app.post('/api/register', (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  if (!user_name || !instansi) return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });

  db.prepare(`INSERT INTO pending_registrations (user_name,instansi,email,whatsapp,device_id) VALUES (?,?,?,?,?)`)
    .run(user_name, instansi, email||'', whatsapp||'', device_id||'');

  log('PENDING', 'SELF_REGISTER', req, `${user_name} - ${instansi}`);
  res.json({ success: true, message: 'Pendaftaran diterima. Tim kami akan menghubungi Anda segera.' });
});

// ════════════════════════════════════════════════════════════════
// SUPER ADMIN API (hanya Anda yang bisa akses)
// ════════════════════════════════════════════════════════════════

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) !== hashPass(SUPERADMIN_PASS)) {
    log('SUPERADMIN', 'ADMIN_LOGIN_FAIL', req);
    return res.status(401).json({ error: 'Password salah' });
  }
  const token = jwt.sign({ role: 'superadmin', ts: Date.now() }, JWT_SECRET, { expiresIn: '12h' });
  log('SUPERADMIN', 'ADMIN_LOGIN_OK', req);
  res.json({ token, expires_in: '12 jam' });
});

// GET /api/admin/licenses — semua lisensi
app.get('/api/admin/licenses', verifyAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM licenses ORDER BY created_at DESC`).all();
  res.json(rows);
});

// POST /api/admin/licenses — buat lisensi baru
app.post('/api/admin/licenses', verifyAdmin, (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  if (!user_name || !instansi) return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });

  const key = genLicenseKey();
  db.prepare(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(key, user_name, instansi, email||'', whatsapp||'',
         tier||'full', 'active',
         max_photos||0, valid_until||null,
         device_locked?1:0, notes||'');

  log(key, 'LICENSE_CREATED', req, `by superadmin for ${user_name}`);
  res.json({ success: true, license_key: key });
});

// PATCH /api/admin/licenses/:key/status — aktif/nonaktif/suspend
app.patch('/api/admin/licenses/:key/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  const allowed = ['active','inactive','suspended','expired'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Status tidak valid' });

  const r = db.prepare(`UPDATE licenses SET status=? WHERE license_key=?`).run(status, req.params.key);
  if (!r.changes) return res.status(404).json({ error: 'Lisensi tidak ditemukan' });

  log(req.params.key, `STATUS_CHANGED_TO_${status.toUpperCase()}`, req);
  res.json({ success: true });
});

// PATCH /api/admin/licenses/:key — update data lisensi
app.patch('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  db.prepare(`UPDATE licenses SET user_name=COALESCE(?,user_name), instansi=COALESCE(?,instansi),
    email=COALESCE(?,email), whatsapp=COALESCE(?,whatsapp), tier=COALESCE(?,tier),
    max_photos=COALESCE(?,max_photos), valid_until=COALESCE(?,valid_until),
    device_locked=COALESCE(?,device_locked), notes=COALESCE(?,notes)
    WHERE license_key=?`)
    .run(user_name||null,instansi||null,email||null,whatsapp||null,tier||null,
         max_photos!=null?max_photos:null, valid_until!==undefined?valid_until:null,
         device_locked!=null?device_locked:null, notes||null, req.params.key);

  log(req.params.key, 'LICENSE_UPDATED', req);
  res.json({ success: true });
});

// DELETE /api/admin/licenses/:key — hapus lisensi
app.delete('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  db.prepare(`DELETE FROM licenses WHERE license_key=?`).run(req.params.key);
  log(req.params.key, 'LICENSE_DELETED', req);
  res.json({ success: true });
});

// PATCH /api/admin/licenses/:key/reset-device — reset device lock
app.patch('/api/admin/licenses/:key/reset-device', verifyAdmin, (req, res) => {
  db.prepare(`UPDATE licenses SET device_id=NULL WHERE license_key=?`).run(req.params.key);
  log(req.params.key, 'DEVICE_RESET', req);
  res.json({ success: true, message: 'Device lock direset. User bisa aktivasi di perangkat baru.' });
});

// GET /api/admin/pending — daftar registrasi menunggu
app.get('/api/admin/pending', verifyAdmin, (req, res) => {
  res.json(db.prepare(`SELECT * FROM pending_registrations ORDER BY created_at DESC`).all());
});

// POST /api/admin/pending/:id/approve — setujui & buat lisensi
app.post('/api/admin/pending/:id/approve', verifyAdmin, (req, res) => {
  const p = db.prepare(`SELECT * FROM pending_registrations WHERE id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Tidak ditemukan' });

  const { tier, max_photos, valid_until, device_locked } = req.body;
  const key = genLicenseKey();

  db.prepare(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,device_id)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(key, p.user_name, p.instansi, p.email, p.whatsapp,
         tier||'full','active', max_photos||0, valid_until||null,
         device_locked?1:0, p.device_id||null);

  db.prepare(`UPDATE pending_registrations SET status='approved' WHERE id=?`).run(req.params.id);
  log(key, 'LICENSE_APPROVED', req, `from pending id ${req.params.id}`);
  res.json({ success: true, license_key: key });
});

// POST /api/admin/pending/:id/reject
app.post('/api/admin/pending/:id/reject', verifyAdmin, (req, res) => {
  db.prepare(`UPDATE pending_registrations SET status='rejected', notes=? WHERE id=?`)
    .run(req.body.reason||'', req.params.id);
  res.json({ success: true });
});

// GET /api/admin/logs — activity log
app.get('/api/admin/logs', verifyAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 500`).all();
  res.json(rows);
});

// GET /api/admin/stats — dashboard stats
app.get('/api/admin/stats', verifyAdmin, (req, res) => {
  const total    = db.prepare(`SELECT COUNT(*) as n FROM licenses`).get().n;
  const active   = db.prepare(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`).get().n;
  const inactive = db.prepare(`SELECT COUNT(*) as n FROM licenses WHERE status='inactive'`).get().n;
  const suspended= db.prepare(`SELECT COUNT(*) as n FROM licenses WHERE status='suspended'`).get().n;
  const expired  = db.prepare(`SELECT COUNT(*) as n FROM licenses WHERE status='expired'`).get().n;
  const pending  = db.prepare(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`).get().n;
  const today    = db.prepare(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND date(created_at)=date('now','localtime')`).get().n;
  res.json({ total, active, inactive, suspended, expired, pending, validate_today: today });
});

// ── START SERVER ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║  SiVerif RHL License Server              ║`);
  console.log(`║  Running on port ${PORT}                   ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
});

module.exports = app;
