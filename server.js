/**
 * SiVerif RHL — License Server v3.0
 * Node.js + sql.js (pure JS SQLite)
 * Deploy: Railway / Render / Koyeb / Fly.io
 *
 * FITUR BARU v3.0:
 * - Endpoint PATCH /api/admin/licenses/:key/extend  (perpanjang masa aktif)
 * - Endpoint POST  /api/admin/bulk                  (buat lisensi massal)
 * - Endpoint GET   /api/admin/export/csv            (export CSV + header BOM)
 * - Endpoint GET   /api/admin/dashboard             (stats lengkap sekaligus)
 * - Endpoint POST  /api/admin/reset-password        (ganti password admin)
 * - Notifikasi WhatsApp via Fonnte API (opsional)
 * - Rate limiting per-IP lebih ketat
 * - Auto-backup DB ke file .bak setiap startup
 * - Pagination pada list lisensi & log
 * - Search/filter lisensi dari server
 * - CORS whitelist (opsional via env WEB_ORIGIN)
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
const START_TIME = new Date();

// ── KONFIGURASI (env vars) ────────────────────────────────────────
const JWT_SECRET      = process.env.JWT_SECRET      || 'SiVerifRHL_DefaultSecret_GANTI_INI_2025!';
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'AdminSiVerif2025!';
const DB_PATH         = process.env.DB_PATH         || './siverif.db';
const FONNTE_TOKEN    = process.env.FONNTE_TOKEN     || '';   // opsional: notif WA
const WEB_ORIGIN      = process.env.WEB_ORIGIN      || '*';  // CORS origin

// ── DATABASE ─────────────────────────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();

  // Backup otomatis saat startup
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
    try { fs.copyFileSync(DB_PATH, DB_PATH + '.bak'); } catch {}
    console.log(`[DB] Database dimuat dari ${DB_PATH}`);
  } else {
    db = new SQL.Database();
    console.log('[DB] Database baru dibuat');
  }

  // Skema
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

  // Index untuk performa
  db.run(`CREATE INDEX IF NOT EXISTS idx_lic_key    ON licenses(license_key)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_lic_status ON licenses(status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_log_key    ON activity_log(license_key)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_log_ts     ON activity_log(created_at)`);

  saveDB();
  autoExpireCheck();
  cleanOldLogs();

  console.log('[DB] Database siap');
}

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();
}

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

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── AUTO-EXPIRE ──────────────────────────────────────────────────
function autoExpireCheck() {
  db.run(`UPDATE licenses SET status='expired'
    WHERE status='active' AND valid_until IS NOT NULL
    AND valid_until < datetime('now','localtime')`);
  saveDB();
}

function cleanOldLogs() {
  db.run(`DELETE FROM activity_log WHERE created_at < datetime('now','localtime','-30 days')`);
  saveDB();
}

// ── MIDDLEWARE ───────────────────────────────────────────────────
app.use(cors({
  origin: WEB_ORIGIN === '*' ? true : WEB_ORIGIN.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 150,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Terlalu banyak request. Coba lagi dalam 15 menit.' }
});
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  message: { error: 'Terlalu banyak percobaan login. Coba lagi dalam 1 jam.' }
});
const validateLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { valid: false, error: 'Terlalu banyak validasi. Tunggu 1 menit.', code: 'RATE_LIMIT' }
});

app.use('/api/', apiLimiter);
app.use('/api/admin/login', loginLimiter);
app.use('/api/validate', validateLimiter);

// ── HELPERS ──────────────────────────────────────────────────────
function genKey() {
  const s = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `SVR-${s()}-${s()}-${s()}`;
}

function logActivity(license_key, action, req, info = '') {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
          || req.socket?.remoteAddress || '';
  const device_id = req.body?.device_id || '';
  dbRun(`INSERT INTO activity_log (license_key,action,device_id,ip,info) VALUES (?,?,?,?,?)`,
    [String(license_key), action, device_id, ip, info]);
}

function verifyAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized — token diperlukan' });
  try {
    const p = jwt.verify(auth.slice(7), JWT_SECRET);
    if (p.role !== 'superadmin')
      return res.status(403).json({ error: 'Forbidden — bukan superadmin' });
    req.admin = p;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Token kadaluarsa, silakan login ulang' });
    res.status(401).json({ error: 'Token tidak valid' });
  }
}

function hashPass(p) {
  return crypto.createHash('sha256').update(p + JWT_SECRET).digest('hex');
}

// Notifikasi WA via Fonnte (opsional)
async function sendWA(phone, message) {
  if (!FONNTE_TOKEN || !phone) return;
  try {
    await fetch('https://api.fonnte.com/send', {
      method: 'POST',
      headers: { 'Authorization': FONNTE_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: phone, message })
    });
  } catch (e) {
    console.warn('[WA] Gagal kirim notifikasi:', e.message);
  }
}

// ════════════════════════════════════════════════════════════════
// HEALTH & INFO
// ════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  autoExpireCheck();
  const uptimeSec = Math.floor((Date.now() - START_TIME.getTime()) / 1000);
  const dbSize    = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
  const total     = dbGet(`SELECT COUNT(*) as n FROM licenses`)?.n || 0;
  const active    = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)?.n || 0;
  res.json({
    status: 'ok',
    app: 'SiVerif RHL License Server',
    version: '3.0.0',
    uptime_seconds: uptimeSec,
    uptime_human: formatUptime(uptimeSec),
    db_size_bytes: dbSize,
    licenses: { total, active },
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString(), uptime: process.uptime() });
});

function formatUptime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}j ${m}m`;
}

// ════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════

// Validasi lisensi
app.post('/api/validate', (req, res) => {
  const { license_key, device_id } = req.body;
  if (!license_key)
    return res.json({ valid: false, error: 'License key diperlukan', code: 'NO_KEY' });

  const key = String(license_key).trim().toUpperCase();
  const lic = dbGet('SELECT * FROM licenses WHERE license_key = ?', [key]);

  if (!lic) {
    logActivity(key, 'VALIDATE_FAIL_NOT_FOUND', req);
    return res.json({ valid: false, error: 'Lisensi tidak ditemukan', code: 'NOT_FOUND' });
  }

  if (lic.status !== 'active') {
    logActivity(key, `VALIDATE_FAIL_${lic.status.toUpperCase()}`, req);
    const msgs = {
      inactive:  'Lisensi dinonaktifkan. Hubungi administrator.',
      expired:   'Lisensi telah kadaluarsa. Hubungi administrator untuk perpanjangan.',
      suspended: 'Lisensi ditangguhkan sementara. Hubungi administrator.'
    };
    return res.json({ valid: false, error: msgs[lic.status] || 'Lisensi tidak aktif', code: lic.status.toUpperCase() });
  }

  // Cek expired by date
  if (lic.valid_until && new Date() > new Date(lic.valid_until)) {
    dbRun(`UPDATE licenses SET status='expired' WHERE license_key=?`, [key]);
    logActivity(key, 'VALIDATE_FAIL_EXPIRED', req);
    return res.json({ valid: false, error: 'Lisensi telah kadaluarsa.', code: 'EXPIRED' });
  }

  // Cek device lock
  if (lic.device_locked) {
    if (lic.device_id && device_id && lic.device_id !== device_id) {
      logActivity(key, 'VALIDATE_FAIL_DEVICE', req);
      return res.json({ valid: false, error: 'Lisensi terdaftar di perangkat lain. Hubungi administrator.', code: 'DEVICE_MISMATCH' });
    }
    // Kunci ke device pertama kali
    if (!lic.device_id && device_id) {
      dbRun(`UPDATE licenses SET device_id=?, activated_at=datetime('now','localtime') WHERE license_key=?`,
        [device_id, key]);
    }
  }

  dbRun(`UPDATE licenses SET last_check=datetime('now','localtime'), check_count=check_count+1 WHERE license_key=?`, [key]);
  logActivity(key, 'VALIDATE_OK', req);

  res.json({
    valid:        true,
    user_name:    lic.user_name,
    instansi:     lic.instansi,
    tier:         lic.tier,
    max_photos:   lic.max_photos,
    valid_until:  lic.valid_until,
    activated_at: lic.activated_at
  });
});

// Pendaftaran mandiri user
app.post('/api/register', (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  if (!user_name?.trim() || !instansi?.trim())
    return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });

  if (whatsapp) {
    const dup = dbGet(`SELECT id FROM pending_registrations WHERE whatsapp=? AND status='pending'`, [whatsapp]);
    if (dup) return res.status(400).json({ error: 'Nomor WhatsApp sudah mendaftar dan sedang diproses' });
  }

  dbRun(`INSERT INTO pending_registrations (user_name,instansi,email,whatsapp,device_id) VALUES (?,?,?,?,?)`,
    [user_name.trim(), instansi.trim(), email||'', whatsapp||'', device_id||'']);

  logActivity('REGISTER', 'SELF_REGISTER', req, `${user_name} @ ${instansi}`);
  res.json({ success: true, message: 'Pendaftaran diterima. Tim kami akan menghubungi Anda segera.' });
});

// ════════════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════════════

// Login admin
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password wajib diisi' });
  if (hashPass(password) !== hashPass(SUPERADMIN_PASS)) {
    logActivity('SUPERADMIN', 'ADMIN_LOGIN_FAIL', req);
    return res.status(401).json({ error: 'Password salah' });
  }
  const token = jwt.sign({ role: 'superadmin', ts: Date.now() }, JWT_SECRET, { expiresIn: '24h' });
  logActivity('SUPERADMIN', 'ADMIN_LOGIN_OK', req);
  res.json({ token, expires_in: '24 jam' });
});

// Dashboard stats lengkap (1 request)
app.get('/api/admin/dashboard', verifyAdmin, (req, res) => {
  autoExpireCheck();
  const total     = dbGet(`SELECT COUNT(*) as n FROM licenses`)?.n || 0;
  const active    = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active'`)?.n || 0;
  const inactive  = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='inactive'`)?.n || 0;
  const suspended = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='suspended'`)?.n || 0;
  const expired   = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='expired'`)?.n || 0;
  const pending   = dbGet(`SELECT COUNT(*) as n FROM pending_registrations WHERE status='pending'`)?.n || 0;
  const today     = dbGet(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND date(created_at)=date('now','localtime')`)?.n || 0;
  const week      = dbGet(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND created_at >= datetime('now','localtime','-7 days')`)?.n || 0;
  const month     = dbGet(`SELECT COUNT(*) as n FROM activity_log WHERE action='VALIDATE_OK' AND created_at >= datetime('now','localtime','-30 days')`)?.n || 0;
  const expireSoon = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE status='active' AND valid_until IS NOT NULL AND valid_until <= datetime('now','localtime','+7 days')`)?.n || 0;
  const dbSize    = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
  const uptimeSec = Math.floor((Date.now() - START_TIME.getTime()) / 1000);

  // Top 5 aktif terakhir
  const recentActive = dbAll(`SELECT license_key, user_name, instansi, last_check, check_count FROM licenses WHERE last_check IS NOT NULL ORDER BY last_check DESC LIMIT 5`);

  // Log terakhir 10
  const recentLogs = dbAll(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10`);

  res.json({
    licenses: { total, active, inactive, suspended, expired, expire_soon: expireSoon },
    pending,
    activity: { validate_today: today, validate_week: week, validate_month: month },
    server: { uptime_seconds: uptimeSec, uptime_human: formatUptime(uptimeSec), db_size: dbSize, version: '3.0.0' },
    recent_active: recentActive,
    recent_logs: recentLogs
  });
});

// List lisensi dengan pagination & search
app.get('/api/admin/licenses', verifyAdmin, (req, res) => {
  autoExpireCheck();
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const limit  = Math.min(200, Math.max(10, parseInt(req.query.limit) || 50));
  const offset = (page - 1) * limit;
  const search = req.query.q || '';
  const status = req.query.status || '';

  let where = '1=1';
  const params = [];
  if (search) {
    where += ` AND (license_key LIKE ? OR user_name LIKE ? OR instansi LIKE ? OR email LIKE ? OR whatsapp LIKE ?)`;
    const s = `%${search}%`;
    params.push(s, s, s, s, s);
  }
  if (status) {
    where += ` AND status=?`;
    params.push(status);
  }

  const total = dbGet(`SELECT COUNT(*) as n FROM licenses WHERE ${where}`, params)?.n || 0;
  const list  = dbAll(`SELECT * FROM licenses WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]);

  res.json({ data: list, total, page, limit, pages: Math.ceil(total / limit) });
});

// Detail 1 lisensi
app.get('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });
  const logs = dbAll(`SELECT * FROM activity_log WHERE license_key=? ORDER BY created_at DESC LIMIT 20`, [req.params.key]);
  res.json({ ...lic, recent_logs: logs });
});

// Buat lisensi baru
app.post('/api/admin/licenses', verifyAdmin, (req, res) => {
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  if (!user_name?.trim() || !instansi?.trim())
    return res.status(400).json({ error: 'Nama dan instansi wajib diisi' });

  const key = genKey();
  dbRun(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,notes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [key, user_name.trim(), instansi.trim(), email||'', whatsapp||'',
     tier||'full', 'active', max_photos||0, valid_until||null,
     device_locked?1:0, notes||'']);
  logActivity(key, 'LICENSE_CREATED', req, `for ${user_name} @ ${instansi}`);

  // Notif WA opsional
  if (whatsapp) {
    const validStr = valid_until ? `s/d ${valid_until.slice(0,10)}` : 'Selamanya';
    sendWA(whatsapp, `Halo ${user_name},\n\nLisensi SiVerif RHL Anda telah aktif:\n\n🔑 License Key: ${key}\n⏳ Berlaku: ${validStr}\n\nSimpan kode ini dengan aman.\n\nTerima kasih.`);
  }

  res.json({ success: true, license_key: key });
});

// Buat lisensi massal (bulk)
app.post('/api/admin/bulk', verifyAdmin, (req, res) => {
  const { items } = req.body; // array of {user_name, instansi, email, whatsapp, tier, valid_until}
  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'items harus berupa array tidak kosong' });
  if (items.length > 100)
    return res.status(400).json({ error: 'Maksimal 100 lisensi sekaligus' });

  const results = [];
  for (const item of items) {
    if (!item.user_name?.trim() || !item.instansi?.trim()) {
      results.push({ error: 'Nama & instansi wajib diisi', item });
      continue;
    }
    const key = genKey();
    dbRun(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,notes)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [key, item.user_name.trim(), item.instansi.trim(), item.email||'', item.whatsapp||'',
       item.tier||'full', 'active', item.max_photos||0, item.valid_until||null,
       item.device_locked?1:0, item.notes||'']);
    logActivity(key, 'LICENSE_BULK_CREATED', req, `bulk: ${item.user_name}`);
    results.push({ license_key: key, user_name: item.user_name, instansi: item.instansi });
  }

  res.json({ success: true, count: results.filter(r => r.license_key).length, results });
});

// Edit data lisensi
app.put('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });

  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  dbRun(`UPDATE licenses SET
    user_name=?, instansi=?, email=?, whatsapp=?, tier=?,
    max_photos=?, valid_until=?, device_locked=?, notes=?
    WHERE license_key=?`,
    [
      user_name?.trim() || lic.user_name,
      instansi?.trim()  || lic.instansi,
      email     !== undefined ? email    : lic.email,
      whatsapp  !== undefined ? whatsapp : lic.whatsapp,
      tier      || lic.tier,
      max_photos !== undefined ? max_photos : lic.max_photos,
      valid_until !== undefined ? (valid_until||null) : lic.valid_until,
      device_locked !== undefined ? (device_locked?1:0) : lic.device_locked,
      notes !== undefined ? notes : lic.notes,
      req.params.key
    ]);
  logActivity(req.params.key, 'LICENSE_EDITED', req);
  res.json({ success: true });
});

// Perpanjang masa aktif
app.patch('/api/admin/licenses/:key/extend', verifyAdmin, (req, res) => {
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });

  const { days, new_date } = req.body;
  let newDate;

  if (new_date) {
    newDate = new Date(new_date).toISOString().slice(0,19).replace('T',' ');
  } else if (days) {
    const base = lic.valid_until && new Date(lic.valid_until) > new Date()
      ? new Date(lic.valid_until)
      : new Date();
    base.setDate(base.getDate() + parseInt(days));
    newDate = base.toISOString().slice(0,19).replace('T',' ');
  } else {
    return res.status(400).json({ error: 'Harap sertakan days atau new_date' });
  }

  dbRun(`UPDATE licenses SET valid_until=?, status=CASE WHEN status='expired' THEN 'active' ELSE status END WHERE license_key=?`,
    [newDate, req.params.key]);
  logActivity(req.params.key, 'LICENSE_EXTENDED', req, `until ${newDate}`);
  res.json({ success: true, new_valid_until: newDate });
});

// Ubah status
app.patch('/api/admin/licenses/:key/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  if (!['active','inactive','suspended','expired'].includes(status))
    return res.status(400).json({ error: 'Status tidak valid' });
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });
  dbRun(`UPDATE licenses SET status=? WHERE license_key=?`, [status, req.params.key]);
  logActivity(req.params.key, `STATUS_${status.toUpperCase()}`, req);
  res.json({ success: true });
});

// Reset device
app.patch('/api/admin/licenses/:key/reset-device', verifyAdmin, (req, res) => {
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });
  dbRun(`UPDATE licenses SET device_id=NULL, activated_at=NULL WHERE license_key=?`, [req.params.key]);
  logActivity(req.params.key, 'DEVICE_RESET', req);
  res.json({ success: true });
});

// Hapus lisensi
app.delete('/api/admin/licenses/:key', verifyAdmin, (req, res) => {
  const lic = dbGet(`SELECT * FROM licenses WHERE license_key=?`, [req.params.key]);
  if (!lic) return res.status(404).json({ error: 'Tidak ditemukan' });
  dbRun(`DELETE FROM licenses WHERE license_key=?`, [req.params.key]);
  logActivity(req.params.key, 'LICENSE_DELETED', req, `${lic.user_name} @ ${lic.instansi}`);
  res.json({ success: true });
});

// Export CSV
app.get('/api/admin/export/csv', verifyAdmin, (req, res) => {
  autoExpireCheck();
  const list = dbAll(`SELECT * FROM licenses ORDER BY created_at DESC`);
  const headers = ['license_key','user_name','instansi','email','whatsapp','tier','status',
    'max_photos','valid_until','device_id','device_locked','last_check','check_count','notes','created_at','activated_at'];
  const esc = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const rows = [headers.join(','), ...list.map(r => headers.map(h => esc(r[h])).join(','))];
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="siverif-licenses-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send('\ufeff' + rows.join('\r\n'));
});

// ── PENDING ──────────────────────────────────────────────────────
app.get('/api/admin/pending', verifyAdmin, (req, res) => {
  const status = req.query.status || 'pending';
  if (status === 'all') return res.json(dbAll(`SELECT * FROM pending_registrations ORDER BY created_at DESC LIMIT 200`));
  res.json(dbAll(`SELECT * FROM pending_registrations WHERE status=? ORDER BY created_at DESC`, [status]));
});

app.post('/api/admin/pending/:id/approve', verifyAdmin, async (req, res) => {
  const p = dbGet(`SELECT * FROM pending_registrations WHERE id=?`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Tidak ditemukan' });

  const { tier, max_photos, valid_until, device_locked } = req.body;
  const key = genKey();
  dbRun(`INSERT INTO licenses (license_key,user_name,instansi,email,whatsapp,tier,status,max_photos,valid_until,device_locked,device_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [key, p.user_name, p.instansi, p.email, p.whatsapp,
     tier||'full', 'active', max_photos||0, valid_until||null,
     device_locked?1:0, (device_locked&&p.device_id)?p.device_id:null]);
  dbRun(`UPDATE pending_registrations SET status='approved' WHERE id=?`, [req.params.id]);
  logActivity(key, 'LICENSE_APPROVED', req, `pending #${p.id}`);

  // Notif WA
  if (p.whatsapp) {
    const validStr = valid_until ? `s/d ${valid_until.slice(0,10)}` : 'Selamanya';
    await sendWA(p.whatsapp, `Halo ${p.user_name},\n\nPendaftaran SiVerif RHL Anda DISETUJUI!\n\n🔑 License Key: ${key}\n⏳ Berlaku: ${validStr}\n\nTerima kasih telah mendaftar.`);
  }

  res.json({ success: true, license_key: key });
});

app.post('/api/admin/pending/:id/reject', verifyAdmin, (req, res) => {
  const p = dbGet(`SELECT * FROM pending_registrations WHERE id=?`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Tidak ditemukan' });
  dbRun(`UPDATE pending_registrations SET status='rejected', notes=? WHERE id=?`,
    [req.body.reason||'', req.params.id]);
  logActivity('pending', 'PENDING_REJECTED', req, `#${req.params.id}`);
  res.json({ success: true });
});

// ── LOGS ─────────────────────────────────────────────────────────
app.get('/api/admin/logs', verifyAdmin, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit)||200, 1000);
  const key    = req.query.key || '';
  const action = req.query.action || '';
  let where = '1=1';
  const params = [];
  if (key)    { where += ' AND license_key=?'; params.push(key); }
  if (action) { where += ' AND action LIKE ?'; params.push(`%${action}%`); }
  const logs = dbAll(`SELECT * FROM activity_log WHERE ${where} ORDER BY created_at DESC LIMIT ?`,
    [...params, limit]);
  res.json(logs);
});

// ── RESET PASSWORD ADMIN ─────────────────────────────────────────
app.post('/api/admin/reset-password', verifyAdmin, (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 8)
    return res.status(400).json({ error: 'Password minimal 8 karakter' });
  // Simpan di environment tidak bisa, tapi catat bahwa password baru di-set
  // Pada Railway: user harus update env var SUPERADMIN_PASS secara manual
  logActivity('SUPERADMIN', 'PASSWORD_RESET_REQUESTED', req);
  res.json({
    success: true,
    message: 'Untuk mengubah password, update env var SUPERADMIN_PASS di Railway dashboard, lalu restart service.',
    new_password_hash: hashPass(new_password)
  });
});

// ── START ─────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n╔════════════════════════════════════════════╗`);
    console.log(`║  SiVerif RHL License Server v3.0           ║`);
    console.log(`║  Port  : ${String(PORT).padEnd(33)}║`);
    console.log(`║  DB    : ${DB_PATH.padEnd(33)}║`);
    console.log(`║  WA    : ${(FONNTE_TOKEN?'Aktif':'Nonaktif').padEnd(33)}║`);
    console.log(`╚════════════════════════════════════════════╝\n`);
  });
}).catch(err => {
  console.error('FATAL: Gagal inisialisasi DB:', err);
  process.exit(1);
});
