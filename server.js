const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const START_TIME = Date.now();
// Environment Variables
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SUPERADMIN_PASS = process.env.SUPERADMIN_PASS || 'admin123';
const JWT_SECRET = process.env.JWT_SECRET || 'siverif-secret-2026';

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('FATAL: SUPABASE_URL or SUPABASE_KEY is missing!');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors());
app.use(express.json());

// Helper: Hash Password (SHA256)
const hashPass = (pass) => crypto.createHash('sha256').update(pass).digest('hex');

// Middleware: Verify Admin JWT
const verifyAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Akses Ditolak' });
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) { res.status(401).json({ error: 'Token Tidak Valid' }); }
};

// ── PUBLIC ENDPOINTS ──

app.get('/', (req, res) => {
  const uptime = Math.floor((Date.now() - START_TIME) / 1000);
  res.json({
    status: 'ok',
    version: '13.0.0',
    uptime_seconds: uptime,
    uptime_human: `${Math.floor(uptime/3600)}j ${Math.floor((uptime%3600)/60)}m`,
    connected: !!supabase
  });
});

// In-memory system config (persists until Vercel restarts)
let systemConfig = {
  maintenance_mode: false,
  maintenance_message: 'Sistem sedang dalam pemeliharaan.',
  maintenance_eta: '',
  current_version: '13.0.0',
  min_version: '12.0.0',
  update_url: 'https://github.com/Tedo1998/siverif-rhl-server/releases/download/v13.0.0/SiVerif_RHL_Ultimate_v13.0.0_Installer.exe',
  update_message: 'Versi baru v13.0.0 tersedia! Support 100K+ foto dan auto-update.',
  update_mandatory: false,
  announcement: ''
};

app.get('/api/system', (req, res) => {
  res.json({
    current_version: systemConfig.current_version,
    min_version: systemConfig.min_version,
    update_url: systemConfig.update_url,
    update_message: systemConfig.update_message,
    update_mandatory: systemConfig.update_mandatory,
    maintenance_mode: systemConfig.maintenance_mode,
    maintenance_message: systemConfig.maintenance_message,
    announcement: systemConfig.announcement,
    changelog: 'v13.0.0: electron-updater, VISIPICS 100K+, fix tabulasi, fix waktu.'
  });
});

app.post('/api/admin/system', verifyAdmin, (req, res) => {
  try {
    const fields = ['maintenance_mode','maintenance_message','maintenance_eta','current_version','min_version','update_url','update_message','update_mandatory','announcement'];
    fields.forEach(f => { if (req.body[f] !== undefined) systemConfig[f] = req.body[f]; });
    res.json({ success: true, state: systemConfig });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/system', verifyAdmin, (req, res) => {
  res.json({ success: true, state: systemConfig });
});

// ── ADMIN: DASHBOARD ──

app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const today = new Date(); today.setHours(0,0,0,0);
    const lastWeek = new Date(); lastWeek.setDate(lastWeek.getDate() - 7);
    const nextWeek = new Date(); nextWeek.setDate(nextWeek.getDate() + 7);

    const [
      { count: total },
      { count: active },
      { count: inactive },
      { count: suspended },
      { count: expired },
      { count: soon },
      { count: pending },
      { data: recent_active },
      { data: recent_logs },
      { count: val_today },
      { count: val_week }
    ] = await Promise.all([
      supabase.from('licenses').select('*', { count: 'exact', head: true }),
      supabase.from('licenses').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('licenses').select('*', { count: 'exact', head: true }).eq('status', 'inactive'),
      supabase.from('licenses').select('*', { count: 'exact', head: true }).eq('status', 'suspended'),
      supabase.from('licenses').select('*', { count: 'exact', head: true }).eq('status', 'expired'),
      supabase.from('licenses').select('*', { count: 'exact', head: true }).gte('valid_until', new Date().toISOString()).lte('valid_until', nextWeek.toISOString()),
      supabase.from('pending_registrations').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabase.from('licenses').select('*').order('last_check', { ascending: false }).limit(5),
      supabase.from('activity_log').select('*').order('created_at', { ascending: false }).limit(10),
      supabase.from('activity_log').select('*', { count: 'exact', head: true }).eq('action', 'VALIDATE_OK').gte('created_at', today.toISOString()),
      supabase.from('activity_log').select('*', { count: 'exact', head: true }).eq('action', 'VALIDATE_OK').gte('created_at', lastWeek.toISOString())
    ]);

    res.json({
      licenses: { 
        total: total||0, active: active||0, inactive: inactive||0, 
        suspended: suspended||0, expired: expired||0, expire_soon: soon||0 
      },
      pending: pending||0,
      recent_active: recent_active||[],
      recent_logs: recent_logs||[],
      activity: { validate_today: val_today||0, validate_week: val_week||0, validate_month: 0 }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/test-db', async (req, res) => {
  const { count, error } = await supabase
    .from('agency_admins')
    .select('*', { count: 'exact', head: true });
  if (error) return res.status(500).json({ success: false, error: error.message });
  res.json({ success: true, message: 'Official Supabase API Connected!', count });
});

// ── AUTHENTICATION ──

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (hashPass(password) === hashPass(SUPERADMIN_PASS)) {
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Password Admin Salah' });
});

app.post('/api/agency/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { data, error } = await supabase
      .from('agency_admins')
      .select('*')
      .eq('username', username)
      .single();
    
    if (error || !data) return res.status(401).json({ error: 'Username atau Password salah' });
    
    // Check password (hashed)
    if (data.password === hashPass(password)) {
      return res.json({ 
        success: true, 
        name: data.name, 
        agency: data.instansi,
        instansi: data.instansi
      });
    }
    res.status(401).json({ error: 'Username atau Password salah' });
  } catch (e) { res.status(500).json({ error: 'Koneksi database terputus' }); }
});

// ── ADMIN: AGENCY & ADMINS ──

app.get('/api/admin/agency/settings', verifyAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('agency_admins')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const admins = data.map(a => ({ ...a, agency: a.instansi }));
  res.json({ success: true, admins, agency_name: 'SiVerif RHL Ultimate Edition' });
});

app.post('/api/admin/agency/admins', verifyAdmin, async (req, res) => {
  const { name, username, password, instansi, agency } = req.body;
  const finalInstansi = instansi || agency || 'Umum';
  const { error } = await supabase
    .from('agency_admins')
    .insert([{ name, username, password: hashPass(password), instansi: finalInstansi }]);
  if (error) return res.status(500).json({ error: 'Gagal menambah admin: ' + error.message });
  res.json({ success: true });
});

app.delete('/api/admin/agency/admins/:username', verifyAdmin, async (req, res) => {
  const { error } = await supabase
    .from('agency_admins')
    .delete()
    .eq('username', req.params.username);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── ADMIN: LICENSES ──

app.get('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('licenses')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(1000);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ data });
});

// GET Detail
app.get('/api/admin/licenses/:key', verifyAdmin, async (req, res) => {
  const { key } = req.params;
  try {
    const { data: l, error } = await supabase
      .from('licenses')
      .select('*')
      .eq('license_key', key)
      .single();
    if (error || !l) return res.status(404).json({ error: 'Lisensi tidak ditemukan' });
    const { data: logs } = await supabase.from('activity_log').select('*').eq('license_key', key).order('created_at', { ascending: false }).limit(10);
    res.json({ ...l, recent_logs: logs || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/licenses', verifyAdmin, async (req, res) => {
  const { user_name, instansi, tier, valid_until, email, whatsapp } = req.body;
  const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const { error } = await supabase
    .from('licenses')
    .insert([{ license_key: key, user_name, instansi, tier: tier || 'full', valid_until: valid_until || null, email, whatsapp }]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, license_key: key });
});

app.put('/api/admin/licenses/:key', verifyAdmin, async (req, res) => {
  const { key } = req.params;
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  const { error } = await supabase.from('licenses').update({ user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes }).eq('license_key', key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/status', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('licenses').update({ status: req.body.status }).eq('license_key', req.params.key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/reset-device', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('licenses').update({ device_id: null, device_locked: 0 }).eq('license_key', req.params.key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/extend', verifyAdmin, async (req, res) => {
  try {
    const { data: l } = await supabase.from('licenses').select('valid_until').eq('license_key', req.params.key).single();
    if (!l) return res.status(404).json({ error: 'Lisensi tidak ditemukan' });
    let newDate = l.valid_until ? new Date(l.valid_until) : new Date();
    if (newDate < new Date()) newDate = new Date();
    newDate.setDate(newDate.getDate() + parseInt(req.body.days));
    const { error } = await supabase.from('licenses').update({ valid_until: newDate.toISOString() }).eq('license_key', req.params.key);
    if (error) throw error;
    res.json({ success: true, new_valid_until: newDate.toISOString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/licenses/:key', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('licenses').delete().eq('license_key', req.params.key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── ADMIN: PENDING REGISTRATIONS ──

app.get('/api/admin/pending', verifyAdmin, async (req, res) => {
  const { data, error } = await supabase.from('pending_registrations').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/admin/pending/:id/approve', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { tier, valid_until } = req.body;
  try {
    const { data: reg } = await supabase.from('pending_registrations').select('*').eq('id', id).single();
    if (!reg) return res.status(404).json({ error: 'Data tidak ditemukan' });
    const key = `SVR-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await supabase.from('licenses').insert([{
      license_key: key, user_name: reg.user_name, instansi: reg.instansi, email: reg.email, whatsapp: reg.whatsapp, device_id: reg.device_id, tier: tier || 'full', status: 'active', valid_until: valid_until || null
    }]);
    await supabase.from('pending_registrations').update({ status: 'approved' }).eq('id', id);
    res.json({ success: true, license_key: key });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/pending/:id/reject', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('pending_registrations').update({ status: 'rejected' }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.delete('/api/admin/pending/:id', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('pending_registrations').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── ADMIN: LOGS ──

app.get('/api/admin/logs', verifyAdmin, async (req, res) => {
  const { action, limit } = req.query;
  let q = supabase.from('activity_log').select('*').order('created_at', { ascending: false }).limit(limit || 200);
  if (action) q = q.eq('action', action);
  const { data, error } = await q;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ── CLIENT: REGISTRATION & VALIDATION ──

app.post('/api/register', async (req, res) => {
  const { user_name, instansi, email, whatsapp, device_id } = req.body;
  const { error } = await supabase.from('pending_registrations').insert([{ user_name, instansi, email, whatsapp, device_id, status: 'pending' }]);
  if (error) return res.status(500).json({ success: false, error: error.message });
  res.json({ success: true });
});

app.post('/api/validate', async (req, res) => {
  const { license_key, device_id } = req.body;
  try {
    const { data, error } = await supabase.from('licenses').select('*').eq('license_key', license_key?.toUpperCase()).eq('status', 'active').single();
    if (data && !error) {
      if (data.device_locked && data.device_id && data.device_id !== device_id) return res.json({ valid: false, error: 'Lisensi terkunci di perangkat lain' });
      await supabase.from('activity_log').insert([{ action: 'VALIDATE_OK', license_key, info: 'Validasi Berhasil' }]);
      await supabase.from('licenses').update({ check_count: (data.check_count || 0) + 1, last_check: new Date() }).eq('id', data.id);
      return res.json({ valid: true, user_name: data.user_name, instansi: data.instansi, tier: data.tier, max_photos: data.max_photos, valid_until: data.valid_until, device_locked: data.device_locked, device_id: data.device_id });
    }
    res.json({ valid: false, error: 'Lisensi Tidak Valid' });
  } catch (e) { res.json({ valid: false, error: 'Koneksi database terputus' }); }
});

app.post('/api/notify/wa', verifyAdmin, async (req, res) => {
  const { phone, message } = req.body;
  if (!phone || !message) return res.status(400).json({ success: false, error: 'phone dan message wajib diisi' });
  try {
    const clean = phone.replace(/\D/g, '');
    const target = clean.startsWith('0') ? '62' + clean.slice(1) : clean;
    const form = new URLSearchParams();
    form.append('target', target);
    form.append('message', message);
    form.append('countryCode', '62');
    const r = await fetch('https://api.fonnte.com/send', {
      method: 'POST',
      headers: { 'Authorization': 'X1YTrbJtGZjGBwjs9pTZ' },
      body: form
    });
    const d = await r.json();
    if (d.status) return res.json({ success: true, detail: d });
    return res.status(500).json({ success: false, error: d.reason || 'Gagal kirim WA' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;
