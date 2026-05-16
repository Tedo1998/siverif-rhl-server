const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

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
  res.json({ status: 'ok', engine: 'Supabase-JS SDK', connected: !!supabase });
});

app.get('/api/system', (req, res) => {
  res.json({
    current_version: '12.1.4',
    update_url: 'https://raw.githubusercontent.com/Tedo1998/siverif-rhl-server/main/patch_v12.1.4.zip',
    changelog: 'Update v12.1.4: Fix Layout, AI Scan, High-Res Zoom, and Admin Panel Control.'
  });
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
  res.json({ success: true, admins, agency_name: 'Kementerian Lingkungan Hidup dan Kehutanan' });
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
  const { user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked, notes } = req.body;
  const { error } = await supabase.from('licenses').update({ user_name, instansi, email, whatsapp, tier, max_photos, valid_until, device_locked: !!device_locked, notes }).eq('license_key', req.params.key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/status', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('licenses').update({ status: req.body.status }).eq('license_key', req.params.key);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/api/admin/licenses/:key/reset-device', verifyAdmin, async (req, res) => {
  const { error } = await supabase.from('licenses').update({ device_id: null, device_locked: false }).eq('license_key', req.params.key);
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
      return res.json({ valid: true, user_name: data.user_name, instansi: data.instansi });
    }
    res.json({ valid: false, error: 'Lisensi Tidak Valid' });
  } catch (e) { res.json({ valid: false, error: 'Koneksi database terputus' }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;
