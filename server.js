require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zagel_secret_2026';

// ── Database ──────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ── Middleware ────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth Middleware ───────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'جلسة منتهية، سجل دخول مجدداً' });
  }
}

function gmOnly(req, res, next) {
  if (req.user.role !== 'gm') return res.status(403).json({ error: 'للمدير العام فقط' });
  next();
}

// ── DB Setup ──────────────────────────────────────────────────────
async function setupDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS branches (
        id SERIAL PRIMARY KEY,
        key VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        hex_color VARCHAR(10) DEFAULT '#4f7cff',
        password_hash VARCHAR(255) NOT NULL,
        company_pct INTEGER DEFAULT 30,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS section_passwords (
        id SERIAL PRIMARY KEY,
        section VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS daily_orders (
        id SERIAL PRIMARY KEY,
        branch_key VARCHAR(50) REFERENCES branches(key) ON DELETE CASCADE,
        delegate_name VARCHAR(100) NOT NULL,
        client_name VARCHAR(200),
        phone VARCHAR(20),
        quantity INTEGER DEFAULT 1,
        price NUMERIC(10,2) DEFAULT 30,
        total NUMERIC(10,2),
        company_share NUMERIC(10,2),
        delegate_share NUMERIC(10,2),
        order_time VARCHAR(10),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS monthly_archive (
        id SERIAL PRIMARY KEY,
        branch_key VARCHAR(50) REFERENCES branches(key) ON DELETE CASCADE,
        month_name VARCHAR(100) NOT NULL,
        month_num INTEGER,
        year_num INTEGER,
        total_orders INTEGER DEFAULT 0,
        total_revenue NUMERIC(12,2) DEFAULT 0,
        total_company NUMERIC(12,2) DEFAULT 0,
        total_pay NUMERIC(12,2) DEFAULT 0,
        delegates_data JSONB DEFAULT '{}',
        clients_data JSONB DEFAULT '{}',
        daily_records JSONB DEFAULT '[]',
        closed_at TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS extra_clients (
        id SERIAL PRIMARY KEY,
        branch_key VARCHAR(50) REFERENCES branches(key) ON DELETE CASCADE,
        name VARCHAR(200) NOT NULL,
        phone VARCHAR(20),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Seed default branches
    const branches = [
      { key: 'mahalla',  name: 'المحلة الكبرى', hex: '#4f7cff', pass: '1111' },
      { key: 'maadi',    name: 'المعادي',        hex: '#22c55e', pass: '2222' },
      { key: 'mansoura', name: 'المنصورة',       hex: '#f59e0b', pass: '3333' },
      { key: 'tanta',    name: 'طنطا',           hex: '#7c5cfc', pass: '4444' },
    ];
    for (const b of branches) {
      const existing = await client.query('SELECT id FROM branches WHERE key=$1', [b.key]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(b.pass, 10);
        await client.query(
          'INSERT INTO branches (key,name,hex_color,password_hash) VALUES ($1,$2,$3,$4)',
          [b.key, b.name, b.hex, hash]
        );
      }
    }

    // Seed section passwords
    const sections = [
      { section: 'gm',      pass: '9999'  },
      { section: 'daily',   pass: '1234'  },
      { section: 'monthly', pass: '5678'  },
      { section: 'yearly',  pass: '9999y' },
    ];
    for (const s of sections) {
      const existing = await client.query('SELECT id FROM section_passwords WHERE section=$1', [s.section]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(s.pass, 10);
        await client.query('INSERT INTO section_passwords (section,password_hash) VALUES ($1,$2)', [s.section, hash]);
      }
    }

    console.log('✅ قاعدة البيانات جاهزة');
  } finally {
    client.release();
  }
}

// ════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// تسجيل دخول فرع أو مدير
app.post('/api/login', async (req, res) => {
  const { type, password } = req.body;
  try {
    if (type === 'gm') {
      const r = await pool.query('SELECT password_hash FROM section_passwords WHERE section=$1', ['gm']);
      if (!r.rows.length) return res.status(400).json({ error: 'خطأ في الإعداد' });
      const ok = await bcrypt.compare(password, r.rows[0].password_hash);
      if (!ok) return res.status(401).json({ error: 'باسورد غلط' });
      const token = jwt.sign({ role: 'gm', branchKey: null }, JWT_SECRET, { expiresIn: '12h' });
      return res.json({ token, role: 'gm', name: 'المدير العام' });
    } else {
      const b = await pool.query('SELECT * FROM branches WHERE key=$1', [type]);
      if (!b.rows.length) return res.status(400).json({ error: 'فرع غير موجود' });
      const branch = b.rows[0];
      const ok = await bcrypt.compare(password, branch.password_hash);
      if (!ok) return res.status(401).json({ error: 'باسورد غلط' });
      const token = jwt.sign({ role: 'branch', branchKey: branch.key }, JWT_SECRET, { expiresIn: '12h' });
      return res.json({ token, role: 'branch', branchKey: branch.key, name: branch.name, hex: branch.hex_color });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// التحقق من باسورد قسم (يومي/شهري/سنوي)
app.post('/api/unlock-section', auth, async (req, res) => {
  const { section, password } = req.body;
  try {
    const r = await pool.query('SELECT password_hash FROM section_passwords WHERE section=$1', [section]);
    if (!r.rows.length) return res.status(400).json({ error: 'قسم غير موجود' });
    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'باسورد غلط' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

// ════════════════════════════════════════════════════════════════
// BRANCHES
// ════════════════════════════════════════════════════════════════

app.get('/api/branches', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key,name,hex_color,company_pct FROM branches ORDER BY id');
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// تغيير باسورد فرع (مدير عام فقط)
app.put('/api/branches/:key/password', auth, gmOnly, async (req, res) => {
  const { password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE branches SET password_hash=$1 WHERE key=$2', [hash, req.params.key]);
  res.json({ ok: true });
});

// تغيير نسبة الشركة
app.put('/api/branches/:key/settings', auth, gmOnly, async (req, res) => {
  const { company_pct } = req.body;
  await pool.query('UPDATE branches SET company_pct=$1 WHERE key=$2', [company_pct, req.params.key]);
  res.json({ ok: true });
});

// تغيير باسورد قسم
app.put('/api/section-password', auth, async (req, res) => {
  const { section, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE section_passwords SET password_hash=$1 WHERE section=$2', [hash, section]);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════
// DAILY ORDERS
// ════════════════════════════════════════════════════════════════

// جلب أوردرات اليوم
app.get('/api/orders/:branchKey', auth, async (req, res) => {
  const bk = req.params.branchKey;
  if (req.user.role !== 'gm' && req.user.branchKey !== bk)
    return res.status(403).json({ error: 'غير مصرح' });
  try {
    const today = new Date().toISOString().split('T')[0];
    const r = await pool.query(
      `SELECT * FROM daily_orders WHERE branch_key=$1 AND DATE(created_at)=$2 ORDER BY created_at`,
      [bk, today]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// إضافة أوردر
app.post('/api/orders', auth, async (req, res) => {
  const { branch_key, delegate_name, client_name, phone, quantity, price, order_time } = req.body;
  if (req.user.role !== 'gm' && req.user.branchKey !== branch_key)
    return res.status(403).json({ error: 'غير مصرح' });
  try {
    const b = await pool.query('SELECT company_pct FROM branches WHERE key=$1', [branch_key]);
    const pct = b.rows[0]?.company_pct || 30;
    const total = quantity * price;
    const company_share = +(total * pct / 100).toFixed(2);
    const delegate_share = +(total - company_share).toFixed(2);
    const r = await pool.query(
      `INSERT INTO daily_orders (branch_key,delegate_name,client_name,phone,quantity,price,total,company_share,delegate_share,order_time)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [branch_key, delegate_name, client_name||'', phone||'', quantity, price, total, company_share, delegate_share, order_time||'']
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// تعديل أوردر
app.put('/api/orders/:id', auth, async (req, res) => {
  const { delegate_name, client_name, phone, quantity, price, order_time } = req.body;
  try {
    const existing = await pool.query('SELECT branch_key FROM daily_orders WHERE id=$1', [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'غير موجود' });
    const bk = existing.rows[0].branch_key;
    if (req.user.role !== 'gm' && req.user.branchKey !== bk)
      return res.status(403).json({ error: 'غير مصرح' });
    const b = await pool.query('SELECT company_pct FROM branches WHERE key=$1', [bk]);
    const pct = b.rows[0]?.company_pct || 30;
    const total = quantity * price;
    const company_share = +(total * pct / 100).toFixed(2);
    const delegate_share = +(total - company_share).toFixed(2);
    const r = await pool.query(
      `UPDATE daily_orders SET delegate_name=$1,client_name=$2,phone=$3,quantity=$4,price=$5,total=$6,company_share=$7,delegate_share=$8,order_time=$9
       WHERE id=$10 RETURNING *`,
      [delegate_name, client_name||'', phone||'', quantity, price, total, company_share, delegate_share, order_time||'', req.params.id]
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// حذف أوردر
app.delete('/api/orders/:id', auth, async (req, res) => {
  try {
    const existing = await pool.query('SELECT branch_key FROM daily_orders WHERE id=$1', [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'غير موجود' });
    const bk = existing.rows[0].branch_key;
    if (req.user.role !== 'gm' && req.user.branchKey !== bk)
      return res.status(403).json({ error: 'غير مصرح' });
    await pool.query('DELETE FROM daily_orders WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// ════════════════════════════════════════════════════════════════
// MONTHLY ARCHIVE + ROLLOVER
// ════════════════════════════════════════════════════════════════

// جلب الأرشيف
app.get('/api/archive/:branchKey', auth, async (req, res) => {
  const bk = req.params.branchKey;
  if (req.user.role !== 'gm' && req.user.branchKey !== bk)
    return res.status(403).json({ error: 'غير مصرح' });
  try {
    const r = await pool.query(
      'SELECT id,month_name,month_num,year_num,total_orders,total_revenue,total_company,total_pay,delegates_data,clients_data,daily_records,closed_at FROM monthly_archive WHERE branch_key=$1 ORDER BY year_num DESC,month_num DESC',
      [bk]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// ترحيل الشهر
app.post('/api/rollover/:branchKey', auth, async (req, res) => {
  const bk = req.params.branchKey;
  if (req.user.role !== 'gm' && req.user.branchKey !== bk)
    return res.status(403).json({ error: 'غير مصرح' });
  const { month_name } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const now = new Date();
    // جلب كل أوردرات اليوم للفرع
    const orders = await client.query(
      'SELECT * FROM daily_orders WHERE branch_key=$1',
      [bk]
    );
    const rows = orders.rows;
    // بناء ملخص المناديب
    const delegates = {};
    const clients_map = {};
    let totalOrders=0, totalRev=0, totalComp=0, totalPay=0;
    rows.forEach(o => {
      totalOrders += o.quantity;
      totalRev += +o.total;
      totalComp += +o.company_share;
      totalPay += +o.delegate_share;
      if (!delegates[o.delegate_name]) delegates[o.delegate_name] = {orders:0,revenue:0,company:0,pay:0};
      delegates[o.delegate_name].orders += o.quantity;
      delegates[o.delegate_name].revenue += +o.total;
      delegates[o.delegate_name].company += +o.company_share;
      delegates[o.delegate_name].pay += +o.delegate_share;
      const k = o.client_name || o.phone || 'غير محدد';
      if (!clients_map[k]) clients_map[k] = {orders:0, revenue:0, phone:o.phone||''};
      clients_map[k].orders += o.quantity;
      clients_map[k].revenue += +o.total;
    });
    // حفظ في الأرشيف
    await client.query(
      `INSERT INTO monthly_archive (branch_key,month_name,month_num,year_num,total_orders,total_revenue,total_company,total_pay,delegates_data,clients_data,daily_records)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [bk, month_name||'شهر جديد', now.getMonth()+1, now.getFullYear(),
       totalOrders, totalRev.toFixed(2), totalComp.toFixed(2), totalPay.toFixed(2),
       JSON.stringify(delegates), JSON.stringify(clients_map),
       JSON.stringify(rows.map(o => ({...o, locked: true})))]
    );
    // مسح الأوردرات اليومية
    await client.query('DELETE FROM daily_orders WHERE branch_key=$1', [bk]);
    await client.query('DELETE FROM extra_clients WHERE branch_key=$1', [bk]);
    await client.query('COMMIT');
    res.json({ ok: true, message: `تم ترحيل ${month_name} بنجاح` });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'خطأ في الترحيل' });
  } finally {
    client.release();
  }
});

// ════════════════════════════════════════════════════════════════
// GM — إحصاءات شاملة
// ════════════════════════════════════════════════════════════════

app.get('/api/gm/stats', auth, gmOnly, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    // أوردرات اليوم لكل فرع
    const todayR = await pool.query(
      `SELECT branch_key, SUM(quantity) as orders, SUM(total) as revenue, SUM(company_share) as company, SUM(delegate_share) as pay
       FROM daily_orders WHERE DATE(created_at)=$1 GROUP BY branch_key`, [today]
    );
    // إحصاءات الأرشيف
    const archR = await pool.query(
      `SELECT branch_key, SUM(total_orders) as orders, SUM(total_revenue) as revenue, SUM(total_company) as company, SUM(total_pay) as pay
       FROM monthly_archive GROUP BY branch_key`
    );
    res.json({ today: todayR.rows, archive: archR.rows });
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// أعلى مناديب — كل الفروع
app.get('/api/gm/top-delegates', auth, gmOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT branch_key, delegate_name, SUM(quantity) as orders, SUM(total) as revenue, SUM(delegate_share) as pay
       FROM daily_orders GROUP BY branch_key, delegate_name ORDER BY orders DESC LIMIT 50`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// كل الأرشيف — كل الفروع
app.get('/api/gm/all-archive', auth, gmOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.*, b.name as branch_name, b.hex_color FROM monthly_archive m
       JOIN branches b ON b.key=m.branch_key ORDER BY year_num DESC, month_num DESC`
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// ════════════════════════════════════════════════════════════════
// EXTRA CLIENTS
// ════════════════════════════════════════════════════════════════

app.get('/api/clients/:branchKey', auth, async (req, res) => {
  const bk = req.params.branchKey;
  if (req.user.role !== 'gm' && req.user.branchKey !== bk)
    return res.status(403).json({ error: 'غير مصرح' });
  try {
    const r = await pool.query('SELECT * FROM extra_clients WHERE branch_key=$1 ORDER BY id', [bk]);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

app.post('/api/clients', auth, async (req, res) => {
  const { branch_key, name, phone } = req.body;
  if (req.user.role !== 'gm' && req.user.branchKey !== branch_key)
    return res.status(403).json({ error: 'غير مصرح' });
  try {
    const r = await pool.query(
      'INSERT INTO extra_clients (branch_key,name,phone) VALUES ($1,$2,$3) RETURNING *',
      [branch_key, name, phone||'']
    );
    res.json(r.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'خطأ' });
  }
});

// ════════════════════════════════════════════════════════════════
// EXCEL IMPORT
// ════════════════════════════════════════════════════════════════

app.post('/api/import/:branchKey', auth, async (req, res) => {
  const bk = req.params.branchKey;
  if (req.user.role !== 'gm' && req.user.branchKey !== bk)
    return res.status(403).json({ error: 'غير مصرح' });
  const { rows } = req.body;
  if (!Array.isArray(rows) || !rows.length)
    return res.status(400).json({ error: 'لا توجد بيانات' });
  try {
    const b = await pool.query('SELECT company_pct FROM branches WHERE key=$1', [bk]);
    const pct = b.rows[0]?.company_pct || 30;
    const now = new Date();
    const time = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    let inserted = 0;
    for (const row of rows) {
      const total = row.qty * row.price;
      const company_share = +(total * pct / 100).toFixed(2);
      const delegate_share = +(total - company_share).toFixed(2);
      await pool.query(
        `INSERT INTO daily_orders (branch_key,delegate_name,client_name,phone,quantity,price,total,company_share,delegate_share,order_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [bk, row.delegate, row.client||'', row.phone||'', row.qty, row.price, total, company_share, delegate_share, time]
      );
      inserted++;
    }
    res.json({ ok: true, inserted });
  } catch (e) {
    res.status(500).json({ error: 'خطأ في الاستيراد' });
  }
});

// ── Serve Frontend ────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────
setupDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 زاجل سبيد شغال على البورت ${PORT}`);
  });
}).catch(err => {
  console.error('خطأ في قاعدة البيانات:', err);
  process.exit(1);
});
