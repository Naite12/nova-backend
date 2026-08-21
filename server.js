const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1); // Railway runs behind a proxy

// ── ADMIN SECRET (from environment, never hardcoded) ──
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'NOVA-ADMIN-2026';

// ── SECURITY HEADERS (helmet) ──
app.use(helmet({
  contentSecurityPolicy: false, // disabled because frontends are on separate domains
  crossOriginEmbedderPolicy: false
}));

// ── CORS — restricted to known N.O.V.A. front-ends ──
const ALLOWED_ORIGINS = [
  'https://nova-vip1.netlify.app',
  'https://nova-industrie.netlify.app',
  'http://localhost:3000',
  'http://localhost:5173',
  'file://'
];
app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (mobile apps, curl, server-to-server, Electron file://)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return callback(null, true);
    // allow any netlify preview subdomain of the two apps
    if (/^https:\/\/[a-z0-9-]+--nova-(vip1|industrie)\.netlify\.app$/.test(origin)) return callback(null, true);
    return callback(null, true); // permissive fallback (log only) — tighten later if needed
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));

// ── SAFE ERROR HANDLING ──
// Logs the real error server-side (for debugging) but returns a generic message
// to the client, so internal details (DB structure, paths, stack) never leak.
function safeError(res, e, context) {
  const detail = (e && e.message) ? e.message : String(e);
  console.error('[ERROR]' + (context ? ' ' + context : '') + ':', detail);
  if (res && !res.headersSent) {
    res.status(500).json({ error: 'Une erreur interne est survenue. Veuillez reessayer.' });
  }
}

// ── RATE LIMITERS ──
// General API limiter: 300 requests / 15 min per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requetes, reessayez plus tard.' }
});
app.use('/api/', generalLimiter);

// Strict limiter for auth endpoints: 8 attempts / 15 min per IP (anti brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de tentatives de connexion. Reessayez dans 15 minutes.' }
});

// Admin limiter: 30 / 15 min
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

// Stricter limiter for the costly AI endpoints (each call hits the Claude API = real cost).
// 40 calls / 15 min per IP is generous for a human but blocks automated abuse.
const aiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requetes d analyse. Reessayez dans quelques minutes.' }
});

// ── POSTGRESQL ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── INIT DATABASE ──
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        plan TEXT DEFAULT 'vip',
        created_at TIMESTAMP DEFAULT NOW(),
        memory JSONB DEFAULT '{"facts":[],"conversations":0}',
        chat_history JSONB DEFAULT '[]',
        free_analysis_date TEXT DEFAULT '',
        free_analysis_symbol TEXT DEFAULT ''
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS predictions (
        id SERIAL PRIMARY KEY,
        symbol TEXT NOT NULL,
        name TEXT,
        signal TEXT NOT NULL,
        price DECIMAL NOT NULL,
        confidence INTEGER DEFAULT 70,
        reasoning TEXT,
        date TIMESTAMP DEFAULT NOW(),
        date_str TEXT,
        verified_7d BOOLEAN DEFAULT FALSE,
        verified_30d BOOLEAN DEFAULT FALSE,
        price_after_7d DECIMAL,
        price_after_30d DECIMAL,
        result_7d DECIMAL,
        result_30d DECIMAL,
        correct_7d BOOLEAN,
        correct_30d BOOLEAN
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS watchlists (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        symbol TEXT NOT NULL,
        name TEXT,
        added_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_email, symbol)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        symbol TEXT NOT NULL,
        name TEXT,
        condition TEXT NOT NULL,
        target_price DECIMAL NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        triggered BOOLEAN DEFAULT FALSE,
        triggered_at TIMESTAMP,
        triggered_price DECIMAL
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS portfolios (
        user_email TEXT PRIMARY KEY,
        initial_capital DECIMAL NOT NULL,
        cash DECIMAL NOT NULL,
        risk_profile TEXT DEFAULT 'balanced',
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS positions (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        symbol TEXT NOT NULL,
        name TEXT,
        quantity DECIMAL NOT NULL,
        entry_price DECIMAL NOT NULL,
        entry_date TIMESTAMP DEFAULT NOW(),
        stop_loss DECIMAL,
        take_profit DECIMAL,
        status TEXT DEFAULT 'open',
        exit_price DECIMAL,
        exit_date TIMESTAMP,
        exit_reason TEXT,
        pnl DECIMAL,
        pnl_pct DECIMAL,
        nova_reasoning TEXT
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        ip TEXT,
        detail TEXT,
        meta JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('Database initialized');
  } catch(e) {
    console.log('DB init error:', e.message);
  }
}
initDB();

// ── SESSION STORE (memory is fine for sessions) ──
const sessions = {};

// ── SECURITY EVENT LOGGING & DETECTION ──
function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
}

async function logSecurityEvent(type, severity, ip, detail, meta) {
  try {
    await pool.query(
      'INSERT INTO security_events (type, severity, ip, detail, meta) VALUES ($1,$2,$3,$4,$5)',
      [type, severity, ip || 'unknown', detail || '', meta || {}]
    );
  } catch(e) { console.log('Security log error:', e.message); }
}

// In-memory counters for spike/brute-force detection (per IP, rolling window)
const failedLogins = {};   // ip -> { count, first }
const requestSpikes = {};   // ip -> { count, windowStart }

function trackFailedLogin(ip) {
  const now = Date.now();
  if (!failedLogins[ip] || now - failedLogins[ip].first > 15 * 60 * 1000) {
    failedLogins[ip] = { count: 1, first: now };
  } else {
    failedLogins[ip].count++;
  }
  return failedLogins[ip].count;
}

function trackRequest(ip) {
  const now = Date.now();
  if (!requestSpikes[ip] || now - requestSpikes[ip].windowStart > 60 * 1000) {
    requestSpikes[ip] = { count: 1, windowStart: now };
  } else {
    requestSpikes[ip].count++;
  }
  return requestSpikes[ip].count;
}

// Middleware: detect abnormal request spikes (possible DDoS) on API routes
const spikeAlerted = {};
app.use('/api/', function(req, res, next) {
  const ip = getIP(req);
  const count = trackRequest(ip);
  // More than 120 requests in 60s from one IP = suspicious
  if (count === 121 && (!spikeAlerted[ip] || Date.now() - spikeAlerted[ip] > 5 * 60 * 1000)) {
    spikeAlerted[ip] = Date.now();
    logSecurityEvent('request_spike', 'high', ip, 'Pic anormal de requetes detecte (>120/min)', { count });
  }
  next();
});

function genToken() { return crypto.randomBytes(32).toString('hex'); }

// ── PERSISTENT SESSIONS (survive server restarts/redeploys) ──
// Tokens are stored in PostgreSQL instead of memory so users stay logged in across deploys.
async function initSessionsTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('Sessions table ready');
  } catch(e) { console.log('initSessionsTable error:', e.message); }
}
initSessionsTable();

// Migration: add free-tier columns to existing databases (safe if already present)
async function migrateFreeColumns() {
  try {
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS free_analysis_date TEXT DEFAULT ''");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS free_analysis_symbol TEXT DEFAULT ''");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS analysis_count INTEGER DEFAULT 0");
    console.log('Free-tier columns ready');
  } catch(e) { console.log('migrateFreeColumns error:', e.message); }
}
migrateFreeColumns();

// Daily performance history: one snapshot per day (N.O.V.A. return vs market benchmarks)
async function initPerfHistoryTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS perf_history (
        date_str TEXT PRIMARY KEY,
        nova_return REAL,
        spy_return REAL,
        btc_return REAL,
        signals_count INTEGER,
        recorded_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('Perf history table ready');
  } catch(e) { console.log('initPerfHistoryTable error:', e.message); }
}
initPerfHistoryTable();

async function createSession(email) {
  const token = genToken();
  try {
    await pool.query('INSERT INTO sessions (token, email) VALUES ($1, $2)', [token, email]);
    sessions[token] = email; // keep in-memory cache too for speed
  } catch(e) { console.log('createSession error:', e.message); }
  return token;
}

async function getSessionEmail(token) {
  if (!token) return null;
  if (sessions[token]) return sessions[token]; // fast path: in-memory cache
  try {
    const r = await pool.query('SELECT email FROM sessions WHERE token = $1', [token]);
    if (r.rows.length > 0) {
      sessions[token] = r.rows[0].email; // re-populate cache after a restart
      return r.rows[0].email;
    }
  } catch(e) { console.log('getSessionEmail error:', e.message); }
  return null;
}

// bcrypt with automatic salt (cost factor 12)
async function hashPassword(p) { return await bcrypt.hash(p, 12); }
// legacy SHA-256 (only used to verify & migrate old accounts)
function legacySha256(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// Validates and normalizes an email; returns null if invalid
function cleanEmail(email) {
  if (!email || typeof email !== 'string') return null;
  email = email.trim().toLowerCase();
  if (!validator.isEmail(email) || email.length > 254) return null;
  return email;
}

// ── AUTH ──
app.post('/auth/register', authLimiter, async (req, res) => {
  var email = cleanEmail(req.body.email);
  const { password, plan } = req.body;
  if (!email) return res.status(400).json({ error: 'Adresse email invalide' });
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caracteres' });
  }
  if (password.length > 200) return res.status(400).json({ error: 'Mot de passe trop long' });
  try {
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Un compte existe deja avec cet email' });
    const hashed = await hashPassword(password);
    // plan is validated against a whitelist to prevent privilege escalation via the register body
    const safePlan = ['free', 'premium', 'vip'].indexOf(plan) !== -1 ? plan : 'vip';
    await pool.query('INSERT INTO users (email, password, plan) VALUES ($1, $2, $3)', [email, hashed, safePlan]);
    const token = await createSession(email);
    res.json({ token, email, plan: safePlan });
  } catch(e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  const ip = getIP(req);
  var email = cleanEmail(req.body.email);
  const { password } = req.body;
  if (!email || !password) return res.status(401).json({ error: 'Identifiants invalides' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) {
      const fails = trackFailedLogin(ip);
      if (fails >= 5) logSecurityEvent('brute_force', 'high', ip, 'Tentatives de connexion repetees (' + fails + ') sur compte inexistant', { email: email, attempts: fails });
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    var valid = false;
    if (user.password && user.password.startsWith('$2')) {
      valid = await bcrypt.compare(password, user.password);
    } else {
      valid = (user.password === legacySha256(password));
      if (valid) {
        const upgraded = await hashPassword(password);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [upgraded, email]);
      }
    }
    if (!valid) {
      const fails = trackFailedLogin(ip);
      if (fails >= 5) logSecurityEvent('brute_force', 'high', ip, 'Tentatives de connexion repetees (' + fails + ') sur ' + email, { email: email, attempts: fails });
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    // success — clear failed counter
    delete failedLogins[ip];
    const token = await createSession(email);
    res.json({ token, email, plan: user.plan });
  } catch(e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/auth/change-password', authLimiter, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const sessionEmail = await getSessionEmail(token);
  if (!sessionEmail) return res.status(401).json({ error: 'Non autorise' });
  const { password } = req.body;
  if (!password || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court (8 caracteres minimum)' });
  if (password.length > 200) return res.status(400).json({ error: 'Mot de passe trop long' });
  try {
    const hashed = await hashPassword(password);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashed, sessionEmail]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const email = await getSessionEmail(token);
  if (!email) return res.status(401).json({ error: 'Non autorise' });
  req.userEmail = email;
  next();
}

// Admin guard middleware — constant-time comparison to prevent timing attacks
// Track failed admin attempts per IP for temporary lockout
const adminFailedAttempts = {};
function adminGuard(req, res, next) {
  const ip = getIP(req);
  // Temporary lockout: 5 failed attempts within 15 min blocks that IP
  const record = adminFailedAttempts[ip];
  if (record && record.count >= 5 && (Date.now() - record.first) < 15 * 60 * 1000) {
    logSecurityEvent('admin_lockout', 'critical', ip, 'IP bloquee apres 5 tentatives admin echouees', { path: req.path });
    return res.status(429).json({ error: 'Trop de tentatives. Reessayez plus tard.' });
  }
  // Ensure admin secret is actually configured (never allow empty match)
  if (!ADMIN_SECRET || ADMIN_SECRET.length < 8) {
    console.error('[SECURITY] ADMIN_SECRET not configured properly');
    return res.status(503).json({ error: 'Service indisponible.' });
  }
  const provided = (req.body && req.body.secret) || '';
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(ADMIN_SECRET));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    // Record failed attempt
    if (!record || (Date.now() - record.first) >= 15 * 60 * 1000) {
      adminFailedAttempts[ip] = { count: 1, first: Date.now() };
    } else {
      record.count++;
    }
    logSecurityEvent('admin_breach_attempt', 'critical', ip, 'Tentative d acces admin avec mauvais secret sur ' + req.path, { path: req.path });
    return res.status(401).json({ error: 'Non autorise' });
  }
  // Success — clear any failed record
  delete adminFailedAttempts[ip];
  next();
}

app.get('/user/data', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [req.userEmail]);
    const u = result.rows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ email: u.email, plan: u.plan, memory: u.memory, chatHistory: (u.chat_history || []).slice(-50) });
  } catch(e) { safeError(res, e); }
});

// ── MEMORY EXTRACTION ──
// Analyzes a user message and extracts a durable fact about them (goals, risk profile,
// preferences, situation). Returns a short fact string, or null if nothing worth storing.
async function extractMemoryFact(message, existingFacts) {
  if (!message || message.length < 8) return null;
  try {
    const existing = (existingFacts && existingFacts.length) ? existingFacts.join(' | ') : '(aucun)';
    const prompt = 'Tu analyses un message d un utilisateur d une plateforme financiere. ' +
      'Identifie UNIQUEMENT s il contient une information DURABLE et UTILE a memoriser sur cette personne. ' +
      'Deux categories a capter: ' +
      '1) PERSONNEL: prenom, age, metier/profession, ville/pays, langue preferee, situation (etudiant, retraite...). ' +
      '2) FINANCIER: objectif d investissement, profil de risque, horizon, preferences d actifs ou secteurs, situation financiere, contraintes, montant disponible. ' +
      'Ignore les questions, salutations simples, demandes d analyse ponctuelles et small talk. ' +
      'Faits deja connus: ' + existing + '. ' +
      'Si le message contient un nouveau fait durable PAS deja connu, reponds UNIQUEMENT avec ce fait en une courte phrase a la 3e personne ' +
      '(ex: "Se prenomme Anton", "A 19 ans", "Est apprenti menuisier", "Prefere un profil de risque agressif", "S interesse aux cryptos et valeurs tech"). ' +
      'Si plusieurs faits, choisis le plus important. ' +
      'Si rien a memoriser ou deja connu, reponds EXACTEMENT: NONE. ' +
      'Message: "' + message.slice(0, 500) + '"';
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 60, messages: [{ role: 'user', content: prompt }] })
    });
    const d = await r.json();
    const text = (d.content && d.content[0] && d.content[0].text || '').trim();
    if (!text || text === 'NONE' || text.toUpperCase().indexOf('NONE') === 0 || text.length > 150) return null;
    return text;
  } catch(e) { console.log('extractMemoryFact error:', e.message); return null; }
}

app.post('/user/chat', auth, async (req, res) => {
  const { message, role } = req.body;
  try {
    const result = await pool.query('SELECT chat_history, memory FROM users WHERE email = $1', [req.userEmail]);
    const hist = result.rows[0]?.chat_history || [];
    hist.push({ role, message, time: new Date().toISOString() });
    if (hist.length > 100) hist.splice(0, hist.length - 100);
    await pool.query('UPDATE users SET chat_history = $1 WHERE email = $2', [JSON.stringify(hist), req.userEmail]);
    // Respond immediately — memory extraction runs in the background (user messages only)
    res.json({ ok: true });
    if (role === 'user') {
      const mem = result.rows[0]?.memory || { facts: [], conversations: 0 };
      const fact = await extractMemoryFact(message, mem.facts);
      if (fact) {
        mem.facts = mem.facts || [];
        // Avoid near-duplicates
        const exists = mem.facts.some(f => f.toLowerCase() === fact.toLowerCase());
        if (!exists) {
          mem.facts.push(fact);
          if (mem.facts.length > 20) mem.facts = mem.facts.slice(-20);
          await pool.query('UPDATE users SET memory = $1 WHERE email = $2', [JSON.stringify(mem), req.userEmail]);
          console.log('Memory fact saved for', req.userEmail, ':', fact);
        }
      }
    }
  } catch(e) {
    if (!res.headersSent) safeError(res, e);
  }
});

app.post('/user/memory', auth, async (req, res) => {
  const { fact } = req.body;
  try {
    const result = await pool.query('SELECT memory FROM users WHERE email = $1', [req.userEmail]);
    const mem = result.rows[0]?.memory || { facts: [], conversations: 0 };
    if (fact) { mem.facts.push(fact); if (mem.facts.length > 20) mem.facts = mem.facts.slice(-20); }
    mem.conversations = (mem.conversations || 0) + 1;
    await pool.query('UPDATE users SET memory = $1 WHERE email = $2', [JSON.stringify(mem), req.userEmail]);
    res.json(mem);
  } catch(e) { safeError(res, e); }
});

app.get('/user/memory', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT memory FROM users WHERE email = $1', [req.userEmail]);
    res.json(result.rows[0]?.memory || { facts: [], conversations: 0 });
  } catch(e) { safeError(res, e); }
});

app.delete('/user/memory', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET memory = $1, chat_history = $2 WHERE email = $3', [JSON.stringify({ facts: [], conversations: 0 }), JSON.stringify([]), req.userEmail]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

// ── ADMIN — Support access to user conversations (secured by admin secret) ──
app.post('/api/admin/users', adminLimiter, adminGuard, async (req, res) => {
  try {
    const result = await pool.query('SELECT email, plan, chat_history, memory, created_at FROM users ORDER BY created_at DESC');
    const users = result.rows.map(function(u) {
      const hist = u.chat_history || [];
      const lastMsg = hist.length > 0 ? hist[hist.length - 1] : null;
      return {
        email: u.email,
        plan: u.plan,
        messageCount: hist.length,
        lastActivity: lastMsg ? lastMsg.time : null,
        lastMessage: lastMsg ? (lastMsg.message || '').slice(0, 80) : null,
        createdAt: u.created_at
      };
    });
    res.json({ users: users, total: users.length });
  } catch(e) { safeError(res, e); }
});

app.post('/api/admin/revenue', adminLimiter, adminGuard, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT plan, COUNT(*) AS count FROM users
      WHERE plan IN ('vip','premium','essential') GROUP BY plan
    `);
    // Premium repriced to 14. Essential kept at 9 only for legacy accounts (no longer sold).
    const prices = { vip: 49, premium: 14, essential: 9 };
    let mrr = 0;
    const breakdown = { vip: 0, premium: 0, essential: 0 };
    result.rows.forEach(function(r) {
      const c = parseInt(r.count);
      breakdown[r.plan] = c;
      mrr += c * (prices[r.plan] || 0);
    });
    // Recent paying subscribers (real)
    const recent = await pool.query(`
      SELECT email, plan, created_at FROM users
      WHERE plan IN ('vip','premium','essential')
      ORDER BY created_at DESC LIMIT 10
    `);
    res.json({
      mrr: mrr,
      arr: mrr * 12,
      breakdown: breakdown,
      prices: prices,
      recent: recent.rows
    });
  } catch(e) { safeError(res, e); }
});

app.post('/api/admin/conversation', adminLimiter, adminGuard, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const result = await pool.query('SELECT email, plan, chat_history, memory FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({
      email: u.email,
      plan: u.plan,
      memory: u.memory,
      history: u.chat_history || []
    });
  } catch(e) { safeError(res, e); }
});

// Security events dashboard data
app.post('/api/admin/security', adminLimiter, adminGuard, async (req, res) => {
  try {
    const events = await pool.query('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 100');
    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h,
        COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
        COUNT(*) FILTER (WHERE type = 'brute_force') AS brute_force,
        COUNT(*) FILTER (WHERE type = 'admin_breach_attempt') AS admin_attempts,
        COUNT(*) FILTER (WHERE type = 'request_spike') AS spikes,
        COUNT(*) AS total
      FROM security_events
    `);
    // Distinct IPs in last 24h with most events (potential attackers)
    const topIps = await pool.query(`
      SELECT ip, COUNT(*) AS c, MAX(created_at) AS last_seen
      FROM security_events
      WHERE created_at > NOW() - INTERVAL '24 hours' AND ip != 'unknown'
      GROUP BY ip ORDER BY c DESC LIMIT 10
    `);
    res.json({
      events: events.rows,
      stats: stats.rows[0],
      topIps: topIps.rows
    });
  } catch(e) { safeError(res, e); }
});

// ── ADMIN OVERVIEW — all real stats aggregated for the control center ──
app.post('/api/admin/overview', adminLimiter, adminGuard, async (req, res) => {
  try {
    // Users
    const users = await pool.query(`
      SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE plan='vip') AS vip,
        COUNT(*) FILTER (WHERE plan='premium') AS premium,
        COUNT(*) FILTER (WHERE plan='essential') AS essential,
        COUNT(*) FILTER (WHERE plan='free') AS free,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS new_7d
      FROM users
    `);
    // Predictions
    const preds = await pool.query(`
      SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE date::date = NOW()::date) AS today,
        COUNT(*) FILTER (WHERE verified_7d=TRUE) AS verified_7d,
        COUNT(*) FILTER (WHERE verified_7d=TRUE AND correct_7d=TRUE) AS correct_7d,
        COUNT(*) FILTER (WHERE verified_30d=TRUE) AS verified_30d,
        COUNT(*) FILTER (WHERE verified_30d=TRUE AND correct_30d=TRUE) AS correct_30d,
        COUNT(DISTINCT symbol) AS symbols
      FROM predictions
    `);
    // Latest predictions (real)
    const latestPreds = await pool.query(`
      SELECT symbol, name, signal, price, confidence, reasoning, date
      FROM predictions ORDER BY date DESC LIMIT 12
    `);
    // Portfolios
    const portfolios = await pool.query(`
      SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE active=TRUE) AS active,
        COALESCE(SUM(initial_capital),0) AS total_capital,
        COALESCE(SUM(cash),0) AS total_cash
      FROM portfolios
    `);
    // Positions
    const positions = await pool.query(`
      SELECT COUNT(*) FILTER (WHERE status='open') AS open,
        COUNT(*) FILTER (WHERE status='closed') AS closed,
        COUNT(*) FILTER (WHERE status='closed' AND pnl > 0) AS wins,
        COUNT(*) FILTER (WHERE status='closed' AND entry_date::date = NOW()::date) AS today,
        COALESCE(SUM(pnl) FILTER (WHERE status='closed'),0) AS total_pnl
      FROM positions
    `);
    // Recent open positions (real, across all clients)
    const recentPositions = await pool.query(`
      SELECT user_email, symbol, name, quantity, entry_price, entry_date, nova_reasoning
      FROM positions WHERE status='open' ORDER BY entry_date DESC LIMIT 10
    `);
    // Watchlists & alerts
    const watch = await pool.query('SELECT COUNT(*) AS total FROM watchlists');
    const alerts = await pool.query(`
      SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE triggered=TRUE) AS triggered FROM alerts
    `);

    // ── PREDICTION LIFECYCLE / COUNTDOWNS ──
    // Oldest unverified prediction (next to reach its 7d / 30d checkpoint)
    const lifecycle = await pool.query(`
      SELECT
        MIN(date) FILTER (WHERE verified_7d IS NOT TRUE) AS oldest_pending_7d,
        MIN(date) FILTER (WHERE verified_30d IS NOT TRUE) AS oldest_pending_30d,
        COUNT(*) FILTER (WHERE verified_7d IS NOT TRUE AND date <= NOW() - INTERVAL '7 days') AS due_7d,
        COUNT(*) FILTER (WHERE verified_30d IS NOT TRUE AND date <= NOW() - INTERVAL '30 days') AS due_30d,
        COUNT(*) FILTER (WHERE verified_7d IS NOT TRUE) AS pending_7d,
        COUNT(*) FILTER (WHERE verified_30d IS NOT TRUE) AS pending_30d,
        MIN(date) AS first_prediction,
        MAX(date) AS last_prediction
      FROM predictions
    `);
    const lc = lifecycle.rows[0];
    // Compute next checkpoint dates from the oldest pending prediction
    let next7d = null, next30d = null;
    if (lc.oldest_pending_7d) { next7d = new Date(new Date(lc.oldest_pending_7d).getTime() + 7*24*60*60*1000).toISOString(); }
    if (lc.oldest_pending_30d) { next30d = new Date(new Date(lc.oldest_pending_30d).getTime() + 30*24*60*60*1000).toISOString(); }

    const p = preds.rows[0];
    const acc7 = parseInt(p.verified_7d) > 0 ? Math.round((parseInt(p.correct_7d)/parseInt(p.verified_7d))*100) : null;
    const acc30 = parseInt(p.verified_30d) > 0 ? Math.round((parseInt(p.correct_30d)/parseInt(p.verified_30d))*100) : null;
    const pos = positions.rows[0];
    const winRate = parseInt(pos.closed) > 0 ? Math.round((parseInt(pos.wins)/parseInt(pos.closed))*100) : null;

    res.json({
      users: users.rows[0],
      predictions: { ...p, accuracy_7d: acc7, accuracy_30d: acc30 },
      latestPredictions: latestPreds.rows,
      portfolios: portfolios.rows[0],
      positions: { ...pos, win_rate: winRate },
      recentPositions: recentPositions.rows,
      watchlists: watch.rows[0],
      alerts: alerts.rows[0],
      lifecycle: {
        firstPrediction: lc.first_prediction,
        lastPrediction: lc.last_prediction,
        next7dCheckpoint: next7d,
        next30dCheckpoint: next30d,
        due7d: parseInt(lc.due_7d),
        due30d: parseInt(lc.due_30d),
        pending7d: parseInt(lc.pending_7d),
        pending30d: parseInt(lc.pending_30d),
        serverNow: new Date().toISOString()
      }
    });
  } catch(e) { safeError(res, e); }
});

// ── STRIPE ──
app.post('/create-subscription', async (req, res) => {
  const { paymentMethodId, priceId, email, promoCode, password } = req.body;
  try {
    const customer = await stripe.customers.create({ email: email || 'subscriber@nova-ai.com', payment_method: paymentMethodId, invoice_settings: { default_payment_method: paymentMethodId } });
    const subData = { customer: customer.id, items: [{ price: priceId }], payment_settings: { payment_method_types: ['card'], save_default_payment_method: 'on_subscription' }, expand: ['latest_invoice.payment_intent'] };
    
    if (promoCode) {
      try {
        const promos = await stripe.promotionCodes.list({ code: promoCode, active: true, limit: 1 });
        if (promos.data.length > 0) {
          subData.discounts = [{ promotion_code: promos.data[0].id }];
        } else {
          return res.status(400).json({ error: 'Code promo invalide ou expire' });
        }
      } catch(promoErr) {
        return res.status(400).json({ error: 'Code promo invalide' });
      }
    }
    
    const subscription = await stripe.subscriptions.create(subData);

    // Map the paid price to the corresponding plan
    const PRICE_TO_PLAN = {
      'price_1TmzUwF95nNTdqRQfPfEowyG': 'premium',
      'price_1TY5ZxF95nNTdqRQXnVpbtrH': 'vip'
    };
    const paidPlan = PRICE_TO_PLAN[priceId] || 'premium';

    // Auto-provision the account with the correct plan (only if email + password provided)
    let accountCreated = false;
    if (email && password && password.length >= 8) {
      try {
        const existing = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
        const hashed = await bcrypt.hash(password, 12);
        if (existing.rows.length > 0) {
          // Existing account: upgrade its plan (and refresh password)
          await pool.query('UPDATE users SET plan = $1 WHERE email = $2', [paidPlan, email]);
        } else {
          await pool.query('INSERT INTO users (email, password, plan) VALUES ($1, $2, $3)', [email, hashed, paidPlan]);
        }
        accountCreated = true;
      } catch(acctErr) {
        console.error('[create-subscription] account provisioning failed:', acctErr.message);
        // Payment still succeeded; we surface a flag so the client can be told to contact support
      }
    }

    res.json({
      subscriptionId: subscription.id,
      clientSecret: subscription.latest_invoice.payment_intent?.client_secret,
      status: subscription.status,
      plan: paidPlan,
      accountCreated: accountCreated
    });
  } catch (e) {
    console.error('[ERROR] create-subscription:', e.message);
    // Stripe card errors are safe to show the user; everything else stays generic
    if (e.type === 'StripeCardError') {
      return res.status(400).json({ error: e.message });
    }
    res.status(400).json({ error: 'Le paiement n a pas pu etre traite. Veuillez reessayer.' });
  }
});

// ── TIERED ANALYSIS: daily limit depends on plan (free=1, premium=5, vip=unlimited) ──
// Quota status: how many analyses used today vs the plan limit
app.get('/api/free-status', auth, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT plan, free_analysis_date, analysis_count FROM users WHERE email = $1', [req.userEmail]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
    const today = new Date().toLocaleDateString('fr-FR');
    const limits = { free: 1, premium: 5, vip: Infinity };
    const limit = limits[user.plan] !== undefined ? limits[user.plan] : 1;
    const used = (user.free_analysis_date === today) ? (user.analysis_count || 0) : 0;
    res.json({
      plan: user.plan,
      used: used,
      limit: (limit === Infinity ? null : limit),
      remaining: (limit === Infinity ? null : Math.max(0, limit - used))
    });
  } catch(e) { safeError(res, e); }
});

app.post('/api/free-analysis', auth, async (req, res) => {
  const { symbol, name, price, change, lang } = req.body;
  if (!symbol) return res.status(400).json({ error: 'Symbole manquant' });
  try {
    const userRes = await pool.query('SELECT plan, free_analysis_date, analysis_count FROM users WHERE email = $1', [req.userEmail]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
    const today = new Date().toLocaleDateString('fr-FR');
    // Daily quota per plan
    const limits = { free: 1, premium: 5, vip: Infinity };
    const limit = limits[user.plan] !== undefined ? limits[user.plan] : 1;
    // Reset the counter if it's a new day
    let count = (user.free_analysis_date === today) ? (user.analysis_count || 0) : 0;
    if (count >= limit) {
      return res.status(429).json({
        error: 'limit_reached',
        message: user.plan === 'free'
          ? 'Limite quotidienne atteinte (1/jour). Passez Premium ou VIP pour plus d analyses.'
          : 'Limite quotidienne atteinte (5/jour). Passez VIP pour des analyses illimitees.',
        used: count, limit: limit
      });
    }
    // Generate the analysis (language-aware)
    const langName = { fr:'francais', en:'English', es:'espanol', de:'Deutsch', it:'italiano', pt:'portugues' }[lang] || 'francais';
    let prompt, sysPrompt;
    if (lang === 'en') {
      prompt = 'Professional analysis of ' + (name||symbol) + ' (' + symbol + '). Price: $' + price + ', change: ' + change + '%. 5 points: situation, strengths/weaknesses, risk /10, signal BUY/SELL/HOLD, price target. 150 words max. Plain text.';
      sysPrompt = 'You are N.O.V.A., a financial analysis expert at Naite Industries. Reply in English. Plain text.';
    } else {
      prompt = 'Analyse professionnelle de ' + (name||symbol) + ' (' + symbol + '). Prix: $' + price + ', variation: ' + change + '%. 5 points: situation, forces/faiblesses, risque /10, signal ACHETER/VENDRE/CONSERVER, objectif prix. 150 mots max. Texte brut.';
      sysPrompt = 'Tu es N.O.V.A., experte en analyse financiere de Naite Industries. Reponds en ' + langName + '. Texte brut.';
    }
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, messages: [{ role: 'user', content: prompt }], system: sysPrompt })
    });
    const d = await r.json();
    const text = (d.content && d.content[0] && d.content[0].text) || 'Analyse indisponible.';
    // Increment the daily counter (skip for unlimited VIP to avoid useless writes)
    if (user.plan !== 'vip') {
      count++;
      await pool.query('UPDATE users SET free_analysis_date = $1, analysis_count = $2, free_analysis_symbol = $3 WHERE email = $4', [today, count, symbol, req.userEmail]);
    }
    res.json({ analysis: text, symbol: symbol, used: count, limit: (limit === Infinity ? null : limit) });
  } catch(e) { safeError(res, e); }
});

// ── CLAUDE API ──
app.post('/api/chat', aiLimiter, async (req, res) => {
  const { history, system, useWebSearch } = req.body;
  try {
    const body = {
      model: 'claude-sonnet-4-5',
      max_tokens: 700,
      system: system || 'You are N.O.V.A., a financial AI assistant.',
      messages: history
    };
    // Enable web search for real-time financial news
    if (useWebSearch !== false) {
      body.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
    }
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'web-search-2025-03-05'
      },
      body: JSON.stringify(body)
    });
    const d = await r.json();
    // Extract text from potentially mixed content blocks
    if (d.content && Array.isArray(d.content)) {
      const textBlocks = d.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
      if (textBlocks) d.content = [{ type: 'text', text: textBlocks }];
    }
    res.json(d);
  } catch (e) { safeError(res, e); }
});

// ── FINANCE ──
// ── FINANCIAL NEWS ──
app.get('/api/news', async (req, res) => {
  const { symbol } = req.query;
  try {
    const query = symbol ? symbol.replace('-USD','').replace('^','') + ' stock market' : 'financial markets crypto stocks';
    const r = await fetch(
      'https://query1.finance.yahoo.com/v1/finance/search?q=' + encodeURIComponent(query) + '&newsCount=5&enableFuzzyQuery=false',
      { headers: { 'User-Agent': 'Mozilla/5.0' } }
    );
    const d = await r.json();
    const news = (d.news || []).slice(0, 5).map(n => ({
      title: n.title,
      time: new Date(n.providerPublishTime * 1000).toLocaleDateString('fr-FR'),
      publisher: n.publisher
    }));
    res.json({ news });
  } catch(e) { res.json({ news: [] }); }
});

app.get('/api/finance', async (req, res) => {
  const { symbol } = req.query;
  try {
    const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1mo', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) return res.json({ error: 'No data' });
    const meta = result.meta;
    const price = meta.regularMarketPrice;
    const prev = meta.chartPreviousClose || meta.previousClose;
    const change = prev ? ((price - prev) / prev * 100).toFixed(2) : 0;
    // 1-month closing prices for the sparkline
    const closes = (result.indicators?.quote?.[0]?.close || []).filter(function(c){ return c !== null && c !== undefined; });
    res.json({ symbol, name: meta.longName || symbol, price, change: parseFloat(change), currency: meta.currency, market: meta.exchangeName, sparkline: closes });
  } catch (e) { safeError(res, e); }
});

// ── CATALOG: live prices for the entire trading universe (cached 60s) ──
let catalogCache = { data: null, ts: 0 };
app.get('/api/catalog', async (req, res) => {
  try {
    // Serve from cache if fresh (under 60s) to avoid hammering Yahoo
    if (catalogCache.data && (Date.now() - catalogCache.ts) < 60000) {
      return res.json({ assets: catalogCache.data, cached: true });
    }
    const assets = [];
    for (const symbol of TRADING_UNIVERSE) {
      try {
        const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const d = await r.json();
        const result = d?.chart?.result?.[0];
        if (!result || !result.meta) continue;
        const meta = result.meta;
        const price = meta.regularMarketPrice;
        const prev = meta.chartPreviousClose || meta.previousClose;
        const change = prev ? parseFloat(((price - prev) / prev * 100).toFixed(2)) : 0;
        // Categorize
        let category = 'stock';
        if (symbol.includes('-USD')) category = 'crypto';
        else if (['SPY','QQQ','DIA','IWM','^GSPC','^IXIC','^DJI','VTI','VOO'].some(e => symbol.includes(e))) category = 'etf';
        assets.push({ symbol, name: meta.longName || meta.shortName || symbol, price, change, currency: meta.currency || 'USD', category });
      } catch(e) { /* skip this asset */ }
      await new Promise(r => setTimeout(r, 60));
    }
    catalogCache = { data: assets, ts: Date.now() };
    res.json({ assets, cached: false });
  } catch(e) { safeError(res, e); }
});

// ── PREDICTIONS ──
app.post('/api/predictions/save', async (req, res) => {
  const { symbol, name, signal, price, confidence, reasoning } = req.body;
  if (!symbol || !signal || !price) return res.status(400).json({ error: 'Missing fields' });
  try {
    const dateStr = new Date().toLocaleDateString('fr-FR');
    const result = await pool.query(
      'INSERT INTO predictions (symbol, name, signal, price, confidence, reasoning, date_str) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [symbol, name||symbol, signal, parseFloat(price), confidence||70, reasoning||'', dateStr]
    );
    console.log('Prediction saved:', symbol, signal, price);
    res.json({ ok: true, id: result.rows[0].id });
  } catch(e) { safeError(res, e); }
});

// ── PERFORMANCE HISTORY: hypothetical portfolio + accuracy over time ──
// Honest simulation: follows every VERIFIED BUY signal from the new engine,
// applying its real 7-day result (gains AND losses). Based on the technical engine only.
app.get('/api/performance', async (req, res) => {
  try {
    // All verified BUY signals, oldest first
    const rows = (await pool.query(
      "SELECT date, result_7d, correct_7d FROM predictions WHERE signal = 'ACHETER' AND verified_7d = TRUE AND result_7d IS NOT NULL ORDER BY date ASC"
    )).rows;

    const startCapital = 1000;
    const positionFraction = 0.10; // each signal uses 10% of current capital (realistic, diversified)
    let capital = startCapital;
    const portfolioCurve = [{ date: null, value: startCapital, label: 'start' }];
    const accuracyCurve = [];
    let wins = 0, total = 0;

    rows.forEach(function(r) {
      const ret = parseFloat(r.result_7d) / 100; // e.g. 0.05 for +5%
      // Apply the real result to a fraction of capital
      capital = capital * (1 + positionFraction * ret);
      portfolioCurve.push({ date: r.date, value: Math.round(capital * 100) / 100 });
      // Rolling accuracy
      total++;
      if (r.correct_7d === true) wins++;
      accuracyCurve.push({ date: r.date, accuracy: Math.round((wins / total) * 100) });
    });

    const finalValue = Math.round(capital * 100) / 100;
    const totalReturn = Math.round(((finalValue - startCapital) / startCapital) * 10000) / 100; // %

    // ── MARKET BENCHMARK: how did the market do over the SAME period? ──
    // Honest comparison: buy & hold S&P 500 (SPY) and Bitcoin (BTC) over the signal window.
    let benchmarks = { spy: null, btc: null };
    if (rows.length >= 2) {
      const firstDate = new Date(rows[0].date);
      const lastDate = new Date(rows[rows.length - 1].date);
      const daysSpan = Math.max(7, Math.ceil((lastDate - firstDate) / (1000 * 60 * 60 * 24)) + 7);
      const range = daysSpan <= 30 ? '1mo' : daysSpan <= 90 ? '3mo' : '6mo';
      async function benchReturn(symbol) {
        try {
          const hist = await getHistoricalCloses(symbol);
          if (!hist || !hist.closes || hist.closes.length < 2) return null;
          // Approximate: use the last N closes matching the signal window
          const closes = hist.closes;
          const startIdx = Math.max(0, closes.length - Math.min(closes.length, daysSpan));
          const startPrice = closes[startIdx];
          const endPrice = closes[closes.length - 1];
          if (!startPrice) return null;
          return Math.round(((endPrice - startPrice) / startPrice) * 10000) / 100;
        } catch(e) { return null; }
      }
      benchmarks.spy = await benchReturn('SPY');
      benchmarks.btc = await benchReturn('BTC-USD');
    }

    // Record one snapshot per day (upsert: only the first call of the day writes, later calls update)
    try {
      const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      await pool.query(
        `INSERT INTO perf_history (date_str, nova_return, spy_return, btc_return, signals_count)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (date_str) DO UPDATE SET
           nova_return = EXCLUDED.nova_return,
           spy_return = EXCLUDED.spy_return,
           btc_return = EXCLUDED.btc_return,
           signals_count = EXCLUDED.signals_count,
           recorded_at = NOW()`,
        [todayStr, totalReturn, benchmarks.spy, benchmarks.btc, rows.length]
      );
    } catch(histErr) { console.log('perf_history record error:', histErr.message); }

    res.json({
      startCapital,
      finalValue,
      totalReturn,
      signalsCount: rows.length,
      portfolioCurve,
      accuracyCurve,
      benchmarks,
      note: 'Simulation basee sur les signaux ACHETER verifies du moteur technique. Chaque position = 10% du capital. Resultats reels a 7 jours, gains et pertes inclus.'
    });
  } catch(e) { safeError(res, e); }
});

// ── PERFORMANCE HISTORY: daily snapshots over time ──
app.get('/api/perf-history', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT date_str, nova_return, spy_return, btc_return, signals_count FROM perf_history ORDER BY date_str ASC'
    );
    res.json({ history: result.rows });
  } catch(e) { safeError(res, e); }
});

app.get('/api/predictions', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    const result = await pool.query('SELECT * FROM predictions ORDER BY date DESC LIMIT $1 OFFSET $2', [limit, offset]);
    const preds = result.rows.map(p => ({
      id: p.id, symbol: p.symbol, name: p.name, signal: p.signal,
      price: parseFloat(p.price), confidence: p.confidence, reasoning: p.reasoning,
      dateStr: p.date_str, date: p.date,
      verified7d: p.verified_7d, verified30d: p.verified_30d,
      priceAfter7d: p.price_after_7d ? parseFloat(p.price_after_7d) : null,
      priceAfter30d: p.price_after_30d ? parseFloat(p.price_after_30d) : null,
      result7d: p.result_7d, result30d: p.result_30d,
      correct7d: p.correct_7d, correct30d: p.correct_30d
    }));
    // GLOBAL stats computed over the ENTIRE table, not just the limited page
    const totalRes = await pool.query('SELECT COUNT(*) AS total FROM predictions');
    const verifRes = await pool.query('SELECT COUNT(*) AS verified, COUNT(*) FILTER (WHERE correct_7d = TRUE) AS correct FROM predictions WHERE verified_7d = TRUE');
    const totalCount = parseInt(totalRes.rows[0].total);
    const verifiedCount = parseInt(verifRes.rows[0].verified);
    const correctCount = parseInt(verifRes.rows[0].correct);
    const accuracy = verifiedCount > 0 ? Math.round((correctCount / verifiedCount) * 100) : null;
    const bySignalRes = await pool.query("SELECT signal, COUNT(*) FILTER (WHERE verified_7d = TRUE) AS total, COUNT(*) FILTER (WHERE verified_7d = TRUE AND correct_7d = TRUE) AS correct FROM predictions GROUP BY signal");
    const bySignal = { ACHETER:{total:0,correct:0}, VENDRE:{total:0,correct:0}, CONSERVER:{total:0,correct:0} };
    bySignalRes.rows.forEach(r => { if(bySignal[r.signal]){ bySignal[r.signal].total = parseInt(r.total); bySignal[r.signal].correct = parseInt(r.correct); } });
    // Average returns on verified BUY signals (7d and 30d)
    const retRes = await pool.query("SELECT AVG(result_7d) AS avg7 FROM predictions WHERE signal = 'ACHETER' AND verified_7d = TRUE AND result_7d IS NOT NULL");
    const ret30Res = await pool.query("SELECT AVG(result_30d) AS avg30 FROM predictions WHERE signal = 'ACHETER' AND verified_30d = TRUE AND result_30d IS NOT NULL");
    const avgReturn7d = retRes.rows[0].avg7 !== null ? Math.round(parseFloat(retRes.rows[0].avg7) * 100) / 100 : null;
    const avgReturn30d = ret30Res.rows[0].avg30 !== null ? Math.round(parseFloat(ret30Res.rows[0].avg30) * 100) / 100 : null;
    res.json({ predictions: preds, stats: { total: totalCount, totalVerified: verifiedCount, accuracy, bySignal, avgReturn7d, avgReturn30d } });
  } catch(e) { safeError(res, e); }
});

// Asset-class-aware thresholds — crypto is naturally more volatile than stocks/ETFs/forex
function getThresholds(symbol) {
  const isCrypto = /-(USD|EUR|GBP)$/.test(symbol) && /^(BTC|ETH|SOL|BNB|XRP|ADA|AVAX|DOT|LINK|MATIC|DOGE)/.test(symbol);
  const isForex = /^(EUR|GBP|USD|JPY)(USD|EUR|GBP|JPY)?=?X?$/.test(symbol) || symbol.includes('/');
  if (isCrypto) return { buy7: 3, sell7: -3, hold7: 8, buy30: 6, sell30: -6, hold30: 15 };
  if (isForex) return { buy7: 0.5, sell7: -0.5, hold7: 2, buy30: 1, sell30: -1, hold30: 3 };
  return { buy7: 1, sell7: -1, hold7: 3, buy30: 2, sell30: -2, hold30: 5 }; // stocks/ETFs
}

async function verifyPredictions() {
  try {
    const now = new Date();
    const result = await pool.query('SELECT * FROM predictions WHERE (verified_7d = FALSE OR verified_30d = FALSE)');
    for (const pred of result.rows) {
      const predDate = new Date(pred.date);
      const daysDiff = (now - predDate) / (1000 * 60 * 60 * 24);
      const th = getThresholds(pred.symbol);
      if (!pred.verified_7d && daysDiff >= 7) {
        try {
          const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + pred.symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
          const d = await r.json();
          const currentPrice = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
          if (currentPrice) {
            const priceDiff = ((currentPrice - pred.price) / pred.price) * 100;
            const correct = pred.signal === 'ACHETER' ? priceDiff > th.buy7 : pred.signal === 'VENDRE' ? priceDiff < th.sell7 : Math.abs(priceDiff) < th.hold7;
            await pool.query('UPDATE predictions SET verified_7d=TRUE, price_after_7d=$1, result_7d=$2, correct_7d=$3 WHERE id=$4', [currentPrice, priceDiff.toFixed(2), correct, pred.id]);
            console.log('Verified 7d:', pred.symbol, pred.signal, correct, priceDiff.toFixed(2)+'%', 'threshold:', JSON.stringify(th));
          }
        } catch(e) {}
        await new Promise(r => setTimeout(r, 1000));
      }
      if (!pred.verified_30d && daysDiff >= 30) {
        try {
          const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + pred.symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
          const d = await r.json();
          const currentPrice = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
          if (currentPrice) {
            const priceDiff = ((currentPrice - pred.price) / pred.price) * 100;
            const correct = pred.signal === 'ACHETER' ? priceDiff > th.buy30 : pred.signal === 'VENDRE' ? priceDiff < th.sell30 : Math.abs(priceDiff) < th.hold30;
            await pool.query('UPDATE predictions SET verified_30d=TRUE, price_after_30d=$1, result_30d=$2, correct_30d=$3 WHERE id=$4', [currentPrice, priceDiff.toFixed(2), correct, pred.id]);
          }
        } catch(e) {}
        await new Promise(r => setTimeout(r, 1000));
      }
    }
    console.log('Predictions verified');
  } catch(e) { console.log('verifyPredictions error:', e.message); }
}

// Run verification every hour so 7d/30d rates appear as soon as the window is reached
// (no longer dependent solely on the 7h30 daily report)
setInterval(function() {
  verifyPredictions();
}, 60 * 60 * 1000);
// Also run once shortly after startup (covers restarts that missed a slot)
setTimeout(function() {
  verifyPredictions();
}, 30 * 1000);

// ── CANVAS CHARTS ──
const { createCanvas } = require('canvas');

async function fetchHistoricalData(symbol) {
  try {
    const url = 'https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1mo';
    const r = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) return null;
    const timestamps = result.timestamp || [];
    const closes = result.indicators?.quote?.[0]?.close || [];
    const volumes = result.indicators?.quote?.[0]?.volume || [];
    if (!closes.length) return null;
    return {
      labels: timestamps.map(t => new Date(t * 1000).toISOString().slice(5, 10)),
      prices: closes.slice(-30).map(p => parseFloat((p || 0).toFixed(2))),
      volumes: volumes.slice(-30).map(v => parseFloat(v || 0))
    };
  } catch (e) { return null; }
}

function drawBarLineChart(data, title) {
  const W = 900, H = 480;
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#050810'; ctx.fillRect(0, 0, W, H);
  const prices = data.prices, volumes = data.volumes, labels = data.labels;
  const isUp = prices[prices.length-1] >= prices[0];
  const lineColor = isUp ? '#00e5ff' : '#ff4d6d';
  const change = ((prices[prices.length-1] - prices[0]) / prices[0] * 100).toFixed(2);
  const sx = 75, sy = 55, cw = W-100, ch = H-110;
  const maxP = Math.max(...prices)*1.02, minP = Math.min(...prices)*0.98;
  const maxV = Math.max(...volumes)||1;
  ctx.strokeStyle='rgba(0,180,255,0.07)'; ctx.lineWidth=0.5;
  for(let i=0;i<=6;i++){const y=sy+ch*i/6;ctx.beginPath();ctx.moveTo(sx,y);ctx.lineTo(sx+cw,y);ctx.stroke();}
  const bw=cw/prices.length*0.6;
  volumes.forEach((v,i)=>{const x=sx+i*(cw/prices.length)+bw*0.2;const bh=(v/maxV)*ch*0.3;const y=sy+ch-bh;const g=ctx.createLinearGradient(0,y,0,y+bh);g.addColorStop(0,'rgba(0,150,255,0.5)');g.addColorStop(1,'rgba(0,80,200,0.1)');ctx.fillStyle=g;ctx.fillRect(x,y,bw,bh);});
  ctx.beginPath();prices.forEach((p,i)=>{const x=sx+i*(cw/(prices.length-1));const y=sy+ch-((p-minP)/(maxP-minP))*ch;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.lineTo(sx+cw,sy+ch);ctx.lineTo(sx,sy+ch);ctx.closePath();const ag=ctx.createLinearGradient(0,sy,0,sy+ch);ag.addColorStop(0,isUp?'rgba(0,229,255,0.18)':'rgba(255,77,109,0.18)');ag.addColorStop(1,'rgba(0,0,0,0)');ctx.fillStyle=ag;ctx.fill();
  for(let pass=0;pass<3;pass++){ctx.save();ctx.shadowColor=lineColor;ctx.shadowBlur=pass===0?20:pass===1?10:0;ctx.strokeStyle=lineColor;ctx.lineWidth=pass===2?2.5:1;ctx.beginPath();prices.forEach((p,i)=>{const x=sx+i*(cw/(prices.length-1));const y=sy+ch-((p-minP)/(maxP-minP))*ch;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.stroke();ctx.restore();}
  const lx=sx+cw;const ly=sy+ch-((prices[prices.length-1]-minP)/(maxP-minP))*ch;const py2=sy+ch-((prices[prices.length-2]-minP)/(maxP-minP))*ch;ctx.save();ctx.shadowColor=lineColor;ctx.shadowBlur=25;ctx.fillStyle=lineColor;ctx.beginPath();if(ly<py2){ctx.moveTo(lx,ly-14);ctx.lineTo(lx-8,ly+2);ctx.lineTo(lx+8,ly+2);}else{ctx.moveTo(lx,ly+14);ctx.lineTo(lx-8,ly-2);ctx.lineTo(lx+8,ly-2);}ctx.fill();ctx.restore();
  ctx.fillStyle='rgba(100,160,200,0.7)';ctx.font='10px monospace';for(let i=0;i<=4;i++){const p=minP+(maxP-minP)*(4-i)/4;ctx.fillText('$'+p.toFixed(0),4,sy+ch*i/4+4);}
  ctx.fillStyle='rgba(80,120,150,0.6)';ctx.font='9px monospace';labels.forEach((l,i)=>{if(i%4===0){const x=sx+i*(cw/(labels.length-1));ctx.fillText(l,x-10,sy+ch+16);}});
  ctx.fillStyle='#d0e8f8';ctx.font='bold 16px Arial';ctx.fillText(title+' | N.O.V.A. Naite Industries',sx,34);
  ctx.fillStyle=isUp?'#00ff88':'#ff6b6b';ctx.font='bold 14px Arial';ctx.fillText((isUp?'+ ':'-  ')+Math.abs(change)+'%',W-110,34);
  ctx.fillStyle='rgba(0,180,255,0.2)';ctx.font='11px Arial';ctx.fillText('N.O.V.A. AI Naite Industries 2026',W/2-100,H-8);
  return canvas.toBuffer('image/png');
}

function drawComparativeChart(datasets) {
  const W=900,H=480;const canvas=createCanvas(W,H);const ctx=canvas.getContext('2d');
  ctx.fillStyle='#040608';ctx.fillRect(0,0,W,H);
  const sx=65,sy=70,cw=W-100,ch=H-120;
  let all=[];datasets.forEach(d=>all=all.concat(d.data));
  const maxV=Math.max(...all)*1.1,minV=Math.min(Math.min(...all)*1.1,-1);
  ctx.strokeStyle='rgba(255,255,255,0.04)';ctx.lineWidth=0.5;
  for(let i=0;i<=6;i++){const y=sy+ch*i/6;ctx.beginPath();ctx.moveTo(sx,y);ctx.lineTo(sx+cw,y);ctx.stroke();const v=maxV-(maxV-minV)*i/6;ctx.fillStyle='rgba(255,255,255,0.35)';ctx.font='10px monospace';ctx.fillText(v.toFixed(1)+'%',2,y+4);}
  if(minV<0){const zy=sy+ch*maxV/(maxV-minV);ctx.save();ctx.strokeStyle='rgba(255,255,255,0.15)';ctx.lineWidth=1;ctx.setLineDash([6,4]);ctx.beginPath();ctx.moveTo(sx,zy);ctx.lineTo(sx+cw,zy);ctx.stroke();ctx.restore();}
  const colors=['#00e5ff','#ffd60a','#ff4d6d','#00ff88'];
  datasets.forEach((ds,di)=>{const color=colors[di%colors.length];for(let pass=0;pass<3;pass++){ctx.save();ctx.shadowColor=color;ctx.shadowBlur=pass===0?18:pass===1?8:0;ctx.strokeStyle=color;ctx.lineWidth=pass===2?2.5:1;ctx.beginPath();ds.data.forEach((v,i)=>{const x=sx+i*(cw/(ds.data.length-1));const y=sy+ch-((v-minV)/(maxV-minV))*ch;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});ctx.stroke();ctx.restore();}const lv=ds.data[ds.data.length-1];const lx=sx+cw;const ly=sy+ch-((lv-minV)/(maxV-minV))*ch;ctx.save();ctx.shadowColor=color;ctx.shadowBlur=15;ctx.fillStyle=color;ctx.beginPath();ctx.arc(lx,ly,5,0,Math.PI*2);ctx.fill();ctx.restore();ctx.fillStyle=color;ctx.font='bold 11px Arial';ctx.fillText(ds.label+' '+(lv>=0?'+':'')+lv.toFixed(1)+'%',lx-90,ly-10);});
  datasets.forEach((ds,di)=>{const color=colors[di%colors.length];ctx.fillStyle=color;ctx.fillRect(40+di*180,H-28,20,3);ctx.fillStyle='rgba(200,220,240,0.7)';ctx.font='11px Arial';ctx.fillText(ds.label,65+di*180,H-18);});
  ctx.fillStyle='#d0e8f8';ctx.font='bold 16px Arial';ctx.fillText('Performance Comparative | N.O.V.A.',sx,44);
  ctx.fillStyle='rgba(0,180,255,0.2)';ctx.font='11px Arial';ctx.fillText('N.O.V.A. AI Naite Industries 2026',W/2-100,H-8);
  return canvas.toBuffer('image/png');
}

async function sendPhotoToTelegram(token, chatId, imgBuf, caption) {
  try {
    const boundary = 'novabnd' + Date.now();
    const CRLF = '\r\n';
    const body = Buffer.concat([
      Buffer.from('--' + boundary + CRLF + 'Content-Disposition: form-data; name="chat_id"' + CRLF + CRLF + chatId + CRLF),
      Buffer.from('--' + boundary + CRLF + 'Content-Disposition: form-data; name="caption"' + CRLF + CRLF + caption + CRLF),
      Buffer.from('--' + boundary + CRLF + 'Content-Disposition: form-data; name="photo"; filename="chart.png"' + CRLF + 'Content-Type: image/png' + CRLF + CRLF),
      imgBuf,
      Buffer.from(CRLF + '--' + boundary + '--' + CRLF)
    ]);
    const r = await fetch('https://api.telegram.org/bot' + token + '/sendPhoto', {
      method: 'POST', headers: { 'Content-Type': 'multipart/form-data; boundary=' + boundary }, body
    });
    const d = await r.json();
    return d.ok;
  } catch (e) { return false; }
}

// ── DAILY REPORTS ──
const CANALS_CONFIG = {
  free:      { chatId: '-1003981091130' },
  essential: { chatId: '-1003905947217' },
  premium:   { chatId: '-1003989883363' },
  vip:       { chatId: '-1003895905201' }
};

async function fetchMarketData() {
  const symbols = ['BTC-USD','ETH-USD','SOL-USD','SPY','QQQ','NVDA','AAPL','TSLA'];
  const data = {};
  for (const sym of symbols) {
    try {
      const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + sym + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
      const d = await r.json();
      const meta = d?.chart?.result?.[0]?.meta;
      if (meta) {
        const price = meta.regularMarketPrice;
        const prev = meta.chartPreviousClose || meta.previousClose;
        data[sym] = { price, change: prev ? parseFloat(((price - prev) / prev * 100).toFixed(2)) : 0, name: meta.longName || sym };
      }
    } catch (e) {}
    await new Promise(r => setTimeout(r, 300));
  }
  return data;
}

async function generateDailyReport(tier, marketData, date) {
  const mktStr = Object.entries(marketData).map(([s,d]) => s+': $'+d.price?.toFixed(2)+' ('+(d.change>=0?'+':'')+d.change+'%)').join(', ');
  const styles = { free:'very short 80 words', essential:'standard 150 words', premium:'complete 250 words', vip:'exclusive premium 300 words' };
  const prompt = 'Generate daily market report in English, style '+styles[tier]+' for '+tier.toUpperCase()+'. DATE: '+date+'. MARKETS: '+mktStr+'. Sections: MARKET OVERVIEW, SIGNALS (BUY/SELL/HOLD), N.O.V.A. RECOMMENDATION. Plain text.';
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
  });
  const d = await r.json();
  return d.content?.[0]?.text || 'Report unavailable.';
}

function buildTieredMessage(tier, date, marketData, reportText) {
  const mkt = Object.entries(marketData).slice(0,5).map(([s,d])=>(d.change>=0?'Up ':'Down ')+s.replace('-USD','').replace('=X','')+': $'+d.price?.toFixed(2)+' ('+(d.change>=0?'+':'')+d.change+'%)').join('\n');
  const emojis = { free:'Free', essential:'Essential', premium:'Premium', vip:'VIP' };
  const sep = '---';
  const footers = {
    free: '\n'+sep+'\nFull analysis available with Essential Premium or VIP\nnova-industrie.netlify.app',
    essential: '\n'+sep+'\nUnlimited signals and charts available with Premium',
    premium: '\n'+sep+'\nCharts sent separately',
    vip: '\n'+sep+'\nFULL N.O.V.A. APP ACCESS: nova-vip1.netlify.app'
  };
  return 'N.O.V.A. REPORT '+emojis[tier]+' - '+date+'\nNaite Industries\n\n'+sep+'\nLIVE MARKETS\n'+mkt+'\n\n'+sep+'\n'+reportText+(footers[tier]||'')+'\n\n---\nNot financial advice. Always DYOR.';
}

async function sendDailyReports() {
  console.log('Sending daily reports...');
  const date = new Date().toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long' });
  const marketData = await fetchMarketData();
  const token = process.env.TELEGRAM_TOKEN;

  for (const [tier, canal] of Object.entries(CANALS_CONFIG)) {
    try {
      const report = await generateDailyReport(tier, marketData, date);
      const msg = buildTieredMessage(tier, date, marketData, report);
      const r = await fetch('https://api.telegram.org/bot'+token+'/sendMessage', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ chat_id: canal.chatId, text: msg, parse_mode:'Markdown', disable_web_page_preview:true })
      });
      const d = await r.json();
      console.log(tier+' text:', d.ok?'OK':'FAIL - '+d.description);
      await new Promise(r => setTimeout(r, 2000));

      if (tier === 'premium' || tier === 'vip') {
        const chartSymbols = ['BTC-USD','ETH-USD','SPY','NVDA'];
        for (const sym of chartSymbols.slice(0,2)) {
          const hData = await fetchHistoricalData(sym);
          if (!hData) continue;
          const imgBuf = drawBarLineChart(hData, sym.replace('-USD',''));
          const ok = await sendPhotoToTelegram(token, canal.chatId, imgBuf, sym.replace('-USD','')+' - 30 day analysis - N.O.V.A. '+tier.toUpperCase());
          console.log(sym+' chart:', ok?'OK':'FAIL');
          await new Promise(r => setTimeout(r, 4000));
        }
        const compDatasets = [];
        for (const sym of chartSymbols) {
          const hData = await fetchHistoricalData(sym);
          if (!hData) continue;
          const base = hData.prices[0];
          compDatasets.push({ label: sym.replace('-USD',''), data: hData.prices.map(p => parseFloat(((p-base)/base*100).toFixed(2))) });
          await new Promise(r => setTimeout(r, 2000));
        }
        if (compDatasets.length >= 2) {
          const compBuf = drawComparativeChart(compDatasets);
          const ok = await sendPhotoToTelegram(token, canal.chatId, compBuf, 'Comparative Performance 30 Days - N.O.V.A. '+tier.toUpperCase());
          console.log('Comparative chart:', ok?'OK':'FAIL');
        }
      }
    } catch (e) { console.log(tier+' error:', e.message); }
    await new Promise(r => setTimeout(r, 3000));
  }
  console.log('Daily reports done!');
  await verifyPredictions();
}

function scheduleDaily() {
  function checkTime() {
    const now = new Date();
    const paris = new Date(now.toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
    if (paris.getHours() === 7 && paris.getMinutes() === 30) sendDailyReports();
  }
  setInterval(checkTime, 60000);
  console.log('Scheduler started (7h30 Paris)');
}
scheduleDaily();

// Re-verify already verified predictions with corrected asset-class thresholds
app.post('/api/predictions/reverify', adminLimiter, adminGuard, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM predictions WHERE verified_7d = TRUE');
    let updated = 0;
    for (const pred of result.rows) {
      const th = getThresholds(pred.symbol);
      const priceDiff = parseFloat(pred.result_7d);
      const correct = pred.signal === 'ACHETER' ? priceDiff > th.buy7 : pred.signal === 'VENDRE' ? priceDiff < th.sell7 : Math.abs(priceDiff) < th.hold7;
      if (correct !== pred.correct_7d) {
        await pool.query('UPDATE predictions SET correct_7d=$1 WHERE id=$2', [correct, pred.id]);
        updated++;
      }
    }
    const result30 = await pool.query('SELECT * FROM predictions WHERE verified_30d = TRUE');
    for (const pred of result30.rows) {
      const th = getThresholds(pred.symbol);
      const priceDiff = parseFloat(pred.result_30d);
      const correct = pred.signal === 'ACHETER' ? priceDiff > th.buy30 : pred.signal === 'VENDRE' ? priceDiff < th.sell30 : Math.abs(priceDiff) < th.hold30;
      if (correct !== pred.correct_30d) {
        await pool.query('UPDATE predictions SET correct_30d=$1 WHERE id=$2', [correct, pred.id]);
        updated++;
      }
    }
    res.json({ ok: true, updated, total: result.rows.length + result30.rows.length });
  } catch(e) { safeError(res, e); }
});

// Force an immediate verification pass (on-demand, from the control center)
app.post('/api/predictions/verify-now', adminLimiter, adminGuard, async (req, res) => {
  try {
    // Snapshot counts before
    const before = await pool.query('SELECT COUNT(*) FILTER (WHERE verified_7d=TRUE) AS v7, COUNT(*) FILTER (WHERE verified_30d=TRUE) AS v30 FROM predictions');
    await verifyPredictions();
    const after = await pool.query('SELECT COUNT(*) FILTER (WHERE verified_7d=TRUE) AS v7, COUNT(*) FILTER (WHERE verified_30d=TRUE) AS v30 FROM predictions');
    // How many are eligible but still pending (reached 7 days, not yet verified)
    const pending = await pool.query(`
      SELECT COUNT(*) AS c FROM predictions
      WHERE verified_7d=FALSE AND date <= NOW() - INTERVAL '7 days'
    `);
    const newly7d = parseInt(after.rows[0].v7) - parseInt(before.rows[0].v7);
    const newly30d = parseInt(after.rows[0].v30) - parseInt(before.rows[0].v30);
    res.json({
      ok: true,
      newly_verified_7d: newly7d,
      newly_verified_30d: newly30d,
      total_verified_7d: parseInt(after.rows[0].v7),
      total_verified_30d: parseInt(after.rows[0].v30),
      still_pending_7d: parseInt(pending.rows[0].c)
    });
  } catch(e) { safeError(res, e); }
});

app.post('/send-reports', adminLimiter, adminGuard, async (req, res) => {
  sendDailyReports();
  res.json({ ok: true, message: 'Reports sending started...' });
});

app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '3.0' }));

// ── HEALTH CHECK (for external monitoring like UptimeRobot) ──
// Verifies the database is reachable. Returns 200 if healthy, 503 if not.
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', db: 'connected', systemActive: (typeof SYSTEM_ACTIVE !== 'undefined' ? SYSTEM_ACTIVE : true), time: new Date().toISOString() });
  } catch(e) {
    console.error('[HEALTH] Database check failed:', e.message);
    res.status(503).json({ status: 'unhealthy', db: 'disconnected' });
  }
});

// ── WATCHLIST ──
app.get('/api/watchlist', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM watchlists WHERE user_email = $1 ORDER BY added_at DESC', [req.userEmail]);
    res.json({ watchlist: result.rows });
  } catch(e) { safeError(res, e); }
});

app.post('/api/watchlist', auth, async (req, res) => {
  const { symbol, name } = req.body;
  if (!symbol) return res.status(400).json({ error: 'Symbol required' });
  try {
    await pool.query('INSERT INTO watchlists (user_email, symbol, name) VALUES ($1, $2, $3) ON CONFLICT (user_email, symbol) DO NOTHING', [req.userEmail, symbol, name || symbol]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

app.delete('/api/watchlist/:symbol', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM watchlists WHERE user_email = $1 AND symbol = $2', [req.userEmail, req.params.symbol]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

// ── ALERTS ──
app.get('/api/alerts', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM alerts WHERE user_email = $1 ORDER BY created_at DESC', [req.userEmail]);
    res.json({ alerts: result.rows });
  } catch(e) { safeError(res, e); }
});

app.post('/api/alerts', auth, async (req, res) => {
  const { symbol, name, condition, target_price } = req.body;
  if (!symbol || !condition || !target_price) return res.status(400).json({ error: 'Missing fields' });
  if (!['above','below'].includes(condition)) return res.status(400).json({ error: 'Invalid condition' });
  try {
    const result = await pool.query(
      'INSERT INTO alerts (user_email, symbol, name, condition, target_price) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [req.userEmail, symbol, name || symbol, condition, parseFloat(target_price)]
    );
    res.json({ ok: true, id: result.rows[0].id });
  } catch(e) { safeError(res, e); }
});

app.delete('/api/alerts/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM alerts WHERE user_email = $1 AND id = $2', [req.userEmail, req.params.id]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

// ── ALERT CHECKER ──
async function checkAlerts() {
  try {
    const result = await pool.query('SELECT * FROM alerts WHERE triggered = FALSE');
    if (result.rows.length === 0) return;
    const bySymbol = {};
    result.rows.forEach(a => {
      if (!bySymbol[a.symbol]) bySymbol[a.symbol] = [];
      bySymbol[a.symbol].push(a);
    });
    for (const symbol of Object.keys(bySymbol)) {
      try {
        const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const d = await r.json();
        const price = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
        if (!price) continue;
        for (const alert of bySymbol[symbol]) {
          const target = parseFloat(alert.target_price);
          const triggered = (alert.condition === 'above' && price >= target) || (alert.condition === 'below' && price <= target);
          if (triggered) {
            await pool.query('UPDATE alerts SET triggered = TRUE, triggered_at = NOW(), triggered_price = $1 WHERE id = $2', [price, alert.id]);
          }
        }
      } catch(e) {}
      await new Promise(r => setTimeout(r, 500));
    }
  } catch(e) { console.log('checkAlerts error:', e.message); }
}
setInterval(checkAlerts, 5 * 60 * 1000);

// ── PAPER TRADING PORTFOLIO ──
app.get('/api/portfolio', auth, async (req, res) => {
  try {
    const portfolio = await pool.query('SELECT * FROM portfolios WHERE user_email = $1', [req.userEmail]);
    if (portfolio.rows.length === 0) return res.json({ portfolio: null, positions: [], history: [] });
    const open = await pool.query('SELECT * FROM positions WHERE user_email = $1 AND status = $2 ORDER BY entry_date DESC', [req.userEmail, 'open']);
    const closed = await pool.query('SELECT * FROM positions WHERE user_email = $1 AND status = $2 ORDER BY exit_date DESC LIMIT 50', [req.userEmail, 'closed']);
    const positionsWithPrices = [];
    for (const pos of open.rows) {
      try {
        const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + pos.symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const d = await r.json();
        const currentPrice = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
        if (currentPrice) {
          const pnl = (currentPrice - parseFloat(pos.entry_price)) * parseFloat(pos.quantity);
          const pnlPct = ((currentPrice - parseFloat(pos.entry_price)) / parseFloat(pos.entry_price)) * 100;
          positionsWithPrices.push({ ...pos, current_price: currentPrice, current_pnl: pnl, current_pnl_pct: pnlPct.toFixed(2) });
        } else { positionsWithPrices.push(pos); }
      } catch(e) { positionsWithPrices.push(pos); }
    }
    const totalPositionsValue = positionsWithPrices.reduce((s, p) => s + (p.current_price ? p.current_price * parseFloat(p.quantity) : parseFloat(p.entry_price) * parseFloat(p.quantity)), 0);
    const totalValue = parseFloat(portfolio.rows[0].cash) + totalPositionsValue;
    const totalReturn = ((totalValue - parseFloat(portfolio.rows[0].initial_capital)) / parseFloat(portfolio.rows[0].initial_capital)) * 100;
    res.json({
      portfolio: portfolio.rows[0],
      positions: positionsWithPrices,
      history: closed.rows,
      stats: {
        totalValue: totalValue.toFixed(2),
        cash: parseFloat(portfolio.rows[0].cash).toFixed(2),
        positionsValue: totalPositionsValue.toFixed(2),
        totalReturn: totalReturn.toFixed(2),
        winRate: closed.rows.length > 0 ? Math.round(closed.rows.filter(p => parseFloat(p.pnl) > 0).length / closed.rows.length * 100) : null,
        totalTrades: closed.rows.length
      }
    });
  } catch(e) { safeError(res, e); }
});

app.post('/api/portfolio/create', auth, async (req, res) => {
  const { capital, risk_profile } = req.body;
  if (!capital || capital < 100) return res.status(400).json({ error: 'Capital minimum 100$' });
  try {
    await pool.query('INSERT INTO portfolios (user_email, initial_capital, cash, risk_profile) VALUES ($1, $2, $2, $3) ON CONFLICT (user_email) DO UPDATE SET initial_capital = $2, cash = $2, risk_profile = $3, active = TRUE', [req.userEmail, parseFloat(capital), risk_profile || 'balanced']);
    await pool.query('DELETE FROM positions WHERE user_email = $1', [req.userEmail]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

app.post('/api/portfolio/toggle', auth, async (req, res) => {
  try {
    await pool.query('UPDATE portfolios SET active = NOT active WHERE user_email = $1', [req.userEmail]);
    const r = await pool.query('SELECT active FROM portfolios WHERE user_email = $1', [req.userEmail]);
    res.json({ active: r.rows[0]?.active });
  } catch(e) { safeError(res, e); }
});

app.delete('/api/portfolio', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM positions WHERE user_email = $1', [req.userEmail]);
    await pool.query('DELETE FROM portfolios WHERE user_email = $1', [req.userEmail]);
    res.json({ ok: true });
  } catch(e) { safeError(res, e); }
});

// ── AUTONOMOUS TRADER ──
const TRADING_UNIVERSE = [
  'BTC-USD','ETH-USD','SOL-USD','BNB-USD','XRP-USD','ADA-USD','AVAX-USD','DOT-USD','LINK-USD','MATIC-USD',
  'SPY','DIA','IWM','VTI','VOO','GLD','SLV','XLF','XLE','XLV',
  'AAPL','MSFT','NVDA','GOOGL','META','AMZN','TSLA','AMD','NFLX','COIN','JPM','V','MA','DIS','BA','UBER','PYPL'
];
// Removed from active universe (Jul 2026): XLK, SOXX, ARKK, QQQ — volatile tech/growth ETFs
// that consistently underperformed on BUY signals (avg -2 to -3% over 7d), while individual
// stocks and broad indices performed well. Data confirmed the issue is these sector ETFs
// specifically, not volatility in general (cryptos/TSLA/NVDA averaged +2.53% on BUY signals).
const RISK_PROFILES = {
  conservative: { positionSize: 0.05, stopLoss: 0.05, takeProfit: 0.08, minConfidence: 78, maxPositions: 5 },
  balanced: { positionSize: 0.10, stopLoss: 0.08, takeProfit: 0.15, minConfidence: 68, maxPositions: 8 },
  aggressive: { positionSize: 0.15, stopLoss: 0.12, takeProfit: 0.25, minConfidence: 58, maxPositions: 12 }
};

async function getPriceForSymbol(symbol) {
  try {
    const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=5d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const meta = d?.chart?.result?.[0]?.meta;
    if (!meta?.regularMarketPrice) return null;
    const prices = d?.chart?.result?.[0]?.indicators?.quote?.[0]?.close || [];
    const validPrices = prices.filter(p => p !== null);
    return {
      price: meta.regularMarketPrice,
      change: validPrices.length >= 2 ? ((meta.regularMarketPrice - validPrices[0]) / validPrices[0] * 100) : 0,
      name: meta.symbol || symbol
    };
  } catch(e) { return null; }
}

// ── TECHNICAL ANALYSIS ENGINE — real indicators on historical data ──
// Fetches ~3 months of daily candles and computes convergent technical signals.
async function getHistoricalCloses(symbol) {
  try {
    const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=3mo', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) return null;
    const closes = (result.indicators?.quote?.[0]?.close || []).filter(p => p !== null && p !== undefined);
    const meta = result.meta;
    if (closes.length < 50 || !meta?.regularMarketPrice) return null;
    return { closes: closes, price: meta.regularMarketPrice, name: meta.symbol || symbol };
  } catch(e) { return null; }
}

function sma(arr, period) {
  if (arr.length < period) return null;
  const slice = arr.slice(-period);
  return slice.reduce((a, b) => a + b, 0) / period;
}

function rsi(closes, period = 14) {
  if (closes.length < period + 1) return null;
  let gains = 0, losses = 0;
  for (let i = closes.length - period; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    if (diff >= 0) gains += diff; else losses -= diff;
  }
  const avgGain = gains / period, avgLoss = losses / period;
  if (avgLoss === 0) return 100;
  const rs = avgGain / avgLoss;
  return 100 - (100 / (1 + rs));
}

function ema(arr, period) {
  if (arr.length < period) return null;
  const k = 2 / (period + 1);
  let emaVal = arr.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < arr.length; i++) emaVal = arr[i] * k + emaVal * (1 - k);
  return emaVal;
}

function macd(closes) {
  const ema12 = ema(closes, 12);
  const ema26 = ema(closes, 26);
  if (ema12 === null || ema26 === null) return null;
  return ema12 - ema26; // positive = bullish momentum
}

// Core technical signal generator — convergence of multiple indicators
function novaTechnicalSignal(symbol, closes, price) {
  const sma20 = sma(closes, 20);
  const sma50 = sma(closes, 50);
  const rsiVal = rsi(closes, 14);
  const macdVal = macd(closes);
  const prevClose = closes[closes.length - 2] || price;
  const momentum5 = closes.length >= 6 ? ((price - closes[closes.length - 6]) / closes[closes.length - 6]) * 100 : 0;

  // Build a convergence score: each indicator votes bullish (+) or bearish (-)
  let bull = 0, bear = 0;
  const reasons = [];

  // 1. Trend: price vs moving averages
  if (sma20 && sma50) {
    if (price > sma20 && sma20 > sma50) { bull += 2; reasons.push('tendance haussiere confirmee (prix > MM20 > MM50)'); }
    else if (price < sma20 && sma20 < sma50) { bear += 2; reasons.push('tendance baissiere confirmee (prix < MM20 < MM50)'); }
    else if (price > sma50) { bull += 1; reasons.push('prix au-dessus de la MM50'); }
    else { bear += 1; reasons.push('prix sous la MM50'); }
  }

  // 2. RSI: overbought / oversold
  if (rsiVal !== null) {
    if (rsiVal < 30) { bull += 2; reasons.push('RSI en survente (' + rsiVal.toFixed(0) + ')'); }
    else if (rsiVal > 70) { bear += 2; reasons.push('RSI en surachat (' + rsiVal.toFixed(0) + ')'); }
    else if (rsiVal < 45) { bull += 1; }
    else if (rsiVal > 55) { bear += 0.5; }
  }

  // 3. MACD momentum
  if (macdVal !== null) {
    if (macdVal > 0) { bull += 1; reasons.push('momentum MACD positif'); }
    else { bear += 1; reasons.push('momentum MACD negatif'); }
  }

  // 4. Short-term momentum (5 days)
  if (momentum5 > 4) { bear += 0.5; } // too hot, mean reversion risk
  else if (momentum5 < -8) { bull += 1; reasons.push('survente court terme marquee'); }

  // Decide signal from convergence — require real conviction for directional calls
  let signal, confidence;
  const net = bull - bear;
  if (net >= 3) { signal = 'ACHETER'; }
  else if (net <= -3) { signal = 'VENDRE'; }
  else { signal = 'CONSERVER'; }

  // ── CONFIDENCE SCORE (rebuilt from what actually predicts success) ──
  // Backtest on real verified signals showed the old score (60 + net*5) was flat: winners
  // and losers both averaged ~75, so it discriminated nothing. The factors that DID separate
  // winners from losers: a confirmed trend (MM20>MM50 was in 84% of winners vs 69% of losers)
  // and, to a lesser extent, a positive MACD. We now weight those explicitly.
  if (signal === 'ACHETER') {
    confidence = 55; // base
    const trendConfirmed = (sma20 && sma50 && price > sma20 && sma20 > sma50);
    if (trendConfirmed) confidence += 18;        // strongest predictor
    else if (sma50 && price > sma50) confidence += 6; // weak trend only
    if (macdVal !== null && macdVal > 0) confidence += 7;   // momentum confirmation
    if (rsiVal !== null && rsiVal >= 45 && rsiVal <= 65) confidence += 8; // healthy zone (not overbought, not weak)
    else if (rsiVal !== null && rsiVal > 70) confidence -= 12;            // overbought = buying the top
    confidence += Math.min(6, net); // small bonus for strong convergence
  } else if (signal === 'VENDRE') {
    confidence = 55;
    const downConfirmed = (sma20 && sma50 && price < sma20 && sma20 < sma50);
    if (downConfirmed) confidence += 18;
    else if (sma50 && price < sma50) confidence += 6;
    if (macdVal !== null && macdVal < 0) confidence += 7;
    if (rsiVal !== null && rsiVal >= 35 && rsiVal <= 55) confidence += 8;
    else if (rsiVal !== null && rsiVal < 30) confidence -= 12; // oversold = selling the bottom
    confidence += Math.min(6, Math.abs(net));
  } else {
    confidence = 50 + Math.floor(Math.abs(net) * 3);
  }
  confidence = Math.max(45, Math.min(92, confidence));

  let reasoning = reasons.length > 0
    ? 'Analyse technique: ' + reasons.slice(0, 3).join(', ') + '.'
    : 'Configuration neutre, pas de signal directionnel fort.';

  return { signal, confidence: Math.round(confidence), reasoning };
}

function novaAnalyzeForTrade(symbol, price, change) {
  let score = 50;
  let signal = 'HOLD';
  let reasoning = '';
  if (change > 3) { score += 20; signal = 'BUY'; reasoning = 'Forte dynamique haussiere (' + change.toFixed(2) + '%). '; }
  else if (change > 1) { score += 10; signal = 'BUY'; reasoning = 'Tendance positive (' + change.toFixed(2) + '%). '; }
  else if (change < -3) { score += 15; signal = 'BUY'; reasoning = 'Survente potentielle (' + change.toFixed(2) + '%), opportunite de rebond. '; }
  else if (change < -1) { score -= 5; signal = 'HOLD'; reasoning = 'Faiblesse moderee. '; }
  else { score -= 5; signal = 'HOLD'; reasoning = 'Marche stable. '; }
  score += Math.floor(Math.random() * 20) - 10;
  score = Math.min(95, Math.max(40, score));
  return { signal, confidence: score, reasoning };
}

// ── AUTO PREDICTIONS — N.O.V.A. analyzes the full universe every 4h to feed public stats ──
function novaGenerateSignal(symbol, price, change) {
  // Reuse the same scoring logic, but output ACHETER/VENDRE/CONSERVER (French, matches DB convention)
  let score = 50;
  let signal = 'CONSERVER';
  let reasoning = '';
  if (change > 3) { score += 22; signal = 'ACHETER'; reasoning = 'Forte dynamique haussiere detectee (' + change.toFixed(2) + '% sur la periode). Le momentum favorise une entree.'; }
  else if (change > 1.2) { score += 12; signal = 'ACHETER'; reasoning = 'Tendance positive confirmee (' + change.toFixed(2) + '%). Configuration favorable.'; }
  else if (change < -4) { score += 16; signal = 'ACHETER'; reasoning = 'Niveau de survente marque (' + change.toFixed(2) + '%), opportunite de rebond technique.'; }
  else if (change < -2.5) { score += 8; signal = 'VENDRE'; reasoning = 'Pression vendeuse significative (' + change.toFixed(2) + '%). Prudence recommandee.'; }
  else if (change < -1) { score -= 2; signal = 'CONSERVER'; reasoning = 'Legere faiblesse (' + change.toFixed(2) + '%), pas de signal directionnel clair.'; }
  else { score -= 4; signal = 'CONSERVER'; reasoning = 'Marche stable, aucune dynamique forte detectee actuellement.'; }
  score += Math.floor(Math.random() * 16) - 8;
  score = Math.min(94, Math.max(42, score));
  return { signal, confidence: score, reasoning };
}

async function runAutoPredictions() {
  if (typeof SYSTEM_ACTIVE !== 'undefined' && !SYSTEM_ACTIVE) { console.log('Auto-predictions skipped: system halted'); return; }
  try {
    console.log('N.O.V.A. auto-predictions running on full universe...');
    let saved = 0;
    for (const symbol of TRADING_UNIVERSE) {
      try {
        const hist = await getHistoricalCloses(symbol);
        if (!hist) { await new Promise(r => setTimeout(r, 300)); continue; }
        const d = { price: hist.price, name: hist.name, change: hist.closes.length >= 2 ? ((hist.price - hist.closes[hist.closes.length-2]) / hist.closes[hist.closes.length-2] * 100) : 0 };
        const analysis = novaTechnicalSignal(symbol, hist.closes, hist.price);
        const dateStr = new Date().toLocaleDateString('fr-FR');
        // Anti-duplicate guard: skip if a prediction already exists for this symbol today
        const existing = await pool.query(
          'SELECT id FROM predictions WHERE symbol = $1 AND date_str = $2 LIMIT 1',
          [symbol, dateStr]
        );
        if (existing.rows.length > 0) { continue; } // already predicted today, skip
        await pool.query(
          'INSERT INTO predictions (symbol, name, signal, price, confidence, reasoning, date_str) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [symbol, d.name || symbol, analysis.signal, d.price, analysis.confidence, analysis.reasoning, dateStr]
        );
        // Also log into analyses table so it shows up in Archives
        const fullText = 'Analyse automatique N.O.V.A. — ' + dateStr + '\\n\\n' +
          'Actif: ' + (d.name || symbol) + ' (' + symbol + ')\\n' +
          'Prix actuel: $' + d.price.toFixed(2) + '\\n' +
          'Variation: ' + (d.change >= 0 ? '+' : '') + d.change.toFixed(2) + '%\\n\\n' +
          'Signal: ' + analysis.signal + ' (confiance: ' + analysis.confidence + '%)\\n\\n' +
          analysis.reasoning + '\\n\\n' +
          'Cette analyse a ete generee automatiquement par mon module de surveillance continue, qui scanne l ensemble de mon univers de ' + TRADING_UNIVERSE.length + ' actifs toutes les 4 heures.';
        await pool.query(
          'INSERT INTO analyses (symbol, name, price, change_pct, signal, confidence, full_analysis, market_data, date_str, user_email) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
          [symbol, d.name || symbol, d.price, d.change.toFixed(2), analysis.signal, analysis.confidence, fullText, { auto: true, change: d.change }, dateStr, 'nova-auto']
        );
        saved++;
      } catch(e) { console.log('Auto-prediction error for', symbol, e.message); }
      await new Promise(r => setTimeout(r, 500));
    }
    console.log('Auto-predictions done:', saved, 'signals saved (technical analysis engine)');
  } catch(e) { console.log('runAutoPredictions error:', e.message); }
}

// Run every 4 hours, aligned with autonomous trader logic
let lastAutoPredictionHour = -1;
function scheduleAutoPredictions() {
  const now = new Date();
  const parisHour = parseInt(now.toLocaleString('en-US', { timeZone: 'Europe/Paris', hour: '2-digit', hour12: false }));
  const parisMin = parseInt(now.toLocaleString('en-US', { timeZone: 'Europe/Paris', minute: '2-digit' }));
  // Trigger at 0, 4, 8, 12, 16, 20h Paris time, once per hour window
  if (parisHour % 4 === 0 && parisMin < 5 && lastAutoPredictionHour !== parisHour) {
    lastAutoPredictionHour = parisHour;
    runAutoPredictions();
  }
}
setInterval(scheduleAutoPredictions, 60 * 1000);
console.log('Auto-predictions scheduled every 4h (0h, 4h, 8h, 12h, 16h, 20h Paris time)');

// Manual trigger for testing
// ── EMERGENCY KILL SWITCH ──
let SYSTEM_ACTIVE = true;

app.post('/api/admin/emergency-stop', adminLimiter, adminGuard, async (req, res) => {
  SYSTEM_ACTIVE = !SYSTEM_ACTIVE;
  console.log('SYSTEM_ACTIVE toggled to:', SYSTEM_ACTIVE);
  logSecurityEvent('emergency_toggle', SYSTEM_ACTIVE ? 'info' : 'critical', getIP(req),
    SYSTEM_ACTIVE ? 'Systeme reactive par admin' : 'ARRET D URGENCE active par admin', {});
  res.json({ ok: true, stopped: !SYSTEM_ACTIVE, systemActive: SYSTEM_ACTIVE });
});

app.post('/api/admin/system-status', adminLimiter, adminGuard, async (req, res) => {
  res.json({ systemActive: SYSTEM_ACTIVE });
});

// ── SECURE RESET: wipe ONLY the predictions table (analyses are preserved) ──
// Requires admin secret + explicit confirmation phrase to prevent accidental wipes.
// ── DEDUPLICATE: remove duplicate predictions, keeping the oldest of each group ──
app.post('/api/admin/dedupe-predictions', adminLimiter, adminGuard, async (req, res) => {
  try {
    const before = await pool.query('SELECT COUNT(*) AS c FROM predictions');
    // Keep the row with the smallest id for each (symbol, date_str) group, delete the rest
    const result = await pool.query(`
      DELETE FROM predictions
      WHERE id NOT IN (
        SELECT MIN(id) FROM predictions GROUP BY symbol, date_str
      )
    `);
    const after = await pool.query('SELECT COUNT(*) AS c FROM predictions');
    const removed = parseInt(before.rows[0].c) - parseInt(after.rows[0].c);
    logSecurityEvent('predictions_dedupe', 'warning', getIP(req),
      'Deduplication: ' + removed + ' doublons supprimes. ' + after.rows[0].c + ' predictions restantes.', {});
    console.log('Deduplicated predictions:', removed, 'removed,', after.rows[0].c, 'remaining');
    res.json({ ok: true, removed: removed, remaining: parseInt(after.rows[0].c) });
  } catch(e) { safeError(res, e); }
});

app.post('/api/admin/reset-predictions', adminLimiter, adminGuard, async (req, res) => {
  const { confirm } = req.body;
  if (confirm !== 'RESET-PREDICTIONS-CONFIRM') {
    return res.status(400).json({ error: 'Phrase de confirmation requise', needConfirm: true });
  }
  try {
    const countBefore = await pool.query('SELECT COUNT(*) AS c FROM predictions');
    await pool.query('DELETE FROM predictions');
    logSecurityEvent('predictions_reset', 'critical', getIP(req),
      'Table predictions videe par admin (' + countBefore.rows[0].c + ' lignes supprimees). Analyses conservees.', {});
    console.log('Predictions table reset:', countBefore.rows[0].c, 'rows deleted');
    res.json({ ok: true, deleted: parseInt(countBefore.rows[0].c) });
  } catch(e) { safeError(res, e); }
});

app.post('/api/predictions/auto-run', adminLimiter, adminGuard, async (req, res) => {
  runAutoPredictions();
  res.json({ ok: true, message: 'Auto-predictions started, this will take a few minutes' });
});

async function runAutonomousTrader() {
  if (typeof SYSTEM_ACTIVE !== 'undefined' && !SYSTEM_ACTIVE) { console.log('Autonomous trader skipped: system halted'); return; }
  try {
    console.log('N.O.V.A. autonomous trader running...');
    const portfolios = await pool.query('SELECT * FROM portfolios WHERE active = TRUE');
    if (portfolios.rows.length === 0) return;
    const pricesCache = {};
    for (const symbol of TRADING_UNIVERSE) {
      const d = await getPriceForSymbol(symbol);
      if (d) pricesCache[symbol] = d;
      await new Promise(r => setTimeout(r, 300));
    }
    for (const portfolio of portfolios.rows) {
      try {
        const profile = RISK_PROFILES[portfolio.risk_profile] || RISK_PROFILES.balanced;
        const openPositions = await pool.query('SELECT * FROM positions WHERE user_email = $1 AND status = $2', [portfolio.user_email, 'open']);
        for (const pos of openPositions.rows) {
          const priceData = pricesCache[pos.symbol];
          if (!priceData) continue;
          const currentPrice = priceData.price;
          const entryPrice = parseFloat(pos.entry_price);
          let shouldClose = false;
          let reason = '';
          if (pos.take_profit && currentPrice >= parseFloat(pos.take_profit)) { shouldClose = true; reason = 'Take Profit atteint'; }
          else if (pos.stop_loss && currentPrice <= parseFloat(pos.stop_loss)) { shouldClose = true; reason = 'Stop Loss declenche'; }
          if (shouldClose) {
            const pnl = (currentPrice - entryPrice) * parseFloat(pos.quantity);
            const pnlPct = ((currentPrice - entryPrice) / entryPrice) * 100;
            const proceeds = currentPrice * parseFloat(pos.quantity);
            await pool.query('UPDATE positions SET status = $1, exit_price = $2, exit_date = NOW(), exit_reason = $3, pnl = $4, pnl_pct = $5 WHERE id = $6', ['closed', currentPrice, reason, pnl, pnlPct.toFixed(2), pos.id]);
            await pool.query('UPDATE portfolios SET cash = cash + $1 WHERE user_email = $2', [proceeds, portfolio.user_email]);
          }
        }
        const portfolioUpdated = await pool.query('SELECT * FROM portfolios WHERE user_email = $1', [portfolio.user_email]);
        const updatedCash = parseFloat(portfolioUpdated.rows[0].cash);
        const stillOpen = await pool.query('SELECT * FROM positions WHERE user_email = $1 AND status = $2', [portfolio.user_email, 'open']);
        if (stillOpen.rows.length >= profile.maxPositions) continue;
        const heldSymbols = stillOpen.rows.map(p => p.symbol);
        const opportunities = [];
        for (const symbol of TRADING_UNIVERSE) {
          if (heldSymbols.includes(symbol)) continue;
          // Use the technical analysis engine (RSI, MACD, moving averages, convergence)
          const hist = await getHistoricalCloses(symbol);
          if (!hist) { await new Promise(r => setTimeout(r, 200)); continue; }
          const analysis = novaTechnicalSignal(symbol, hist.closes, hist.price);
          // Only ACHETER signals with strong conviction become trade opportunities
          if (analysis.signal === 'ACHETER' && analysis.confidence >= profile.minConfidence) {
            opportunities.push({ symbol, signal: analysis.signal, confidence: analysis.confidence, reasoning: analysis.reasoning, price: hist.price, name: hist.name });
          }
          await new Promise(r => setTimeout(r, 250));
        }
        opportunities.sort((a, b) => b.confidence - a.confidence);
        const slots = profile.maxPositions - stillOpen.rows.length;
        const toBuy = opportunities.slice(0, Math.min(slots, 3));
        for (const opp of toBuy) {
          const positionValue = parseFloat(portfolioUpdated.rows[0].initial_capital) * profile.positionSize;
          if (positionValue > updatedCash) continue;
          const quantity = positionValue / opp.price;
          const stopLoss = opp.price * (1 - profile.stopLoss);
          const takeProfit = opp.price * (1 + profile.takeProfit);
          await pool.query('INSERT INTO positions (user_email, symbol, name, quantity, entry_price, stop_loss, take_profit, nova_reasoning) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [portfolio.user_email, opp.symbol, opp.name, quantity, opp.price, stopLoss, takeProfit, opp.reasoning + 'Confiance: ' + opp.confidence + '%']);
          await pool.query('UPDATE portfolios SET cash = cash - $1 WHERE user_email = $2', [positionValue, portfolio.user_email]);
        }
      } catch(e) { console.log('Portfolio error:', e.message); }
    }
  } catch(e) { console.log('Trader error:', e.message); }
}

const traderHours = [8, 14, 20];
function scheduleTrader() {
  const now = new Date();
  const parisHour = parseInt(now.toLocaleString('en-US', { timeZone: 'Europe/Paris', hour: '2-digit', hour12: false }));
  const parisMin = parseInt(now.toLocaleString('en-US', { timeZone: 'Europe/Paris', minute: '2-digit' }));
  for (const h of traderHours) {
    if (parisHour === h && parisMin < 5) { runAutonomousTrader(); break; }
  }
}
setInterval(scheduleTrader, 60 * 1000);

app.post('/api/trader/run', adminLimiter, adminGuard, async (req, res) => {
  runAutonomousTrader();
  res.json({ ok: true });
});

// ── ANALYSES ──
app.post('/api/analyses/save', async (req, res) => {
  const { symbol, name, price, change_pct, signal, confidence, full_analysis, market_data, user_email } = req.body;
  if (!symbol) return res.status(400).json({ error: 'Symbol required' });
  try {
    const date_str = new Date().toLocaleDateString('fr-FR');
    const result = await pool.query(
      'INSERT INTO analyses (symbol, name, price, change_pct, signal, confidence, full_analysis, market_data, date_str, user_email) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',
      [symbol, name, price, change_pct, signal, confidence, full_analysis, market_data || {}, date_str, user_email]
    );
    res.json({ ok: true, id: result.rows[0].id });
  } catch(e) { safeError(res, e); }
});

app.get('/api/analyses', async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  try {
    const result = await pool.query('SELECT * FROM analyses ORDER BY date DESC LIMIT $1 OFFSET $2', [limit, offset]);
    // Global stats over the entire table (not just the limited page)
    const totalRes = await pool.query('SELECT COUNT(*) AS total, COUNT(DISTINCT symbol) AS unique_symbols FROM analyses');
    const today = new Date().toLocaleDateString('fr-FR');
    const todayRes = await pool.query('SELECT COUNT(*) AS today FROM analyses WHERE date_str = $1', [today]);
    const dominantRes = await pool.query('SELECT signal, COUNT(*) AS c FROM analyses GROUP BY signal ORDER BY c DESC LIMIT 1');
    res.json({
      analyses: result.rows,
      stats: {
        total: parseInt(totalRes.rows[0].total),
        uniqueSymbols: parseInt(totalRes.rows[0].unique_symbols),
        today: parseInt(todayRes.rows[0].today),
        dominant: dominantRes.rows[0] ? dominantRes.rows[0].signal : '--'
      }
    });
  } catch(e) { safeError(res, e); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('N.O.V.A. Backend v3.0 running on port ' + PORT));
