const express = require('express');
const stripe = require('stripe')('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');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Simple in-memory DB (replace with real DB later)
const users = {};
const sessions = {};

// Helper: generate token
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper: hash password
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}


// Send Telegram welcome message
async function sendTelegramWelcome(plan, email) {
  const tokens = {
    'free': { token: '8817894057:AAFuTPqWPk66h3gLhI7k3p88g9eTsQYTNvw', chat: '-1003981091130' },
    'essential': { token: '8817894057:AAFuTPqWPk66h3gLhI7k3p88g9eTsQYTNvw', chat: '-1003981091130' },
    'premium': { token: '8817894057:AAFuTPqWPk66h3gLhI7k3p88g9eTsQYTNvw', chat: '-1003981091130' },
    'vip': { token: '8817894057:AAFuTPqWPk66h3gLhI7k3p88g9eTsQYTNvw', chat: '-1003981091130' }
  };
  const cfg = tokens[plan.toLowerCase()] || tokens['free'];
  const msg = `🎉 *Nouveau membre ${plan.toUpperCase()}* !\n\n📧 ${email}\n⚡ Plan: *${plan}*\n📅 ${new Date().toLocaleDateString('fr-FR')}\n\n_Bienvenue sur N.O.V.A. — Naite Industries_`;
  try {
    await fetch(`https://api.telegram.org/bot${cfg.token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: cfg.chat, text: msg, parse_mode: 'Markdown' })
    });
  } catch(e) { console.log('Telegram notify error:', e.message); }
}

// ── AUTH ROUTES ──
app.post('/auth/register', (req, res) => {
  const { email, password, plan } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (users[email]) return res.status(400).json({ error: 'Account already exists' });
  
  const user = {
    email,
    password: hashPassword(password),
    plan: plan || 'vip',
    createdAt: new Date().toISOString(),
    chatHistory: [],
    tradingHistory: [],
    memory: { facts: [], conversations: 0 }
  };
  users[email] = user;
  
  const token = genToken();
  sessions[token] = email;
  
  res.json({ token, email, plan: user.plan });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = genToken();
  sessions[token] = email;
  res.json({ token, email, plan: user.plan });
});

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  req.userEmail = sessions[token];
  req.user = users[req.userEmail];
  next();
}

// ── USER DATA ROUTES ──
app.get('/user/data', auth, (req, res) => {
  const u = req.user;
  res.json({ email: u.email, plan: u.plan, memory: u.memory, chatHistory: u.chatHistory.slice(-50), tradingHistory: u.tradingHistory.slice(-30) });
});

app.post('/user/chat', auth, (req, res) => {
  const { message, role } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  req.user.chatHistory.push({ role, message, time: new Date().toISOString() });
  if (req.user.chatHistory.length > 100) req.user.chatHistory = req.user.chatHistory.slice(-100);
  res.json({ ok: true });
});

app.post('/user/memory', auth, (req, res) => {
  const { fact } = req.body;
  if (fact) {
    req.user.memory.facts.push(fact);
    if (req.user.memory.facts.length > 20) req.user.memory.facts = req.user.memory.facts.slice(-20);
  }
  req.user.memory.conversations++;
  req.user.memory.lastSeen = new Date().toISOString();
  res.json(req.user.memory);
});

app.get('/user/memory', auth, (req, res) => res.json(req.user.memory));
app.delete('/user/memory', auth, (req, res) => {
  req.user.memory = { facts: [], conversations: 0 };
  res.json({ ok: true });
});

// ── STRIPE ROUTES ──
app.post('/create-subscription', async (req, res) => {
  const { paymentMethodId, priceId, email } = req.body;
  try {
    const customer = await stripe.customers.create({
      email: email || 'subscriber@nova-ai.com',
      payment_method: paymentMethodId,
      invoice_settings: { default_payment_method: paymentMethodId },
    });
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: priceId }],
      payment_settings: {
        payment_method_options: { card: { request_three_d_secure: 'any' } },
        payment_method_types: ['card'],
        save_default_payment_method: 'on_subscription',
      },
      expand: ['latest_invoice.payment_intent'],
    });
    const paymentIntent = subscription.latest_invoice.payment_intent;
    sendTelegramWelcome(req.body.plan || 'premium', req.body.email || 'unknown');
    res.json({ subscriptionId: subscription.id, clientSecret: paymentIntent?.client_secret, status: subscription.status });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── CLAUDE PROXY ──
app.post('/api/chat', async (req, res) => {
  const { history, system } = req.body;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_KEY || '',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-5',
        max_tokens: 1000,
        system: system || 'Tu es N.O.V.A., experte en analyse financière pour Naite Industries.',
        messages: history
      })
    });
    const d = await r.json();
    res.json(d);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── FINANCE PROXY ──
app.get('/api/finance', async (req, res) => {
  const { symbol } = req.query;
  try {
    const r = await fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?interval=1d&range=1d`);
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) return res.json({ error: 'No data' });
    const meta = result.meta;
    const price = meta.regularMarketPrice;
    const prev = meta.chartPreviousClose || meta.previousClose;
    const change = prev ? ((price - prev) / prev * 100).toFixed(2) : 0;
    res.json({ symbol, name: meta.longName || symbol, price, change: parseFloat(change), currency: meta.currency, market: meta.exchangeName });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '2.0' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`N.O.V.A. Backend v2.0 running on port ${PORT}`));
