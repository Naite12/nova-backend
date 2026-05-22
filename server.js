const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
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
    'free': { token: process.env.TELEGRAM_TOKEN, chat: '-1003981091130' },
    'essential': { token: process.env.TELEGRAM_TOKEN, chat: '-1003981091130' },
    'premium': { token: process.env.TELEGRAM_TOKEN, chat: '-1003981091130' },
    'vip': { token: process.env.TELEGRAM_TOKEN, chat: '-1003981091130' }
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
        'x-api-key': process.env.ANTHROPIC_KEY,
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


// ── DAILY REPORT SCHEDULER (7h30 Paris time) ──
const CANALS_CONFIG = {
  free:      { chatId: '-1003981091130',  tier: 'free' },
  essential: { chatId: '-1003905947217', tier: 'essential' },
  premium:   { chatId: '-1003989883363',  tier: 'premium' },
  vip:       { chatId: '-1003895905201',  tier: 'vip' }
};

async function fetchMarketData() {
  const symbols = ['BTC-USD','ETH-USD','SOL-USD','SPY','QQQ','NVDA','AAPL','TSLA'];
  const data = {};
  for(const sym of symbols) {
    try {
      const r = await fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${sym}?interval=1d&range=1d`);
      const d = await r.json();
      const meta = d?.chart?.result?.[0]?.meta;
      if(meta) {
        const price = meta.regularMarketPrice;
        const prev = meta.chartPreviousClose || meta.previousClose;
        const change = prev ? ((price - prev) / prev * 100).toFixed(2) : 0;
        data[sym] = { price, change: parseFloat(change), name: meta.longName || sym };
      }
    } catch(e) {}
    await new Promise(r => setTimeout(r, 300));
  }
  return data;
}

async function generateDailyReport(tier, marketData, date) {
  const mktStr = Object.entries(marketData).map(([s,d]) => `${s}: $${d.price?.toFixed(2)} (${d.change>=0?'+':''}${d.change}%)`).join(', ');
  const tierStyle = { free: 'très court, résumé uniquement, 80 mots max', essential: 'standard, 150 mots', premium: 'complet et détaillé, 250 mots', vip: 'premium exclusif avec recommandation personnalisée, 300 mots' };
  const prompt = `Génère un rapport quotidien ${tierStyle[tier]} pour abonnés ${tier.toUpperCase()}. DATE: ${date}. MARCHÉS: ${mktStr}. Sections: BILAN DES MARCHÉS, SIGNAUX DU JOUR (ACHETER/VENDRE/CONSERVER), RECOMMANDATION N.O.V.A. Texte brut sans astérisques.`;
  
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
  });
  const d = await r.json();
  return d.content?.[0]?.text || 'Rapport indisponible.';
}

function buildTieredMessage(tier, date, marketData, reportText) {
  const mkt = Object.entries(marketData).slice(0,5).map(([s,d]) => `${d.change>=0?'📈':'📉'} *${s.replace('-USD','').replace('=X','')}*: $${d.price?.toFixed(2)} (${d.change>=0?'+':''}${d.change}%)`).join('\n');
  const emojis = { free:'🆓', essential:'⚡', premium:'💎', vip:'👑' };
  const sep = '━━━━━━━━━━━━━━━━━';
  const footer = tier === 'vip' ? `\n${sep}\n🤖 *ACCÈS APP N.O.V.A.*\n👉 nova-vip1.netlify.app` : tier === 'free' ? `\n${sep}\n🔒 Analyse complète avec Essential/Premium/VIP\n👉 nova-industrie.netlify.app` : '';
  return `${emojis[tier]} *RAPPORT NOVA ${tier.toUpperCase()}* — ${date}\n_Naite Industries_\n\n${sep}\n📊 *MARCHÉS EN TEMPS RÉEL*\n${mkt}\n\n${sep}\n${reportText}${footer}\n\n${sep}\n_⚠️ Non constitutif d'un conseil en investissement_`;
}

async function sendDailyReports() {
  console.log('🚀 Sending daily reports...');
  const date = new Date().toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long' });
  const marketData = await fetchMarketData();
  
  for(const [tier, canal] of Object.entries(CANALS_CONFIG)) {
    try {
      const report = await generateDailyReport(tier, marketData, date);
      const msg = buildTieredMessage(tier, date, marketData, report);
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: canal.chatId, text: msg, parse_mode: 'Markdown', disable_web_page_preview: true })
      });
      const d = await r.json();
      console.log(`${tier}: ${d.ok ? '✅ sent' : '❌ ' + d.description}`);
    } catch(e) {
      console.log(`${tier}: ❌ error - ${e.message}`);
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  console.log('✅ Daily reports done!');
}

// Schedule at 7h30 Paris time (UTC+2 = 5h30 UTC)
function scheduleDaily() {
  function checkTime() {
    const now = new Date();
    const paris = new Date(now.toLocaleString('en-US', { timeZone: 'Europe/Paris' }));
    if(paris.getHours() === 7 && paris.getMinutes() === 30) {
      sendDailyReports();
    }
  }
  setInterval(checkTime, 60000); // Check every minute
  console.log('📅 Daily report scheduler started (7h30 Paris time)');
}

scheduleDaily();

// Manual trigger endpoint
app.post('/send-reports', async (req, res) => {
  const { secret } = req.body;
  if(secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
  sendDailyReports();
  res.json({ ok: true, message: 'Reports sending started...' });
});


app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '2.0' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`N.O.V.A. Backend v2.0 running on port ${PORT}`));
