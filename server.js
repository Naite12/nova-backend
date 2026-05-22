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
  const footerMap = {
    vip: `\n${sep}\n🤖 *ACCÈS APP N.O.V.A. COMPLÈTE*\n👉 nova-vip1.netlify.app`,
    free: `\n${sep}\n🔒 Analyse complète disponible avec Essential, Premium ou VIP\n👉 nova-industrie.netlify.app`,
    essential: `\n${sep}\n💎 Signaux illimités et graphiques disponibles avec Premium`,
    premium: `\n${sep}\n📊 Graphiques d'analyse envoyés séparément`
  };
  const footer = footerMap[tier] || '';
  return `${emojis[tier]} *RAPPORT NOVA ${tier.toUpperCase()}* — ${date}\n_Naite Industries_\n\n${sep}\n📊 *MARCHÉS EN TEMPS RÉEL*\n${mkt}\n\n${sep}\n${reportText}${footer}\n\n${sep}\n_⚠️ Non constitutif d'un conseil en investissement_`;
}

async function sendDailyReports() {
  console.log('🚀 Sending daily reports...');
  const date = new Date().toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long' });
  const marketData = await fetchMarketData();
  const token = process.env.TELEGRAM_TOKEN;

  for(const [tier, canal] of Object.entries(CANALS_CONFIG)) {
    try {
      // Send text report
      const report = await generateDailyReport(tier, marketData, date);
      const msg = buildTieredMessage(tier, date, marketData, report);
      const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: canal.chatId, text: msg, parse_mode: 'Markdown', disable_web_page_preview: true })
      });
      const d = await r.json();
      console.log(`${tier} text: ${d.ok ? '✅' : '❌ ' + d.description}`);
      
      await new Promise(r => setTimeout(r, 2000));

      // Send charts for Premium and VIP only
      if(tier === 'premium' || tier === 'vip') {
        const chartSymbols = ['BTC-USD', 'ETH-USD', 'SPY', 'NVDA'];
        
        // Individual bar+line charts
        for(const sym of chartSymbols.slice(0,2)) {
          const chartUrl = await getChartUrl(sym);
          await sendChartToTelegram(token, canal.chatId, chartUrl, `📊 *${sym.replace('-USD','')}* — Analyse 30 jours\n_N.O.V.A. ${tier.toUpperCase()} — Naite Industries_`);
          await new Promise(r => setTimeout(r, 3000));
        }
        
        // Comparative chart
        await sendComparativeChart(token, canal.chatId, chartSymbols);
        await new Promise(r => setTimeout(r, 2000));
        
        console.log(`${tier} charts: ✅ sent`);
      }
      
    } catch(e) {
      console.log(`${tier}: ❌ error - ${e.message}`);
    }
    await new Promise(r => setTimeout(r, 3000));
  }
  console.log('✅ Daily reports done!');
}


// ── CHART GENERATION FOR PREMIUM & VIP ──
async function getChartUrl(symbol) {
  const isCrypto = symbol.includes('-USD');
  const avSym = symbol.replace('-USD','').replace('=X','');
  try {
    const url = isCrypto
      ? `https://www.alphavantage.co/query?function=DIGITAL_CURRENCY_DAILY&symbol=${avSym}&market=EUR&apikey=ME8M6L7KU4HVB023`
      : `https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=${avSym}&outputsize=compact&apikey=ME8M6L7KU4HVB023`;
    const r = await fetch(url);
    const d = await r.json();
    const ts = isCrypto ? d['Time Series (Digital Currency Daily)'] : d['Time Series (Daily)'];
    if(!ts) return null;
    const entries = Object.entries(ts).slice(0,30).reverse();
    const prices = entries.map(([,v]) => parseFloat(isCrypto?(v['4a. close (EUR)']||v['4. close']):v['4. close']));
    const volumes = entries.map(([,v]) => parseFloat(v['5. volume']||0));
    const labels = entries.map(([k]) => k.slice(5));
    const cfg = {
      type:'bar',
      data:{
        labels,
        datasets:[
          {type:'line',label:avSym,data:prices,borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.08)',borderWidth:3,fill:true,tension:0.3,pointRadius:0,yAxisID:'y1'},
          {type:'bar',label:'Volume',data:volumes,backgroundColor:'rgba(0,100,255,0.25)',borderWidth:0,yAxisID:'y2'}
        ]
      },
      options:{
        plugins:{
          legend:{labels:{color:'#aaa',font:{size:11}}},
          title:{display:true,text:avSym+' — 30 Jours | N.O.V.A.',color:'#ffffff',font:{size:15,weight:'bold'}}
        },
        scales:{
          y1:{type:'linear',position:'left',ticks:{color:'#aaa',font:{size:10}},grid:{color:'rgba(255,255,255,0.05)'}},
          y2:{type:'linear',position:'right',ticks:{color:'rgba(0,150,255,0.4)',font:{size:9}},grid:{display:false}}
        }
      }
    };
    return `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(cfg))}&width=800&height=400&backgroundColor=%230a0e1a`;
  } catch(e) { return null; }
}

async function getComparativeChartUrl(symbols) {
  try {
    const datasets = [];
    const colors = ['#00aaff','#ffaa00','#ff5555','#00ff88'];
    for(const sym of symbols.slice(0,4)) {
      const isCrypto = sym.includes('-USD');
      const avSym = sym.replace('-USD','').replace('=X','');
      const url = isCrypto
        ? `https://www.alphavantage.co/query?function=DIGITAL_CURRENCY_DAILY&symbol=${avSym}&market=EUR&apikey=ME8M6L7KU4HVB023`
        : `https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=${avSym}&outputsize=compact&apikey=ME8M6L7KU4HVB023`;
      const r = await fetch(url);
      const d = await r.json();
      const ts = isCrypto ? d['Time Series (Digital Currency Daily)'] : d['Time Series (Daily)'];
      if(!ts) continue;
      const entries = Object.entries(ts).slice(0,30).reverse();
      const prices = entries.map(([,v]) => parseFloat(isCrypto?(v['4a. close (EUR)']||v['4. close']):v['4. close']));
      const base = prices[0];
      datasets.push({label:avSym, data:prices.map(p=>parseFloat(((p-base)/base*100).toFixed(2))), borderColor:colors[datasets.length], backgroundColor:'transparent', borderWidth:2.5, tension:0.3, pointRadius:0, fill:false});
      await new Promise(r=>setTimeout(r,1500));
    }
    if(!datasets.length) return null;
    const labels = Array.from({length:30},(_,i)=>`J${i+1}`);
    const cfg = {
      type:'line',
      data:{labels, datasets},
      options:{
        plugins:{
          legend:{labels:{color:'#cccccc',font:{size:11}}},
          title:{display:true,text:"Comparative Performance (%) — 30 Jours | N.O.V.A.",color:'#ffffff',font:{size:15,weight:'bold'}}
        },
        scales:{
          x:{ticks:{color:'#666',font:{size:9}},grid:{color:'rgba(255,255,255,0.04)'}},
          y:{ticks:{color:'#888',font:{size:10},callback:v=>v+'%'},grid:{color:'rgba(255,255,255,0.05)'}}
        }
      }
    };
    return `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(cfg))}&width=800&height=400&backgroundColor=%23050810`;
  } catch(e) { return null; }
}

async function sendChartToTelegram(token, chatId, chartUrl, caption) {
  if(!chartUrl) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendPhoto`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({chat_id:chatId, photo:chartUrl, caption, parse_mode:'Markdown'})
    });
    const d = await r.json();
    return d.ok;
  } catch(e) { console.log('sendChart error:', e.message); return false; }
}

async function sendComparativeChart(token, chatId, symbols) {
  const url = await getComparativeChartUrl(symbols);
  return sendChartToTelegram(token, chatId, url, '📈 *Performance Comparative — 30 Jours*
_Analyse multi-actifs N.O.V.A. — Naite Industries_');
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
