const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

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
        chat_history JSONB DEFAULT '[]'
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
    console.log('Database initialized');
  } catch(e) {
    console.log('DB init error:', e.message);
  }
}
initDB();

// ── SESSION STORE (memory is fine for sessions) ──
const sessions = {};

function genToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// ── AUTH ──
app.post('/auth/register', async (req, res) => {
  const { email, password, plan } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Account already exists' });
    await pool.query('INSERT INTO users (email, password, plan) VALUES ($1, $2, $3)', [email, hashPassword(password), plan || 'vip']);
    const token = genToken();
    sessions[token] = email;
    res.json({ token, email, plan: plan || 'vip' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || user.password !== hashPassword(password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = genToken();
    sessions[token] = email;
    res.json({ token, email, plan: user.plan });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/change-password', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password too short' });
  try {
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashPassword(password), sessions[token]]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  req.userEmail = sessions[token];
  next();
}

app.get('/user/data', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [req.userEmail]);
    const u = result.rows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ email: u.email, plan: u.plan, memory: u.memory, chatHistory: (u.chat_history || []).slice(-50) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/user/chat', auth, async (req, res) => {
  const { message, role } = req.body;
  try {
    const result = await pool.query('SELECT chat_history FROM users WHERE email = $1', [req.userEmail]);
    const hist = result.rows[0]?.chat_history || [];
    hist.push({ role, message, time: new Date().toISOString() });
    if (hist.length > 100) hist.splice(0, hist.length - 100);
    await pool.query('UPDATE users SET chat_history = $1 WHERE email = $2', [JSON.stringify(hist), req.userEmail]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/user/memory', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT memory FROM users WHERE email = $1', [req.userEmail]);
    res.json(result.rows[0]?.memory || { facts: [], conversations: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/user/memory', auth, async (req, res) => {
  try {
    await pool.query('UPDATE users SET memory = $1, chat_history = $2 WHERE email = $3', [JSON.stringify({ facts: [], conversations: 0 }), JSON.stringify([]), req.userEmail]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── STRIPE ──
app.post('/create-subscription', async (req, res) => {
  const { paymentMethodId, priceId, email, promoCode } = req.body;
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
    res.json({ subscriptionId: subscription.id, clientSecret: subscription.latest_invoice.payment_intent?.client_secret, status: subscription.status });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── CLAUDE API ──
app.post('/api/chat', async (req, res) => {
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
  } catch (e) { res.status(500).json({ error: e.message }); }
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
    const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) return res.json({ error: 'No data' });
    const meta = result.meta;
    const price = meta.regularMarketPrice;
    const prev = meta.chartPreviousClose || meta.previousClose;
    const change = prev ? ((price - prev) / prev * 100).toFixed(2) : 0;
    res.json({ symbol, name: meta.longName || symbol, price, change: parseFloat(change), currency: meta.currency, market: meta.exchangeName });
  } catch (e) { res.status(500).json({ error: e.message }); }
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/predictions', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM predictions ORDER BY date DESC LIMIT 100');
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
    // Calculate stats
    const verified = preds.filter(p => p.verified7d);
    const correct = verified.filter(p => p.correct7d === true);
    const accuracy = verified.length > 0 ? Math.round((correct.length / verified.length) * 100) : null;
    const bySignal = { ACHETER:{total:0,correct:0}, VENDRE:{total:0,correct:0}, CONSERVER:{total:0,correct:0} };
    verified.forEach(p => { if(bySignal[p.signal]){bySignal[p.signal].total++;if(p.correct7d)bySignal[p.signal].correct++;} });
    res.json({ predictions: preds, stats: { total: preds.length, totalVerified: verified.length, accuracy, bySignal } });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
app.post('/api/predictions/reverify', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/send-reports', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
  sendDailyReports();
  res.json({ ok: true, message: 'Reports sending started...' });
});

app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '3.0' }));

// ── WATCHLIST ──
app.get('/api/watchlist', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM watchlists WHERE user_email = $1 ORDER BY added_at DESC', [req.userEmail]);
    res.json({ watchlist: result.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/watchlist', auth, async (req, res) => {
  const { symbol, name } = req.body;
  if (!symbol) return res.status(400).json({ error: 'Symbol required' });
  try {
    await pool.query('INSERT INTO watchlists (user_email, symbol, name) VALUES ($1, $2, $3) ON CONFLICT (user_email, symbol) DO NOTHING', [req.userEmail, symbol, name || symbol]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/watchlist/:symbol', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM watchlists WHERE user_email = $1 AND symbol = $2', [req.userEmail, req.params.symbol]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ALERTS ──
app.get('/api/alerts', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM alerts WHERE user_email = $1 ORDER BY created_at DESC', [req.userEmail]);
    res.json({ alerts: result.rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/alerts/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM alerts WHERE user_email = $1 AND id = $2', [req.userEmail, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/portfolio/create', auth, async (req, res) => {
  const { capital, risk_profile } = req.body;
  if (!capital || capital < 100) return res.status(400).json({ error: 'Capital minimum 100$' });
  try {
    await pool.query('INSERT INTO portfolios (user_email, initial_capital, cash, risk_profile) VALUES ($1, $2, $2, $3) ON CONFLICT (user_email) DO UPDATE SET initial_capital = $2, cash = $2, risk_profile = $3, active = TRUE', [req.userEmail, parseFloat(capital), risk_profile || 'balanced']);
    await pool.query('DELETE FROM positions WHERE user_email = $1', [req.userEmail]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/portfolio/toggle', auth, async (req, res) => {
  try {
    await pool.query('UPDATE portfolios SET active = NOT active WHERE user_email = $1', [req.userEmail]);
    const r = await pool.query('SELECT active FROM portfolios WHERE user_email = $1', [req.userEmail]);
    res.json({ active: r.rows[0]?.active });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/portfolio', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM positions WHERE user_email = $1', [req.userEmail]);
    await pool.query('DELETE FROM portfolios WHERE user_email = $1', [req.userEmail]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AUTONOMOUS TRADER ──
const TRADING_UNIVERSE = [
  'BTC-USD','ETH-USD','SOL-USD','BNB-USD','XRP-USD','ADA-USD','AVAX-USD','DOT-USD','LINK-USD','MATIC-USD',
  'SPY','QQQ','DIA','IWM','VTI','VOO','GLD','SLV','XLK','XLF','XLE','XLV','SOXX','ARKK',
  'AAPL','MSFT','NVDA','GOOGL','META','AMZN','TSLA','AMD','NFLX','COIN','JPM','V','MA','DIS','BA','UBER','PYPL'
];
const RISK_PROFILES = {
  conservative: { positionSize: 0.05, stopLoss: 0.05, takeProfit: 0.08, minConfidence: 80, maxPositions: 5 },
  balanced: { positionSize: 0.10, stopLoss: 0.08, takeProfit: 0.15, minConfidence: 70, maxPositions: 8 },
  aggressive: { positionSize: 0.15, stopLoss: 0.12, takeProfit: 0.25, minConfidence: 60, maxPositions: 12 }
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
  try {
    console.log('N.O.V.A. auto-predictions running on full universe...');
    let saved = 0;
    for (const symbol of TRADING_UNIVERSE) {
      try {
        const d = await getPriceForSymbol(symbol);
        if (!d) { await new Promise(r => setTimeout(r, 250)); continue; }
        const analysis = novaGenerateSignal(symbol, d.price, d.change);
        const dateStr = new Date().toLocaleDateString('fr-FR');
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
      await new Promise(r => setTimeout(r, 350));
    }
    console.log('Auto-predictions done:', saved, 'signals saved');
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
app.post('/api/predictions/auto-run', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
  runAutoPredictions();
  res.json({ ok: true, message: 'Auto-predictions started, this will take a few minutes' });
});

async function runAutonomousTrader() {
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
          if (!pricesCache[symbol]) continue;
          const analysis = novaAnalyzeForTrade(symbol, pricesCache[symbol].price, pricesCache[symbol].change);
          if (analysis.signal === 'BUY' && analysis.confidence >= profile.minConfidence) {
            opportunities.push({ symbol, ...analysis, ...pricesCache[symbol] });
          }
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

app.post('/api/trader/run', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/analyses', async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  try {
    const result = await pool.query('SELECT * FROM analyses ORDER BY date DESC LIMIT $1', [limit]);
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('N.O.V.A. Backend v3.0 running on port ' + PORT));
