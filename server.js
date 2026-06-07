const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ── IN-MEMORY DB ──
const users = {};
const sessions = {};
let predictions = [];
let predictionId = 1;

function genToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// ── AUTH ──
app.post('/auth/register', (req, res) => {
  const { email, password, plan } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (users[email]) return res.status(400).json({ error: 'Account already exists' });
  users[email] = { email, password: hashPassword(password), plan: plan || 'vip', createdAt: new Date().toISOString(), chatHistory: [], memory: { facts: [], conversations: 0 } };
  const token = genToken();
  sessions[token] = email;
  res.json({ token, email, plan: users[email].plan });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || user.password !== hashPassword(password)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = genToken();
  sessions[token] = email;
  res.json({ token, email, plan: user.plan });
});

app.post('/auth/change-password', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  const user = users[sessions[token]];
  if (!user) return res.status(401).json({ error: 'User not found' });
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password too short' });
  user.password = hashPassword(password);
  res.json({ ok: true });
});

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  req.userEmail = sessions[token];
  req.user = users[req.userEmail];
  next();
}

app.get('/user/data', auth, (req, res) => {
  const u = req.user;
  res.json({ email: u.email, plan: u.plan, memory: u.memory, chatHistory: u.chatHistory.slice(-50) });
});
app.post('/user/chat', auth, (req, res) => {
  const { message, role } = req.body;
  req.user.chatHistory.push({ role, message, time: new Date().toISOString() });
  if (req.user.chatHistory.length > 100) req.user.chatHistory = req.user.chatHistory.slice(-100);
  res.json({ ok: true });
});
app.post('/user/memory', auth, (req, res) => {
  const { fact } = req.body;
  if (fact) { req.user.memory.facts.push(fact); if (req.user.memory.facts.length > 20) req.user.memory.facts = req.user.memory.facts.slice(-20); }
  req.user.memory.conversations++;
  res.json(req.user.memory);
});
app.get('/user/memory', auth, (req, res) => res.json(req.user.memory));
app.delete('/user/memory', auth, (req, res) => {
  req.user.memory = { facts: [], conversations: 0 };
  res.json({ ok: true });
});

// ── STRIPE ──
app.post('/create-subscription', async (req, res) => {
  const { paymentMethodId, priceId, email } = req.body;
  try {
    const customer = await stripe.customers.create({ email: email || 'subscriber@nova-ai.com', payment_method: paymentMethodId, invoice_settings: { default_payment_method: paymentMethodId } });
    const subscription = await stripe.subscriptions.create({ customer: customer.id, items: [{ price: priceId }], payment_settings: { payment_method_types: ['card'], save_default_payment_method: 'on_subscription' }, expand: ['latest_invoice.payment_intent'] });
    res.json({ subscriptionId: subscription.id, clientSecret: subscription.latest_invoice.payment_intent?.client_secret, status: subscription.status });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── CLAUDE API ──
app.post('/api/chat', async (req, res) => {
  const { history, system } = req.body;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, system: system || 'You are N.O.V.A., a financial AI assistant.', messages: history })
    });
    const d = await r.json();
    res.json(d);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FINANCE ──
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
  const pred = {
    id: predictionId++,
    symbol, name: name || symbol,
    signal,
    price: parseFloat(price),
    confidence: confidence || 70,
    reasoning: reasoning || '',
    date: new Date().toISOString(),
    dateStr: new Date().toLocaleDateString('fr-FR'),
    verified7d: false, verified30d: false,
    priceAfter7d: null, priceAfter30d: null,
    result7d: null, result30d: null,
    correct7d: null, correct30d: null
  };
  predictions.push(pred);
  console.log('Prediction saved:', symbol, signal, price);
  res.json({ ok: true, id: pred.id });
});

app.get('/api/predictions', (req, res) => {
  const stats = calculateStats();
  res.json({ predictions: predictions.slice(-100).reverse(), stats });
});

function calculateStats() {
  const verified = predictions.filter(p => p.verified7d);
  const correct = verified.filter(p => p.correct7d === true);
  const accuracy = verified.length > 0 ? Math.round((correct.length / verified.length) * 100) : null;
  const bySignal = { ACHETER: { total: 0, correct: 0 }, VENDRE: { total: 0, correct: 0 }, CONSERVER: { total: 0, correct: 0 } };
  verified.forEach(p => {
    if (bySignal[p.signal]) { bySignal[p.signal].total++; if (p.correct7d) bySignal[p.signal].correct++; }
  });
  return { total: predictions.length, totalVerified: verified.length, accuracy, bySignal };
}

async function verifyPredictions() {
  const now = new Date();
  for (const pred of predictions) {
    const predDate = new Date(pred.date);
    const daysDiff = (now - predDate) / (1000 * 60 * 60 * 24);
    if (!pred.verified7d && daysDiff >= 7) {
      try {
        const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + pred.symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const d = await r.json();
        const currentPrice = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
        if (currentPrice) {
          const priceDiff = ((currentPrice - pred.price) / pred.price) * 100;
          pred.priceAfter7d = currentPrice;
          pred.verified7d = true;
          if (pred.signal === 'ACHETER') pred.correct7d = priceDiff > 1;
          else if (pred.signal === 'VENDRE') pred.correct7d = priceDiff < -1;
          else pred.correct7d = Math.abs(priceDiff) < 3;
          pred.result7d = priceDiff.toFixed(2);
        }
      } catch(e) {}
      await new Promise(r => setTimeout(r, 1000));
    }
    if (!pred.verified30d && daysDiff >= 30) {
      try {
        const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + pred.symbol + '?interval=1d&range=1d', { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const d = await r.json();
        const currentPrice = d?.chart?.result?.[0]?.meta?.regularMarketPrice;
        if (currentPrice) {
          const priceDiff = ((currentPrice - pred.price) / pred.price) * 100;
          pred.priceAfter30d = currentPrice;
          pred.verified30d = true;
          if (pred.signal === 'ACHETER') pred.correct30d = priceDiff > 2;
          else if (pred.signal === 'VENDRE') pred.correct30d = priceDiff < -2;
          else pred.correct30d = Math.abs(priceDiff) < 5;
          pred.result30d = priceDiff.toFixed(2);
        }
      } catch(e) {}
      await new Promise(r => setTimeout(r, 1000));
    }
  }
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

app.post('/send-reports', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'NOVA-ADMIN-2026') return res.status(401).json({ error: 'Unauthorized' });
  sendDailyReports();
  res.json({ ok: true, message: 'Reports sending started...' });
});

app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '3.0' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('N.O.V.A. Backend v3.0 running on port ' + PORT));
