const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const users = {};
const sessions = {};

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
  req.user.memory.lastSeen = new Date().toISOString();
  res.json(req.user.memory);
});

app.get('/user/memory', auth, (req, res) => res.json(req.user.memory));
app.delete('/user/memory', auth, (req, res) => { req.user.memory = { facts: [], conversations: 0 }; res.json({ ok: true }); });

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
      body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, system: system || 'Tu es N.O.V.A., experte en analyse financiere pour Naite Industries.', messages: history })
    });
    const d = await r.json();
    res.json(d);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── FINANCE ──
app.get('/api/finance', async (req, res) => {
  const { symbol } = req.query;
  try {
    const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1d');
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

// ── CHART GENERATION ──
async function fetchHistoricalData(symbol) {
  try {
    // Use Yahoo Finance for historical data - no limits
    const yahooSym = symbol.includes('-USD') ? symbol.replace('-USD', '-EUR') : symbol;
    const url = 'https://query1.finance.yahoo.com/v8/finance/chart/' + symbol + '?interval=1d&range=1mo';
    const r = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = await r.json();
    const result = d?.chart?.result?.[0];
    if (!result) { console.log('No Yahoo data for', symbol); return null; }
    const timestamps = result.timestamp || [];
    const closes = result.indicators?.quote?.[0]?.close || [];
    const volumes = result.indicators?.quote?.[0]?.volume || [];
    if (!closes.length) { console.log('No price data for', symbol); return null; }
    const labels = timestamps.map(t => new Date(t * 1000).toISOString().slice(5, 10));
    return {
      labels: labels.slice(-30),
      prices: closes.slice(-30).map(p => parseFloat((p || 0).toFixed(2))),
      volumes: volumes.slice(-30).map(v => parseFloat(v || 0))
    };
  } catch (e) { console.log('fetchHistorical error:', e.message); return null; }
}

function buildBarLineChartUrl(data, title) {
  const prices = data.prices;
  const isUp = prices[prices.length-1] >= prices[0];
  const lineColor = isUp ? '#00e5ff' : '#ff4d6d';
  const fillColor = isUp ? 'rgba(0,229,255,0.12)' : 'rgba(255,77,109,0.10)';
  const barColor = isUp ? 'rgba(0,150,255,0.35)' : 'rgba(255,100,100,0.25)';
  const change = ((prices[prices.length-1] - prices[0]) / prices[0] * 100).toFixed(2);
  const cfg = {
    type: 'bar',
    data: {
      labels: data.labels,
      datasets: [
        {
          type: 'line',
          label: title + ' (' + (isUp ? '+' : '') + change + '%)',
          data: prices,
          borderColor: lineColor,
          backgroundColor: fillColor,
          borderWidth: 2.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: lineColor,
          yAxisID: 'y1',
          order: 1
        },
        {
          type: 'bar',
          label: 'Volume',
          data: data.volumes,
          backgroundColor: barColor,
          borderColor: 'rgba(0,180,255,0.4)',
          borderWidth: 1,
          borderRadius: 2,
          yAxisID: 'y2',
          order: 2
        }
      ]
    },
    options: {
      animation: false,
      plugins: {
        legend: {
          display: true,
          labels: { color: '#a0c4d8', font: { size: 11, weight: 'bold' }, boxWidth: 14, padding: 16 }
        },
        title: {
          display: true,
          text: title + '  |  N.O.V.A. — Naite Industries',
          color: '#e0f0ff',
          font: { size: 14, weight: 'bold' },
          padding: { bottom: 16 }
        }
      },
      scales: {
        x: {
          ticks: { color: '#4a6a7a', font: { size: 8 }, maxTicksLimit: 10 },
          grid: { color: 'rgba(0,180,255,0.06)', lineWidth: 1 }
        },
        y1: {
          type: 'linear',
          position: 'left',
          ticks: { color: '#6a9ab0', font: { size: 9 }, callback: function(v) { return '$' + v.toLocaleString(); } },
          grid: { color: 'rgba(0,180,255,0.08)', lineWidth: 1 }
        },
        y2: {
          type: 'linear',
          position: 'right',
          ticks: { color: 'rgba(0,150,255,0.4)', font: { size: 8 } },
          grid: { display: false }
        }
      }
    }
  };
  return 'https://quickchart.io/chart?backgroundColor=%230a0d1a&width=900&height=450&c=' + encodeURIComponent(JSON.stringify(cfg));
}

function buildComparativeChartUrl(datasets) {
  const colors = ['#00e5ff', '#ffd60a', '#ff4d6d', '#00ff88'];
  const bgColors = ['rgba(0,229,255,0.08)', 'rgba(255,214,10,0.06)', 'rgba(255,77,109,0.06)', 'rgba(0,255,136,0.06)'];
  const cfg = {
    type: 'line',
    data: {
      labels: Array.from({ length: 30 }, (_, i) => 'J' + (i + 1)),
      datasets: datasets.map((ds, i) => {
        const lastVal = ds.data[ds.data.length - 1];
        return {
          label: ds.label + ' (' + (lastVal >= 0 ? '+' : '') + lastVal.toFixed(1) + '%)',
          data: ds.data,
          borderColor: colors[i % colors.length],
          backgroundColor: bgColors[i % bgColors.length],
          borderWidth: 2.5,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 5,
          fill: false
        };
      })
    },
    options: {
      animation: false,
      plugins: {
        legend: {
          display: true,
          labels: { color: '#a0c4d8', font: { size: 11, weight: 'bold' }, boxWidth: 14, padding: 14 }
        },
        title: {
          display: true,
          text: 'Performance Comparative (%)  |  N.O.V.A. — Naite Industries',
          color: '#e0f0ff',
          font: { size: 14, weight: 'bold' },
          padding: { bottom: 16 }
        }
      },
      scales: {
        x: {
          ticks: { color: '#4a6a7a', font: { size: 8 }, maxTicksLimit: 10 },
          grid: { color: 'rgba(0,180,255,0.06)' }
        },
        y: {
          ticks: {
            color: '#6a9ab0',
            font: { size: 9 },
            callback: function(v) { return v + '%'; }
          },
          grid: { color: 'rgba(0,180,255,0.08)' }
        }
      }
    }
  };
  return 'https://quickchart.io/chart?backgroundColor=%23050810&width=900&height=450&c=' + encodeURIComponent(JSON.stringify(cfg));
}

async function sendPhotoToTelegram(token, chatId, chartUrl, caption) {
  try {
    console.log('Downloading chart from QuickChart...');
    const imgRes = await fetch(chartUrl);
    if (!imgRes.ok) { console.log('QuickChart error:', imgRes.status); return false; }
    const arrayBuf = await imgRes.arrayBuffer();
    const imgBuf = Buffer.from(arrayBuf);
    console.log('Image downloaded, size:', imgBuf.length, 'bytes');

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
      method: 'POST',
      headers: { 'Content-Type': 'multipart/form-data; boundary=' + boundary },
      body
    });
    const d = await r.json();
    console.log('sendPhoto result:', JSON.stringify(d).slice(0, 200));
    return d.ok;
  } catch (e) { console.log('sendPhoto exception:', e.message); return false; }
}

// ── DAILY REPORTS ──
const CANALS_CONFIG = {
  free:      { chatId: '-1003981091130',  tier: 'free' },
  essential: { chatId: '-1003905947217', tier: 'essential' },
  premium:   { chatId: '-1003989883363',  tier: 'premium' },
  vip:       { chatId: '-1003895905201',  tier: 'vip' }
};

async function fetchMarketData() {
  const symbols = ['BTC-USD', 'ETH-USD', 'SOL-USD', 'SPY', 'QQQ', 'NVDA', 'AAPL', 'TSLA'];
  const data = {};
  for (const sym of symbols) {
    try {
      const r = await fetch('https://query1.finance.yahoo.com/v8/finance/chart/' + sym + '?interval=1d&range=1d');
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
  const mktStr = Object.entries(marketData).map(([s, d]) => s + ': $' + d.price?.toFixed(2) + ' (' + (d.change >= 0 ? '+' : '') + d.change + '%)').join(', ');
  const styles = { free: 'tres court, resume uniquement, 80 mots max', essential: 'standard, 150 mots', premium: 'complet et detaille, 250 mots', vip: 'premium exclusif avec recommandation personnalisee, 300 mots' };
  const prompt = 'Genere un rapport quotidien ' + styles[tier] + ' pour abonnes ' + tier.toUpperCase() + '. DATE: ' + date + '. MARCHES: ' + mktStr + '. Sections: BILAN DES MARCHES, SIGNAUX DU JOUR (ACHETER/VENDRE/CONSERVER), RECOMMANDATION N.O.V.A. Texte brut sans asterisques.';
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-5', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
  });
  const d = await r.json();
  return d.content?.[0]?.text || 'Rapport indisponible.';
}

function buildTieredMessage(tier, date, marketData, reportText) {
  const mkt = Object.entries(marketData).slice(0, 5).map(([s, d]) => (d.change >= 0 ? 'Up ' : 'Down ') + s.replace('-USD', '').replace('=X', '') + ': $' + d.price?.toFixed(2) + ' (' + (d.change >= 0 ? '+' : '') + d.change + '%)').join('\n');
  const emojis = { free: 'Free', essential: 'Essential', premium: 'Premium', vip: 'VIP' };
  const sep = '---';
  const footers = {
    free: '\n' + sep + '\nAnalyse complete disponible avec Essential, Premium ou VIP\nnova-industrie.netlify.app',
    essential: '\n' + sep + '\nSignaux illimites et graphiques disponibles avec Premium',
    premium: '\n' + sep + '\nGraphiques analyses envoyes separement',
    vip: '\n' + sep + '\nACCES APP N.O.V.A. COMPLETE: nova-vip1.netlify.app'
  };
  return 'RAPPORT N.O.V.A. ' + emojis[tier] + ' - ' + date + '\nNaite Industries\n\n' + sep + '\nMARCHES EN TEMPS REEL\n' + mkt + '\n\n' + sep + '\n' + reportText + (footers[tier] || '') + '\n\n---\nNon constitutif dun conseil en investissement';
}

async function sendDailyReports() {
  console.log('Sending daily reports...');
  const date = new Date().toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long' });
  const marketData = await fetchMarketData();
  const token = process.env.TELEGRAM_TOKEN;

  for (const [tier, canal] of Object.entries(CANALS_CONFIG)) {
    try {
      const report = await generateDailyReport(tier, marketData, date);
      const msg = buildTieredMessage(tier, date, marketData, report);
      const r = await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: canal.chatId, text: msg, parse_mode: 'Markdown', disable_web_page_preview: true })
      });
      const d = await r.json();
      console.log(tier + ' text:', d.ok ? 'OK' : 'FAIL - ' + d.description);
      await new Promise(r => setTimeout(r, 2000));

      if (tier === 'premium' || tier === 'vip') {
        console.log('Generating charts for', tier);
        const chartSymbols = ['BTC-USD', 'ETH-USD', 'SPY', 'NVDA'];

        for (const sym of chartSymbols.slice(0, 2)) {
          console.log('Fetching data for', sym);
          const hData = await fetchHistoricalData(sym);
          if (!hData) { console.log('No data for', sym); continue; }
          const chartUrl = buildBarLineChartUrl(hData, sym.replace('-USD', ''));
          const cap = sym.replace('-USD', '') + ' - Analyse 30 jours - N.O.V.A. ' + tier.toUpperCase();
          const ok = await sendPhotoToTelegram(token, canal.chatId, chartUrl, cap);
          console.log(sym + ' chart:', ok ? 'OK' : 'FAIL');
          await new Promise(r => setTimeout(r, 4000));
        }

        const compDatasets = [];
        for (const sym of chartSymbols) {
          const hData = await fetchHistoricalData(sym);
          if (!hData) continue;
          const base = hData.prices[0];
          compDatasets.push({ label: sym.replace('-USD', ''), data: hData.prices.map(p => parseFloat(((p - base) / base * 100).toFixed(2))) });
          await new Promise(r => setTimeout(r, 2000));
        }
        if (compDatasets.length >= 2) {
          const compUrl = buildComparativeChartUrl(compDatasets);
          const ok = await sendPhotoToTelegram(token, canal.chatId, compUrl, 'Performance Comparative 30 Jours - N.O.V.A. ' + tier.toUpperCase());
          console.log('Comparative chart:', ok ? 'OK' : 'FAIL');
        }
      }
    } catch (e) { console.log(tier + ' error:', e.message); }
    await new Promise(r => setTimeout(r, 3000));
  }
  console.log('Daily reports done!');
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

app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online', version: '2.0' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('N.O.V.A. Backend v2.0 running on port ' + PORT));
