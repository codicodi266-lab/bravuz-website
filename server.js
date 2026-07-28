const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();
const PORT = 3000;
const DISCORD_CHANNEL_ID = process.env.DISCORD_CHANNEL_ID || '';
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const WEBHOOK_URL = process.env.WEBHOOK_URL || '';

const db = new Database(path.join(__dirname, 'bravuz.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    key TEXT NOT NULL,
    product TEXT DEFAULT 'Bravuz Menu',
    hwid TEXT DEFAULT NULL,
    hwid_anchored INTEGER DEFAULT 0,
    used INTEGER DEFAULT 0,
    used_by TEXT DEFAULT 'UNBOUND',
    activated_at TEXT DEFAULT NULL,
    expires_at TEXT DEFAULT NULL,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);
for (const col of ['hwid TEXT DEFAULT NULL','hwid_anchored INTEGER DEFAULT 0',"product TEXT DEFAULT 'Bravuz Menu'",
  'used INTEGER DEFAULT 0',"used_by TEXT DEFAULT 'UNBOUND'",'activated_at TEXT DEFAULT NULL',
  'expires_at TEXT DEFAULT NULL','active INTEGER DEFAULT 1']) {
  try { db.exec(`ALTER TABLE users ADD COLUMN ${col}`); } catch {}
}

const sessions = {};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { username, created: Date.now() };
  return token;
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Not logged in' });
  if (Date.now() - sessions[token].created > 24 * 60 * 60 * 1000) {
    delete sessions[token];
    return res.status(401).json({ error: 'Session expired' });
  }
  req.username = sessions[token].username;
  next();
}

function sendDiscordMessage(content) {
  const payload = JSON.stringify({ content });
  const url = new URL(WEBHOOK_URL);
  const options = {
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

app.post('/api/login', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  if (!user.active) return res.status(403).json({ error: 'Account is deactivated' });

  let hwidStatus = 'unknown';
  if (hwid) {
    if (!user.hwid || user.hwid === '') {
      db.prepare('UPDATE users SET hwid = ?, hwid_anchored = 1 WHERE username = ?').run(hwid, username);
      hwidStatus = 'anchored';
      try {
        await sendDiscordMessage(
          `**NEW HWID ANCHOR**\n` +
          `User: \`${username}\`\n` +
          `HWID: \`${hwid}\`\n` +
          `Key: \`${user.key}\`\n` +
          `Product: \`${user.product}\`\n` +
          `IP: \`${req.ip}\`\n` +
          `Time: ${new Date().toISOString()}`
        );
      } catch (e) { console.error('Discord send failed:', e.message); }
    } else if (user.hwid !== hwid) {
      hwidStatus = 'mismatch';
      try {
        await sendDiscordMessage(
          `**HWID MISMATCH**\n` +
          `User: \`${username}\`\n` +
          `Stored: \`${user.hwid}\`\n` +
          `New: \`${hwid}\`\n` +
          `Key: \`${user.key}\`\n` +
          `IP: \`${req.ip}\`\n` +
          `Time: ${new Date().toISOString()}`
        );
      } catch (e) { console.error('Discord send failed:', e.message); }
      return res.status(403).json({ error: 'HWID mismatch. This account is locked to another device. Contact support to reset.' });
    } else {
      hwidStatus = 'match';
    }
  } else if (user.hwid && user.hwid !== '') {
    return res.status(403).json({ error: 'This account is HWID-locked. Enter your HWID.', hwidRequired: true });
  }

  const token = createSession(user.username);
  res.json({ success: true, token, username: user.username, hwidStatus });
});

app.get('/api/verify', authMiddleware, (req, res) => {
  res.json({ success: true, username: req.username });
});

app.get('/api/download', authMiddleware, (req, res) => {
  res.download(path.join(__dirname, 'bravuz-menu.zip'), 'bravuz-menu.zip');
});

app.post('/api/add-user', (req, res) => {
  const { username, password, key, product, expires_at } = req.body;
  if (!username || !password || !key) return res.status(400).json({ error: 'Missing fields' });
  try {
    db.prepare('INSERT INTO users (username, password, key, product, expires_at) VALUES (?, ?, ?, ?, ?)').run(
      username, password, key, product || 'Bravuz Menu', expires_at || null
    );
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.post('/api/remove-user', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  db.prepare('DELETE FROM users WHERE username = ?').run(username);
  res.json({ success: true });
});

app.post('/api/toggle-active', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const user = db.prepare('SELECT active FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET active = ? WHERE username = ?').run(user.active ? 0 : 1, username);
  res.json({ success: true, active: !user.active });
});

app.get('/api/users', (req, res) => {
  const users = db.prepare(
    'SELECT id, username, key, product, hwid, used, used_by, activated_at, expires_at, active, created_at FROM users'
  ).all();
  res.json(users);
});

// Seed default account on startup
try {
  const existing = db.prepare('SELECT username FROM users WHERE username = ?').get('wes');
  if (!existing) {
    db.prepare('INSERT INTO users (username, password, key, product) VALUES (?, ?, ?, ?)').run('wes', '123', 'NXKO-KTGP-S418-OMA1', 'Bravuz Menu');
    console.log('Default account seeded: wes/123');
  }
} catch (e) { console.error('Seed error:', e.message); }

app.listen(PORT, () => {
  console.log(`Bravuz Panel running at http://localhost:${PORT}`);
});
