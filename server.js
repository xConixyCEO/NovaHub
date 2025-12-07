/**
 * server.js
 * NovaHub unified backend (auth, discord oauth, obfuscation, ALU logs, presence, file uploads)
 *
 * Usage: configure .env (see instructions) and run `node server.js`
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_access_secret';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const CLI_LAUNCH_CMD = process.env.CLI_LAUNCH_CMD || 'lua src/cli.lua';
const TEMP_DIR = process.env.TEMP_DIR || require('os').tmpdir();
const MAX_CONCURRENCY = process.env.MAX_CONCURRENCY ? Number(process.env.MAX_CONCURRENCY) : 2;
const ACCESS_EXP = process.env.ACCESS_EXP || '1h';
const REFRESH_EXP = process.env.REFRESH_EXP || '30d';

if (!DATABASE_URL) {
  console.error('DATABASE_URL not set. Exiting.');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });

// Middleware
app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'static')));

// DB setup (simple)
async function ensureTables() {
  const c = await pool.connect();
  try {
    await c.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE,
      username TEXT,
      password_hash TEXT,
      discord_id TEXT UNIQUE,
      discord_avatar TEXT,
      role TEXT DEFAULT 'user',
      refresh_token TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS scripts (
      key VARCHAR(64) PRIMARY KEY,
      script TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      uses INTEGER DEFAULT 0,
      last_used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      title TEXT
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS alu_logs (
      id SERIAL PRIMARY KEY,
      script_key VARCHAR(64),
      user_id INTEGER,
      event_type TEXT,
      ip TEXT,
      user_agent TEXT,
      extra JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    console.log('DB tables ensured');
  } finally {
    c.release();
  }
}
ensureTables().catch(err => { console.error('DB init failed', err); process.exit(1); });

// Utils
const genId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');
const signAccess = (userId) => jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_EXP });
const signRefresh = (userId) => jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXP });
const verifyAccess = (token) => { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } };
const verifyRefresh = (token) => { try { return jwt.verify(token, JWT_REFRESH_SECRET); } catch { return null; } };
const log = (...args) => console.log(new Date().toISOString(), ...args);

// Rate limits
const authLimiter = rateLimit({ windowMs: 60*1000, max: 12, message: { error: 'Too many requests' } });
const obfLimiter = rateLimit({ windowMs: 60*1000, max: 6, message: { error: 'Too many obfuscation requests' } });

// Simple job queue to limit CLI concurrency
let activeJobs = 0;
const jobQueue = [];
function enqueueJob(fn) {
  return new Promise((resolve, reject) => {
    const job = async () => {
      try {
        activeJobs++;
        const r = await fn();
        resolve(r);
      } catch (err) {
        reject(err);
      } finally {
        activeJobs--;
        if (jobQueue.length > 0 && activeJobs < MAX_CONCURRENCY) {
          const next = jobQueue.shift();
          setImmediate(next);
        }
      }
    };
    if (activeJobs < MAX_CONCURRENCY) job();
    else jobQueue.push(job);
  });
}

// Auth middleware
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = (auth.split(' ')[1] || '').trim();
  if (!token) return res.status(401).json({ error: 'Missing token' });
  const payload = verifyAccess(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
  req.userId = payload.id;
  next();
}

// ALU logging
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = null, user_agent = null, extra = {} } = {}) {
  try {
    await pool.query('INSERT INTO alu_logs(script_key, user_id, event_type, ip, user_agent, extra) VALUES($1,$2,$3,$4,$5,$6)', [script_key, user_id, event_type, ip, user_agent, extra]);
  } catch (e) {
    console.error('ALU log error', e.message || e);
  }
}

// Simple helpers
async function findUserByEmail(email) { const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]); return r.rows[0] || null; }
async function findUserById(id) { const r = await pool.query('SELECT id,email,username,discord_id,discord_avatar,role,created_at FROM users WHERE id=$1', [id]); return r.rows[0] || null; }
async function findUserByDiscordId(did) { const r = await pool.query('SELECT * FROM users WHERE discord_id=$1', [did]); return r.rows[0] || null; }

// Auth routes: register / login / refresh / logout
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const insert = await pool.query('INSERT INTO users(email, username, password_hash) VALUES($1,$2,$3) RETURNING id,email,username', [email, username || null, hash]);
    const user = insert.rows[0];
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.status(201).json({ user: { id: user.id, email: user.email, username: user.username }, accessToken: access, refreshToken: refresh });
  } catch (err) { console.error('/auth/register', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);
    res.json({ user: { id: user.id, email: user.email, username: user.username, role: user.role }, accessToken: access, refreshToken: refresh });
  } catch (err) { console.error('/auth/login', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.status(401).json({ error: 'Invalid refresh token' });
    const userId = payload.id;
    const r = await pool.query('SELECT refresh_token FROM users WHERE id=$1', [userId]);
    if (r.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (r.rows[0].refresh_token !== refreshToken) return res.status(401).json({ error: 'Refresh token mismatch' });
    const newAccess = signAccess(userId);
    const newRefresh = signRefresh(userId);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [newRefresh, userId]);
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (err) { console.error('/auth/refresh', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.json({ ok: true });
    const payload = verifyRefresh(refreshToken);
    if (!payload) return res.json({ ok: true });
    const userId = payload.id;
    await pool.query('UPDATE users SET refresh_token=NULL WHERE id=$1', [userId]);
    res.json({ ok: true });
  } catch (err) { console.error('/auth/logout', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const u = await findUserById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) { console.error('/auth/me', err); res.status(500).json({ error: 'Server error' }); }
});

// Discord OAuth endpoints
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) return res.status(400).send('Discord OAuth not configured on server.');
  const state = genId(8);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
    return res.status(400).send('Discord OAuth not configured.');
  }
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code parameter.');
  try {
    const form = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: DISCORD_REDIRECT_URI,
    });

    const tokenResp = await axios.post('https://discord.com/api/oauth2/token', form.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const tokenJson = tokenResp.data;
    if (!tokenJson.access_token) {
      console.error('Discord token exchange failed', tokenJson);
      return res.status(500).send('Discord token exchange failed');
    }

    const userResp = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const discordUser = userResp.data;
    // Upsert user
    let user = await findUserByDiscordId(discordUser.id);
    if (!user) {
      const insert = await pool.query('INSERT INTO users (discord_id, username, discord_avatar) VALUES ($1,$2,$3) RETURNING id,discord_id,username,discord_avatar', [discordUser.id, discordUser.username, discordUser.avatar || null]);
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET username=$1, discord_avatar=$2 WHERE id=$3', [discordUser.username, discordUser.avatar || null, user.id]);
    }
    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    // send tokens to opener window (client) via simple html+script
    res.send(`
      <html>
        <body>
          <script>
            (function(){
              const data = ${JSON.stringify({ accessToken: access, refreshToken: refresh, user: { id: user.id, discord_id: user.discord_id, username: user.username } })};
              if (window.opener && window.opener.postMessage) {
                window.opener.postMessage(data, '*');
              }
              document.write('Discord sign-in successful. You can close this window.');
            })();
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    console.error('Discord callback error', err?.response?.data || err.message || err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// File upload (multer)
const upload = multer({ dest: path.join(TEMP_DIR, 'uploads'), limits: { fileSize: 5 * 1024 * 1024 } });

// Obfuscator CLI wrapper
function sanitizeFilename(n) { return (n || '').replace(/[^a-zA-Z0-9_.-]/g, '_'); }
async function callObfuscatorCLI(rawLua, preset = 'Medium') {
  const ts = Date.now();
  const tmpIn = path.join(TEMP_DIR, `novahub_in_${ts}_${genId(4)}.lua`);
  const tmpOut = path.join(TEMP_DIR, `novahub_out_${ts}_${genId(4)}.lua`);
  try {
    fs.writeFileSync(tmpIn, rawLua, 'utf8');
    const cmd = `${CLI_LAUNCH_CMD} --preset ${sanitizeFilename(preset)} --out ${tmpOut} ${tmpIn}`;
    log('Obfuscator cmd:', cmd);
    const execPromise = () => new Promise((resolve) => {
      exec(cmd, { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
        if (err || stderr) {
          try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: false, output: null, error: (err && err.message) || stderr });
        }
        if (!fs.existsSync(tmpOut)) return resolve({ success: false, output: null, error: 'No output' });
        try {
          const out = fs.readFileSync(tmpOut, 'utf8');
          try { fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: true, output: out, error: null });
        } catch (e) { return resolve({ success: false, output: null, error: e.message }); }
      });
    });
    const r = await enqueueJob(execPromise);
    return r;
  } catch (err) {
    try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
    try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
    return { success: false, output: null, error: err.message || String(err) };
  }
}

const WATERMARK = '--[[ v0.1.0 NovaHub Lua Obfuscator ]] ';
const FALLBACK = '--[[ OBFUSCATION FAILED: returning raw ]]';
function applyFallback(raw) { return `${FALLBACK}\n${raw}`; }

app.post('/obfuscate', obfLimiter, requireAuth, async (req, res) => {
  const { code, preset } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });
  try {
    const r = await callObfuscatorCLI(code, preset || 'Medium');
    if (!r.success) return res.json({ obfuscatedCode: WATERMARK + applyFallback(code), success: false, error: r.error });
    return res.json({ obfuscatedCode: WATERMARK + r.output, success: true });
  } catch (err) { console.error('/obfuscate', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/obfuscate-and-store', obfLimiter, requireAuth, async (req, res) => {
  const { script, preset, title } = req.body || {};
  if (!script || typeof script !== 'string') return res.status(400).json({ error: 'Missing script' });
  try {
    const r = await callObfuscatorCLI(script, preset || 'Medium');
    let obf;
    let success = false;
    if (!r.success) { obf = applyFallback(script); success = false; }
    else { obf = WATERMARK + r.output; success = true; }
    const key = genId(16);
    await pool.query('INSERT INTO scripts(key, script, user_id, title) VALUES($1,$2,$3,$4)', [key, obf, req.userId, title || null]);
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'create', ip: req.ip, user_agent: req.headers['user-agent'], extra: { preset: preset || 'Medium', success } });
    res.status(201).json({ key, success });
  } catch (err) { console.error('/obfuscate-and-store', err); res.status(500).json({ error: 'Server error' }); }
});

// Retrieve: enforce Roblox UA check (prevent raw access from browsers)
app.get('/retrieve/:key', async (req, res) => {
  const key = req.params.key;
  if (!key) return res.status(400).send('-- Invalid key');
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection?.remoteAddress || '';
  try {
    const r = await pool.query('SELECT script, user_id FROM scripts WHERE key=$1', [key]);
    if (r.rows.length === 0) {
      await recordAluLog({ script_key: key, event_type: 'retrieve_not_found', ip, user_agent: ua });
      res.setHeader('Content-Type', 'text/plain'); return res.status(404).send('-- Script Not Found.');
    }
    // Roblox UA check
    if (!ua.includes('Roblox')) {
      await recordAluLog({ script_key: key, user_id: r.rows[0].user_id, event_type: 'blocked_nonroblox', ip, user_agent: ua });
      res.setHeader('Content-Type', 'text/plain'); return res.status(403).send('-- Access Denied. Roblox UA required.');
    }
    await pool.query('UPDATE scripts SET uses = uses + 1, last_used_at = NOW() WHERE key=$1', [key]);
    await recordAluLog({ script_key: key, user_id: r.rows[0].user_id, event_type: 'retrieve', ip, user_agent: ua, extra: { maybeRoblox: true } });
    res.setHeader('Content-Type', 'text/plain'); return res.send(r.rows[0].script);
  } catch (err) { console.error('/retrieve', err); res.setHeader('Content-Type', 'text/plain'); return res.status(500).send('-- Internal Server Error.'); }
});

// Scripts CRUD endpoints (protected)
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/scripts', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at, script FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) { console.error('/api/scripts/:key', err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('DELETE FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found or not owned' });
    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'delete', ip: req.ip, user_agent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (err) { console.error('DELETE /api/scripts/:key', err); res.status(500).json({ error: 'Server error' }); }
});

// ALU endpoints
app.get('/api/alu/logs', requireAuth, async (req, res) => {
  try {
    const u = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (u.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (u.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const limit = Math.min(200, Number(req.query.limit || 50));
    const r = await pool.query('SELECT * FROM alu_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (err) { console.error('/api/alu/logs', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/alu/stats', requireAuth, async (req, res) => {
  try {
    const u = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (u.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (u.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const totalScriptsR = await pool.query('SELECT COUNT(*) FROM scripts');
    const totalAccessR = await pool.query('SELECT COUNT(*) FROM alu_logs');
    const topScriptsR = await pool.query('SELECT script_key, COUNT(*) AS hits FROM alu_logs WHERE script_key IS NOT NULL GROUP BY script_key ORDER BY hits DESC LIMIT 10');
    res.json({ totalScripts: Number(totalScriptsR.rows[0].count), totalAccessLogs: Number(totalAccessR.rows[0].count), topScripts: topScriptsR.rows });
  } catch (err) { console.error('/api/alu/stats', err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/user/activity', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM alu_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.userId]);
    res.json(r.rows);
  } catch (err) { console.error('/api/user/activity', err); res.status(500).json({ error: 'Server error' }); }
});

// Discord presence endpoint (returns DB info; if DISCORD_BOT_TOKEN present, tries to fetch from Discord API)
app.get('/api/discord/presence/:discordId', requireAuth, async (req, res) => {
  try {
    const did = req.params.discordId;
    const userDb = await findUserByDiscordId(did);
    const result = { discordId: did, username: userDb ? userDb.username : null, avatar: userDb ? userDb.discord_avatar : null, presence: 'unknown' };
    if (DISCORD_BOT_TOKEN) {
      try {
        // Attempt to fetch user via bot token - note: /users/:id requires the bot token and the API may restrict presence access
        const r = await axios.get(`https://discord.com/api/v10/users/${did}`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } });
        result.username = r.data.username;
        result.avatar = r.data.avatar;
        // Presence data usually requires the bot to be in the same guild and use the gateway - can't reliably get presence via REST
        result.presence = 'unknown (bot token present, but presence requires gateway)';
      } catch (e) {
        result.presence = 'unavailable';
      }
    }
    res.json(result);
  } catch (err) { console.error('/api/discord/presence', err); res.status(500).json({ error: 'Server error' }); }
});

// Serve main index.html (if present in project root)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Basic health
app.get('/health', (req, res) => res.json({ ok: true }));

// Start server
app.listen(PORT, () => log(`NovaHub server listening on port ${PORT}`));
