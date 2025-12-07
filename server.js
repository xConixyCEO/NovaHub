/**
 * server.js
 * Unified NovaHub backend (single-file)
 * - Auth (email/password + Discord OAuth)
 * - JWT access + refresh
 * - Obfuscation via CLI (src/cli.lua)
 * - Storage (Postgres)
 * - ALU logging
 * - Rate-limiting
 * - File uploads (multer)
 * - Serves static public/ (index.html)
 *
 * Required env:
 *  - PORT (optional, default 4000)
 *  - DATABASE_URL
 *  - JWT_SECRET
 *  - JWT_REFRESH_SECRET
 *  - DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI (optional)
 *  - CLI_LAUNCH_CMD (optional, default "lua src/cli.lua")
 *  - MAX_CONCURRENCY (optional)
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const axios = require('axios');
const os = require('os');

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_jwt_refresh_change_me';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || '';
const CLI_LAUNCH_CMD = process.env.CLI_LAUNCH_CMD || 'lua src/cli.lua';
const TEMP_DIR = process.env.TEMP_DIR || os.tmpdir();
const MAX_CONCURRENCY = process.env.MAX_CONCURRENCY ? Number(process.env.MAX_CONCURRENCY) : 2;
const ACCESS_EXP = process.env.ACCESS_EXP || '1h';
const REFRESH_EXP = process.env.REFRESH_EXP || '30d';

if (!DATABASE_URL) {
  console.error("DATABASE_URL not set in environment. Exiting.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
});

// app middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// file upload (multer) - store in temp directory then read
const upload = multer({ dest: path.join(TEMP_DIR, 'uploads') });

// basic logger
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

const genId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');

function signAccess(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_EXP });
}
function signRefresh(userId) {
  return jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXP });
}
function verifyAccess(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) { return null; }
}
function verifyRefresh(token) {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET);
  } catch (e) { return null; }
}

// ensure db tables
async function ensureTables() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        username TEXT,
        password_hash TEXT,
        discord_id TEXT UNIQUE,
        discord_avatar TEXT,
        role TEXT DEFAULT 'user',
        refresh_token TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS scripts (
        key VARCHAR(64) PRIMARY KEY,
        script TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        uses INTEGER DEFAULT 0,
        last_used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        title TEXT
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS alu_logs (
        id SERIAL PRIMARY KEY,
        script_key VARCHAR(64),
        user_id INTEGER,
        event_type TEXT,
        ip TEXT,
        user_agent TEXT,
        extra JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_alu_script_key ON alu_logs(script_key);`);

    log('DB tables ensured');
  } finally {
    client.release();
  }
}
ensureTables().catch(err => {
  console.error('Failed to ensure DB tables:', err);
  process.exit(1);
});

// rate limiters
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many requests, slow down.' }
});
const obfLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 6,
  message: { error: 'Too many obfuscation requests, try again later.' }
});
const retrieveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: '-- Rate limit exceeded.'
});

// concurrency limiter for CLI
let activeJobs = 0;
const jobQueue = [];
function enqueueJob(fn) {
  return new Promise((resolve, reject) => {
    const job = async () => {
      try {
        activeJobs++;
        const result = await fn();
        resolve(result);
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

// requireAuth middleware
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

// helpers
async function findUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  return r.rows[0] || null;
}
async function findUserById(id) {
  const r = await pool.query('SELECT id,email,username,discord_id,discord_avatar,role,created_at FROM users WHERE id=$1', [id]);
  return r.rows[0] || null;
}
async function findUserByDiscordId(did) {
  const r = await pool.query('SELECT * FROM users WHERE discord_id=$1', [did]);
  return r.rows[0] || null;
}
async function recordAluLog({ script_key = null, user_id = null, event_type = 'access', ip = null, user_agent = null, extra = {} } = {}) {
  try {
    await pool.query(
      `INSERT INTO alu_logs(script_key, user_id, event_type, ip, user_agent, extra) VALUES($1,$2,$3,$4,$5,$6)`,
      [script_key, user_id, event_type, ip, user_agent, extra]
    );
  } catch (err) {
    console.error('Failed to write ALU log', err);
  }
}

// Discord presence endpoint - returns stored DB info (avatar/username) and status unknown unless you run a bot/gateway
app.get('/api/discord-status/:discordId', async (req, res) => {
  try {
    const rid = req.params.discordId;
    if (!rid) return res.status(400).json({ error: 'Missing discord id' });
    const r = await pool.query('SELECT username, discord_avatar FROM users WHERE discord_id=$1', [rid]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    const row = r.rows[0];
    // presence (online/offline) would require a bot connected to gateway; return unknown
    res.json({ username: row.username, avatar: row.discord_avatar, presence: 'unknown' });
  } catch (err) {
    console.error('/api/discord-status error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Auth endpoints ----------
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const insert = await pool.query(
      'INSERT INTO users(email, username, password_hash) VALUES($1,$2,$3) RETURNING id,email,username',
      [email, username || null, hash]
    );
    const user = insert.rows[0];

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

    res.status(201).json({
      user: { id: user.id, email: user.email, username: user.username },
      accessToken: access,
      refreshToken: refresh
    });
  } catch (err) {
    console.error('/auth/register error', err);
    res.status(500).json({ error: 'Server error' });
  }
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

    res.json({
      user: { id: user.id, email: user.email, username: user.username, role: user.role },
      accessToken: access,
      refreshToken: refresh
    });
  } catch (err) {
    console.error('/auth/login error', err);
    res.status(500).json({ error: 'Server error' });
  }
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
  } catch (err) {
    console.error('/auth/refresh error', err);
    res.status(500).json({ error: 'Server error' });
  }
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
  } catch (err) {
    console.error('/auth/logout', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const u = await findUserById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) {
    console.error('/auth/me', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Discord OAuth
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) {
    return res.status(400).send('Discord OAuth not configured on server.');
  }
  const state = genId(8);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
    state
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
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
      redirect_uri: DISCORD_REDIRECT_URI
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

    let user = await findUserByDiscordId(discordUser.id);
    if (!user) {
      const insert = await pool.query(
        'INSERT INTO users (discord_id, username, discord_avatar) VALUES ($1,$2,$3) RETURNING id,discord_id,username,discord_avatar',
        [discordUser.id, discordUser.username, discordUser.avatar || null]
      );
      user = insert.rows[0];
    } else {
      await pool.query('UPDATE users SET username=$1, discord_avatar=$2 WHERE id=$3', [discordUser.username, discordUser.avatar || null, user.id]);
    }

    const access = signAccess(user.id);
    const refresh = signRefresh(user.id);
    await pool.query('UPDATE users SET refresh_token=$1 WHERE id=$2', [refresh, user.id]);

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
    console.error('Discord callback error', err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// ---------- Obfuscation helpers ----------
function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_.-]/g, '_');
}
async function callObfuscatorCLI(rawLua, preset = 'Medium') {
  const ts = Date.now();
  const tmpIn = path.join(TEMP_DIR, `novahub_in_${ts}_${genId(4)}.lua`);
  const tmpOut = path.join(TEMP_DIR, `novahub_out_${ts}_${genId(4)}.lua`);
  try {
    fs.writeFileSync(tmpIn, rawLua, 'utf8');
    const cmd = `${CLI_LAUNCH_CMD} --preset ${sanitizeFilename(preset)} --out ${tmpOut} ${tmpIn}`;
    log('Running obfuscator CLI:', cmd);

    const execPromise = () => new Promise((resolve) => {
      const proc = exec(cmd, { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
        if (err || stderr) {
          log('Obfuscator CLI error', err ? err.message : stderr);
          try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: false, output: null, error: (err && err.message) || stderr });
        }
        if (!fs.existsSync(tmpOut)) {
          log('Obfuscator CLI did not produce output file.');
          return resolve({ success: false, output: null, error: 'No output produced' });
        }
        try {
          const out = fs.readFileSync(tmpOut, 'utf8');
          try { fs.unlinkSync(tmpOut); } catch (e) {}
          return resolve({ success: true, output: out, error: null });
        } catch (e) {
          log('Failed reading obf output', e);
          return resolve({ success: false, output: null, error: e.message });
        }
      });
    });

    const result = await enqueueJob(execPromise);
    return result;
  } catch (err) {
    try { if (fs.existsSync(tmpIn)) fs.unlinkSync(tmpIn); } catch (e) {}
    try { if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut); } catch (e) {}
    return { success: false, output: null, error: err.message || String(err) };
  }
}

const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK = "--[[ OBFUSCATION FAILED: returning raw ]]";
function applyFallback(raw) {
  return `${FALLBACK}\n${raw}`;
}

// ---------- Upload endpoint (file uploads allowed) ----------
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const filepath = req.file.path;
    const content = fs.readFileSync(filepath, 'utf8');
    // cleanup
    try { fs.unlinkSync(filepath); } catch (e) {}
    res.json({ filename: req.file.originalname, content });
  } catch (err) {
    console.error('/upload error', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ---------- Obfuscation endpoints ----------
app.post('/obfuscate', obfLimiter, requireAuth, async (req, res) => {
  const { code, preset } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Missing code' });

  try {
    const r = await callObfuscatorCLI(code, preset || 'Medium');
    if (!r.success) {
      const fallback = applyFallback(code);
      return res.json({ obfuscatedCode: WATERMARK + fallback, success: false, error: r.error });
    }
    const obf = WATERMARK + r.output;
    await recordAluLog({ event_type: 'obfuscate', user_id: req.userId, extra: { preset: preset || 'Medium' } });
    res.json({ obfuscatedCode: obf, success: true });
  } catch (err) {
    console.error('/obfuscate error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/obfuscate-and-store', obfLimiter, requireAuth, async (req, res) => {
  const { script, preset, title } = req.body || {};
  if (!script || typeof script !== 'string') return res.status(400).json({ error: 'Missing script' });

  try {
    const r = await callObfuscatorCLI(script, preset || 'Medium');
    let obf; let success = false;
    if (!r.success) { obf = applyFallback(script); success = false; }
    else { obf = WATERMARK + r.output; success = true; }

    const key = genId(16);
    await pool.query('INSERT INTO scripts(key, script, user_id, title) VALUES($1,$2,$3,$4)', [key, obf, req.userId, title || null]);

    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'create', ip: req.ip, user_agent: req.headers['user-agent'], extra: { preset: preset || 'Medium', success } });

    res.status(201).json({ key, success });
  } catch (err) {
    console.error('/obfuscate-and-store error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Retrieve endpoint (Roblox-only restriction) ----------
app.get('/retrieve/:key', retrieveLimiter, async (req, res) => {
  const key = req.params.key;
  const ua = req.headers['user-agent'] || '';
  if (!ua || !ua.includes('Roblox')) {
    res.setHeader('Content-Type', 'text/plain');
    return res.status(403).send('-- Access Denied.');
  }

  try {
    const result = await pool.query('SELECT script, user_id FROM scripts WHERE key = $1', [key]);
    if (result.rows.length === 0) {
      await recordAluLog({ script_key: key, event_type: 'retrieve_not_found', ip: req.ip, user_agent: ua });
      res.setHeader('Content-Type', 'text/plain');
      return res.status(404).send('-- Script Not Found.');
    }
    const row = result.rows[0];
    await pool.query('UPDATE scripts SET uses = uses + 1, last_used_at = NOW() WHERE key=$1', [key]);
    await recordAluLog({ script_key: key, user_id: row.user_id, event_type: 'retrieve', ip: req.ip, user_agent: ua, extra: { maybeRoblox: ua.includes('Roblox') } });

    res.setHeader('Content-Type', 'text/plain');
    res.send(row.script);
  } catch (err) {
    console.error('/retrieve error', err);
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('-- Internal Server Error.');
  }
});

// ---------- Script management endpoints (protected) ----------
app.get('/api/scripts', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE user_id=$1 ORDER BY created_at DESC', [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/scripts', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('SELECT key, title, uses, created_at, last_used_at FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) {
    console.error('/api/scripts/:key', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/scripts/:key', requireAuth, async (req, res) => {
  try {
    const key = req.params.key;
    const r = await pool.query('DELETE FROM scripts WHERE key=$1 AND user_id=$2', [key, req.userId]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'Not found or not owned' });

    await recordAluLog({ script_key: key, user_id: req.userId, event_type: 'delete', ip: req.ip, user_agent: req.headers['user-agent'] });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/scripts/:key', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- ALU logs and admin endpoints ----------
app.get('/api/alu/logs', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const limit = Math.min(200, Number(req.query.limit || 50));
    const r = await pool.query('SELECT * FROM alu_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/alu/logs', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/alu/stats', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const totalScriptsR = await pool.query('SELECT COUNT(*) FROM scripts');
    const totalAccessR = await pool.query('SELECT COUNT(*) FROM alu_logs');
    // top scripts will count logs grouped by script_key
    const topScriptsR = await pool.query('SELECT script_key, COUNT(*) as hits FROM alu_logs WHERE script_key IS NOT NULL GROUP BY script_key ORDER BY hits DESC LIMIT 10');

    res.json({
      totalScripts: Number(totalScriptsR.rows[0].count),
      totalAccessLogs: Number(totalAccessR.rows[0].count),
      topScripts: topScriptsR.rows
    });
  } catch (err) {
    console.error('/api/alu/stats', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/activity', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM alu_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.userId]);
    res.json(r.rows);
  } catch (err) {
    console.error('/api/user/activity', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: list users (admin only)
app.get('/api/admin/users', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT role FROM users WHERE id=$1', [req.userId]);
    if (user.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const r = await pool.query('SELECT id,email,username,discord_id,role,created_at FROM users ORDER BY created_at DESC LIMIT 500');
    res.json(r.rows);
  } catch (err) {
    console.error('/api/admin/users', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Root
app.get('/', (req, res) => {
  // serve index.html from public if exists; express.static will normally do this
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// start
app.listen(PORT, () => {
  log(`NovaHub server listening on port ${PORT}`);
});
