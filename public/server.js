/**
 * server.js
 *
 * Consolidated server implementing:
 * - Discord OAuth
 * - Google OAuth
 * - Email signup & verification (verification code)
 * - JWT access / refresh tokens
 * - File uploads (Multer)
 * - Rate limiting
 * - Script storage (Postgres)
 * - Loader retrieval endpoint (with UA check)
 * - Admin API endpoints
 * - ALU logs
 * - Static serving of frontend (index.html)
 *
 * Environment variables (REQUIRED)
 *  - PORT (optional, default 3000)
 *  - DATABASE_URL (postgres connection URI)
 *  - SESSION_SECRET (random string)
 *  - JWT_SECRET (random string for signing JWTs)
 *
 *  - DISCORD_CLIENT_ID
 *  - DISCORD_CLIENT_SECRET
 *  - DISCORD_REDIRECT_URI (https://yourdomain.com/auth/discord/callback)
 *
 *  - GOOGLE_CLIENT_ID
 *  - GOOGLE_CLIENT_SECRET
 *  - GOOGLE_REDIRECT_URI (https://yourdomain.com/auth/google/callback)
 *
 *  - SMTP_HOST
 *  - SMTP_PORT
 *  - SMTP_USER
 *  - SMTP_PASS
 *
 *  - ADMIN_API_TOKEN (simple admin bearer token)
 *
 * NOTE: This file contains placeholders for obfuscation logic and discord presence updates.
 */

require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // node-fetch v3, import as fetch
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fs = require('fs');

// -- Config & env checks ----------------------------------------------------
const REQUIRED_ENVS = [
  'DATABASE_URL',
  'SESSION_SECRET',
  'JWT_SECRET',
  // OAuth secrets can be optional but we warn if missing
];

for (const k of REQUIRED_ENVS) {
  if (!process.env[k]) {
    console.error(`Missing required environment variable: ${k}`);
    // We do not exit; we'll still run but many features won't work. Up to you.
  }
}

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || null;

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

// -- DB --------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ssl etc if necessary
});

// Create tables if necessary
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text UNIQUE,
      username text,
      password_hash text,
      verified boolean DEFAULT false,
      created_at timestamptz DEFAULT now(),
      discord_id text,
      google_id text
    );
  `).catch(async (err) => {
    // some Postgres setups don't have gen_random_uuid; fall back to uuid_generate_v4
    if (err && /gen_random_uuid/.test(err.message)) {
      await pool.query(`
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        CREATE TABLE IF NOT EXISTS users (
          id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
          email text UNIQUE,
          username text,
          password_hash text,
          verified boolean DEFAULT false,
          created_at timestamptz DEFAULT now(),
          discord_id text,
          google_id text
        );
      `);
    } else {
      console.error('Error ensuring schema (users):', err);
      throw err;
    }
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS scripts (
      key text PRIMARY KEY,
      owner_id uuid REFERENCES users(id) ON DELETE SET NULL,
      title text,
      script text,
      preset text,
      uses integer DEFAULT 0,
      created_at timestamptz DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text,
      code text,
      expires_at timestamptz
    );
  `).catch(() => {});
}

ensureSchema().catch(e => {
  console.error('Schema init error:', e);
});

// -- Email transporter -----------------------------------------------------
let transporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT) || 587,
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
} else {
  console.warn('SMTP not fully configured. Email verification will fail until SMTP envs are set.');
}

// -- App initialization ----------------------------------------------------
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting: global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Serve static frontend (put your built index.html in /public)
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
app.use(express.static(PUBLIC_DIR));

// -- Utilities -------------------------------------------------------------
function randomKey(len = 28) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}
function nowPlusMinutes(min) {
  const d = new Date(); d.setMinutes(d.getMinutes() + min); return d;
}
function signJWT(payload, expiresIn = '1h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
function verifyJWT(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}
async function getUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return r.rows[0];
}
async function upsertUserByEmail(payload) {
  // payload={email, username, passwordHash, verified, google_id, discord_id}
  const user = await getUserByEmail(payload.email);
  if (user) {
    await pool.query(
      `UPDATE users SET username=$2, password_hash=$3, verified=$4, google_id=$5, discord_id=$6 WHERE id=$1`,
      [user.id, payload.username || user.username, payload.passwordHash || user.password_hash, payload.verified ?? user.verified, payload.google_id || user.google_id, payload.discord_id || user.discord_id]
    );
    return (await pool.query('SELECT * FROM users WHERE id=$1', [user.id])).rows[0];
  } else {
    const insert = await pool.query(
      `INSERT INTO users(email, username, password_hash, verified, google_id, discord_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [payload.email, payload.username || null, payload.passwordHash || null, payload.verified || false, payload.google_id || null, payload.discord_id || null]
    );
    return insert.rows[0];
  }
}

// -- Email verification endpoints -----------------------------------------
/**
 * POST /auth/email/register
 *  { email, username, password }
 * sends verification code to email and stores a record in email_verifications
 */
app.post('/auth/email/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    // Save hashed password (but don't mark verified yet)
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await upsertUserByEmail({ email, username, passwordHash, verified: false });

    // create verification code (hex 24)
    const code = randomKey(24);
    const expiresAt = nowPlusMinutes(60);

    await pool.query('INSERT INTO email_verifications(id, email, code, expires_at) VALUES(gen_random_uuid(), $1, $2, $3) ON CONFLICT DO NOTHING', [email, code, expiresAt]);

    if (!transporter) {
      console.warn('Email transporter not configured; cannot send verification email.');
      return res.status(500).json({ error: 'Email sending not configured' });
    }

    const verificationUrl = `${req.protocol}://${req.get('host')}/auth/email/verify?email=${encodeURIComponent(email)}&code=${code}`;

    await transporter.sendMail({
      from: `"NovaHub" <${SMTP_USER}>`,
      to: email,
      subject: 'NovaHub verification code',
      text: `Your verification code: ${code}\nOr click: ${verificationUrl}\nThis code expires in 60 minutes.`,
      html: `<p>Your verification code: <b>${code}</b></p><p>Or click: <a href="${verificationUrl}">verify</a></p><p>Expires in 60 minutes.</p>`
    });

    return res.json({ ok: true, message: 'Verification email sent' });
  } catch (err) {
    console.error('email register err', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /auth/email/verify?email=&code=
 * marks user verified if code matches and not expired
 */
app.get('/auth/email/verify', async (req, res) => {
  try {
    const { email, code } = req.query;
    if (!email || !code) return res.status(400).send('Missing email or code');

    const q = await pool.query('SELECT * FROM email_verifications WHERE email=$1 AND code=$2', [email, code]);
    const row = q.rows[0];
    if (!row) return res.status(400).send('Invalid verification code');

    if (new Date(row.expires_at) < new Date()) return res.status(400).send('Code expired');

    // mark user verified
    await pool.query('UPDATE users SET verified=true WHERE email=$1', [email]);
    await pool.query('DELETE FROM email_verifications WHERE email=$1', [email]);

    // create JWT
    const user = await getUserByEmail(email);
    const token = signJWT({ sub: user.id, email: user.email }, '7d');

    // your frontend expects a message (we return a small HTML that posts message to opener if popup)
    const html = `
      <html><body>
        <script>
          (function(){
            const data = { accessToken: "${token}" };
            if (window.opener) {
              window.opener.postMessage(data, "*");
              window.close();
            } else {
              document.body.innerText = "Verified. Token: " + JSON.stringify(data);
            }
          })();
        </script>
      </body></html>
    `;
    res.set('Content-Type', 'text/html');
    return res.send(html);
  } catch (err) {
    console.error('verify err', err);
    return res.status(500).send('Server error');
  }
});

// -- JWT login (email/password) -------------------------------------------
/**
 * POST /auth/email/login
 * { email, password }
 */
app.post('/auth/email/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const user = await getUserByEmail(email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    if (!user.password_hash) return res.status(400).json({ error: 'No password set' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = signJWT({ sub: user.id, email: user.email }, '7d');
    const refreshToken = signJWT({ sub: user.id }, '30d');

    return res.json({ accessToken: token, refreshToken, user: { id: user.id, email: user.email, username: user.username } });
  } catch (err) {
    console.error('email login', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// -- Discord OAuth ---------------------------------------------------------
/**
 * GET /auth/discord
 * Redirects to Discord OAuth
 */
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) return res.status(500).send('Discord OAuth not configured on server.');
  const state = crypto.randomBytes(12).toString('hex');
  const scope = encodeURIComponent('identify email');
  const url = `https://discord.com/oauth2/authorize?response_type=code&client_id=${DISCORD_CLIENT_ID}&scope=${scope}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&state=${state}`;
  // In production, save state to DB or cookie to validate
  res.redirect(url);
});

/**
 * GET /auth/discord/callback?code=&state=
 * Exchanges code for token, fetches user info, upserts into users table and returns token to opener
 */
app.get('/auth/discord/callback', async (req, res) => {
  try {
    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
      return res.status(500).send('Discord oauth not configured on server.');
    }
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing code');

    const form = new URLSearchParams();
    form.append('client_id', DISCORD_CLIENT_ID);
    form.append('client_secret', DISCORD_CLIENT_SECRET);
    form.append('grant_type', 'authorization_code');
    form.append('code', code);
    form.append('redirect_uri', DISCORD_REDIRECT_URI);
    form.append('scope', 'identify email');

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      body: form
    });
    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      console.error('discord token error', tokenRes.status, body);
      return res.status(500).send('Discord OAuth failed.');
    }
    const tokenJson = await tokenRes.json();
    const accessToken = tokenJson.access_token;

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userJson = await userRes.json();

    // userJson contains id, username, discriminator, avatar, email (if scope permitted)
    const email = userJson.email || `${userJson.id}@discord.invalid`;
    const username = `${userJson.username}#${userJson.discriminator}`;

    const user = await upsertUserByEmail({ email, username, verified: true, discord_id: userJson.id });
    const token = signJWT({ sub: user.id, email: user.email }, '7d');

    // return as popup postMessage if opened by popup
    const html = `
      <html><body>
        <script>
          (function(){
            const data = { accessToken: "${token}" };
            if (window.opener) {
              window.opener.postMessage(data, "*");
              window.close();
            } else {
              document.body.innerText = "Signed in. Token: " + JSON.stringify(data);
            }
          })();
        </script>
      </body></html>
    `;
    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('discord callback error', err);
    res.status(500).send('Discord OAuth failed.');
  }
});

// -- Google OAuth ----------------------------------------------------------
/**
 * GET /auth/google
 * Redirects to Google OAuth consent screen
 */
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) return res.status(500).send('Google OAuth not configured on server.');
  const state = crypto.randomBytes(12).toString('hex');
  const scope = encodeURIComponent('openid email profile');
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&response_type=code&scope=${scope}&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&state=${state}&prompt=select_account`;
  res.redirect(url);
});

/**
 * GET /auth/google/callback
 */
app.get('/auth/google/callback', async (req, res) => {
  try {
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) {
      return res.status(500).send('Google OAuth not configured on server.');
    }
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing code');

    // exchange code for tokens
    const params = new URLSearchParams();
    params.append('code', code);
    params.append('client_id', GOOGLE_CLIENT_ID);
    params.append('client_secret', GOOGLE_CLIENT_SECRET);
    params.append('redirect_uri', GOOGLE_REDIRECT_URI);
    params.append('grant_type', 'authorization_code');

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      body: params
    });
    if (!tokenRes.ok) {
      const text = await tokenRes.text();
      console.error('google token error', text);
      return res.status(500).send('Google token exchange failed.');
    }
    const tokenJson = await tokenRes.json();
    const idToken = tokenJson.id_token;
    const accessToken = tokenJson.access_token;

    // fetch profile
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!profileRes.ok) {
      const t = await profileRes.text();
      console.error('google profile err', t);
      return res.status(500).send('Google profile fetch failed.');
    }
    const profile = await profileRes.json();
    // profile: id, email, verified_email, name, given_name, family_name, picture

    const email = profile.email;
    const username = profile.name;

    const user = await upsertUserByEmail({ email, username, verified: true, google_id: profile.id });
    const token = signJWT({ sub: user.id, email: user.email }, '7d');

    const html = `
      <html><body>
        <script>
          (function(){
            const data = { accessToken: "${token}" };
            if (window.opener) {
              window.opener.postMessage(data, "*");
              window.close();
            } else {
              document.body.innerText = "Signed in with Google. Token: " + JSON.stringify(data);
            }
          })();
        </script>
      </body></html>
    `;
    res.set('Content-Type', 'text/html');
    res.send(html);

  } catch (err) {
    console.error('google callback err', err);
    res.status(500).send('Google OAuth failed.');
  }
});

// -- Script obfuscation & store -------------------------------------------
/**
 * POST /obfuscate
 * { code, preset }
 * returns obfuscated code (placeholder - integrate your obfuscator)
 */
app.post('/obfuscate', async (req, res) => {
  try {
    const { code, preset } = req.body;
    if (!code) return res.status(400).json({ error: 'Missing code' });

    // Placeholder obfuscation: you MUST replace this with your obfuscator
    function obfuscatePlaceholder(src, presetName) {
      // VERY SIMPLE: base64 encode and wrap in a loader.
      const b64 = Buffer.from(src, 'utf8').toString('base64');
      return `-- NOVAHUB-OBFUSCATED (preset=${presetName})
local b64 = "${b64}"
local src = (game and game.HttpGet) and (loadstring(game.HttpGet or function() return "" end)) or (loadstring or load)
-- decode and run:
local decoded = (function(s) return (require and require("buffer") and s) or s end)(b64)
-- NOTE: replace with real decode in loader
print("[Obfuscated] length", #b64)
`;
    }

    const obf = obfuscatePlaceholder(code, preset || 'medium');
    return res.json({ obfuscated: obf, preset: preset || 'medium' });

  } catch (err) {
    console.error('obfuscate err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /obfuscate-and-store
 * { script, preset, title }
 * Stores obfuscated script and returns a key; requires Authorization Bearer token
 */
app.post('/obfuscate-and-store', async (req, res) => {
  try {
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    const userData = verifyJWT(auth);
    if (!userData) return res.status(401).json({ error: 'Unauthorized' });

    const userId = userData.sub;
    const { script, preset, title } = req.body;
    if (!script) return res.status(400).json({ error: 'Missing script' });

    // Run obfuscator (placeholder)
    const obf = (await (async () => {
      // call /obfuscate inner function or reuse code above
      const b64 = Buffer.from(script, 'utf8').toString('base64');
      return `-- NOVAHUB OBF (preset=${preset||'medium'})\nlocal b64="${b64}"\n-- loader: ...`;
    })());

    const key = randomKey(24);
    await pool.query('INSERT INTO scripts(key, owner_id, title, script, preset) VALUES($1,$2,$3,$4,$5)', [key, userId, title || null, obf, preset || 'medium']);

    return res.json({ ok: true, key });
  } catch (err) {
    console.error('store err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- Retrieve loader (public) ---------------------------------------------
/**
 * GET /retrieve/:key
 * Returns the script associated with key. For safety, optionally restrict to a UA (Roblox)
 */
app.get('/retrieve/:key', async (req, res) => {
  try {
    const { key } = req.params;
    const r = await pool.query('SELECT * FROM scripts WHERE key=$1', [key]);
    const row = r.rows[0];
    if (!row) return res.status(404).send('Not found');

    // basic UA restriction: only allow if UA contains 'Roblox' or if a query param ?allow=true (for testing)
    const ua = (req.get('User-Agent') || '');
    const allowAny = req.query.allow === 'true';
    if (!allowAny && !/Roblox/i.test(ua)) {
      return res.status(403).send('Forbidden: loader restricted by UA');
    }

    // increment uses
    await pool.query('UPDATE scripts SET uses = COALESCE(uses,0)+1 WHERE key=$1', [key]);

    // return raw script as text/plain
    res.set('Content-Type', 'text/plain');
    res.send(row.script);
  } catch (err) {
    console.error('retrieve err', err);
    res.status(500).send('Server error');
  }
});

// -- Scripts API (user) ---------------------------------------------------
/**
 * GET /api/scripts
 * returns list of scripts for current user
 */
app.get('/api/scripts', async (req, res) => {
  try {
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    const u = verifyJWT(auth);
    if (!u) return res.status(401).json({ error: 'Unauthorized' });

    const r = await pool.query('SELECT key, title, uses, created_at FROM scripts WHERE owner_id=$1 ORDER BY created_at DESC', [u.sub]);
    return res.json(r.rows);
  } catch (err) {
    console.error('api scripts', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/scripts/:key
 * Returns script metadata + content if owner
 */
app.get('/api/scripts/:key', async (req, res) => {
  try {
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    const u = verifyJWT(auth);
    if (!u) return res.status(401).json({ error: 'Unauthorized' });

    const { key } = req.params;
    const r = await pool.query('SELECT * FROM scripts WHERE key=$1', [key]);
    const row = r.rows[0];
    if (!row) return res.status(404).json({ error: 'Not found' });
    if (String(row.owner_id) !== String(u.sub)) return res.status(403).json({ error: 'Forbidden' });

    return res.json({ key: row.key, title: row.title, script: row.script, uses: row.uses, created_at: row.created_at });
  } catch (err) {
    console.error('api script get', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * DELETE /api/scripts/:key
 */
app.delete('/api/scripts/:key', async (req, res) => {
  try {
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    const u = verifyJWT(auth);
    if (!u) return res.status(401).json({ error: 'Unauthorized' });

    const { key } = req.params;
    const r = await pool.query('SELECT owner_id FROM scripts WHERE key=$1', [key]);
    const row = r.rows[0];
    if (!row) return res.status(404).json({ error: 'Not found' });
    if (String(row.owner_id) !== String(u.sub)) return res.status(403).json({ error: 'Forbidden' });

    await pool.query('DELETE FROM scripts WHERE key=$1', [key]);
    return res.json({ ok: true });
  } catch (err) {
    console.error('delete script', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- File uploads ----------------------------------------------------------
const upload = multer({ dest: path.join(__dirname, 'uploads/'), limits: { fileSize: 5 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    // simple upload endpoint; you can store file path in DB
    if (!req.file) return res.status(400).json({ error: 'No file' });
    return res.json({ ok: true, filename: req.file.filename, original: req.file.originalname });
  } catch (e) {
    console.error('upload err', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- Admin API -------------------------------------------------------------
function requireAdmin(req, res, next) {
  const a = (req.headers.authorization || '').replace('Bearer ', '');
  if (!ADMIN_API_TOKEN) return res.status(500).json({ error: 'Admin token not configured' });
  if (!a || a !== ADMIN_API_TOKEN) return res.status(403).json({ error: 'Forbidden' });
  next();
}

/**
 * GET /admin/stats
 */
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    const users = (await pool.query('SELECT COUNT(*) FROM users')).rows[0].count;
    const scripts = (await pool.query('SELECT COUNT(*) FROM scripts')).rows[0].count;
    return res.json({ users: Number(users), scripts: Number(scripts) });
  } catch (err) {
    console.error('admin stats', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /admin/obfuscator/test - admin-only endpoint to test obfuscator with preset
 */
app.post('/admin/obfuscator/test', requireAdmin, async (req, res) => {
  try {
    const { code, preset } = req.body;
    // integrate your obfuscator here and return result
    const obf = Buffer.from(code || '').toString('base64');
    return res.json({ obfuscated: obf, preset: preset || 'medium' });
  } catch (err) {
    console.error('admin obf test', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- ALU logs endpoint (activity logging) ---------------------------------
app.post('/api/alu/logs', async (req, res) => {
  try {
    // simply accept logs post and write to file or DB (for now file append)
    const payload = req.body;
    fs.appendFileSync(path.join(__dirname, 'alu_logs.txt'), `[${new Date().toISOString()}] ${JSON.stringify(payload)}\n`);
    return res.json({ ok: true });
  } catch (err) {
    console.error('alu logs err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- Discord presence backend placeholder ----------------------------------
/**
 * POST /api/discord/presence
 * { token, status }
 */
app.post('/api/discord/presence', async (req, res) => {
  try {
    // for security: require admin token or a valid bot token on server side
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    if (!ADMIN_API_TOKEN || auth !== ADMIN_API_TOKEN) return res.status(403).json({ error: 'Forbidden' });

    // TODO: update presence via discord.js bot or REST call
    // placeholder: write to file
    fs.appendFileSync(path.join(__dirname, 'presence_log.txt'), `[${new Date().toISOString()}] ${JSON.stringify(req.body)}\n`);
    return res.json({ ok: true, message: 'Presence updated (placeholder)' });
  } catch (err) {
    console.error('presence err', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -- Healthcheck & misc ---------------------------------------------------
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Serve single-page frontend fallback
app.get('*', (req, res, next) => {
  const index = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  return res.status(404).send('Not found');
});

// Start server
app.listen(PORT, () => {
  console.log(`NovaHub backend listening on port ${PORT}`);
  console.log('Session secret set:', !!SESSION_SECRET);
  console.log('JWT secret set:', !!JWT_SECRET);
  console.log('Discord configured:', !!DISCORD_CLIENT_ID);
  console.log('Google configured:', !!GOOGLE_CLIENT_ID);
  console.log('SMTP configured:', !!transporter);
});
