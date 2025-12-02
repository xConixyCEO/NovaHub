// bot.js
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  Routes,
  REST,
  EmbedBuilder
} = require("discord.js");

// --- Config from env (sensible defaults) ---
const API_BASE = process.env.API_BASE || "https://novahub-zd14.onrender.com";
const OWNER_ID = process.env.OWNER_ID || ""; // set in .env
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "users.json");

const INITIAL_TOKENS = parseInt(process.env.INITIAL_TOKENS || "15", 10);
const COMMAND_COST = parseInt(process.env.COMMAND_COST || "5", 10);

const GIFT_LIMIT = parseInt(process.env.GIFT_LIMIT || "30", 10);
const GIFT_TIMES = parseInt(process.env.GIFT_TIMES || "3", 10);
const GIFT_RESET_HOURS = parseInt(process.env.GIFT_RESET_HOURS || "6", 10);

const PREMIUM_COMMANDS = (process.env.PREMIUM_COMMANDS || "/ApiService").split(",").filter(Boolean);
const COMMANDS_WITH_COST = (process.env.COMMANDS_WITH_COST || "/obf,/store,/api").split(",").filter(Boolean);
const FREE_COMMANDS = (process.env.FREE_COMMANDS || "/info,/verify,/vf,/view,/help,/ping,/retrieve").split(",").filter(Boolean);

const REQUIRE_VERIFY = (process.env.REQUIRE_VERIFY || "true").toLowerCase() === "true";

if (!process.env.DISCORD_TOKEN) {
  console.error("DISCORD_TOKEN is missing from .env — exiting.");
  process.exit(1);
}
if (!process.env.CLIENT_ID) {
  console.error("CLIENT_ID is missing from .env — exiting.");
  process.exit(1);
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// --- Ensure data dir + file exist ---
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ users: {} }, null, 2));
}
ensureDataFile();

function loadData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    console.error("Failed to load data file:", e);
    return { users: {} };
  }
}
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// --- User helpers ---
function ensureUserRecord(userId) {
  const db = loadData();
  if (!db.users[userId]) {
    db.users[userId] = {
      verified: false,
      tokens: INITIAL_TOKENS,
      whitelisted: false,
      giftsGiven: [], // timestamps of gifts given (for window)
      createdAt: new Date().toISOString()
    };
    saveData(db);
  }
  return db.users[userId];
}

function isOwner(userId) {
  return OWNER_ID && userId === OWNER_ID;
}

function isWhitelisted(userId) {
  const db = loadData();
  const u = db.users[userId];
  return u && u.whitelisted === true;
}

function userHasInfinite(userId) {
  return isOwner(userId) || isWhitelisted(userId);
}

// Count gifts in rolling window (last GIFT_RESET_HOURS)
function giftsInWindow(userRecord) {
  const now = Date.now();
  const cutoff = now - GIFT_RESET_HOURS * 60 * 60 * 1000;
  return (userRecord.giftsGiven || []).filter(ts => ts >= cutoff).length;
}

// Record a gift given by giverId
function recordGift(giverId) {
  const db = loadData();
  const u = ensureUserRecord(giverId);
  u.giftsGiven = u.giftsGiven || [];
  u.giftsGiven.push(Date.now());
  saveData(db);
}

// Cleanup old gift timestamps across DB (periodic)
function cleanupOldGifts() {
  const db = loadData();
  const cutoff = Date.now() - GIFT_RESET_HOURS * 60 * 60 * 1000;
  let changed = false;
  Object.values(db.users).forEach(u => {
    if (Array.isArray(u.giftsGiven)) {
      const filtered = u.giftsGiven.filter(ts => ts >= cutoff);
      if (filtered.length !== u.giftsGiven.length) {
        u.giftsGiven = filtered;
        changed = true;
      }
    } else {
      u.giftsGiven = [];
      changed = true;
    }
  });
  if (changed) saveData(db);
}
setInterval(cleanupOldGifts, 60 * 60 * 1000); // hourly

// Charge tokens; returns { ok, remaining } or { ok:false, reason }
function chargeTokens(userId, amount) {
  const db = loadData();
  const u = ensureUserRecord(userId);
  if (userHasInfinite(userId)) {
    return { ok: true, remaining: Infinity };
  }
  if ((u.tokens || 0) >= amount) {
    u.tokens = (u.tokens || 0) - amount;
    saveData(db);
    return { ok: true, remaining: u.tokens };
  } else {
    return { ok: false, reason: "Insufficient tokens" };
  }
}

// Give tokens
function addTokens(userId, amount) {
  const db = loadData();
  const u = ensureUserRecord(userId);
  if (userHasInfinite(userId)) return; // infinite users don't need tokens
  u.tokens = (u.tokens || 0) + amount;
  saveData(db);
}

// --- Slash commands setup ---
const commands = [
  new SlashCommandBuilder()
    .setName("obf") // renamed from /obfuscate
    .setDescription("Obfuscate Lua code instantly")
    .addStringOption(o => o.setName("code").setDescription("Paste your Lua script").setRequired(true)),

  new SlashCommandBuilder()
    .setName("store")
    .setDescription("Obfuscate and store a script → returns a key")
    .addStringOption(o => o.setName("code").setDescription("Paste your Lua code").setRequired(true)),

  new SlashCommandBuilder()
    .setName("api")
    .setDescription("Obfuscate + store + return loader")
    .addStringOption(o => o.setName("code").setDescription("Paste your Lua script").setRequired(true)),

  new SlashCommandBuilder()
    .setName("retrieve")
    .setDescription("Retrieve a stored script by key")
    .addStringOption(o => o.setName("key").setDescription("The script key").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ping")
    .setDescription("Check API response speed"),

  new SlashCommandBuilder()
    .setName("info")
    .setDescription("Show commands, explain rules & beta details"),

  new SlashCommandBuilder()
    .setName("verify")
    .setDescription("Accept the rules and enable commands"),

  new SlashCommandBuilder()
    .setName("vf")
    .setDescription("Alias for /verify"),

  new SlashCommandBuilder()
    .setName("view")
    .setDescription("View your remaining tokens"),

  new SlashCommandBuilder()
    .setName("gift")
    .setDescription("Gift tokens to a user (owner & whitelisted only)")
    .addUserOption(o => o.setName("user").setDescription("Recipient").setRequired(true))
    .addIntegerOption(o => o.setName("amount").setDescription("Amount of tokens").setRequired(true)),

  new SlashCommandBuilder()
    .setName("wl")
    .setDescription("Whitelist a user (owner only)")
    .addUserOption(o => o.setName("user").setDescription("User to whitelist").setRequired(true)),

  new SlashCommandBuilder()
    .setName("bl")
    .setDescription("Remove user from whitelist (owner only)")
    .addUserOption(o => o.setName("user").setDescription("User to blacklist").setRequired(true)),

  new SlashCommandBuilder()
    .setName("help")
    .setDescription("Shows all NovaHub commands")
];

// register commands
const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_TOKEN);
(async () => {
  try {
    await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: commands });
    console.log("Registered slash commands.");
  } catch (err) {
    console.error("Failed to register commands:", err);
  }
})();

// Info embed
function infoEmbed() {
  const emb = new EmbedBuilder()
    .setTitle("📘 NovaHub — Info & Rules (BETA)")
    .setColor("Blue")
    .setDescription(
`Welcome to NovaHub (BETA). You must run \`/verify\` (or \`/vf\`) to accept the rules before using most commands.

Commands:
• /obf — Obfuscate Lua (costs tokens)
• /store — Obfuscate + store (costs tokens)
• /api — Obfuscate + store + return loader (costs tokens)
• /retrieve — Retrieve a stored script by key
• /ping — API ping
• /view — Show your tokens
• /gift — Owner / whitelisted users can gift tokens
• /wl / /bl — Owner only: whitelist / remove whitelist
• /help — Show help

Notes:
• Each charged command costs ${COMMAND_COST} tokens (configurable via .env).
• New users start with ${INITIAL_TOKENS} tokens.
• Whitelisted users and the owner have infinite tokens and can use premium commands (see: ${PREMIUM_COMMANDS.join(", ") || "none"}).
• /gift: max ${GIFT_LIMIT} tokens per gift, up to ${GIFT_TIMES} gifts per ${GIFT_RESET_HOURS} hours (non-owner).
• First-time users MUST read this with /info and then /verify to use other commands (if REQUIRE_VERIFY is enabled).
• This bot is in BETA — use responsibly.
`
    );
  return emb;
}

// --- Interaction handler ---
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  const name = interaction.commandName;
  const uid = interaction.user.id;

  ensureUserRecord(uid);
  const db = loadData();
  const me = db.users[uid];

  const isFreeCommand = FREE_COMMANDS.includes(`/${name}`);
  if (REQUIRE_VERIFY && !me.verified && !isFreeCommand) {
    await interaction.reply({ content: "🔒 You must run `/info` and then `/verify` (or `/vf`) before using that command.", ephemeral: true });
    return;
  }

  // /info
  if (name === "info") {
    ensureUserRecord(uid);
    await interaction.reply({ embeds: [infoEmbed()], ephemeral: true });
    return;
  }

  // /verify, /vf
  if (name === "verify" || name === "vf") {
    const db2 = loadData();
    const u = ensureUserRecord(uid);
    if (u.verified) {
      await interaction.reply({ content: "✅ You are already verified.", ephemeral: true });
      return;
    }
    u.verified = true;
    saveData(db2);
    await interaction.reply({ content: "✅ Verified — you can now use commands.", ephemeral: true });
    return;
  }

  // /view
  if (name === "view") {
    const u = ensureUserRecord(uid);
    const tokens = userHasInfinite(uid) ? "∞ (whitelisted/owner)" : (u.tokens || 0);
    await interaction.reply({ content: `🪙 You have **${tokens}** tokens.`, ephemeral: true });
    return;
  }

  // /gift
  if (name === "gift") {
    const target = interaction.options.getUser("user");
    const amount = interaction.options.getInteger("amount");
    if (!target || typeof amount !== "number") {
      await interaction.reply({ content: "❌ Invalid options.", ephemeral: true });
      return;
    }
    if (amount <= 0) {
      await interaction.reply({ content: "❌ Amount must be positive.", ephemeral: true });
      return;
    }
    if (amount > GIFT_LIMIT && !isOwner(uid)) {
      await interaction.reply({ content: `❌ Max per-gift is ${GIFT_LIMIT} tokens.`, ephemeral: true });
      return;
    }

    // Only owner or whitelisted can gift
    if (!isOwner(uid) && !isWhitelisted(uid)) {
      await interaction.reply({ content: "❌ Only the bot owner or whitelisted users can gift tokens.", ephemeral: true });
      return;
    }

    const giverRecord = ensureUserRecord(uid);
    if (!isOwner(uid)) {
      const count = giftsInWindow(giverRecord);
      if (count >= GIFT_TIMES) {
        await interaction.reply({ content: `❌ You reached the gifting limit (${GIFT_TIMES}) for the last ${GIFT_RESET_HOURS} hours.`, ephemeral: true });
        return;
      }
    }

    addTokens(target.id, amount);
    if (!isOwner(uid)) recordGift(uid);

    await interaction.reply({ content: `✅ Gifted **${amount}** tokens to ${target.tag}.`, ephemeral: true });
    try {
      await target.send(`🎁 You received **${amount}** tokens from ${interaction.user.tag}.`);
    } catch (_) { /* ignore DM failure */ }
    return;
  }

  // /wl (owner-only)
  if (name === "wl") {
    if (!isOwner(uid)) {
      await interaction.reply({ content: "❌ Only the owner can whitelist users.", ephemeral: true });
      return;
    }
    const target = interaction.options.getUser("user");
    if (!target) { await interaction.reply({ content: "❌ Provide a user.", ephemeral: true }); return; }
    const db2 = loadData();
    const u = ensureUserRecord(target.id);
    u.whitelisted = true;
    saveData(db2);
    await interaction.reply({ content: `✅ ${target.tag} is now whitelisted. They have infinite tokens.`, ephemeral: true });
    return;
  }

  // /bl (owner-only)
  if (name === "bl") {
    if (!isOwner(uid)) {
      await interaction.reply({ content: "❌ Only the owner can blacklist (remove whitelist).", ephemeral: true });
      return;
    }
    const target = interaction.options.getUser("user");
    if (!target) { await interaction.reply({ content: "❌ Provide a user.", ephemeral: true }); return; }
    const db2 = loadData();
    const u = ensureUserRecord(target.id);
    u.whitelisted = false;
    saveData(db2);
    await interaction.reply({ content: `✅ ${target.tag} was removed from the whitelist.`, ephemeral: true });
    return;
  }

  // Charge for commands that cost tokens (unless infinite)
  const commandPath = `/${name}`;
  const costsTokens = COMMANDS_WITH_COST.includes(commandPath);
  if (costsTokens) {
    if (!userHasInfinite(uid)) {
      const res = chargeTokens(uid, COMMAND_COST);
      if (!res.ok) {
        await interaction.reply({ content: `❌ You need ${COMMAND_COST} tokens to run this command. Use /view or ask for a gift.`, ephemeral: true });
        return;
      }
    }
  }

  // /obf (was /obfuscate)
  if (name === "obf") {
    const code = interaction.options.getString("code");
    await interaction.reply({ content: "🔄 Obfuscating...", ephemeral: true });
    try {
      const res = await axios.post(`${API_BASE}/obfuscate`, { code });
      const obf = res.data.obfuscatedCode || res.data.obfuscated || String(res.data);
      await interaction.followUp({
        content: "✅ Obfuscation complete!",
        files: [{ attachment: Buffer.from(obf), name: "obfuscated.lua" }],
        ephemeral: true
      });
    } catch (e) {
      console.error(e);
      await interaction.followUp({ content: "❌ API error.", ephemeral: true });
    }
    return;
  }

  // /store
  if (name === "store") {
    const code = interaction.options.getString("code");
    await interaction.reply({ content: "🔄 Processing...", ephemeral: true });
    try {
      const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { script: code });
      const key = res.data.key;
      await interaction.followUp({
        content: `✅ **Stored Successfully**\n🔑 Key: \`${key}\``,
        ephemeral: true
      });
    } catch (e) {
      console.error(e);
      await interaction.followUp({ content: "❌ Storage failed.", ephemeral: true });
    }
    return;
  }

  // /api
  if (name === "api") {
    const code = interaction.options.getString("code");
    await interaction.reply({ content: "🔄 Generating API Loader...", ephemeral: true });
    try {
      const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { script: code });
      const key = res.data.key;
      const loader = `loadstring(game:HttpGet("${API_BASE}/retrieve/${key}"))()`;
      await interaction.followUp({
        content: `✅ **API Loader Created**\n🔑 Key: \`${key}\``,
        files: [{ attachment: Buffer.from(loader), name: "loader.lua" }],
        ephemeral: true
      });
    } catch (e) {
      console.error(e);
      await interaction.followUp({ content: "❌ API Loader failed.", ephemeral: true });
    }
    return;
  }

  // /retrieve
  if (name === "retrieve") {
    const key = interaction.options.getString("key");
    await interaction.reply({ content: "🔎 Fetching script...", ephemeral: true });
    try {
      const res = await axios.get(`${API_BASE}/retrieve/${key}`, { headers: { "User-Agent": "Roblox" } });
      await interaction.followUp({
        content: "✅ Script retrieved!",
        files: [{ attachment: Buffer.from(res.data), name: "retrieved.lua" }],
        ephemeral: true
      });
    } catch (e) {
      await interaction.followUp({ content: "❌ Key not found.", ephemeral: true });
    }
    return;
  }

  // /ping
  if (name === "ping") {
    const start = Date.now();
    try { await axios.get(`${API_BASE}/`); } catch (_) { /* ignore */ }
    const ms = Date.now() - start;
    await interaction.reply({ content: `🏓 API Pong! **${ms}ms**`, ephemeral: true });
    return;
  }

  // /help
  if (name === "help") {
    const embed = new EmbedBuilder()
      .setTitle("📘 NovaHub Command List")
      .setColor("Blue")
      .setDescription(`
**/info** — Show info & rules (first-run)
**/verify / /vf** — Accept rules
**/obf** — Obfuscate Lua (costs tokens)
**/store** — Obfuscate + Save (costs tokens)
**/api** — Obfuscate + Save + Generate API Loader (costs tokens)
**/retrieve** — Get stored script
**/view** — Show token balance
**/gift** — Owner: /whitelist gift tokens
**/wl / /bl** — Owner: whitelist / remove whitelist
**/ping** — API ping
**/help** — Show this menu
      `);
    await interaction.reply({ embeds: [embed], ephemeral: true });
    return;
  }

  // fallback
  await interaction.reply({ content: "Unhandled command.", ephemeral: true });
});

// start
client.once("ready", () => {
  console.log(`NovaHub bot online → ${client.user?.tag || "unknown"}`);
});
client.login(process.env.DISCORD_TOKEN);
