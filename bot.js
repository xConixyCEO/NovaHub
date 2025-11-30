// FULL NOVA BOT WITH /obf LOGIC ADDED
// All commands working, token system, whitelist, verification, API service, obfuscation, and more.

require('dotenv').config();
const { Client, GatewayIntentBits, SlashCommandBuilder, Routes, EmbedBuilder } = require('discord.js');
const axios = require('axios');
const Database = require('better-sqlite3');
const { REST } = require('@discordjs/rest');

// ==========================
// CONFIG
// ==========================
const OWNER_ID = process.env.OWNER_ID;
const API_BASE = "https://novahub-zd14.onrender.com";

// ==========================
// DATABASE
// ==========================
const db = new Database('nova.db');

db.prepare(`CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  verified INTEGER DEFAULT 0,
  whitelisted INTEGER DEFAULT 0,
  tokens INTEGER DEFAULT 15,
  last_refresh INTEGER DEFAULT 0
)`).run();

function getUser(userId) {
  let user = db.prepare('SELECT * FROM users WHERE user_id = ?').get(userId);
  if (!user) {
    db.prepare('INSERT INTO users (user_id, verified, whitelisted, tokens, last_refresh) VALUES (?, 0, 0, 15, ?)')
      .run(userId, Date.now());
    user = db.prepare('SELECT * FROM users WHERE user_id = ?').get(userId);
  }
  return user;
}

function refreshTokens(userId) {
  const user = getUser(userId);
  const now = Date.now();
  if (now - user.last_refresh >= 24 * 60 * 60 * 1000) {
    db.prepare('UPDATE users SET tokens = 15, last_refresh = ? WHERE user_id = ?').run(now, userId);
  }
  return getUser(userId);
}

// ==========================
// DISCORD CLIENT
// ==========================
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// ==========================
// COMMANDS
// ==========================
const commands = [
  new SlashCommandBuilder().setName('info').setDescription('Shows bot info.'),
  new SlashCommandBuilder().setName('verify').setDescription('Accept rules.'),
  new SlashCommandBuilder().setName('view').setDescription('View tokens.'),

  new SlashCommandBuilder()
    .setName('gift')
    .setDescription('Owner: Gift tokens to a user.')
    .addUserOption(o => o.setName('user').setDescription('User').setRequired(true))
    .addIntegerOption(o => o.setName('amount').setDescription('Amount').setRequired(true)),

  new SlashCommandBuilder()
    .setName('wl')
    .setDescription('Whitelist a user.')
    .addUserOption(o => o.setName('user').setDescription('User').setRequired(true)),

  new SlashCommandBuilder()
    .setName('bn')
    .setDescription('Remove whitelist from a user.')
    .addUserOption(o => o.setName('user').setDescription('User').setRequired(true)),

  new SlashCommandBuilder()
    .setName('apiservice')
    .setDescription('Obfuscate + Store (WL only, costs 5 tokens).')
    .addStringOption(o => o.setName('code').setDescription('Lua code').setRequired(true)),

  new SlashCommandBuilder()
    .setName('obf')
    .setDescription('Obfuscate code only (costs 5 tokens).')
    .addStringOption(o => o.setName('code').setDescription('Lua code').setRequired(true))
]
.map(c => c.toJSON());

// ==========================
// REGISTER COMMANDS
// ==========================
const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
(async () => {
  await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: commands });
})();

// ==========================
// BOT LOGIC
// ==========================
client.on('interactionCreate', async interaction => {
  if (!interaction.isChatInputCommand()) return;

  const userId = interaction.user.id;
  let user = refreshTokens(userId);

  // INFO
  if (interaction.commandName === 'info') {
    const embed = new EmbedBuilder()
      .setTitle('Nova Hub — Info')
      .setDescription('Bot is in **beta**.\nCommands:\n• /verify\n• /view\n• /apiservice (WL)\n• /obf\n• /gift (owner)\n• /wl\n• /bn')
      .setColor('Blue');
    return interaction.reply({ embeds: [embed], ephemeral: true });
  }

  // VERIFY
  if (interaction.commandName === 'verify') {
    db.prepare('UPDATE users SET verified = 1 WHERE user_id = ?').run(userId);

    // webhook
    try {
      await axios.post("https://discord.com/api/webhooks/1444682978968993885/g_FTpNMFkr7HYPlx1AbEqEA-sZaEvI5GwPYAVRIb4wFzyWq9FLizQGQFehwEjHqSu-8U", {
        content: `🟢 **User Verified**\\nUser: <@${userId}>\\nID: ${userId}`
      });
    } catch {}

    return interaction.reply({ content: 'You are now verified! 🎉', ephemeral: true });
  }

  // VIEW TOKENS
  if (interaction.commandName === 'view') {
    user = refreshTokens(userId);
    return interaction.reply({ content: `You have **${user.tokens} tokens**.`, ephemeral: true });
  }

  // GIFT TOKENS
  if (interaction.commandName === 'gift') {
    if (userId !== OWNER_ID) return interaction.reply({ content: 'Only owner can gift.', ephemeral: true });

    const target = interaction.options.getUser('user');
    const amount = interaction.options.getInteger('amount');

    db.prepare('UPDATE users SET tokens = tokens + ? WHERE user_id = ?').run(amount, target.id);

    return interaction.reply({ content: `Gifted **${amount} tokens** to ${target.username}.` });
  }

  // WL ADD
  if (interaction.commandName === 'wl') {
    if (userId !== OWNER_ID) return interaction.reply({ content: 'Only owner.', ephemeral: true });

    const target = interaction.options.getUser('user');
    db.prepare('UPDATE users SET whitelisted = 1 WHERE user_id = ?').run(target.id);

    return interaction.reply({ content: `${target.username} whitelisted.` });
  }

  // WL REMOVE
  if (interaction.commandName === 'bn') {
    if (userId !== OWNER_ID) return interaction.reply({ content: 'Only owner.', ephemeral: true });

    const target = interaction.options.getUser('user');
    db.prepare('UPDATE users SET whitelisted = 0 WHERE user_id = ?').run(target.id);

    return interaction.reply({ content: `${target.username} unwhitelisted.` });
  }

  // ==========================
  // API SERVICE — WL + 5 tokens
  // ==========================
  if (interaction.commandName === 'apiservice') {
    if (!user.verified) return interaction.reply({ content: 'Use **/verify** first.', ephemeral: true });
    if (!user.whitelisted) return interaction.reply({ content: 'You must be **whitelisted**.', ephemeral: true });
    if (user.tokens < 5) return interaction.reply({ content: 'Not enough tokens.', ephemeral: true });

    const code = interaction.options.getString('code');

    try {
      const res = await axios.post(`${API_BASE}/obfuscate-and-store`, { code });
      const key = res.data.key;

      db.prepare('UPDATE users SET tokens = tokens - 5 WHERE user_id = ?').run(userId);

      const embed = new EmbedBuilder()
        .setTitle('Nova Hub Loader')
        .setDescription(
          `URL:**https://novahub-zd14.onrender.com/retrieve/${key}**\n\n` +
          "```lua\\nreturn loadstring(game:HttpGet(\"https://novahub-zd14.onrender.com/retrieve/" + key + "\"))()\\n```"
        )
        .setColor('Green');

      return interaction.reply({ embeds: [embed] });
    } catch (err) {
      return interaction.reply({ content: 'API error.', ephemeral: true });
    }
  }

  // ==========================
  // OBF — Public, 5 tokens
  // ==========================
  if (interaction.commandName === 'obf') {
    if (!user.verified) return interaction.reply({ content: 'Use **/verify** first.', ephemeral: true });
    if (user.tokens < 5) return interaction.reply({ content: 'Not enough tokens.', ephemeral: true });

    const code = interaction.options.getString('code');

    try {
      const res = await axios.post(`${API_BASE}/obfuscate`, { code });
      const obf = res.data.obfuscatedCode;

      db.prepare('UPDATE users SET tokens = tokens - 5 WHERE user_id = ?').run(userId);

      const embed = new EmbedBuilder()
        .setTitle('Obfuscation Complete')
        .setDescription('```lua\n' + obf.slice(0, 1900) + '\n```')
        .setColor('Purple');

      return interaction.reply({ embeds: [embed] });
    } catch (err) {
      return interaction.reply({ content: 'Obfuscation error.', ephemeral: true });
    }
  }
});

client.login(process.env.DISCORD_TOKEN);
