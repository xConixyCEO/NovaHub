require("dotenv").config();
const {
  Client,
  Intents, // NOTE: Intents.FLAGS is deprecated. This is imported for backwards compatibility, but we use string literals below.
  MessageEmbed,
  MessageActionRow,
  MessageSelectMenu,
  MessageAttachment,
} = require("discord.js");
const axios = require("axios");
const fs = require("fs");
const child_process = require("child_process");
const path = require("path");

const log = (...e) => console.log("[PROMETHEUS]", ...e);
const error = (...e) => console.error("[PROMETHEUS]", ...e);

const tempDir = path.join(__dirname, "Temp_files");
if (!fs.existsSync(tempDir)) {
  error("❌ Temp_files directory does not exist! Please create it manually.");
  process.exit(1);
}

const STORAGE_CHANNEL_ID = process.env.STORAGE_CHANNEL_ID || process.env.CDN_STORAGE_CHANNEL_ID;

/**
 * Fetches and verifies the storage channel.
 * @param {Client} client - The Discord client.
 * @returns {Promise<import('discord.js').TextChannel>} The storage channel.
 */
async function ensureStorageChannel(client) {
  if (!STORAGE_CHANNEL_ID) throw new Error("STORAGE_CHANNEL_ID is not set in .env");
  let ch = client.channels.cache.get(STORAGE_CHANNEL_ID);
  if (!ch) ch = await client.channels.fetch(STORAGE_CHANNEL_ID).catch(() => null);
  // Using 'send' in ch is a quick way to check if it's a TextChannel or a DMChannel that the bot can send to
  if (!ch || !("send" in ch)) throw new Error("STORAGE_CHANNEL_ID does not point to a text channel the bot can send to.");
  return ch;
}

/**
 * Executes the obfuscation process using luajit.
 * @param {string} inputFile - Path to the input Lua file.
 * @param {string} preset - Obfuscation preset (Weak, Medium, Strong).
 * @returns {Promise<string>} Path to the output obfuscated Lua file.
 */
function obfuscate(inputFile, preset) {
  return new Promise((resolve, reject) => {
    const outputFile = path.join(tempDir, `obfuscated_${Date.now()}.lua`);
    
    // Note: If you face path errors, you might need to use absolute paths for the executables.
    const proc = child_process.spawn("./bin/luajit.exe", [
      "./lua/cli.lua",
      "--preset",
      preset,
      inputFile,
      "--out",
      outputFile,
    ]);
    
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    
    proc.on("close", (code) => {
      if (code !== 0) return reject(stderr || `luajit exited with code ${code}`);
      resolve(outputFile);
    });
    
    proc.on("error", (err) => {
      reject(`Failed to start luajit process: ${err.message}. Ensure ./bin/luajit.exe is executable.`);
    });
  });
}

// Collect all tokens from env
const tokens = Object.keys(process.env)
  .filter((key) => key.startsWith("DISCORD_TOKEN"))
  .map((key) => process.env[key]);

if (tokens.length === 0) {
  error("❌ No DISCORD_TOKEN found in .env!");
  process.exit(1);
}

/**
 * Creates and initializes a Discord bot client.
 * @param {string} token - The Discord bot token.
 * @param {number} botNumber - The number identifier for the bot instance.
 */
function createBot(token, botNumber) {
  const client = new Client({
    // Use string literals for Intents (recommended and non-deprecated)
    intents: ["GUILDS", "GUILD_MESSAGES", "DIRECT_MESSAGES"],
    partials: ["CHANNEL"],
  });

  client.once("ready", () => {
    log(`✅ Bot #${botNumber} logged in as ${client.user?.tag || "Unknown"}`);

    // Set presence: DND + Playing Obfuscating Nyx Files
    client.user.setPresence({
      status: "dnd",
      activities: [
        {
          name: "Obfuscating Nyx Files",
          type: "PLAYING",
        },
      ],
    });
  });

  client.login(token);

  client.on("messageCreate", async (msg) => {
    if (msg.author.bot) return;

    // .help
    if (msg.content.toLowerCase() === ".help") {
      const helpText = `📖 Obfuscator Bot Help
Here’s how to use the bot to obfuscate your scripts:
🔹 **Command**: \`.obf\` [attach your .lua/.txt file or paste inside a codeblock]
🔹 **Supported Files**: \`.lua\` and \`.txt\` only, or codeblocks
🔹 **Obfuscation Levels**: Weak 🪶, Medium 🛡️, Strong 💪 (chosen via dropdown)
🔒 **Privacy**: Use this bot in Direct Messages (DMs) for privacy.
🔹 **Example**: \`.obf\` → Attach file OR paste in codeblock → Choose obfuscation level → Get protected file ✅
Made with ❤️ by Slayerson`;

      const helpEmbed = new MessageEmbed()
        .setColor("BLUE")
        .setTitle("📖 Obfuscator Bot Help")
        .setDescription(helpText)
        .setFooter({ text: "Made by Slayerson • Credits to Vyxonq • Powered by Nyx Obfuscator" });

      msg.channel.send({ embeds: [helpEmbed] }).catch((err) => error("Failed to send help message:", err));
      return;
    }

    // .obf
    if (msg.content.toLowerCase().startsWith(".obf")) {
      let inputFile;
      let originalFileName;

      // --- Helper function for cleanup ---
      const cleanup = () => {
        try { fs.unlinkSync(inputFile); } catch (e) { /* ignore */ }
        try { fs.unlinkSync(path.join(tempDir, `obfuscated_${Date.now()}.lua`)); } catch (e) { /* ignore */ }
        try { fs.unlinkSync(path.join(tempDir, `obfuscated_final_${Date.now()}.lua`)); } catch (e) { /* ignore */ }
      };

      try {
        const attachment = msg.attachments.first();
        if (attachment) {
          const ext = path.extname(attachment.name).toLowerCase();
          if (ext !== ".lua" && ext !== ".txt") {
            const errorEmbed = new MessageEmbed()
              .setColor("RED")
              .setTitle("❌ Obfuscation Failed")
              .setDescription("Only **`.lua`** and **`.txt`** files are supported!\nWe apologize for the inconvenience. 🙏");
            msg.reply({ embeds: [errorEmbed] });
            return;
          }

          inputFile = path.join(tempDir, `input_${Date.now()}${ext}`);
          const response = await axios({ method: "GET", url: attachment.url, responseType: "stream" });
          response.data.pipe(fs.createWriteStream(inputFile));
          await new Promise((resolve, reject) => {
            response.data.on("end", resolve);
            response.data.on("error", reject);
          });
          originalFileName = attachment.name;
        } else {
          // FIX: The regular expression is now correct and complete.
          // It captures the content inside a standard Discord code block.
          const codeBlockMatch = msg.content.match(/```(?:lua)?\n([\s\S]*?)```/i); 
          
          if (!codeBlockMatch) {
            const errorEmbed = new MessageEmbed()
              .setColor("RED")
              .setTitle("❌ Obfuscation Failed")
              .setDescription("You must attach a **`.lua`** or **`.txt`** file OR paste your code inside a valid **code block** (` ```lua code ``` `) to use `.obf`!\nWe apologize for the inconvenience. 🙏");
            msg.reply({ embeds: [errorEmbed] });
            return;
          }

          const code = codeBlockMatch[1];
          inputFile = path.join(tempDir, `input_${Date.now()}.lua`);
          fs.writeFileSync(inputFile, code, "utf-8");
          originalFileName = `codeblock_${Date.now()}.lua`;
        }

        // Ask for level
        const chooseEmbed = new MessageEmbed()
          .setColor("PURPLE")
          .setTitle("🔐 Choose Obfuscation Level")
          .setDescription("Please select the obfuscation level:\nSelect wisely for the best protection! 🧐");

        const row = new MessageActionRow().addComponents(
          new MessageSelectMenu()
            .setCustomId(`obfuscation_level_${Date.now()}`)
            .setPlaceholder("🛡️ Select Obfuscation Level")
            .addOptions([
              { label: "Weak", description: "Weak Obfuscation Level 🪶", value: "Weak" },
              { label: "Medium", description: "Medium Obfuscation Level 🛡️", value: "Medium" },
              { label: "Strong", description: "Strong Obfuscation Level 💪", value: "Strong" },
            ])
        );

        const promptMsg = await msg.reply({ embeds: [chooseEmbed], components: [row] });

        const filter = (i) => i.user.id === msg.author.id;
        const collector = promptMsg.createMessageComponentCollector({
          filter,
          componentType: "SELECT_MENU",
          time: 60000,
        });

        collector.on("collect", async (i) => {
          await i.deferUpdate();
          const selected = i.values[0];
          collector.stop();

          let outputFile;
          try {
            // Note: If 'Strong' is not a valid preset for your luajit,
            // this maps 'Strong' selection to 'Medium'. Adjust as needed.
            const presetToUse = selected === "Strong" ? "Medium" : selected; 
            outputFile = await obfuscate(inputFile, presetToUse);
          } catch (err) {
            error("Obfuscation execution failed:", err);
            await msg.reply("❌ Failed to obfuscate the script. An internal error occurred during processing.");
            cleanup();
            return;
          }

          const obfuscatedCode = fs.readFileSync(outputFile, "utf-8");
          const watermark = `--[[

Nyx Obfuscator

This Script Was Obfuscated Using Nyx Obfuscator Made for Omega Hub!

]]\n\n`;
          const finalCode = watermark + obfuscatedCode;

          const finalFile = path.join(tempDir, `obfuscated_final_${Date.now()}.lua`);
          fs.writeFileSync(finalFile, finalCode, "utf-8");

          // Upload to storage
          let fileUrl;
          try {
            const storageChannel = await ensureStorageChannel(client);
            const storageMsg = await storageChannel.send({
              files: [new MessageAttachment(finalFile, originalFileName)],
            });
            fileUrl = storageMsg.attachments.first()?.url;
          } catch (e) {
            error("Storage upload failed:", e);
            await msg.reply("❌ Storage channel misconfigured. Set `STORAGE_CHANNEL_ID` in your `.env` and ensure the bot can send there.");
            cleanup();
            return;
          }
          
          const MAX_PREVIEW_LENGTH = 500;
          const preview = finalCode.length > MAX_PREVIEW_LENGTH ? finalCode.slice(0, MAX_PREVIEW_LENGTH) + "..." : finalCode;

          const successEmbed = new MessageEmbed()
            .setColor("DARK_BLUE")
            .setTitle("Obfuscation Results")
            .setDescription(`**File:** ${originalFileName}\n[ **Click here to download** ](${fileUrl})\n\n\`\`\`lua\n${preview}\n\`\`\``)
            .setFooter({ text: "Made by Slayerson • Credits to Vyxonq • Powered by Nyx Obfuscator" });

          await msg.reply({ embeds: [successEmbed] });

          try { await promptMsg.delete(); } catch {}
          cleanup();
        });

        collector.on("end", collected => { 
          if (collected.size === 0) {
            const cancelEmbed = new MessageEmbed()
              .setColor("RED")
              .setTitle("❌ Obfuscation Canceled")
              .setDescription("No selection made in time. Please try again.");
            msg.reply({ embeds: [cancelEmbed] });
            cleanup();
          }
        });
      } catch (e) {
        error("An unexpected error occurred during message processing:", e);
        cleanup();
        msg.reply("❌ An unexpected error occurred. Please check the console logs.").catch(() => {});
      }
    }
  });
}

// Launch all bots
tokens.forEach((token, index) => createBot(token, index + 1));
