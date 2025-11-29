const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, REST, Routes, AttachmentBuilder } = require('discord.js');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Ensure Discord token is available from the environment variables set on Render
if (!process.env.DISCORD_TOKEN) {
    console.error("FATAL ERROR: DISCORD_TOKEN is not set in environment variables.");
    process.exit(1);
}

// --- CONFIGURATION ---
const TOKEN = process.env.DISCORD_TOKEN;
// Your specific Client ID:
const CLIENT_ID = '1444160895872663615'; 
const TEMP_DIR = path.join(__dirname, 'temp_files');

// Create temp directory if it doesn't exist
if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR);
}

// --- CLIENT SETUP ---
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
    ],
    partials: [Partials.Channel],
});

client.commands = new Collection();
// Using clientReady to fix the deprecation warning and confirm login
client.once('clientReady', () => { 
    console.log(`[BOT] Logged in as ${client.user.tag}!`);
    registerSlashCommands();
});

// --- COMMAND HANDLER ---

// Handle interaction created (slash commands)
client.on('interactionCreate', async interaction => {
    if (!interaction.isCommand()) return;

    // --- /obf COMMAND ---
    if (interaction.commandName === 'obf') {
        // Initial reply is private (ephemeral)
        await interaction.reply({ content: 'Processing file for obfuscation... This message is private.', ephemeral: true });

        const attachment = interaction.options.getAttachment('file'); 
        const fileName = attachment?.name.toLowerCase();

        // 1. UPDATED VALIDATION: Accept both .lua and .txt
        if (
            !attachment || 
            (!fileName.endsWith('.lua') && !fileName.endsWith('.txt'))
        ) {
            return interaction.editReply({ 
                content: '❌ Error: Please upload a valid script file ending with either `.lua` or `.txt`.',
                ephemeral: true 
            });
        }

        const inputFilePath = path.join(TEMP_DIR, `input_${interaction.id}.lua`);
        const outputFilePath = path.join(TEMP_DIR, `output_${interaction.id}.lua`);

        try {
            // 2. Download the file content
            const response = await fetch(attachment.url);
            if (!response.ok) throw new Error(`Failed to download file: ${response.statusText}`);
            
            const fileBuffer = await response.buffer();
            fs.writeFileSync(inputFilePath, fileBuffer);

            // 3. Execute the Lua Obfuscator 
            const obfuscatorProcess = spawn('lua', [
                'obfuscator/obfuscator.lua', // Path to your Lua obfuscator script
                inputFilePath, 
                outputFilePath
            ]);

            let stderr = '';
            obfuscatorProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            await new Promise((resolve, reject) => {
                obfuscatorProcess.on('close', (code) => {
                    if (code === 0) {
                        resolve();
                    } else {
                        // Obfuscator failed (likely a syntax error in the uploaded code)
                        reject(new Error(stderr || 'Obfuscation process failed with a non-zero exit code.'));
                    }
                });
                obfuscatorProcess.on('error', (err) => {
                    reject(err);
                });
            });

            // 4. Check for successful output file generation
            if (!fs.existsSync(outputFilePath)) {
                 throw new Error('Obfuscation failed to produce an output file. Check the obfuscator script/binary path.');
            }

            // 5. Determine the output file name, ensuring it always ends in .lua
            let outputFileName = attachment.name;
            if (outputFileName.toLowerCase().endsWith('.txt')) {
                // If the original was .txt, change the extension to .lua
                outputFileName = outputFileName.slice(0, -4) + '.lua';
            }
            // If it was already .lua, the name remains the same.


            // 6. Send success reply with the obfuscated file (STILL PRIVATE)
            const attachmentToSend = new AttachmentBuilder(outputFilePath, { name: `obfuscated_${outputFileName}` });
            
            await interaction.editReply({
                content: '✅ Obfuscation successful! Your private obfuscated file is attached below.',
                files: [attachmentToSend],
                ephemeral: true // Ensures the final message and file remain private
            });

        } catch (error) {
            console.error(`Obfuscation Error for ${interaction.id}:`, error.message);
            
            let errorMessage;
            
            // Check if the error indicates a syntax issue
            const syntaxErrorMatch = error.message.toLowerCase().includes('syntax') || error.message.toLowerCase().includes('failed');
            if (syntaxErrorMatch) {
                 errorMessage = '❌ Error: Invalid Lua syntax. Please check your code.';
            } else {
                 errorMessage = '❌ Error: An unknown error occurred during obfuscation. Please try again.';
            }

            // Send failure message (STILL PRIVATE)
            await interaction.editReply({ 
                content: errorMessage,
                ephemeral: true 
            });

        } finally {
            // 7. Cleanup temporary files
            try {
                if (fs.existsSync(inputFilePath)) fs.unlinkSync(inputFilePath);
                if (fs.existsSync(outputFilePath)) fs.unlinkSync(outputFilePath);
            } catch (cleanupError) {
                console.error("Error cleaning up temp files:", cleanupError);
            }
        }
    }
});

// --- COMMAND REGISTRATION ---

// Define the slash command structure
const commands = [
    {
        name: 'obf',
        description: 'Uploads a Lua script for private obfuscation (accepts .lua and .txt).',
        options: [
            {
                name: 'file',
                description: 'The .lua or .txt file containing the script.',
                type: 11, // ApplicationCommandOptionType.Attachment
                required: true,
            },
        ],
    },
];

// Function to register the slash commands with Discord
async function registerSlashCommands() {
    try {
        const rest = new REST({ version: '10' }).setToken(TOKEN);
        
        // Registering commands globally using your specific CLIENT_ID
        await rest.put(
            Routes.applicationCommands(CLIENT_ID),
            { body: commands },
        );
        console.log('[BOT] Registered /obf slash command.');

    } catch (error) {
        console.error('[BOT] Failed to register commands:', error);
    }
}

client.login(TOKEN);
