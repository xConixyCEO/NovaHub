const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

/* ---------------- Payload Config ---------------- */
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

/* ---------------- Database Setup ---------------- */
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to PostgreSQL.');

    client.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `, (err) => {
        done();
        if (err) console.error('Error creating table:', err.stack);
        else console.log('Table "scripts" ready.');
    });
});

/* ---------------- Constants ---------------- */
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";

/* ---------------- Helper Functions ---------------- */
const generateId = () => crypto.randomBytes(16).toString("hex");
const applyFallback = (raw) => `${FALLBACK_WATERMARK}\n${raw}`;

/* -----------------------------------------------------
     FIXED OBFUSCATION HANDLER (WORKING VERSION)
------------------------------------------------------ */
async function runObfuscator(rawLua, preset = "Medium") {
    const timestamp = Date.now();
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);

    let success = false;
    let finalCode = "";

    try {
        fs.writeFileSync(tempFile, rawLua, 'utf8');

        const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;

        await new Promise(resolve => {
            exec(command, (error, stdout, stderr) => {

                // Remove input file early
                try { fs.unlinkSync(tempFile); } catch {}

                // 🔥 Only treat REAL errors as failure — stderr is ignored
                if (error) {
                    console.error("Lua error:", error.message);
                    finalCode = applyFallback(rawLua);
                    return resolve();
                }

                // If no output file generated → fail
                if (!fs.existsSync(outputFile)) {
                    console.error("Obfuscator produced no output file.");
                    finalCode = applyFallback(rawLua);
                    return resolve();
                }

                // Success
                finalCode = fs.readFileSync(outputFile, 'utf8');
                finalCode = WATERMARK + finalCode;

                try { fs.unlinkSync(outputFile); } catch {}

                success = true;
                resolve();
            });
        });

    } catch (err) {
        console.error("Internal execution error:", err);
        finalCode = applyFallback(rawLua);
        success = false;
    }

    return { success, code: finalCode };
}

/* -----------------------------------------------------
                POST /obfuscate  (BOT USES THIS)
------------------------------------------------------ */
app.post("/obfuscate", async (req, res) => {
    const rawLua = req.body.code;

    if (!rawLua)
        return res.status(400).json({ error: "Missing 'code' in request body." });

    const { success, code } = await runObfuscator(rawLua, "Medium");

    if (!success)
        console.warn("⚠ Obfuscation failed — fallback returned.");

    res.status(200).json({ obfuscatedCode: code });
});

/* -----------------------------------------------------
       POST /obfuscate-and-store (Loader system)
------------------------------------------------------ */
app.post("/obfuscate-and-store", async (req, res) => {
    const raw = req.body.script;

    if (!raw)
        return res.status(400).json({ error: "Missing 'script' in request body." });

    const { success, code } = await runObfuscator(raw, "Medium");

    const key = generateId();

    try {
        await pool.query(
            "INSERT INTO scripts(key, script) VALUES($1, $2)",
            [key, code]
        );

        res.status(201).json({
            message: success ? "Obfuscation + storage complete." :
                "Stored, but obfuscation failed.",
            key
        });

    } catch (err) {
        console.error("DB error:", err);
        res.status(500).json({ error: "Database storage failure." });
    }
});

/* -----------------------------------------------------
                GET /retrieve/:key
------------------------------------------------------ */
app.get("/retrieve/:key", async (req, res) => {
    const key = req.params.key;

    if (!req.headers["user-agent"]?.includes("Roblox")) {
        res.setHeader("Content-Type", "text/plain");
        return res.status(403).send("-- Access Denied.");
    }

    try {
        const result = await pool.query(
            "SELECT script FROM scripts WHERE key = $1", [key]
        );

        if (result.rows.length === 0)
            return res.status(404).send("-- Script not found.");

        res.setHeader("Content-Type", "text/plain");
        res.send(result.rows[0].script);

    } catch (err) {
        console.error("DB fetch error:", err);
        res.status(500).send("-- Internal Server Error.");
    }
});

/* -----------------------------------------------------
                      ROOT
------------------------------------------------------ */
app.get("/", (req, res) => {
    res.send("NovaHub Backend is running.");
});

/* -----------------------------------------------------
                    START SERVER
------------------------------------------------------ */
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
