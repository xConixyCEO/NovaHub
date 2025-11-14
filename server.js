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

// --- CRITICAL: INCREASED PAYLOAD LIMIT TO 100MB ---
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
// --------------------------------------------------

// --- Database Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Define constants
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] "; 
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";
const OBFUSCATOR_PRESET = 'Medium';

// Test connection and initialize table
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Successfully connected to PostgreSQL.');
    
    // --- UPDATED DATABASE SCHEMA ---
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            edit_password_hash VARCHAR(64) NOT NULL, -- New: Hashed password for editing
            raw_script TEXT NOT NULL,               -- New: Stores the original, human-readable code
            obfuscated_script TEXT NOT NULL,        -- Updated: Stores the secure code for retrieval
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    client.query(createTableQuery, (err, res) => {
        done();
        if (err) {
            console.error('Error creating table:', err.stack);
        } else {
            console.log('Database table "scripts" initialized with secure edit schema.');
        }
    });
});

// Middleware for static files and CORS
app.use(express.static('public')); 
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    return crypto.randomBytes(16).toString('hex');
};

const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

const applyFallback = (rawCode) => {
    return `${FALLBACK_WATERMARK}\n${rawCode}`;
};

// Reusable function to execute Prometheus Obfuscator
const runObfuscationStep = async (rawLuaCode) => {
    const timestamp = Date.now();
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    fs.writeFileSync(tempFile, rawLuaCode, 'utf8');

    const command = `lua src/cli.lua --preset ${OBFUSCATOR_PRESET} --out ${outputFile} ${tempFile}`;
    
    return new Promise((resolve) => {
        exec(command, (error, stdout, stderr) => {
            fs.unlinkSync(tempFile); 
            
            if (error || stderr) {
                console.error(`Prometheus Execution Failed: ${error ? error.message : stderr}`);
                if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                
                // --- FALLBACK: Return raw code with warning header ---
                resolve({ 
                    code: applyFallback(rawLuaCode), 
                    success: false 
                });
                return;
            }
            
            // Success path
            let obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
            obfuscatedCode = WATERMARK + obfuscatedCode;
            fs.unlinkSync(outputFile);
            
            resolve({ 
                code: obfuscatedCode, 
                success: true 
            });
        });
    });
};


// =======================================================
// === 1. OBFUSCATE ROUTE (For Raw Output Preview) ======
// =======================================================
app.post('/obfuscate', async (req, res) => {
    const rawLuaCode = req.body.code;
    
    try {
        const result = await runObfuscationStep(rawLuaCode);
        
        res.status(200).json({ 
            obfuscatedCode: result.code,
            success: result.success
        });
        
    } catch (error) {
        console.error('Obfuscate route execution error:', error);
        return res.status(500).json({ error: 'Internal execution error.' });
    }
});


// ==========================================================
// === 2. CREATE SECURE SCRIPT (Replaces /obfuscate-and-store)
// ==========================================================
// Creates the initial entry, performing the first obfuscation.
app.post('/create-secure-script', async (req, res) => {
    const rawLuaCode = req.body.script; 
    const password = req.body.password;

    if (!rawLuaCode || rawLuaCode.trim() === '' || !password || password.length < 4) {
        return res.status(400).json({ error: 'Script and a strong password (min 4 chars) are required.' });
    }
    
    // Step 1: Obfuscate the initial script
    const obfuscationResult = await runObfuscationStep(rawLuaCode);
    
    // Step 2: Store Raw, Obfuscated, and Password Hash
    const scriptKey = generateUniqueId();
    const passwordHash = hashPassword(password);
    
    try {
        await pool.query(
            'INSERT INTO scripts(key, edit_password_hash, raw_script, obfuscated_script) VALUES($1, $2, $3, $4)',
            [scriptKey, passwordHash, rawLuaCode, obfuscationResult.code]
        );

        // Success: Return the Loader Key and the original password (as the Edit Key)
        res.status(201).json({ 
            message: obfuscationResult.success ? 'Secure script created.' : 'Script created, but obfuscation failed (using fallback).',
            key: scriptKey,
            editPassword: password, // Send the original password back so the user can save it
            loaderUrl: `/retrieve/${scriptKey}`
        });

    } catch (error) {
        console.error('Database error during script creation:', error);
        res.status(500).json({ error: 'Internal server error during script storage.' });
    }
});


// ====================================================
// === 3. GET RAW FOR EDIT (Password Protected) =======
// ====================================================
// Retrieves the raw code for the user to edit.
app.post('/get-raw-for-edit', async (req, res) => {
    const scriptKey = req.body.key;
    const password = req.body.password;
    const passwordHash = hashPassword(password);

    try {
        const result = await pool.query(
            'SELECT raw_script, edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        const storedHash = result.rows[0].edit_password_hash;

        // Check password
        if (storedHash !== passwordHash) {
            return res.status(403).json({ error: 'Invalid password or key combination.' });
        }

        // Success: Return the raw code
        res.status(200).json({ 
            rawScript: result.rows[0].raw_script 
        });

    } catch (error) {
        console.error('Database error during raw script retrieval:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});


// ====================================================
// === 4. SAVE AND OBFUSCATE (Password Protected) =====
// ====================================================
// Re-obfuscates the edited script and updates the database.
app.post('/save-and-obfuscate', async (req, res) => {
    const scriptKey = req.body.key;
    const password = req.body.password;
    const newRawScript = req.body.newScript;
    const passwordHash = hashPassword(password);

    if (!newRawScript || newRawScript.trim() === '') {
        return res.status(400).json({ error: 'New script cannot be empty.' });
    }

    try {
        // Step 1: Verify Password Hash
        const checkResult = await pool.query(
            'SELECT edit_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }
        
        if (checkResult.rows[0].edit_password_hash !== passwordHash) {
            return res.status(403).json({ error: 'Invalid password or key combination.' });
        }

        // Step 2: Obfuscate the new script
        const obfuscationResult = await runObfuscationStep(newRawScript);
        
        // Step 3: Update the database
        await pool.query(
            'UPDATE scripts SET raw_script = $1, obfuscated_script = $2 WHERE key = $3',
            [newRawScript, obfuscationResult.code, scriptKey]
        );

        // Success
        res.status(200).json({ 
            message: obfuscationResult.success ? 'Script saved and re-obfuscated successfully.' : 'Script saved, but re-obfuscation failed (using fallback).',
            success: obfuscationResult.success
        });

    } catch (error) {
        console.error('Database error during save and obfuscate:', error);
        res.status(500).json({ error: 'Internal server error during script update.' });
    }
});


// ====================================================
// === 5. STORAGE API ENDPOINTS (PostgreSQL Retrieval)===
// ====================================================

// GET /retrieve/:key (Retrieves the SECURE, obfuscated Lua script - Roblox only)
app.get('/retrieve/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const userAgent = req.headers['user-agent'];

    // 1. Validate User-Agent (ROBLOX SECURITY CHECK)
    if (!userAgent || !userAgent.includes('Roblox')) {
        res.setHeader('Content-Type', 'text/plain');
        return res.status(403).send('-- Access Denied .');
    }

    try {
        // Retrieve ONLY the obfuscated script
        const result = await pool.query(
            'SELECT obfuscated_script FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            res.setHeader('Content-Type', 'text/plain');
            return res.status(404).send('-- Error: Script not found or has expired.');
        }

        // Deliver the highly secured script
        const script = result.rows[0].obfuscated_script;
        res.setHeader('Content-Type', 'text/plain');
        res.status(200).send(script);
        
    } catch (error) {
        console.error('Database error during retrieval:', error);
        res.setHeader('Content-Type', 'text/plain');
        res.status(500).send('-- Error: Internal Server Failure.');
    }
});


// Basic Health Check
app.get('/', (req, res) => {
    res.send('NovaHub Unified Backend (Secure Edit Locker) is running and connected to PostgreSQL.');
});


// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
