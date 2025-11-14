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

// --- Database Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Add SSL support for cloud databases like Render/Heroku
    ssl: { rejectUnauthorized: false } 
});

// Define constants
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] "; 
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";
const OBFUSCATOR_PRESET = 'Medium';
const SCRIPT_LUA_PATH = path.join(__dirname, 'src', 'cli.lua'); 

// Temporary token storage for secure access (in-memory)
const tempAccessTokens = {}; 

// Test connection and initialize table
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Successfully connected to PostgreSQL.');
    
    // --- UPDATED DATABASE SCHEMA to include access_password_hash ---
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            edit_password_hash VARCHAR(64) NOT NULL,
            access_password_hash VARCHAR(64), 
            raw_script TEXT NOT NULL,
            obfuscated_script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    client.query(createTableQuery, (err, res) => {
        done();
        if (err) {
            console.error('Error creating table:', err.stack);
        } else {
            console.log('Database table "scripts" initialized.');
        }
    });
});

// Middleware for static files and CORS
app.use(express.static('public')); 
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    // Generate a 16-byte (32-character hex) key
    return crypto.randomBytes(16).toString('hex');
};

const hashPassword = (password) => {
    // Standard SHA-256 hash for password storage
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
    
    // 1. Write raw code to temporary input file
    try {
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');
    } catch (e) {
        console.error('File Write Error:', e);
        return { code: applyFallback(rawLuaCode), success: false };
    }

    // 2. Execute obfuscator
    const command = `lua ${SCRIPT_LUA_PATH} --preset ${OBFUSCATOR_PRESET} --out ${outputFile} ${tempFile}`;
    
    return new Promise((resolve) => {
        exec(command, (error, stdout, stderr) => {
            // 3. Cleanup input file immediately
            try { fs.unlinkSync(tempFile); } catch (e) { /* silent fail */ } 
            
            if (error || stderr) {
                console.error(`Prometheus Execution Failed: ${error ? error.message : stderr}`);
                // 4. Cleanup output file if it exists, then fallback
                if (fs.existsSync(outputFile)) { try { fs.unlinkSync(outputFile); } catch (e) { /* silent fail */ } }
                
                resolve({ 
                    code: applyFallback(rawLuaCode), 
                    success: false 
                });
                return;
            }
            
            // 5. Success: Read output, apply watermark, cleanup output file
            let obfuscatedCode = '';
            try {
                obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                obfuscatedCode = WATERMARK + obfuscatedCode;
                fs.unlinkSync(outputFile);
            } catch (e) {
                 console.error('Obfuscator output file read/cleanup error:', e);
                 // Fallback if file ops fail after successful execution
                 resolve({ code: applyFallback(rawLuaCode), success: false });
                 return;
            }
            
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
        console.error('Obfuscate route execution error:', error.stack);
        return res.status(500).json({ error: 'Internal execution error.' });
    }
});


// ==========================================================
// === 2. CREATE SECURE SCRIPT 
// ==========================================================
app.post('/create-secure-script', async (req, res) => {
    const rawLuaCode = req.body.script; 
    const editPassword = req.body.editPassword; 
    const accessPassword = req.body.accessPassword || null; // NEW: Optional access password

    if (!rawLuaCode || rawLuaCode.trim() === '' || !editPassword || editPassword.length < 4) {
        return res.status(400).json({ error: 'Script and a strong edit password (min 4 chars) are required.' });
    }
    
    // Step 1: Obfuscate the initial script
    const obfuscationResult = await runObfuscationStep(rawLuaCode);
    
    // Step 2: Store Raw, Obfuscated, and Password Hashes
    const scriptKey = generateUniqueId();
    const editPasswordHash = hashPassword(editPassword);
    // Only hash the access password if one was provided
    const accessPasswordHash = accessPassword ? hashPassword(accessPassword) : null; 

    try {
        await pool.query(
            'INSERT INTO scripts(key, edit_password_hash, access_password_hash, raw_script, obfuscated_script) VALUES($1, $2, $3, $4, $5)',
            [scriptKey, editPasswordHash, accessPasswordHash, rawLuaCode, obfuscationResult.code]
        );

        console.log(`Script created successfully. Key: ${scriptKey}`);

        // Success: Return the Loader Key and the original passwords
        res.status(201).json({ 
            message: obfuscationResult.success ? 'Secure script created.' : 'Script created, but obfuscation failed (using fallback).',
            key: scriptKey,
            editPassword: editPassword, 
            accessPassword: accessPassword, 
            loaderUrl: `/retrieve/${scriptKey}`
        });

    } catch (error) {
        console.error('Database error during script creation (Check Schema!):', error.stack); 
        res.status(500).json({ error: 'Internal server error during script storage.' });
    }
});


// ====================================================
// === 3. GET RAW FOR EDIT (Password Protected) =======
// ====================================================
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
        console.error('Database error during raw script retrieval:', error.stack);
        res.status(500).json({ error: 'Internal server error.' });
    }
});


// ====================================================
// === 4. SAVE AND OBFUSCATE (Password Protected) =====
// ====================================================
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
        console.error('Database error during save and obfuscate:', error.stack);
        res.status(500).json({ error: 'Internal server error during script update.' });
    }
});


// ====================================================
// === 5. SECURE STORAGE API ENDPOINTS ===
// ====================================================

// GET /retrieve/:key: Conditional access point (Roblox gets script, browser gets prompt)
app.get('/retrieve/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const userAgent = req.headers['user-agent'];

    // 1. If request comes from Roblox, always serve the script directly
    if (userAgent && userAgent.includes('Roblox')) {
        console.log(`Roblox request for key: ${scriptKey}`);
        try {
            const result = await pool.query(
                'SELECT obfuscated_script FROM scripts WHERE key = $1', 
                [scriptKey]
            );

            if (result.rows.length === 0) {
                res.setHeader('Content-Type', 'text/plain');
                return res.status(404).send('-- Error: Script not found or has expired.');
            }
            res.setHeader('Content-Type', 'text/plain');
            res.status(200).send(result.rows[0].obfuscated_script);
            
        } catch (error) {
            console.error('Database error during Roblox retrieval:', error.stack);
            res.setHeader('Content-Type', 'text/plain');
            res.status(500).send('-- Error: Internal Server Failure.');
        }
        return;
    }

    // 2. If request is from a browser, check for access password
    console.log(`Browser request for key: ${scriptKey}`);
    try {
        const result = await pool.query(
            'SELECT access_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).send('Script not found.');
        }

        const accessPasswordHash = result.rows[0].access_password_hash;

        if (accessPasswordHash) {
            // Script requires a password, serve the HTML prompt page
            return res.sendFile(path.join(__dirname, 'public', 'secure-access.html'));
        } else {
            // No password required, serve the script directly
            const scriptResult = await pool.query(
                'SELECT obfuscated_script FROM scripts WHERE key = $1', 
                [scriptKey]
            );
            res.setHeader('Content-Type', 'text/plain');
            res.status(200).send(scriptResult.rows[0].obfuscated_script);
        }
    } catch (error) {
        console.error('Database error during browser retrieval check:', error.stack);
        res.status(500).send('Internal Server Error.');
    }
});

// NEW: Endpoint to verify access password from the secure-access.html page
app.post('/verify-access/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const { accessPassword } = req.body;

    if (!accessPassword) {
        return res.status(400).json({ error: 'Password is required.' });
    }

    try {
        const result = await pool.query(
            'SELECT access_password_hash FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Script not found.' });
        }

        const storedHash = result.rows[0].access_password_hash;
        const providedHash = hashPassword(accessPassword);

        if (storedHash && storedHash === providedHash) {
            // Generate a temporary token for this successful access
            const tempToken = generateUniqueId();
            tempAccessTokens[tempToken] = {
                key: scriptKey,
                expires: Date.now() + 60 * 1000 // Token valid for 1 minute
            };
            console.log(`Access granted for key ${scriptKey}. Token: ${tempToken}`);
            return res.status(200).json({ accessGranted: true, tempToken: tempToken });
        } else {
            return res.status(401).json({ error: 'Invalid password.' });
        }

    } catch (error) {
        console.error('Database error during access password verification:', error.stack);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// NEW: Endpoint to retrieve actual content after token verification
app.get('/retrieve-content/:key/:token', async (req, res) => {
    const scriptKey = req.params.key;
    const tempToken = req.params.token;

    const tokenData = tempAccessTokens[tempToken];

    if (!tokenData || tokenData.key !== scriptKey || tokenData.expires < Date.now()) {
        console.warn(`Invalid or expired token attempt for key ${scriptKey}, token ${tempToken}`);
        delete tempAccessTokens[tempToken]; // Clean up expired/invalid tokens
        return res.status(403).send('Access denied or token expired. Please try again from the main link.');
    }

    // Token is valid, serve the obfuscated script
    try {
        const result = await pool.query(
            'SELECT obfuscated_script FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).send('Script not found.');
        }
        
        // Invalidate the token after use
        delete tempAccessTokens[tempToken]; 
        
        res.setHeader('Content-Type', 'text/plain');
        res.status(200).send(result.rows[0].obfuscated_script);

    } catch (error) {
        console.error('Database error during token-verified script retrieval:', error.stack);
        res.status(500).send('Internal Server Error.');
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
