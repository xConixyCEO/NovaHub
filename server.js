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

// --- CRITICAL FIX: INCREASED PAYLOAD LIMIT TO 100MB ---
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
// ------------------------------------------------------

// --- Database Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Test connection and initialize table
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Successfully connected to PostgreSQL.');
    
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            script TEXT NOT NULL,
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

// Define the watermark constant
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] "; 

// Middleware for static files
app.use(express.static('public')); 
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    return crypto.randomBytes(16).toString('hex');
};


// =======================================================
// === 1. OBFUSCATION ENDPOINT (Uses Prometheus CLI) ===
// =======================================================

app.post('/obfuscate', (req, res) => {
    const luaCode = req.body.code;
    const preset = req.body.preset || 'Medium'; 
    const timestamp = Date.now();
    
    // Create temporary files in the root directory
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    // 1. Write the user's code to a temporary file
    fs.writeFileSync(tempFile, luaCode, 'utf8');

    // 2. Define the command to run Prometheus
    const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
    
    // 3. Execute the Prometheus CLI
    exec(command, (error, stdout, stderr) => {
        // 4. Clean up the temporary input file
        fs.unlinkSync(tempFile); 
        
        // 5. Check for errors
        if (error || stderr) {
            console.error(`Obfuscation failed: ${error ? error.message : stderr}`);
            if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
            
            return res.status(500).json({ 
                error: 'Obfuscation failed.', 
                details: stderr || error.message 
            });
        }
        
        // 6. Read the obfuscated result
        try {
            let obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
            
            // Prepend the watermark
            obfuscatedCode = WATERMARK + obfuscatedCode;
            
            // 7. Send the result back and clean up the output file
            res.json({ obfuscatedCode: obfuscatedCode });
            fs.unlinkSync(outputFile);
        } catch (readError) {
            return res.status(500).json({ error: 'Failed to read output file.' });
        }
    });
});


// ====================================================
// === 2. STORAGE API ENDPOINTS (PostgreSQL Storage)===
// ====================================================

// POST /store (Stores the final, executable Lua script)
app.post('/store', async (req, res) => {
    const { script } = req.body;

    if (!script || typeof script !== 'string' || script.length === 0) {
        return res.status(400).json({ error: 'Missing or empty "script" parameter.' });
    }

    const scriptKey = generateUniqueId();
    
    try {
        await pool.query(
            'INSERT INTO scripts(key, script) VALUES($1, $2)',
            [scriptKey, script]
        );

        res.status(201).json({ 
            message: 'Script stored successfully.',
            key: scriptKey
        });

    } catch (error) {
        console.error('Database error during storage:', error);
        res.status(500).json({ error: 'Internal server error during script storage.' });
    }
});

// GET /retrieve/:key (Retrieves the Lua script - Roblox only)
app.get('/retrieve/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const userAgent = req.headers['user-agent'];

    // 1. Validate User-Agent 
    if (!userAgent || !userAgent.includes('Roblox')) {
        res.setHeader('Content-Type', 'text/plain');
        return res.status(403).send('-- Access Denied');
    }

    try {
        const result = await pool.query(
            'SELECT script FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            res.setHeader('Content-Type', 'text/plain');
            return res.status(404).send('-- Error: Script not found or has expired.');
        }

        const script = result.rows[0].script;

        // 2. Deliver the script
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
    res.send('NovaHub Unified Backend is running and connected to PostgreSQL.');
});


// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
