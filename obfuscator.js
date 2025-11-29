const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Constants for output formatting and error handling
const WATERMARK = "\n-- </> v0.1.0 NovaHub Lua Obfuscator "; 
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";

const applyFallback = (rawCode) => {
    // This fallback is only used if the execution fails for non-syntax reasons
    return `${FALLBACK_WATERMARK}\n${rawCode}`;
};

/**
 * Executes the external Lua obfuscator tool.
 * @param {string} rawLuaCode - The raw Lua code input.
 * @param {string} preset - The obfuscation preset (e.g., 'Medium').
 * @returns {Promise<string>} The obfuscated code.
 * @throws {Error} Throws specific errors for syntax or internal tool issues.
 */
async function runObfuscator(rawLuaCode, preset = 'Medium') {
    const timestamp = Date.now();
    
    // Use a temporary folder for files
    const tempDir = path.join(__dirname, 'temp_files');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
    }
    
    const tempFile = path.join(tempDir, `temp_${timestamp}.lua`);
    const outputFile = path.join(tempDir, `obf_${timestamp}.lua`);
    
    let obfuscatedCode = '';

    try {
        // 1. Write the raw code to a temporary file
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');

        // Note: The 'src/cli.lua' path must be correct relative to where the script runs!
        const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
        
        // 2. Execute the Obfuscator
        await new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                
                // If there's a system error or non-zero exit code
                if (error) {
                    const errorOutput = stderr.toString() + (error.message || '');
                    
                    // Check if the error suggests a syntax issue (this is what bot.js checks for!)
                    if (errorOutput.includes('syntax error') || errorOutput.includes('attempt to index')) {
                        return reject(new Error('Invalid Lua syntax. Please check your code.'));
                    }
                    
                    console.error(`Obfuscator Execution Failed: ${error.message}`);
                    return reject(new Error('Internal obfuscation tool error.'));
                }
                
                // Check if the obfuscator printed errors to stderr
                if (stderr) {
                    console.error(`Obfuscator Stderr: ${stderr}`);
                    return reject(new Error(`Obfuscator reported an error: ${stderr.trim()}`));
                }

                // Success path
                try {
                    if (fs.existsSync(outputFile)) {
                        obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                        obfuscatedCode = WATERMARK + obfuscatedCode;
                    } else {
                        return reject(new Error('Obfuscation failed to produce an output file.'));
                    }
                } catch (readError) {
                    console.error('File Read Error:', readError);
                    return reject(new Error('Failed to read obfuscated output.'));
                } finally {
                    // Clean up temporary files regardless of success or failure
                    try {
                        if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
                        if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    } catch (cleanupError) {
                        console.error("Error cleaning up temp files in obfuscator.js:", cleanupError);
                    }
                }
                
                resolve();
            });
        });

    } catch (error) {
        // Re-throw the error so bot.js can catch the specific message
        throw error;
    }

    // Return the successful code.
    return obfuscatedCode;
}

module.exports = {
    runObfuscator,
};
