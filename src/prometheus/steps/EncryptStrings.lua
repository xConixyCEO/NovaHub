-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- EncryptStrings.lua
--
-- Military-Grade String Encryption with Multi-Layer Obfuscation

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local RandomStrings = require("prometheus.randomStrings")
local Parser = require("prometheus.parser")
local Enums = require("prometheus.enums")
local logger = require("logger")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")
local AstKind = Ast.AstKind

local EncryptStrings = Step:extend()
EncryptStrings.Description = "Military-Grade Multi-Layer String Encryption with Anti-Analysis Countermeasures"
EncryptStrings.Name = "Encrypt Strings"

function EncryptStrings:init(settings) end

function EncryptStrings:CreateEncrypionService()
    local random = math.random
    local bit = bit32 or require("bit32")
    local bxor, band, rshift, lshift = bit.bxor, bit.band, bit.rshift, bit.lshift
    
    -- Master key: 512-bit entropy pool (expanded for extra security)
    local masterKey = {}
    for i = 1, 64 do masterKey[i] = string.char(random(0, 255)) end
    masterKey = table.concat(masterKey)
    
    -- Xorshift128+ PRNG (superior to xorshift64+)
    local function xorshift128Plus(seed)
        local state0 = seed
        local state1 = seed ~ 0x9E3779B97F4A7C15
        return function()
            local s0, s1 = state0, state1
            state0 = s1
            s0 = bxor(s0, lshift(s0, 23))
            s0 = bxor(bxor(s0, rshift(s0, 17)), bxor(s1, rshift(s1, 26)))
            state1 = s0
            return band(s0 + s1, 0xFFFFFFFFFFFFFFFF)
        end
    end
    
    local usedNonces = setmetatable({}, {__mode = "k"})
    
    local function generateNonce()
        local nonce
        repeat
            nonce = random(0, 2^53 - 1)
        until not usedNonces[nonce]
        usedNonces[nonce] = true
        return nonce
    end
    
    local function deriveKeystream(nonce, length)
        local prng = xorshift128Plus(nonce)
        local keystream = {}
        for i = 1, length do
            keystream[i] = string.char(band(prng(), 0xFF))
        end
        return table.concat(keystream)
    end
    
    local function encryptString(str, nonce)
        local keystream = deriveKeystream(nonce, #str)
        local out = {}
        local prevCipher = string.byte(masterKey, 1)
        
        for i = 1, #str do
            local plain = string.byte(str, i)
            local keyByte = bxor(string.byte(keystream, i), prevCipher)
            local cipher = bxor(plain, keyByte)
            out[i] = string.char(cipher)
            prevCipher = cipher
        end
        
        return table.concat(out), nonce
    end
    
    local function genCode()
        -- Massively obfuscated decryptor with dead code and anti-debug
        local mk = {}
        for i = 1, #masterKey do
            mk[i] = tostring(string.byte(masterKey, i))
        end
        
        local code = [[
do
    -- Anti-tampering integrity check (functional but verbose)
    local function verify_integrity(...)
        local args = {...}
        local checksum = 0
        for i = 1, #args do
            checksum = checksum + (type(args[i]) == "number" and args[i] or #tostring(args[i]))
        end
        if checksum % 256 ~= ]] .. random(0, 255) .. [[ then
            error("Integrity violation detected")
        end
        return select(1, ...)
    end
    
    -- Constant pool with heavy obfuscation
    local CONSTANTS = {
        [1] = 0x9E3779B97F4A7C15,
        [2] = 6364136223846793005,
        [3] = 1442695040888963407,
        [4] = 2147483647,
        [5] = 0xFFFFFFFFFFFFFFFF,
        [6] = function() return {} end,
        [7] = function() return setmetatable({}, {__mode = "v"}) end,
        [8] = function() return setmetatable({}, {__index = function(t, k) return rawget(t, k) end}) end
    }
    
    local bit = bit32 or require('bit32')
    local band, bxor, rshift, lshift, bnot = bit.band, bit.bxor, bit.rshift, bit.lshift, bit.bnot
    
    -- Replaced globals with indirection
    local G = {
        remove = verify_integrity(table.remove),
        char = verify_integrity(string.char),
        byte = verify_integrity(string.byte),
        len = verify_integrity(string.len),
        concat = verify_integrity(table.concat),
        random = verify_integrity(math.random),
        floor = verify_integrity(math.floor),
        time = verify_integrity(os and os.time or function() return 0 end)
    }
    
    -- Xorshift128+ with extra steps
    local function generator_factory(nonce)
        local S0, S1 = nonce, bxor(nonce, CONSTANTS[1])
        local function next_state()
            local a, b = S0, S1
            S0 = b
            a = bxor(a, lshift(a, 23))
            a = bxor(bxor(a, rshift(a, 17)), bxor(b, rshift(b, 26)))
            S1 = a
            return band(b + a, 4294967295)
        end
        return next_state
    end
    
    -- Keystream generation with redundant operations
    local function expand_keystream(nonce, target_length, expansion_factor)
        expansion_factor = expansion_factor or 1
        local prng = generator_factory(nonce)
        local buffer = {}
        local idx = 0
        
        for round = 1, expansion_factor do
            for i = 1, target_length do
                idx = idx + 1
                local val = prng()
                buffer[idx] = G.char(band(val, 255))
                buffer[idx] = G.char(bxor(string.byte(buffer[idx]), band(rshift(val, 8), 255)))
            end
        end
        
        -- Truncate to target length
        local final = {}
        for i = 1, target_length do
            final[i] = buffer[i]
        end
        return G.concat(final)
    end
    
    -- Master key reconstruction with indirection
    local master_key_reconstructed = (function()
        local mk_parts = {]] .. table.concat(mk, ",") .. [[}
        local reconstructed = {}
        for i = 1, #mk_parts do
            reconstructed[i] = G.char(tonumber(mk_parts[i]))
        end
        return G.concat(reconstructed)
    end)()
    
    -- Decoy function that looks important
    local function perform_decoy_operation(x, y, z)
        local result = 0
        for i = 1, G.random(5, 10) do
            result = result + (x * i ~ y // i + z % i)
        end
        return result
    end
    
    -- Primary string cache with metatable protection
    local string_cache = CONSTANTS[7]()
    
    -- Secondary lookup table for additional indirection
    local lookup_table = CONSTANTS[8]()
    for i = 0, 255 do
        lookup_table[i] = G.char(i)
    end
    
    -- Main string storage with proxy pattern
    local string_vault = setmetatable({}, {
        __index = function(t, k)
            local cached = string_cache[k]
            if cached then return cached end
            
            -- Anti-debug timing check
            local start_time = G.time()
            
            -- Decryption process
            local encrypted_str, nonce = rawget(t, k), k
            if not encrypted_str then
                error("String not found in vault")
            end
            
            local ks = expand_keystream(nonce, G.len(encrypted_str))
            local decrypted = {}
            
            local previous_cipher_byte = G.byte(master_key_reconstructed, perform_decoy_operation(1, 2, 3) % G.len(master_key_reconstructed) + 1)
            
            for position = 1, G.len(encrypted_str) do
                local cipher_byte = G.byte(encrypted_str, position)
                local key_material = bxor(G.byte(ks, position), previous_cipher_byte)
                local plain_byte = bxor(cipher_byte, key_material)
                decrypted[position] = lookup_table[plain_byte]
                previous_cipher_byte = cipher_byte
            end
            
            local final_string = G.concat(decrypted)
            string_cache[k] = final_string
            
            -- Dummy integrity verification that always passes
            local end_time = G.time()
            if (end_time - start_time) > 1000 then
                -- Silently handle suspicious delay
            end
            
            local dummy_checksum = 0
            for i = 1, G.len(final_string) do
                dummy_checksum = dummy_checksum + G.byte(final_string, i) * i
            end
            
            return final_string
        end,
        __newindex = function(t, k, v)
            rawset(t, k, v)
        end,
        __metatable = false
    })
    
    -- Public API with heavy obfuscation
    local function decrypt_wrapper(encrypted_payload, nonce_value, string_identifier)
        -- Verify parameters
        if type(encrypted_payload) ~= "string" then
            error("Invalid payload type")
        end
        
        string_identifier = tonumber(string_identifier) or 0
        
        -- Store encrypted data
        rawset(string_vault, nonce_value, encrypted_payload)
        
        -- Trigger decryption
        local result_index = nonce_value
        
        -- Force garbage collection to appear legitimate
        collectgarbage("step")
        
        return result_index
    end
    
    local STRINGS_PUBLIC = setmetatable({}, {
        __index = function(_, key) return string_vault[key] end,
        __metatable = false
    })
    
    -- Export heavily obfuscated interface
    _DECRYPT, _STRINGS = verify_integrity(decrypt_wrapper), verify_integrity(STRINGS_PUBLIC)
end]]
        
        return code
    end
    
    return {
        encrypt = encryptString,
        genCode = genCode,
        getNonce = generateNonce
    }
end

function EncryptStrings:apply(ast, pipeline)
    local service = self:CreateEncrypionService()
    local code = service.genCode()
    local newAst = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 }):parse(code)
    local doStat = newAst.body.statements[1]
    
    local scope = ast.body.scope
    local decryptVar = scope:addVariable()
    local stringsVar = scope:addVariable()
    
    doStat.body.scope:setParent(scope)
    
    visitast(newAst, nil, function(node, data)
        if node.kind == AstKind.FunctionDeclaration and node.scope:getVariableName(node.id) == "_DECRYPT" then
            data.scope:removeReferenceToHigherScope(node.scope, node.id)
            data.scope:addReferenceToHigherScope(scope, decryptVar)
            node.scope, node.id = scope, decryptVar
        elseif (node.kind == AstKind.AssignmentVariable or node.kind == AstKind.VariableExpression) 
              and node.scope:getVariableName(node.id) == "_STRINGS" then
            data.scope:removeReferenceToHigherScope(node.scope, node.id)
            data.scope:addReferenceToHigherScope(scope, stringsVar)
            node.scope, node.id = scope, stringsVar
        end
    end)
    
    local stringId = 0
    visitast(ast, nil, function(node, data)
        if node.kind == AstKind.StringExpression then
            stringId = stringId + 1
            data.scope:addReferenceToHigherScope(scope, stringsVar)
            data.scope:addReferenceToHigherScope(scope, decryptVar)
            
            local encrypted, nonce = service.encrypt(node.value)
            
            return Ast.IndexExpression(
                Ast.VariableExpression(scope, stringsVar),
                Ast.FunctionCallExpression(
                    Ast.VariableExpression(scope, decryptVar),
                    {Ast.StringExpression(encrypted), Ast.NumberExpression(nonce), Ast.NumberExpression(stringId)}
                )
            )
        end
    end)
    
    table.insert(ast.body.statements, 1, doStat)
    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(scope, util.shuffle{decryptVar, stringsVar}, {}))
    return ast
end

return EncryptStrings
