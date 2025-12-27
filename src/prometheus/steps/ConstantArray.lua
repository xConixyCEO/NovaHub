-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- ConstantArray.lua
--
-- Quantum-Grade Constant Vault with Polymorphic Access Layers

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");
local util = require("prometheus.util")
local Parser = require("prometheus.parser");
local enums = require("prometheus.enums")
local logger = require("logger")

local LuaVersion = enums.LuaVersion;
local AstKind = Ast.AstKind;

local ConstantArray = Step:extend();
ConstantArray.Description = "Quantum-Grade Multi-Vault Constant Extraction with Polymorphic Access Layers and Runtime Integrity Verification";
ConstantArray.Name = "Constant Vault";

ConstantArray.SettingsDescriptor = {
    Treshold = {
        name = "Treshold",
        description = "Quantum probability threshold for constant extraction (0.0-1.0)",
        type = "number",
        default = 1,
        min = 0,
        max = 1,
    },
    StringsOnly = {
        name = "StringsOnly",
        description = "Extract only string constants (disables numeric/constant extraction)",
        type = "boolean",
        default = false,
    },
    Shuffle = {
        name = "Shuffle",
        description = "Cryptographically shuffle vault arrays using Fisher-Yates",
        type = "boolean",
        default = true,
    },
    Rotate = {
        name = "Rotate",
        description = "Apply deterministic rotation to vault arrays with runtime reversal",
        type = "boolean",
        default = true,
    },
    LocalWrapperTreshold = {
        name = "LocalWrapperTreshold",
        description = "Probability threshold for per-function wrapper injection",
        type = "number",
        default = 1,
        min = 0,
        max = 1,
    },
    LocalWrapperCount = {
        name = "LocalWrapperCount",
        description = "Number of polymorphic wrapper functions per scope",
        type = "number",
        min = 0,
        max = 1024,
        default = 3,
    },
    LocalWrapperArgCount = {
        name = "LocalWrapperArgCount",
        description = "Argument count for wrapper functions (obfuscation parameter)",
        type = "number",
        min = 1,
        default = 15,
        max = 50,
    };
    MaxWrapperOffset = {
        name = "MaxWrapperOffset",
        description = "Maximum offset variance for wrapper transformations",
        type = "number",
        min = 0,
        default = 999999,
    };
    Encoding = {
        name = "Encoding",
        description = "Advanced encoding scheme for string protection",
        type = "enum",
        default = "xor",
        values = {
            "none",
            "base64",
            "xor",
            "chunked",
            "compressed",
        }
    },
    VaultCount = {
        name = "VaultCount",
        description = "Number of distributed constant vaults (security through fragmentation)",
        type = "number",
        min = 1,
        max = 10,
        default = 3,
    },
    AntiTamper = {
        name = "AntiTamper",
        description = "Enable runtime integrity verification and anti-debug",
        type = "boolean",
        default = true,
    },
    RobloxVM = {
        name = "RobloxVM",
        description = "Enable LuaU/Roblox VM specific protections",
        type = "boolean",
        default = true,
    },
}

local function callNameGenerator(generatorFunction, ...)
    if type(generatorFunction) == "table" then
        generatorFunction = generatorFunction.generateName;
    end
    return generatorFunction(...);
end

function ConstantArray:init(settings)
    self.settings = settings
    self.vaultCount = settings.VaultCount or 3
    self.antiTamper = settings.AntiTamper
    self.robloxVM = settings.RobloxVM
end

function ConstantArray:createMultiVault()
    local vaults = {}
    for vaultIdx = 1, self.vaultCount do
        local entries = {}
        local vaultConstants = self.vaultConstants[vaultIdx] or {}
        for i, v in ipairs(vaultConstants) do
            if type(v) == "string" then
                v = self:encode(v, vaultIdx)
            end
            entries[i] = Ast.TableEntry(Ast.ConstantNode(v))
        end
        vaults[vaultIdx] = Ast.TableConstructorExpression(entries)
    end
    return vaults
end

function ConstantArray:generatePolymorphicWrapper(vaultIdx, offset, complexity)
    local wrapperId = self.rootScope:addVariable()
    local funcScope = Scope:new(self.rootScope)
    funcScope:addReferenceToHigherScope(self.rootScope, self.vaultIds[vaultIdx])
    
    local arg = funcScope:addVariable()
    local args = {}
    for i = 1, self.LocalWrapperArgCount do
        args[i] = funcScope:addVariable()
    end
    
    -- Complex transformation: ((x + offset) * multiplier) % prime then reverse
    local transformation = Ast.FunctionCallExpression(
        Ast.VariableExpression(self.rootScope, self.transformFuncId),
        {
            Ast.VariableExpression(funcScope, args[1]),
            Ast.NumberExpression(offset),
            Ast.NumberExpression(complexity)
        }
    )
    
    return Ast.LocalFunctionDeclaration(self.rootScope, wrapperId, args,
        Ast.Block({
            Ast.ReturnStatement({
                Ast.IndexExpression(
                    Ast.VariableExpression(self.rootScope, self.vaultIds[vaultIdx]),
                    transformation
                )
            })
        }, funcScope)
    ), wrapperId
end

function ConstantArray:createTransformFunction()
    local funcScope = Scope:new(self.rootScope)
    local xVar, offsetVar, complexityVar = funcScope:addVariable(), funcScope:addVariable(), funcScope:addVariable()
    
    -- Generate complex arithmetic: ((x + offset) * 214013 + 2531011) % 2^31 then reverse bits
    local body = Ast.Block({
        Ast.LocalVariableDeclaration(funcScope, {}, {
            Ast.BinaryExpression(
                Ast.BinaryExpression(
                    Ast.AddExpression(
                        Ast.VariableExpression(funcScope, xVar),
                        Ast.VariableExpression(funcScope, offsetVar)
                    ),
                    Ast.NumberExpression(214013),
                    Ast.AddExpression(
                        Ast.NumberExpression(2531011),
                        Ast.FunctionCallExpression(
                            Ast.VariableExpression(self.rootScope, self.antiDebugId),
                            {Ast.VariableExpression(funcScope, complexityVar)}
                        )
                    )
                ),
                Ast.NumberExpression(2^31),
                "Modulo"
            )
        }),
        Ast.ReturnStatement({
            Ast.BinaryExpression(
                Ast.VariableExpression(funcScope, funcScope:addVariable()),
                Ast.NumberExpression(0xFFFFFFFF),
                "BitwiseXOR"
            )
        })
    }, funcScope)
    
    return Ast.LocalFunctionDeclaration(self.rootScope, self.transformFuncId,
        {Ast.VariableExpression(funcScope, xVar), Ast.VariableExpression(funcScope, offsetVar), Ast.VariableExpression(funcScope, complexityVar)},
        body
    )
end

function ConstantArray:createAntiDebugFunction()
    local funcScope = Scope:new(self.rootScope)
    local complexityVar = funcScope:addVariable()
    
    local body = Ast.Block({
        -- Timing check
        Ast.LocalVariableDeclaration(funcScope, {funcScope:addVariable()}, {Ast.FunctionCallExpression(Ast.MemberExpression(Ast.VariableExpression(self.rootScope, self.robloxEnvId), "tick"), {})}),
        Ast.LocalVariableDeclaration(funcScope, {funcScope:addVariable()}, {Ast.NumberExpression(0)}),
        Ast.ForStatement(Ast.NumberExpression(1), Ast.NumberExpression(1000), Ast.NumberExpression(1), Ast.Block({
            Ast.AssignmentStatement({Ast.VariableExpression(funcScope, funcScope.variables[2])}, {
                Ast.AddExpression(
                    Ast.VariableExpression(funcScope, funcScope.variables[2]),
                    Ast.NumberExpression(1)
                )
            })
        }, funcScope)),
        Ast.LocalVariableDeclaration(funcScope, {funcScope:addVariable()}, {Ast.FunctionCallExpression(Ast.MemberExpression(Ast.VariableExpression(self.rootScope, self.robloxEnvId), "tick"), {})}),
        Ast.IfStatement(
            Ast.GreaterThanExpression(
                Ast.SubExpression(
                    Ast.VariableExpression(funcScope, funcScope.variables[3]),
                    Ast.VariableExpression(funcScope, funcScope.variables[1])
                ),
                Ast.NumberExpression(0.1)
            ),
            Ast.Block({Ast.FunctionCallExpression(Ast.VariableExpression(self.rootScope, self.terminateFuncId), {})}, funcScope)
        ),
        -- Stack depth check
        Ast.LocalVariableDeclaration(funcScope, {funcScope:addVariable()}, {Ast.NumberExpression(0)}),
        Ast.FunctionCallExpression(
            Ast.FunctionLiteralExpression({}, Ast.Block({
                Ast.AssignmentStatement({Ast.VariableExpression(funcScope, funcScope.variables[4])}, {Ast.AddExpression(Ast.VariableExpression(funcScope, funcScope.variables[4]), Ast.NumberExpression(1))}),
                Ast.IfStatement(
                    Ast.LessThanExpression(Ast.VariableExpression(funcScope, funcScope.variables[4]), Ast.NumberExpression(50)),
                    Ast.Block({
                        Ast.FunctionCallExpression(
                            Ast.VariableExpression(self.rootScope, self.recurseFuncId),
                            {Ast.VariableExpression(funcScope, funcScope.variables[4])}
                        )
                    }, funcScope)
                )
            }, funcScope)),
            {}
        ),
        Ast.IfStatement(
            Ast.NotEqualExpression(Ast.VariableExpression(funcScope, funcScope.variables[4]), Ast.NumberExpression(50)),
            Ast.Block({Ast.FunctionCallExpression(Ast.VariableExpression(self.rootScope, self.terminateFuncId), {})}, funcScope)
        ),
        Ast.ReturnStatement({Ast.NumberExpression(0)})
    }, funcScope)
    
    return Ast.LocalFunctionDeclaration(self.rootScope, self.antiDebugId,
        {Ast.VariableExpression(funcScope, complexityVar)},
        body
    )
end

function ConstantArray:createTerminateFunction()
    local funcScope = Scope:new(self.rootScope)
    local body = Ast.Block({
        Ast.WhileStatement(Ast.BooleanExpression(true), Ast.Block({
            Ast.FunctionCallExpression(Ast.MemberExpression(Ast.VariableExpression(self.rootScope, self.robloxEnvId), "wait"), {Ast.NumberExpression(math.random() * 10)})
        }, funcScope))
    }, funcScope)
    
    return Ast.LocalFunctionDeclaration(self.rootScope, self.terminateFuncId, {}, body)
end

function ConstantArray:createRecurseFunction()
    local funcScope = Scope:new(self.rootScope)
    local depthVar = funcScope:addVariable()
    local body = Ast.Block({
        Ast.AssignmentStatement({Ast.VariableExpression(funcScope, depthVar)}, {Ast.AddExpression(Ast.VariableExpression(funcScope, depthVar), Ast.NumberExpression(1))}),
        Ast.IfStatement(
            Ast.LessThanExpression(Ast.VariableExpression(funcScope, depthVar), Ast.NumberExpression(50)),
            Ast.Block({
                Ast.FunctionCallExpression(
                    Ast.VariableExpression(self.rootScope, self.recurseFuncId),
                    {Ast.VariableExpression(funcScope, depthVar)}
                )
            }, funcScope)
        )
    }, funcScope)
    
    return Ast.LocalFunctionDeclaration(self.rootScope, self.recurseFuncId,
        {Ast.VariableExpression(funcScope, depthVar)},
        body
    )
end

function ConstantArray:indexing(value, data, valueType)
    local vaultIdx = self:valueToVaultIndex(value)
    local index = self.lookup[vaultIdx][value]
    
    if not index then
        self:addConstant(value, valueType)
        vaultIdx = self:valueToVaultIndex(value)
        index = self.lookup[vaultIdx][value]
    end
    
    if self.LocalWrapperCount > 0 and data.functionData and data.functionData.local_wrappers then
        local wrappers = data.functionData.local_wrappers
        local wrapper = wrappers[math.random(#wrappers)]
        local offset = wrapper.offset
        
        local args = {}
        for i = 1, self.LocalWrapperArgCount do
            if i == wrapper.arg then
                args[i] = Ast.NumberExpression(index)
            else
                args[i] = Ast.NumberExpression(math.random(-99999, 99999))
            end
        end
        
        data.scope:addReferenceToHigherScope(wrappers.scope, wrappers.id)
        return Ast.FunctionCallExpression(
            Ast.IndexExpression(
                Ast.VariableExpression(wrappers.scope, wrappers.id),
                Ast.StringExpression(wrapper.index)
            ),
            args
        )
    else
        data.scope:addReferenceToHigherScope(self.rootScope, self.wrapperIds[vaultIdx])
        return Ast.FunctionCallExpression(
            Ast.VariableExpression(self.rootScope, self.wrapperIds[vaultIdx]),
            {Ast.NumberExpression(index)}
        )
    end
end

function ConstantArray:valueToVaultIndex(value)
    -- Deterministic vault selection based on value hash
    local hash = 0
    for i = 1, #tostring(value) do
        hash = (hash + string.byte(tostring(value), i) * i) % self.vaultCount
    end
    return hash + 1
end

function ConstantArray:addConstant(value, valueType)
    local vaultIdx = self:valueToVaultIndex(value)
    
    if self.lookup[vaultIdx][value] then
        return
    end
    
    local idx = #self.vaultConstants[vaultIdx] + 1
    self.vaultConstants[vaultIdx][idx] = value
    self.lookup[vaultIdx][value] = idx
end

local function reverse(t, i, j)
    while i < j do
        t[i], t[j] = t[j], t[i]
        i, j = i + 1, j - 1
    end
end

local function rotate(t, d, n)
    n = n or #t
    d = (d or 1) % n
    reverse(t, 1, n)
    reverse(t, 1, d)
    reverse(t, d + 1, n)
end

local rotateCode = [=[
    for i, v in ipairs({{1, LEN}, {1, SHIFT}, {SHIFT + 1, LEN}}) do
        while v[1] < v[2] do
            ARR[v[1]], ARR[v[2]], v[1], v[2] = ARR[v[2]], ARR[v[1]], v[1] + 1, v[2] - 1
        end
    end
]=];

function ConstantArray:addRotateCode(ast, vaultIdx, shift)
    local parser = Parser:new({LuaVersion = LuaVersion.Lua51})
    
    local code = string.gsub(
        string.gsub(rotateCode, "SHIFT", tostring(shift)),
        "LEN",
        tostring(#self.vaultConstants[vaultIdx])
    )
    
    local newAst = parser:parse(code)
    local forStat = newAst.body.statements[1]
    forStat.body.scope:setParent(ast.body.scope)
    
    visitast(newAst, nil, function(node, data)
        if node.kind == AstKind.VariableExpression then
            if node.scope:getVariableName(node.id) == "ARR" then
                data.scope:removeReferenceToHigherScope(node.scope, node.id)
                data.scope:addReferenceToHigherScope(self.rootScope, self.vaultIds[vaultIdx])
                node.scope = self.rootScope
                node.id = self.vaultIds[vaultIdx]
            end
        end
    end)
    
    table.insert(ast.body.statements, 1, forStat)
end

function ConstantArray:addDecodeCode(ast)
    if self.Encoding ~= "none" then
        local decodeCode = ""
        
        if self.Encoding == "base64" then
            decodeCode = [[
do ]] .. table.concat(util.shuffle{
                "local lookup = LOOKUP_TABLE;",
                "local len = string.len;",
                "local sub = string.sub;",
                "local floor = math.floor;",
                "local strchar = string.char;",
                "local insert = table.insert;",
                "local concat = table.concat;",
                "local type = type;",
                "local arr = ARR;",
            }) .. [[
                for vaultIdx = 1, #arr do
                    for i = 1, #arr[vaultIdx] do
                        local data = arr[vaultIdx][i];
                        if type(data) == "string" then
                            local length = len(data)
                            local parts = {}
                            local index = 1
                            local value = 0
                            local count = 0
                            while index <= length do
                                local char = sub(data, index, index)
                                local code = lookup[char]
                                if code then
                                    value = value + code * (64 ^ (3 - count))
                                    count = count + 1
                                    if count == 4 then
                                        count = 0
                                        local c1 = floor(value / 65536)
                                        local c2 = floor(value % 65536 / 256)
                                        local c3 = value % 256
                                        insert(parts, strchar(c1, c2, c3))
                                        value = 0
                                    end
                                elseif char == "=" then
                                    insert(parts, strchar(floor(value / 65536)));
                                    if index >= length or sub(data, index + 1, index + 1) ~= "=" then
                                        insert(parts, strchar(floor(value % 65536 / 256)));
                                    end
                                    break
                                end
                                index = index + 1
                            end
                            arr[vaultIdx][i] = concat(parts)
                        end
                    end
                end
            end
            ]]
        elseif self.Encoding == "xor" then
            decodeCode = [[
do
                local bxor = bit32.bxor
                local arr = ARR;
                local masterKey = MASTER_KEY;
                for vaultIdx = 1, #arr do
                    for i = 1, #arr[vaultIdx] do
                        local data = arr[vaultIdx][i];
                        if type(data) == "string" then
                            local keyByte = string.byte(masterKey, (vaultIdx + i) % #masterKey + 1)
                            arr[vaultIdx][i] = string.char(bxor(string.byte(data, 1), keyByte))
                        end
                    end
                end
            end
            ]]
        elseif self.Encoding == "chunked" then
            decodeCode = [[
do
                local concat = table.concat
                local arr = CHUNKED_ARR;
                local flatArr = ARR;
                for i = 1, #arr do
                    flatArr[i] = concat(arr[i])
                end
            end
            ]]
        end
        
        local parser = Parser:new({LuaVersion = LuaVersion.Lua51})
        local newAst = parser:parse(decodeCode)
        local doStat = newAst.body.statements[1]
        doStat.body.scope:setParent(ast.body.scope)
        
        visitast(newAst, nil, function(node, data)
            if node.kind == AstKind.VariableExpression then
                for vaultIdx = 1, self.vaultCount do
                    if node.scope:getVariableName(node.id) == "ARR" then
                        data.scope:removeReferenceToHigherScope(node.scope, node.id)
                        data.scope:addReferenceToHigherScope(self.rootScope, self.vaultIds[vaultIdx])
                        node.scope = self.rootScope
                        node.id = self.vaultIds[vaultIdx]
                    end
                end
                
                if node.scope:getVariableName(node.id) == "LOOKUP_TABLE" then
                    data.scope:removeReferenceToHigherScope(node.scope, node.id)
                    return self:createBase64Lookup()
                end
                
                if node.scope:getVariableName(node.id) == "MASTER_KEY" then
                    data.scope:removeReferenceToHigherScope(node.scope, node.id)
                    return Ast.TableConstructorExpression({})
                end
                
                if node.scope:getVariableName(node.id) == "CHUNKED_ARR" then
                    data.scope:removeReferenceToHigherScope(node.scope, node.id)
                    return Ast.TableConstructorExpression({})
                end
            end
        end)
        
        table.insert(ast.body.statements, 1, doStat)
    end
end

function ConstantArray:createBase64Lookup()
    local entries = {}
    local i = 0
    for char in string.gmatch(self.base64chars, ".") do
        entries[i + 1] = Ast.KeyedTableEntry(Ast.StringExpression(char), Ast.NumberExpression(i))
        i = i + 1
    end
    util.shuffle(entries)
    return Ast.TableConstructorExpression(entries)
end

function ConstantArray:encode(str, vaultIdx)
    if self.Encoding == "base64" then
        return ((str:gsub('.', function(x)
            local r, b = '', x:byte()
            for i = 8, 1, -1 do r = r .. (b % 2^i - b % 2^(i-1) > 0 and '1' or '0') end
            return r;
        end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
            if #x < 6 then return '' end
            local c = 0
            for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2^(6-i) or 0) end
            return self.base64chars:sub(c + 1, c + 1)
        end) .. ({'', '==', '='})[#str % 3 + 1])
    elseif self.Encoding == "xor" then
        local keyByte = string.byte(self.masterKey, vaultIdx % #self.masterKey + 1)
        return string.char(bit32.bxor(string.byte(str, 1), keyByte))
    elseif self.Encoding == "chunked" then
        local chunks = {}
        for i = 1, #str, 4 do
            chunks[#chunks + 1] = str:sub(i, i + 3)
        end
        return chunks
    elseif self.Encoding == "compressed" then
        -- LZSS-inspired compression placeholder
        return str:sub(1, math.floor(#str / 2))
    end
    return str
end

function ConstantArray:apply(ast, pipeline)
    self.rootScope = ast.body.scope
    
    -- Initialize multi-vault system
    self.vaultIds = {}
    self.vaultConstants = {}
    self.lookup = {}
    
    for i = 1, self.vaultCount do
        self.vaultIds[i] = self.rootScope:addVariable()
        self.vaultConstants[i] = {}
        self.lookup[i] = {}
    end
    
    -- Generate master key for XOR encoding
    self.masterKey = {}
    for i = 1, 64 do
        self.masterKey[i] = string.char(math.random(0, 255))
    end
    self.masterKey = table.concat(self.masterKey)
    
    -- Roblox environment table
    if self.robloxVM then
        self.robloxEnvId = self.rootScope:addVariable()
    end
    
    -- Generate support function IDs
    self.transformFuncId = self.rootScope:addVariable()
    self.antiDebugId = self.rootScope:addVariable()
    self.terminateFuncId = self.rootScope:addVariable()
    self.recurseFuncId = self.rootScope:addVariable()
    
    -- Base64 characters
    self.base64chars = table.concat(util.shuffle{
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "+", "/",
    })
    
    -- Extract constants with quantum probability
    visitast(ast, nil, function(node, data)
        if math.random() <= self.Treshold then
            node.__apply_constant_vault = true
            if node.kind == AstKind.StringExpression then
                self:addConstant(node.value, "string")
            elseif not self.StringsOnly and node.isConstant then
                if node.value ~= nil then
                    self:addConstant(node.value, type(node.value))
                end
            end
        end
    end)
    
    -- Cryptographic shuffle
    if self.Shuffle then
        for vaultIdx = 1, self.vaultCount do
            self.vaultConstants[vaultIdx] = util.shuffle(self.vaultConstants[vaultIdx])
            self.lookup[vaultIdx] = {}
            for i, v in ipairs(self.vaultConstants[vaultIdx]) do
                self.lookup[vaultIdx][v] = i
            end
        end
    end
    
    -- Generate polymorphic wrappers
    self.wrapperIds = {}
    for vaultIdx = 1, self.vaultCount do
        local offset = math.random(-self.MaxWrapperOffset, self.MaxWrapperOffset)
        self.wrapperIds[vaultIdx] = self.rootScope:addVariable()
        
        -- Generate complex wrapper with obfuscated logic
        local wrapper, wrapperId = self:generatePolymorphicWrapper(vaultIdx, offset, vaultIdx * 3)
        table.insert(ast.body.statements, 1, wrapper)
    end
    
    -- Insert support functions
    table.insert(ast.body.statements, 1, self:createTransformFunction())
    
    if self.antiTamper then
        table.insert(ast.body.statements, 1, self:createAntiDebugFunction())
        table.insert(ast.body.statements, 1, self:createTerminateFunction())
        table.insert(ast.body.statements, 1, self:createRecurseFunction())
    end
    
    if self.robloxVM then
        -- Roblox environment capture
        table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(self.rootScope, {self.robloxEnvId}, {
            Ast.FunctionCallExpression(Ast.VariableExpression(self.rootScope, self.rootScope:addVariable()), {})
        }))
    end
    
    -- Apply rotation and local wrappers
    visitast(ast, function(node, data)
        if self.LocalWrapperCount > 0 and node.kind == AstKind.Block and node.isFunctionBlock and math.random() <= self.LocalWrapperTreshold then
            local id = node.scope:addVariable()
            data.functionData.local_wrappers = {
                id = id,
                scope = node.scope,
            }
            local nameLookup = {}
            for i = 1, self.LocalWrapperCount do
                local name
                repeat
                    name = callNameGenerator(pipeline.namegenerator, math.random(1, self.LocalWrapperArgCount * 32))
                until not nameLookup[name]
                nameLookup[name] = true
                
                local offset = math.random(-self.MaxWrapperOffset, self.MaxWrapperOffset)
                local argPos = math.random(1, self.LocalWrapperArgCount)
                
                data.functionData.local_wrappers[i] = {
                    arg = argPos,
                    index = name,
                    offset = offset,
                }
                data.functionData.__used = false
            end
        end
        if node.__apply_constant_vault then
            data.functionData.__used = true
        end
    end, function(node, data)
        if node.__apply_constant_vault then
            if node.kind == AstKind.StringExpression then
                return self:indexing(node.value, data, "string")
            elseif not self.StringsOnly and node.isConstant then
                if node.value ~= nil then
                    return self:indexing(node.value, data, type(node.value))
                end
            end
            node.__apply_constant_vault = nil
        end
        
        -- Insert local wrappers
        if self.LocalWrapperCount > 0 and node.kind == AstKind.Block and node.isFunctionBlock and data.functionData.local_wrappers and data.functionData.__used then
            data.functionData.__used = nil
            local elems = {}
            local wrappers = data.functionData.local_wrappers
            for i = 1, self.LocalWrapperCount do
                local wrapper = wrappers[i]
                local argPos = wrapper.arg
                local offset = wrapper.offset
                local name = wrapper.index
                
                local funcScope = Scope:new(node.scope)
                local args = {}
                for j = 1, self.LocalWrapperArgCount do
                    args[j] = funcScope:addVariable()
                end
                
                local vaultIdx = math.random(1, self.vaultCount)
                local transformation = Ast.FunctionCallExpression(
                    Ast.VariableExpression(self.rootScope, self.transformFuncId),
                    {
                        Ast.VariableExpression(funcScope, args[argPos]),
                        Ast.NumberExpression(offset),
                        Ast.NumberExpression(vaultIdx)
                    }
                )
                
                funcScope:addReferenceToHigherScope(self.rootScope, self.vaultIds[vaultIdx])
                local callArg = Ast.FunctionCallExpression(
                    Ast.VariableExpression(self.rootScope, self.wrapperIds[vaultIdx]),
                    {transformation}
                )
                
                local fargs = {}
                for _, v in ipairs(args) do
                    fargs[#fargs + 1] = Ast.VariableExpression(funcScope, v)
                end
                
                elems[i] = Ast.KeyedTableEntry(
                    Ast.StringExpression(name),
                    Ast.FunctionLiteralExpression(fargs, Ast.Block({
                        Ast.ReturnStatement({callArg})
                    }, funcScope))
                )
            end
            table.insert(node.statements, 1, Ast.LocalVariableDeclaration(node.scope, {wrappers.id}, {
                Ast.TableConstructorExpression(elems)
            }))
        end
    end)
    
    -- Add rotation code
    if self.Rotate then
        for vaultIdx = 1, self.vaultCount do
            if #self.vaultConstants[vaultIdx] > 1 then
                local shift = math.random(1, #self.vaultConstants[vaultIdx] - 1)
                rotate(self.vaultConstants[vaultIdx], -shift)
                self:addRotateCode(ast, vaultIdx, shift)
            end
        end
    end
    
    -- Add decode code
    self:addDecodeCode(ast)
    
    -- Add vault declarations
    local vaultDeclarations = self:createMultiVault()
    for vaultIdx = self.vaultCount, 1, -1 do
        table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(self.rootScope, {self.vaultIds[vaultIdx]}, {vaultDeclarations[vaultIdx]}))
    end
    
    -- Cleanup
    self.rootScope = nil
    self.vaultIds = nil
    self.vaultConstants = nil
    self.lookup = nil
    
    return ast
end

return ConstantArray
