-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- AntiTamper.lua
--
-- Military-Grade Anti-Tamper for LuaU with Multi-Layer Validation

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local RandomStrings = require("prometheus.randomStrings")
local Parser = require("prometheus.parser");
local Enums = require("prometheus.enums");
local logger = require("logger");

local AntiTamper = Step:extend();
AntiTamper.Description = "LuaU-Compatible Multi-Layer Anti-Tamper with Roblox Environment Validation";
AntiTamper.Name = "Anti Tamper";

AntiTamper.SettingsDescriptor = {
    UseDebug = {
        type = "boolean",
        default = true,
        description = "Enable LuaU-compatible tamper detection (Recommended)"
    }
}

function AntiTamper:init(settings)
    self.UseDebug = settings.UseDebug
end

function AntiTamper:apply(ast, pipeline)
    if pipeline.PrettyPrint then
        logger:warn(string.format("\"%s\" cannot be used with PrettyPrint, ignoring \"%s\"", self.Name, self.Name));
        return ast;
    end
    
    local code = "do local valid = true;";
    
    if self.UseDebug then
        local testString = RandomStrings.randomString()
        local randomNum1 = math.random(1, 2^24)
        local randomNum2 = math.random(1, 2^24)
        local randomNum3 = math.random(1, 2^24)
        local randomNum4 = math.random(1, 2^24)
        
        code = code .. [[
            -- [LAYER 1] ROBLOX VM ENVIRONMENT VALIDATION
            local function validate_roblox_execution_environment()
                local execution_environment = getfenv()
                local critical_native_symbols = {
                    "game", "workspace", "script", "Instance", 
                    "Vector3", "CFrame", "pcall", "xpcall", 
                    "error", "typeof", "tick", "wait"
                }
                
                for _, native_symbol_name in ipairs(critical_native_symbols) do
                    local native_symbol_value = execution_environment[native_symbol_name]
                    if native_symbol_value == nil then
                        return false
                    end
                    if native_symbol_name == "pcall" or native_symbol_name == "xpcall" or native_symbol_name == "error" then
                        if type(native_symbol_value) ~= "function" then
                            return false
                        end
                    end
                end
                return true
            end
            
            -- [LAYER 2] SEALED REFERENCE INTEGRITY CHECKPOINT
            local sealed_reference_pcall = pcall
            local sealed_reference_xpcall = xpcall
            local sealed_reference_error = error
            local sealed_reference_string_char = string.char
            local sealed_reference_string_len = string.len
            local sealed_reference_string_gmatch = string.gmatch
            local sealed_reference_string_rep = string.rep
            local sealed_reference_string_sub = string.sub
            local sealed_reference_string_byte = string.byte
            local sealed_reference_tonumber = tonumber
            local sealed_reference_tostring = tostring
            local sealed_reference_table_concat = table.concat
            local sealed_reference_table_insert = table.insert
            local sealed_reference_math_random = math.random
            local sealed_reference_math_floor = math.floor
            local sealed_reference_math_abs = math.abs
            local sealed_reference_type = type
            local sealed_reference_rawget = rawget
            local sealed_reference_rawset = rawset
            local sealed_reference_getmetatable = getmetatable
            local sealed_reference_setmetatable = setmetatable
            
            -- [LAYER 3] FUNCTIONAL PURITY VERIFICATION
            local function verify_native_function_purity()
                local native_function_registry = {
                    pcall = sealed_reference_pcall,
                    xpcall = sealed_reference_xpcall,
                    error = sealed_reference_error,
                    string = {
                        char = sealed_reference_string_char,
                        len = sealed_reference_string_len,
                        gmatch = sealed_reference_string_gmatch,
                        rep = sealed_reference_string_rep,
                        sub = sealed_reference_string_sub,
                        byte = sealed_reference_string_byte
                    },
                    tonumber = sealed_reference_tonumber,
                    tostring = sealed_reference_tostring,
                    table = {
                        concat = sealed_reference_table_concat,
                        insert = sealed_reference_table_insert
                    },
                    math = {
                        random = sealed_reference_math_random,
                        floor = sealed_reference_math_floor,
                        abs = sealed_reference_math_abs
                    },
                    type = sealed_reference_type
                }
                
                local global_environment = _G
                for function_category, category_reference in pairs(native_function_registry) do
                    if function_category == "string" or function_category == "table" or function_category == "math" then
                        for method_name, sealed_method_reference in pairs(category_reference) do
                            if global_environment[function_category][method_name] ~= sealed_method_reference then
                                return false
                            end
                        end
                    else
                        if global_environment[function_category] ~= category_reference then
                            return false
                        end
                    end
                end
                return true
            end
            
            -- [LAYER 4] CALL STACK BEHAVIORAL ANALYSIS
            local function analyze_call_stack_behavioral_patterns()
                local recursion_depth_counter = 0
                local maximum_recursion_observed = 0
                
                local function recursive_stack_probe_mechanism()
                    recursion_depth_counter = recursion_depth_counter + 1
                    if recursion_depth_counter > maximum_recursion_observed then
                        maximum_recursion_observed = recursion_depth_counter
                    end
                    
                    if recursion_depth_counter < 20 then
                        sealed_reference_pcall(recursive_stack_probe_mechanism)
                    end
                    
                    recursion_depth_counter = recursion_depth_counter - 1
                end
                
                sealed_reference_pcall(recursive_stack_probe_mechanism)
                return maximum_recursion_observed >= 20
            end
            
            -- [LAYER 5] ERROR PROPAGATION VALIDATION
            local function validate_error_message_propagation_mechanism()
                local test_error_message_payload = "]] .. testString .. [["
                
                local propagation_result_status, propagated_error_payload = sealed_reference_pcall(function()
                    sealed_reference_error(test_error_message_payload, 0)
                end)
                
                if not propagation_result_status then
                    local error_string_representation = sealed_reference_tostring(propagated_error_payload)
                    return error_string_representation == test_error_message_payload
                end
                
                return false
            end
            
            -- [LAYER 6] MATHEMATICAL OPERATION INTEGRITY VERIFICATION
            local function verify_mathematical_operation_integrity()
                local operand_alpha = ]] .. randomNum1 .. [[
                local operand_beta = ]] .. randomNum2 .. [[
                local operand_gamma = ]] .. randomNum3 .. [[
                local operand_delta = ]] .. randomNum4 .. [[
                
                local complex_computation_result = ((operand_alpha * operand_beta) + (operand_gamma * operand_delta)) % 1000000
                local expected_computation_result = ]] .. tostring(((randomNum1 * randomNum2) + (randomNum3 * randomNum4)) % 1000000) .. [[
                
                return complex_computation_result == expected_computation_result
            end
            
            -- [LAYER 7] STRING MANIPULATION CONSISTENCY VALIDATION
            local function verify_string_manipulation_consistency()
                local alphabet_test_sequence = "abcdefghijklmnopqrstuvwxyz"
                local length_verification_result = sealed_reference_string_len(alphabet_test_sequence) == 26
                local byte_verification_result = sealed_reference_string_byte(alphabet_test_sequence, 1) == 97
                local char_verification_result = sealed_reference_string_char(97, 98, 99) == "abc"
                local rep_verification_result = sealed_reference_string_rep("x", 10) == "xxxxxxxxxx"
                local sub_verification_result = sealed_reference_string_sub(alphabet_test_sequence, 1, 5) == "abcde"
                
                return length_verification_result and byte_verification_result and char_verification_result and rep_verification_result and sub_verification_result
            end
            
            -- [LAYER 8] TABLE OPERATION INTEGRITY VALIDATION
            local function verify_table_operation_integrity()
                local sequential_table = {}
                for i = 1, 100 do
                    sealed_reference_table_insert(sequential_table, i * 2)
                end
                
                local concatenation_result = sealed_reference_table_concat(sequential_table, ",")
                local insertion_verification = #sequential_table == 100
                local value_verification = sequential_table[50] == 100
                local concatenation_header_verification = concatenation_result:sub(1, 5) == "2,4,6"
                
                return insertion_verification and value_verification and concatenation_header_verification
            end
            
            -- [LAYER 9] METATABLE INTEGRITY PROTECTION
            local function verify_metatable_integrity_protection()
                local protected_metatable_instance = {
                    __index = function(tabl, key) return sealed_reference_rawget(tabl, key) end,
                    __metatable = false
                }
                
                local protected_table_instance = sealed_reference_setmetatable({}, protected_metatable_instance)
                local metatable_access_success = sealed_reference_pcall(function()
                    local test_value = protected_table_instance.nonexistent_key
                end)
                
                return metatable_access_success
            end
            
            -- [LAYER 10] EXECUTION TIMING ANALYSIS
            local function analyze_execution_timing_characteristics()
                local timing_start_timestamp = tick()
                local computation_accumulator = 0
                
                for iteration_index = 1, 1000 do
                    computation_accumulator = computation_accumulator + (iteration_index * 2)
                end
                
                local timing_end_timestamp = tick()
                local elapsed_duration = timing_end_timestamp - timing_start_timestamp
                
                -- Computation should complete in reasonable time (< 1 second)
                -- Excessive delay suggests instrumentation
                return elapsed_duration < 1.0 and computation_accumulator == 1001000
            end
            
            -- [LAYER 11] TYPE SYSTEM INTEGRITY VALIDATION
            local function validate_type_system_integrity()
                local type_test_cases = {
                    number = 42,
                    string = "test",
                    boolean = true,
                    table = {},
                    ["function"] = function() end,
                    userdata = newproxy(true),
                    thread = coroutine.create(function() end)
                }
                
                for expected_type, test_value in pairs(type_test_cases) do
                    if sealed_reference_type(test_value) ~= expected_type then
                        return false
                    end
                end
                
                return true
            end
            
            -- [LAYER 12] FINAL DECISIVE VALIDATION PROTOCOL
            valid = valid and validate_roblox_execution_environment()
            valid = valid and verify_native_function_purity()
            valid = valid and analyze_call_stack_behavioral_patterns()
            valid = valid and validate_error_message_propagation_mechanism()
            valid = valid and verify_mathematical_operation_integrity()
            valid = valid and verify_string_manipulation_consistency()
            valid = valid and verify_table_operation_integrity()
            valid = valid and verify_metatable_integrity_protection()
            valid = valid and analyze_execution_timing_characteristics()
            valid = valid and validate_type_system_integrity()
            
            -- CRITICAL FAILURE RESPONSE
            if not valid then
                -- Execute infinite loop to halt script execution
                while true do
                    -- Permanent execution block
                end
            end
        ]]
    end
    
    code = code .. [[
    -- [POST-DEBUG] GENERAL ANTI-TAMPER CHECKS
    
    -- Anti-Beautify String Pattern Validation
    local gmatch = string.gmatch;
    local err = function() error("Tamper Detected!") end;

    local pcallIntact2 = false;
    local pcallIntact = pcall(function()
        pcallIntact2 = true;
    end) and pcallIntact2;

    local random = math.random;
    local tblconcat = table.concat;
    local unpkg = table and table.unpack or unpack;
    local n = random(3, 65);
    local acc1 = 0;
    local acc2 = 0;
    local pcallRet = {pcall(function() local a = ]] .. tostring(math.random(1, 2^24)) .. [[ - "]] .. RandomStrings.randomString() .. [[" ^ ]] .. tostring(math.random(1, 2^24)) .. [[ return "]] .. RandomStrings.randomString() .. [[" / a; end)};
    local origMsg = pcallRet[2];
    local line = tonumber(gmatch(tostring(origMsg), ':(%d*):')());
    
    for i = 1, n do
        local len = math.random(1, 100);
        local n2 = random(0, 255);
        local pos = random(1, len);
        local shouldErr = random(1, 2) == 1;
        local msg = origMsg:gsub(':(%d*):', ':' .. tostring(random(0, 10000)) .. ':');
        local arr = {pcall(function()
            if random(1, 2) == 1 or i == n then
                local line2 = tonumber(gmatch(tostring(({pcall(function() local a = ]] .. tostring(math.random(1, 2^24)) .. [[ - "]] .. RandomStrings.randomString() .. [[" ^ ]] .. tostring(math.random(1, 2^24)) .. [[ return "]] .. RandomStrings.randomString() .. [[" / a; end)})[2]), ':(%d*):')());
                valid = valid and line == line2;
            end
            if shouldErr then
                error(msg, 0);
            end
            local arr = {};
            for i = 1, len do
                arr[i] = random(0, 255);
            end
            arr[pos] = n2;
            return unpkg(arr);
        end)};
        if shouldErr then
            valid = valid and arr[1] == false and arr[2] == msg;
        else
            valid = valid and arr[1];
            acc1 = (acc1 + arr[pos + 1]) % 256;
            acc2 = (acc2 + n2) % 256;
        end
    end
    valid = valid and acc1 == acc2;

    -- Anti-Function-Arg-Hook
    local obj = setmetatable({}, {
        __tostring = err,
    });
    obj[math.random(1, 100)] = obj;
    (function() end)(obj);

    -- Execution Lock
    repeat until valid;
    ]]

    local parsed = Parser:new({LuaVersion = Enums.LuaVersion.Lua51}):parse(code);
    local doStat = parsed.body.statements[1];
    doStat.body.scope:setParent(ast.body.scope);
    table.insert(ast.body.statements, 1, doStat);

    return ast;
end

return AntiTamper;
