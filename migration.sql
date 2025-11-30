-- Whitelist + Blacklist
CREATE TABLE IF NOT EXISTS whitelist (
    user_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS blacklist (
    user_id TEXT PRIMARY KEY
);

-- Token system
CREATE TABLE IF NOT EXISTS tokens (
    user_id TEXT PRIMARY KEY,
    tokens INTEGER DEFAULT 0,
    last_reset TIMESTAMP DEFAULT NOW()
);

-- Gift cooldowns (3 gifts every 6 hours)
CREATE TABLE IF NOT EXISTS gift_cooldowns (
    user_id TEXT PRIMARY KEY,
    gifts_used INTEGER DEFAULT 0,
    last_gift TIMESTAMP DEFAULT NOW()
);

-- Script storage (your obfuscator system)
CREATE TABLE IF NOT EXISTS scripts (
    key VARCHAR(32) PRIMARY KEY,
    script TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
