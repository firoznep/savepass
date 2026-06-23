-- PostgreSQL Schema for SafePass Password Manager

-- Drop tables if they exist (for clean setup/reset if needed)
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS vault_items;
DROP TABLE IF EXISTS users;

-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- bcrypt of the client-side Auth Hash
    key_derivation_salt VARCHAR(255) NOT NULL, -- unique salt used in client-side PBKDF2
    -- Recovery fields (wrapped master key + verifier)
    recovery_key_ciphertext TEXT,
    recovery_key_iv VARCHAR(255),
    recovery_code_hash VARCHAR(255), -- bcrypt of the recovery auth hash
    recovery_key_derivation_salt VARCHAR(255),
    vault_key_ciphertext TEXT,
    vault_key_iv VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Vault Items Table
CREATE TABLE vault_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_ciphertext TEXT NOT NULL, -- Encrypted label/key
    key_iv VARCHAR(255) NOT NULL, -- Initialization vector for label
    value_ciphertext TEXT NOT NULL, -- Encrypted value/password
    value_iv VARCHAR(255) NOT NULL, -- Initialization vector for value
    notes_ciphertext TEXT, -- Encrypted notes (optional)
    notes_iv VARCHAR(255), -- Initialization vector for notes
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Password reset tokens table (store hashed token + expiry)
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id)
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_vault_items_user_id ON vault_items(user_id);
CREATE INDEX idx_password_reset_user_id ON password_reset_tokens(user_id);
