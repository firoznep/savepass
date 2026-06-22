-- PostgreSQL Schema for SafePass Password Manager

-- Drop tables if they exist (for clean setup/reset if needed)
DROP TABLE IF EXISTS vault_items;
DROP TABLE IF EXISTS users;

-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- bcrypt of the client-side Auth Hash
    key_derivation_salt VARCHAR(255) NOT NULL, -- unique salt used in client-side PBKDF2
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

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_vault_items_user_id ON vault_items(user_id);
