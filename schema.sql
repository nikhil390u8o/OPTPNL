-- Supabase SQL Editor me yeh sab run karo --

CREATE TABLE IF NOT EXISTS users (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    balance         NUMERIC DEFAULT 0,
    total_deposited NUMERIC DEFAULT 0,
    total_spent     NUMERIC DEFAULT 0,
    is_admin        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    phone          TEXT NOT NULL,
    country        TEXT NOT NULL,
    price          NUMERIC NOT NULL,
    string_session TEXT NOT NULL,
    is_sold        BOOLEAN DEFAULT FALSE,
    sold_to        BIGINT,
    sold_at        TIMESTAMP,
    created_at     TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    account_id BIGINT NOT NULL,
    amount     NUMERIC NOT NULL,
    phone      TEXT NOT NULL,
    otp        TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS used_utrs (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id  BIGINT,
    utr      TEXT UNIQUE NOT NULL,
    amount   NUMERIC,
    used_at  TIMESTAMP DEFAULT NOW()
);

-- Admin user banao (password change karo!)
INSERT INTO users (username, password_hash, is_admin)
VALUES ('admin', '$2b$12$placeholder', TRUE);
-- Note: Admin ka password app se register karke banao, phir is_admin=TRUE karo:
-- UPDATE users SET is_admin=TRUE WHERE username='tumhara_username';
