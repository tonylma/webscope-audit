CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    risk_score DOUBLE PRECISION DEFAULT 0,
    summary TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS domain_records (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    ip TEXT,
    record_type TEXT DEFAULT 'A',
    status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS url_discoveries (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    source TEXT DEFAULT 'manual',
    status_code INTEGER DEFAULT 0,
    depth INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public_files (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    file_type TEXT DEFAULT 'unknown',
    size_bytes INTEGER DEFAULT 0,
    sha256 TEXT DEFAULT '',
    risk_level TEXT DEFAULT 'low'
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    category TEXT DEFAULT 'general',
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT ''
);
