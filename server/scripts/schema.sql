CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS grant_batches (
    id UUID PRIMARY KEY,
    source_file TEXT NOT NULL,
    log_file_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'uploaded',
    environment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS grant_requests (
    id BIGSERIAL PRIMARY KEY,
    batch_id UUID NOT NULL REFERENCES grant_batches(id) ON DELETE CASCADE,
    row_number INTEGER NOT NULL,
    reference_id TEXT,
    title TEXT,
    card_number TEXT,
    adjustment_type TEXT,
    amount NUMERIC(18,2),
    merchant_id TEXT,
    remarks TEXT,
    base_points INTEGER,
    bonus_points INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    response_status INTEGER,
    error_message TEXT,
    raw_error JSONB,
    raw_response JSONB,
    environment TEXT,
    last_attempt_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_grant_requests_status ON grant_requests(status);
CREATE INDEX IF NOT EXISTS idx_grant_requests_batch ON grant_requests(batch_id);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_grant_batches_updated_at ON grant_batches;
CREATE TRIGGER set_grant_batches_updated_at
BEFORE UPDATE ON grant_batches
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS set_grant_requests_updated_at ON grant_requests;
CREATE TRIGGER set_grant_requests_updated_at
BEFORE UPDATE ON grant_requests
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
