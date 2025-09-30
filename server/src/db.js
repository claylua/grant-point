import bcrypt from 'bcryptjs';
import { Pool } from 'pg';
import { dbConfig } from './config.js';

export const pool = new Pool(dbConfig);

export async function initDatabase() {
  const client = await pool.connect();
  let beganTransaction = false;
  try {
    const schemaStatements = [
      'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";',
      `CREATE TABLE IF NOT EXISTS grant_batches (
        id UUID PRIMARY KEY,
        source_file TEXT NOT NULL,
        log_file_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'uploaded',
        environment TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );`,
      `CREATE TABLE IF NOT EXISTS grant_requests (
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
      );`,
      'CREATE INDEX IF NOT EXISTS idx_grant_requests_status ON grant_requests(status);',
      'CREATE INDEX IF NOT EXISTS idx_grant_requests_batch ON grant_requests(batch_id);',
      `CREATE OR REPLACE FUNCTION set_updated_at()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = NOW();
          RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;`,
      `DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_trigger
          WHERE tgname = 'set_grant_batches_updated_at'
        ) THEN
          CREATE TRIGGER set_grant_batches_updated_at
          BEFORE UPDATE ON grant_batches
          FOR EACH ROW
          EXECUTE FUNCTION set_updated_at();
        END IF;
      END;
      $$;`,
      `DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_trigger
          WHERE tgname = 'set_grant_requests_updated_at'
        ) THEN
          CREATE TRIGGER set_grant_requests_updated_at
          BEFORE UPDATE ON grant_requests
          FOR EACH ROW
          EXECUTE FUNCTION set_updated_at();
        END IF;
      END;
      $$;`,
      `CREATE TABLE IF NOT EXISTS app_users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );`,
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_app_users_username ON app_users(LOWER(username));',
      `DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_trigger WHERE tgname = 'set_app_users_updated_at'
        ) THEN
          CREATE TRIGGER set_app_users_updated_at
          BEFORE UPDATE ON app_users
          FOR EACH ROW
          EXECUTE FUNCTION set_updated_at();
        END IF;
      END;
      $$;`
    ];

    for (const statement of schemaStatements) {
      await client.query(statement);
    }

    await client.query('BEGIN');
    beganTransaction = true;
    await client.query("UPDATE grant_requests SET status = 'pending' WHERE status = 'in_progress'");
    const { rows: existingAdmin } = await client.query(
      'SELECT id FROM app_users WHERE LOWER(username) = LOWER($1) LIMIT 1',
      ['clay']
    );

    if (!existingAdmin.length) {
      const hash = await bcrypt.hash('Setelsetel@2025', 10);
      await client.query(
        'INSERT INTO app_users (username, password_hash, role) VALUES ($1, $2, $3)',
        ['clay', hash, 'admin']
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    if (beganTransaction) {
      await client.query('ROLLBACK');
    }
    console.error('Failed to initialize database state', error);
    throw error;
  } finally {
    client.release();
  }
}

export async function query(text, params) {
  return pool.query(text, params);
}

export async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
