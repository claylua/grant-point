import bcrypt from 'bcryptjs';
import connectPgSimple from 'connect-pg-simple';
import cors from 'cors';
import express from 'express';
import session from 'express-session';
import multer from 'multer';
import csv from 'csv-parser';
import streamifier from 'streamifier';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

import { initDatabase, pool, query, withTransaction } from './db.js';
import { environments, logDirectory, processingConfig } from './config.js';
import { getProcessingState, startProcessing } from './processor.js';

const app = express();
const port = process.env.PORT || 4000;

const PgSessionStore = connectPgSimple(session);

const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS
  ? process.env.CORS_ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean)
  : [];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

app.use((err, req, res, next) => {
  if (err?.message === 'Not allowed by CORS') {
    return res.status(403).json({ message: 'Origin not allowed by CORS policy.' });
  }
  return next(err);
});

app.use(express.json());

app.use(
  session({
    store: new PgSessionStore({
      pool,
      tableName: 'session',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'setel-session-secret',
    saveUninitialized: false,
    resave: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    },
  })
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
  },
});

const requiredColumns = [
  'title',
  'cardNumber',
  'adjustmentType',
  'amount',
  'basePoints',
  'bonusPoints',
];

const allowedRoles = ['admin', 'user'];

function sanitizeUser(row) {
  if (!row) {
    return null;
  }
  const { password_hash: _password, ...rest } = row;
  return rest;
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin privileges required' });
  }
  return next();
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    const { rows } = await query(
      `SELECT id, username, password_hash, role, created_at, updated_at
       FROM app_users
       WHERE LOWER(username) = LOWER($1)
       LIMIT 1`,
      [username]
    );

    if (!rows.length) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    res.json({ user: sanitizeUser(user) });
  } catch (err) {
    console.error('Login failed', err);
    res.status(500).json({ message: 'Failed to login.' });
  }
});

app.post('/api/logout', (req, res) => {
  if (!req.session) {
    return res.json({ message: 'Logged out' });
  }
  req.session.destroy((err) => {
    if (err) {
      console.error('Failed to destroy session', err);
      return res.status(500).json({ message: 'Failed to logout.' });
    }
    res.clearCookie('connect.sid');
    return res.json({ message: 'Logged out' });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  res.json({ user: req.session.user });
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await query(
    `SELECT id, username, role, created_at, updated_at
     FROM app_users
     ORDER BY username`
  );
  res.json({ users: rows });
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role = 'user' } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await query(
      `INSERT INTO app_users (username, password_hash, role)
       VALUES ($1, $2, $3)
       RETURNING id, username, role, created_at, updated_at`,
      [username.trim(), hash, role]
    );
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    console.error('Create user failed', err);
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Username already exists.' });
    }
    res.status(500).json({ message: 'Failed to create user.' });
  }
});

app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password, role } = req.body || {};
  if (!password && !role) {
    return res.status(400).json({ message: 'Provide password and/or role to update.' });
  }

  if (role && !allowedRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role.' });
  }

  try {
    const updates = [];
    const values = [];
    let index = 1;

    if (role) {
      updates.push(`role = $${index++}`);
      values.push(role);
    }

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${index++}`);
      values.push(hash);
    }

    values.push(id);

    const { rows } = await query(
      `UPDATE app_users
       SET ${updates.join(', ')}, updated_at = NOW()
       WHERE id = $${index}
       RETURNING id, username, role, created_at, updated_at`,
      values
    );

    if (!rows.length) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({ user: rows[0] });
  } catch (err) {
    console.error('Update user failed', err);
    res.status(500).json({ message: 'Failed to update user.' });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;

  if (req.session.user.id === id) {
    return res.status(400).json({ message: 'You cannot delete your own account.' });
  }

  try {
    const { rows: targetRows } = await query(
      'SELECT id, role FROM app_users WHERE id = $1',
      [id]
    );

    if (!targetRows.length) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (targetRows[0].role === 'admin') {
      const { rows: adminCountRows } = await query(
        "SELECT COUNT(*)::int AS count FROM app_users WHERE role = 'admin'"
      );
      if (adminCountRows[0].count <= 1) {
        return res.status(400).json({ message: 'Cannot remove the last admin user.' });
      }
    }

    await query('DELETE FROM app_users WHERE id = $1', [id]);
    res.json({ message: 'User removed.' });
  } catch (err) {
    console.error('Delete user failed', err);
    res.status(500).json({ message: 'Failed to delete user.' });
  }
});

function validateRow(row) {
  for (const column of requiredColumns) {
    if (!(column in row)) {
      throw new Error(`Missing required column: ${column}`);
    }
  }
  const amount = row.amount !== undefined && row.amount !== '' ? Number(row.amount) : null;
  const basePoints = row.basePoints !== undefined && row.basePoints !== '' ? Number(row.basePoints) : null;
  const bonusPoints = row.bonusPoints !== undefined && row.bonusPoints !== '' ? Number(row.bonusPoints) : null;

  if (amount !== null && Number.isNaN(amount)) {
    throw new Error(`Invalid amount value: ${row.amount}`);
  }

  if (basePoints !== null && Number.isNaN(basePoints)) {
    throw new Error(`Invalid basePoints value: ${row.basePoints}`);
  }

  if (bonusPoints !== null && Number.isNaN(bonusPoints)) {
    throw new Error(`Invalid bonusPoints value: ${row.bonusPoints}`);
  }

  return {
    referenceId: row.referenceId?.trim() || null,
    title: row.title?.trim() || null,
    cardNumber: row.cardNumber?.trim() || null,
    adjustmentType: row.adjustmentType?.trim() || null,
    amount,
    merchantId: row.merchantId?.trim() || null,
    remarks: row.remarks?.trim() || null,
    basePoints,
    bonusPoints,
  };
}

app.get('/api/environments', requireAuth, (req, res) => {
  res.json({
    environments: Object.values(environments).map((env) => ({
      key: env.key,
      label: env.label,
    })),
  });
});

app.get('/api/status', requireAuth, async (req, res) => {
  const countsQuery = await query(
    `SELECT status, COUNT(*)::int AS count
     FROM grant_requests
     GROUP BY status`
  );

  const counts = countsQuery.rows.reduce(
    (acc, row) => {
      acc[row.status] = row.count;
      return acc;
    },
    { pending: 0, success: 0, error: 0, in_progress: 0 }
  );

  const total = Object.values(counts).reduce((sum, val) => sum + val, 0);

  const { rows: batchRows } = await query(
    'SELECT * FROM grant_batches ORDER BY created_at DESC LIMIT 1'
  );

  res.json({
    counts: {
      ...counts,
      total,
      processed: counts.success + counts.error,
      remaining: counts.pending + counts.in_progress,
    },
    batch: batchRows.length ? batchRows[0] : null,
    processing: getProcessingState(),
    pollIntervalMs: processingConfig.pollIntervalMs,
  });
});

app.get('/api/errors', requireAuth, async (req, res) => {
  const limit = Number(req.query.limit) || 100;
  const { rows } = await query(
    `SELECT id, row_number, reference_id, title, card_number, adjustment_type,
            amount, merchant_id, remarks, base_points, bonus_points, response_status,
            error_message, raw_error, processed_at
     FROM grant_requests
     WHERE status = 'error'
     ORDER BY id
     LIMIT $1`,
    [limit]
  );

  res.json({ errors: rows });
});

app.post('/api/upload', requireAuth, upload.single('csv'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'CSV file is required.' });
  }

  const { rows: existingRows } = await query(
    'SELECT COUNT(*)::int AS count FROM grant_requests'
  );

  if (existingRows[0].count > 0) {
    return res.status(400).json({
      message: 'Existing data found. Please delete current data before uploading a new CSV.',
    });
  }

  const parsedRows = [];

  try {
    await new Promise((resolve, reject) => {
      streamifier
        .createReadStream(req.file.buffer)
        .pipe(csv())
        .on('data', (data) => {
          parsedRows.push(validateRow(data));
        })
        .on('end', resolve)
        .on('error', reject);
    });
  } catch (err) {
    return res.status(400).json({ message: `Failed to parse CSV: ${err.message}` });
  }

  if (!parsedRows.length) {
    return res.status(400).json({ message: 'CSV file is empty.' });
  }

  const batchId = uuidv4();
  const logFileName = `GrantPointResult-${batchId}.csv`;

  try {
    await withTransaction(async (client) => {
      await client.query(
        'INSERT INTO grant_batches (id, source_file, log_file_name) VALUES ($1, $2, $3)',
        [batchId, req.file.originalname, logFileName]
      );

      const batchSize = 500;
      for (let i = 0; i < parsedRows.length; i += batchSize) {
        const chunk = parsedRows.slice(i, i + batchSize);
        const values = [];
        const placeholders = chunk.map((row, index) => {
          const baseIndex = index * 11;
          values.push(
            batchId,
            i + index + 1,
            row.referenceId,
            row.title,
            row.cardNumber,
            row.adjustmentType,
            row.amount,
            row.merchantId,
            row.remarks,
            row.basePoints,
            row.bonusPoints
          );
          return `($${baseIndex + 1}, $${baseIndex + 2}, $${baseIndex + 3}, $${baseIndex + 4}, $${baseIndex + 5}, $${baseIndex + 6}, $${baseIndex + 7}, $${baseIndex + 8}, $${baseIndex + 9}, $${baseIndex + 10}, $${baseIndex + 11})`;
        });

        await client.query(
          `INSERT INTO grant_requests (
            batch_id,
            row_number,
            reference_id,
            title,
            card_number,
            adjustment_type,
            amount,
            merchant_id,
            remarks,
            base_points,
            bonus_points
          ) VALUES ${placeholders.join(',')}`,
          values
        );
      }
    });
  } catch (err) {
    console.error('Failed to store CSV data', err);
    return res.status(500).json({ message: 'Failed to store CSV data.' });
  }

  res.json({
    message: `Uploaded ${parsedRows.length} rows successfully.`,
    batchId,
    logFileName,
    totalRows: parsedRows.length,
  });
});

app.post('/api/process', requireAuth, async (req, res) => {
  const { environment, confirmProduction } = req.body;
  if (!environment) {
    return res.status(400).json({ message: 'Environment is required.' });
  }

  if (environment === 'production' && !confirmProduction) {
    return res.status(400).json({ message: 'Production processing requires explicit confirmation.' });
  }

  const envConfig = environments[environment];
  if (!envConfig) {
    return res.status(400).json({ message: 'Invalid environment selection.' });
  }

  const { rows: pendingRows } = await query(
    "SELECT COUNT(*)::int AS count FROM grant_requests WHERE status = 'pending'"
  );
  if (!pendingRows[0].count) {
    return res.status(400).json({ message: 'No pending records to process.' });
  }

  try {
    const state = await startProcessing(environment);
    res.json({ message: 'Processing started.', state });
  } catch (err) {
    res.status(409).json({ message: err.message });
  }
});

app.delete('/api/data', requireAuth, requireAdmin, async (req, res) => {
  const { confirm } = req.query;
  if (confirm !== 'true') {
    return res.status(400).json({ message: 'Confirmation required to delete data.' });
  }

  const { rows: batches } = await query(
    'SELECT log_file_name FROM grant_batches ORDER BY created_at DESC'
  );

  try {
    await withTransaction(async (client) => {
      await client.query('TRUNCATE grant_requests RESTART IDENTITY');
      await client.query('DELETE FROM grant_batches');
    });

    for (const batch of batches) {
      const filePath = path.join(logDirectory, batch.log_file_name);
      try {
        await fs.promises.unlink(filePath);
      } catch (err) {
        if (err.code !== 'ENOENT') {
          console.warn(`Unable to remove log file ${filePath}`, err.message);
        }
      }
    }
  } catch (err) {
    console.error('Failed to delete data', err);
    return res.status(500).json({ message: 'Failed to delete data.' });
  }

  res.json({ message: 'Data and logs removed.' });
});

app.get('/api/log-file', requireAuth, async (req, res) => {
  const { rows } = await query(
    'SELECT log_file_name FROM grant_batches ORDER BY created_at DESC LIMIT 1'
  );
  if (!rows.length) {
    return res.status(404).json({ message: 'No log file available.' });
  }

  const logFile = rows[0].log_file_name;
  const filePath = path.join(logDirectory, logFile);
  try {
    await fs.promises.access(filePath, fs.constants.R_OK);
  } catch (err) {
    return res.status(404).json({ message: 'Log file not found.' });
  }

  res.download(filePath, logFile);
});

app.get('/api/ping', requireAuth, (req, res) => {
  res.json({ ok: true });
});

(async () => {
  try {
    await initDatabase();
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
