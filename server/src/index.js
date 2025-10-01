import './env.js';
import bcrypt from 'bcryptjs';
import connectPgSimple from 'connect-pg-simple';
import cors from 'cors';
import express from 'express';
import https from 'https';
import session from 'express-session';
import multer from 'multer';
import csv from 'csv-parser';
import streamifier from 'streamifier';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

import { initDatabase, pool, query, withTransaction } from './db.js';
import { getRecentAuditLogs, recordAuditEvent } from './audit.js';
import { environments, logDirectory, processingConfig, serverConfig } from './config.js';
import {
  getProcessingState,
  getProcessingSettings,
  startProcessing,
  updateProcessingSettings,
  pauseProcessing,
  resumeProcessing,
} from './processor.js';

const app = express();
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

function requireClay(req, res, next) {
  const username = req.session?.user?.username;
  if (!username || username.toLowerCase() !== 'clay') {
    return res.status(403).json({ message: 'Clay privileges required' });
  }
  return next();
}

function tryStartHttpsServer() {
  const {
    enabled,
    keyPath,
    certPath,
    port: httpsPort,
    passphrase,
    explicitlyEnabled,
    hasCredentials,
  } = serverConfig.https;

  if (!enabled) {
    if (explicitlyEnabled && !hasCredentials) {
      console.warn(
        'HTTPS_ENABLED is set but HTTPS_KEY_PATH or HTTPS_CERT_PATH is missing. Skipping HTTPS server startup.'
      );
    }
    return;
  }

  try {
    const credentials = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };

    if (passphrase) {
      credentials.passphrase = passphrase;
    }

    https.createServer(credentials, app).listen(httpsPort, () => {
      console.log(`HTTPS server running on port ${httpsPort}`);
    });
  } catch (error) {
    console.error('Failed to start HTTPS server', error);
  }
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    await recordAuditEvent({
      username,
      action: 'login_attempt',
      details: {
        outcome: 'missing_credentials',
        hasUsername: Boolean(username),
        hasPassword: Boolean(password),
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
      await recordAuditEvent({
        username,
        action: 'login_attempt',
        details: { outcome: 'user_not_found' },
        ipAddress: req.ip,
        method: req.method,
        path: req.path,
      });
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await recordAuditEvent({
        userId: user.id,
        username: user.username,
        action: 'login_attempt',
        details: { outcome: 'invalid_password' },
        ipAddress: req.ip,
        method: req.method,
        path: req.path,
      });
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    await recordAuditEvent({
      userId: user.id,
      username: user.username,
      action: 'login',
      details: { outcome: 'success' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.json({ user: sanitizeUser(user) });
  } catch (err) {
    console.error('Login failed', err);
    await recordAuditEvent({
      username,
      action: 'login_attempt',
      details: { outcome: 'error', error: err.message },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.status(500).json({ message: 'Failed to login.' });
  }
});

app.post('/api/logout', (req, res) => {
  const user = req.session?.user;
  if (!req.session) {
    return res.json({ message: 'Logged out' });
  }
  req.session.destroy((err) => {
    if (err) {
      console.error('Failed to destroy session', err);
      if (user) {
        recordAuditEvent({
          userId: user.id,
          username: user.username,
          action: 'logout',
          details: { outcome: 'error', error: err.message },
          ipAddress: req.ip,
          method: req.method,
          path: req.path,
        }).catch((error) => {
          console.error('Failed to record logout error audit event', error);
        });
      }
      return res.status(500).json({ message: 'Failed to logout.' });
    }
    res.clearCookie('connect.sid');
    if (user) {
      recordAuditEvent({
        userId: user.id,
        username: user.username,
        action: 'logout',
        details: { outcome: 'success' },
        ipAddress: req.ip,
        method: req.method,
        path: req.path,
      }).catch((error) => {
        console.error('Failed to record logout audit event', error);
      });
    }
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

app.get('/api/audit-logs', requireAuth, requireClay, async (req, res) => {
  const limit = Number(req.query.limit) || 200;
  const logs = await getRecentAuditLogs({ limit });
  res.json({ logs });
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role = 'user' } = req.body || {};
  if (!username || !password) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'create_user',
      details: {
        outcome: 'missing_fields',
        providedUsername: Boolean(username),
        providedPassword: Boolean(password),
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  if (!allowedRoles.includes(role)) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'create_user',
      details: { outcome: 'invalid_role', attemptedRole: role },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
    const createdUser = rows[0];

    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'create_user',
      details: {
        targetUserId: createdUser.id,
        targetUsername: createdUser.username,
        role,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.status(201).json({ user: createdUser });
  } catch (err) {
    console.error('Create user failed', err);
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'create_user',
      details: {
        outcome: err.code === '23505' ? 'duplicate_username' : 'error',
        targetUsername: username.trim(),
        role,
        error: err.message,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'update_user',
      details: { outcome: 'missing_fields', targetUserId: id },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'Provide password and/or role to update.' });
  }

  if (role && !allowedRoles.includes(role)) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'update_user',
      details: { outcome: 'invalid_role', targetUserId: id, attemptedRole: role },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
      await recordAuditEvent({
        userId: req.session.user.id,
        username: req.session.user.username,
        action: 'update_user',
        details: {
          outcome: 'target_not_found',
          targetUserId: id,
          updatedRole: role,
          passwordReset: Boolean(password),
        },
        ipAddress: req.ip,
        method: req.method,
        path: req.path,
      });
      return res.status(404).json({ message: 'User not found.' });
    }

    const updatedUser = rows[0];
    const details = {
      targetUserId: updatedUser.id,
      targetUsername: updatedUser.username,
    };
    if (role) {
      details.updatedRole = role;
    }
    if (password) {
      details.passwordReset = true;
    }

    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'update_user',
      details,
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.json({ user: updatedUser });
  } catch (err) {
    console.error('Update user failed', err);
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'update_user',
      details: {
        outcome: 'error',
        targetUserId: id,
        updatedRole: role,
        passwordReset: Boolean(password),
        error: err.message,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.status(500).json({ message: 'Failed to update user.' });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;

  if (req.session.user.id === id) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'delete_user',
      details: { outcome: 'self_delete_attempt' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'You cannot delete your own account.' });
  }

  try {
    const { rows: targetRows } = await query(
      'SELECT id, username, role FROM app_users WHERE id = $1',
      [id]
    );

    if (!targetRows.length) {
      await recordAuditEvent({
        userId: req.session.user.id,
        username: req.session.user.username,
        action: 'delete_user',
        details: { outcome: 'target_not_found', targetUserId: id },
        ipAddress: req.ip,
        method: req.method,
        path: req.path,
      });
      return res.status(404).json({ message: 'User not found.' });
    }

    if (targetRows[0].role === 'admin') {
      const { rows: adminCountRows } = await query(
        "SELECT COUNT(*)::int AS count FROM app_users WHERE role = 'admin'"
      );
      if (adminCountRows[0].count <= 1) {
        await recordAuditEvent({
          userId: req.session.user.id,
          username: req.session.user.username,
          action: 'delete_user',
          details: {
            outcome: 'prevented_last_admin_removal',
            targetUserId: targetRows[0].id,
            targetUsername: targetRows[0].username,
          },
          ipAddress: req.ip,
          method: req.method,
          path: req.path,
        });
        return res.status(400).json({ message: 'Cannot remove the last admin user.' });
      }
    }

    await query('DELETE FROM app_users WHERE id = $1', [id]);

    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'delete_user',
      details: {
        targetUserId: targetRows[0].id,
        targetUsername: targetRows[0].username,
        targetRole: targetRows[0].role,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.json({ message: 'User removed.' });
  } catch (err) {
    console.error('Delete user failed', err);
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'delete_user',
      details: { outcome: 'error', targetUserId: id, error: err.message },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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

  const processing = getProcessingState();
  const settings = await getProcessingSettings();

  const activeChunkSize = processing.running ? processing.chunkSize : settings.chunkSize;
  const activeDelaySeconds = processing.running ? processing.delaySeconds : settings.delaySeconds;
  const totalRemaining = counts.pending + counts.in_progress;
  const estimatedChunks = activeChunkSize > 0 ? Math.ceil(totalRemaining / activeChunkSize) : 0;
  const estimatedDurationSeconds = estimatedChunks * activeDelaySeconds;

  res.json({
    counts: {
      ...counts,
      total,
      processed: counts.success + counts.error,
      remaining: totalRemaining,
    },
    batch: batchRows.length ? batchRows[0] : null,
    processing,
    settings: {
      current: settings,
      defaults: {
        chunkSize: processingConfig.defaultChunkSize,
        delaySeconds: processingConfig.defaultDelaySeconds,
      },
      limits: {
        minChunkSize: processingConfig.minChunkSize,
        maxChunkSize: processingConfig.maxChunkSize,
        minDelaySeconds: processingConfig.minDelaySeconds,
        maxDelaySeconds: processingConfig.maxDelaySeconds,
      },
      editable: !processing.running || processing.paused,
    },
    estimates: {
      totalRemaining,
      chunkSize: activeChunkSize,
      delaySeconds: activeDelaySeconds,
      estimatedDurationSeconds,
      estimatedChunks,
    },
    pollIntervalMs: processingConfig.pollIntervalMs,
  });
});

app.get('/api/processing-settings', requireAuth, async (req, res) => {
  const [settings, processing] = await Promise.all([
    getProcessingSettings(),
    getProcessingState(),
  ]);

  res.json({
    settings,
    defaults: {
      chunkSize: processingConfig.defaultChunkSize,
      delaySeconds: processingConfig.defaultDelaySeconds,
    },
    limits: {
      minChunkSize: processingConfig.minChunkSize,
      maxChunkSize: processingConfig.maxChunkSize,
      minDelaySeconds: processingConfig.minDelaySeconds,
      maxDelaySeconds: processingConfig.maxDelaySeconds,
    },
    editable: !processing.running || processing.paused,
  });
});

app.put('/api/processing-settings', requireAuth, requireAdmin, async (req, res) => {
  const { chunkSize, delaySeconds } = req.body || {};
  const processing = getProcessingState();

  if (processing.running && !processing.paused) {
    return res.status(409).json({ message: 'Pause processing before updating settings.' });
  }

  if (chunkSize === undefined || delaySeconds === undefined) {
    return res.status(400).json({ message: 'Both chunkSize and delaySeconds are required.' });
  }

  const previous = await getProcessingSettings();

  try {
    const updated = await updateProcessingSettings({ chunkSize, delaySeconds });

    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'update_processing_settings',
      details: {
        previous,
        updated,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.json({ settings: updated });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
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

app.get('/api/errors/export', requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT reference_id, title, card_number, adjustment_type, amount,
            merchant_id, remarks, base_points, bonus_points
     FROM grant_requests
     WHERE status = 'error'
     ORDER BY row_number, id`
  );

  if (!rows.length) {
    return res.status(404).json({ message: 'No error rows available to export.' });
  }

  const header = [
    'referenceId',
    'title',
    'cardNumber',
    'adjustmentType',
    'amount',
    'merchantId',
    'remarks',
    'basePoints',
    'bonusPoints',
  ];

  const escape = (value) => {
    if (value === null || value === undefined) {
      return '';
    }
    const stringValue = String(value);
    if (stringValue.includes('"') || stringValue.includes(',') || stringValue.includes('\n')) {
      return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
  };

  const lines = [header.join(',')];
  for (const row of rows) {
    lines.push(
      [
        row.reference_id || '',
        row.title || '',
        row.card_number || '',
        row.adjustment_type || '',
        row.amount ?? '',
        row.merchant_id || '',
        row.remarks || '',
        row.base_points ?? '',
        row.bonus_points ?? '',
      ]
        .map(escape)
        .join(',')
    );
  }

  const csvContent = lines.join('\n');
  const timestamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
  const filename = `grant-errors-${timestamp}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csvContent);

  recordAuditEvent({
    userId: req.session.user.id,
    username: req.session.user.username,
    action: 'export_error_csv',
    details: { outcome: 'success', rows: rows.length },
    ipAddress: req.ip,
    method: req.method,
    path: req.path,
  }).catch((error) => {
    console.error('Failed to record export_error_csv audit event', error);
  });
});

app.get('/api/success/export', requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT reference_id, title, card_number, adjustment_type, amount,
            merchant_id, remarks, base_points, bonus_points
     FROM grant_requests
     WHERE status = 'success'
     ORDER BY row_number, id`
  );

  if (!rows.length) {
    return res.status(404).json({ message: 'No successful rows available to export.' });
  }

  const header = [
    'referenceId',
    'title',
    'cardNumber',
    'adjustmentType',
    'amount',
    'merchantId',
    'remarks',
    'basePoints',
    'bonusPoints',
  ];

  const escape = (value) => {
    if (value === null || value === undefined) {
      return '';
    }
    const stringValue = String(value);
    if (stringValue.includes('"') || stringValue.includes(',') || stringValue.includes('\n')) {
      return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
  };

  const lines = [header.join(',')];
  for (const row of rows) {
    lines.push(
      [
        row.reference_id || '',
        row.title || '',
        row.card_number || '',
        row.adjustment_type || '',
        row.amount ?? '',
        row.merchant_id || '',
        row.remarks || '',
        row.base_points ?? '',
        row.bonus_points ?? '',
      ]
        .map(escape)
        .join(',')
    );
  }

  const csvContent = lines.join('\n');
  const timestamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0];
  const filename = `grant-success-${timestamp}.csv`;

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csvContent);

  recordAuditEvent({
    userId: req.session.user.id,
    username: req.session.user.username,
    action: 'export_success_csv',
    details: { outcome: 'success', rows: rows.length },
    ipAddress: req.ip,
    method: req.method,
    path: req.path,
  }).catch((error) => {
    console.error('Failed to record export_success_csv audit event', error);
  });
});

app.post('/api/upload', requireAuth, upload.single('csv'), async (req, res) => {
  if (!req.file) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'upload_csv',
      details: { outcome: 'missing_file' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'CSV file is required.' });
  }

  const { rows: existingRows } = await query(
    'SELECT COUNT(*)::int AS count FROM grant_requests'
  );

  if (existingRows[0].count > 0) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'upload_csv',
      details: { outcome: 'aborted_existing_data', existingRows: existingRows[0].count },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'upload_csv',
      details: { outcome: 'parse_error', error: err.message },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: `Failed to parse CSV: ${err.message}` });
  }

  if (!parsedRows.length) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'upload_csv',
      details: { outcome: 'empty_file', fileName: req.file.originalname },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'upload_csv',
      details: { outcome: 'storage_error', error: err.message, fileName: req.file.originalname },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(500).json({ message: 'Failed to store CSV data.' });
  }

  const responsePayload = {
    message: `Uploaded ${parsedRows.length} rows successfully.`,
    batchId,
    logFileName,
    totalRows: parsedRows.length,
  };

  await recordAuditEvent({
    userId: req.session.user.id,
    username: req.session.user.username,
    action: 'upload_csv',
    details: {
      outcome: 'success',
      batchId,
      fileName: req.file.originalname,
      totalRows: parsedRows.length,
    },
    ipAddress: req.ip,
    method: req.method,
    path: req.path,
  });

  res.json(responsePayload);
});

app.post('/api/process/pause', requireAuth, requireAdmin, async (req, res) => {
  const stateBefore = getProcessingState();

  if (!stateBefore.running) {
    return res.status(400).json({ message: 'Processor is not running.' });
  }

  if (stateBefore.paused) {
    return res.json({ processing: stateBefore });
  }

  try {
    const state = pauseProcessing();
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'pause_processing',
      details: {
        outcome: 'success',
        environment: state.environment,
        chunkSize: state.chunkSize,
        delaySeconds: state.delaySeconds,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.json({ processing: state });
  } catch (error) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'pause_processing',
      details: {
        outcome: 'error',
        error: error.message,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.status(400).json({ message: error.message });
  }
});

app.post('/api/process/resume', requireAuth, requireAdmin, async (req, res) => {
  const stateBefore = getProcessingState();

  if (!stateBefore.running) {
    return res.status(400).json({ message: 'Processor is not running.' });
  }

  if (!stateBefore.paused) {
    return res.status(400).json({ message: 'Processor is not paused.' });
  }

  try {
    const state = resumeProcessing();
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'resume_processing',
      details: {
        outcome: 'success',
        environment: state.environment,
        chunkSize: state.chunkSize,
        delaySeconds: state.delaySeconds,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });

    res.json({ processing: state });
  } catch (error) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'resume_processing',
      details: {
        outcome: 'error',
        error: error.message,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.status(400).json({ message: error.message });
  }
});

app.post('/api/process', requireAuth, async (req, res) => {
  const { environment, confirmProduction } = req.body;
  if (!environment) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: { outcome: 'missing_environment' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'Environment is required.' });
  }

  if (environment === 'production' && !confirmProduction) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: { outcome: 'missing_production_confirmation' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'Production processing requires explicit confirmation.' });
  }

  const envConfig = environments[environment];
  if (!envConfig) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: { outcome: 'invalid_environment', environment },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'Invalid environment selection.' });
  }

  const { rows: pendingRows } = await query(
    "SELECT COUNT(*)::int AS count FROM grant_requests WHERE status = 'pending'"
  );
  if (!pendingRows[0].count) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: { outcome: 'no_pending_records', environment },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(400).json({ message: 'No pending records to process.' });
  }

  try {
    const state = await startProcessing(environment);
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: {
        outcome: 'success',
        environment,
        chunkSize: state.chunkSize,
        delaySeconds: state.delaySeconds,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.json({ message: 'Processing started.', state });
  } catch (err) {
    const current = getProcessingState();
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'start_processing',
      details: {
        outcome: 'error',
        environment,
        error: err.message,
        chunkSize: current.chunkSize,
        delaySeconds: current.delaySeconds,
        running: current.running,
      },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    res.status(409).json({ message: err.message });
  }
});

app.delete('/api/data', requireAuth, requireAdmin, async (req, res) => {
  const { confirm } = req.query;
  if (confirm !== 'true') {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'delete_data',
      details: { outcome: 'missing_confirmation' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
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
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'delete_data',
      details: { outcome: 'error', error: err.message },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(500).json({ message: 'Failed to delete data.' });
  }

  await recordAuditEvent({
    userId: req.session.user.id,
    username: req.session.user.username,
    action: 'delete_data',
    details: { outcome: 'success', logFilesRemoved: batches.length },
    ipAddress: req.ip,
    method: req.method,
    path: req.path,
  });

  res.json({ message: 'Data and logs removed.' });
});

app.get('/api/log-file', requireAuth, async (req, res) => {
  const { rows } = await query(
    'SELECT log_file_name FROM grant_batches ORDER BY created_at DESC LIMIT 1'
  );
  if (!rows.length) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'download_log_file',
      details: { outcome: 'no_log_file' },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(404).json({ message: 'No log file available.' });
  }

  const logFile = rows[0].log_file_name;
  const filePath = path.join(logDirectory, logFile);
  try {
    await fs.promises.access(filePath, fs.constants.R_OK);
  } catch (err) {
    await recordAuditEvent({
      userId: req.session.user.id,
      username: req.session.user.username,
      action: 'download_log_file',
      details: { outcome: 'file_not_found', logFile },
      ipAddress: req.ip,
      method: req.method,
      path: req.path,
    });
    return res.status(404).json({ message: 'Log file not found.' });
  }

  recordAuditEvent({
    userId: req.session.user.id,
    username: req.session.user.username,
    action: 'download_log_file',
    details: { outcome: 'success', logFile },
    ipAddress: req.ip,
    method: req.method,
    path: req.path,
  }).catch((error) => {
    console.error('Failed to record download log audit event', error);
  });

  res.download(filePath, logFile);
});

app.get('/api/ping', requireAuth, (req, res) => {
  res.json({ ok: true });
});

(async () => {
  try {
    await initDatabase();
    const httpPort = serverConfig.port;
    app.listen(httpPort, () => {
      console.log(`HTTP server running on port ${httpPort}`);
    });
    tryStartHttpsServer();
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
