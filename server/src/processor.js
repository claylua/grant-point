import fs from 'fs';
import path from 'path';
import axios from 'axios';
import csvWriter from 'csv-write-stream';
import { v4 as uuidv4 } from 'uuid';
import { credentials, environments, logDirectory, processingConfig } from './config.js';
import { pool, query } from './db.js';

const writerHeaders = [
  'referenceId',
  'title',
  'cardNumber',
  'adjustmentType',
  'amount',
  'merchantId',
  'remarks',
  'basePoints',
  'bonusPoints',
  'Status',
  'Error Message',
  'Raw Error'
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const PROCESSING_SETTINGS_TABLE_SQL = `CREATE TABLE IF NOT EXISTS processing_settings (
  id BOOLEAN PRIMARY KEY DEFAULT TRUE,
  chunk_size INTEGER NOT NULL CHECK (chunk_size > 0),
  delay_seconds INTEGER NOT NULL CHECK (delay_seconds > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`;

const INSERT_PROCESSING_DEFAULTS_SQL = `INSERT INTO processing_settings (id, chunk_size, delay_seconds)
VALUES (TRUE, $1, $2)
ON CONFLICT (id) DO NOTHING`;

const processingState = {
  running: false,
  paused: false,
  environment: null,
  batchId: null,
  startedAt: null,
  lastProcessedId: null,
  lastChunkStartedAt: null,
  lastChunkCompletedAt: null,
  nextRunAt: null,
  nextRunReason: null,
  chunkSize: processingConfig.defaultChunkSize,
  delaySeconds: processingConfig.defaultDelaySeconds,
  currentChunkSize: 0,
  totalProcessed: 0,
  totalErrors: 0,
  error: null,
};

export function getProcessingState() {
  return { ...processingState };
}

function setNextRun(atIso, reason = null) {
  processingState.nextRunAt = atIso;
  processingState.nextRunReason = reason;
}

function clearNextRun() {
  processingState.nextRunAt = null;
  processingState.nextRunReason = null;
}

function clearProcessingState(options = {}) {
  const {
    preserveCounters = false,
    preserveError = false,
  } = options;
  processingState.running = false;
  processingState.paused = false;
  processingState.environment = null;
  processingState.batchId = null;
  processingState.startedAt = null;
  processingState.lastProcessedId = null;
  processingState.lastChunkStartedAt = null;
  processingState.lastChunkCompletedAt = null;
  clearNextRun();
  processingState.currentChunkSize = 0;
  if (!preserveCounters) {
    processingState.totalProcessed = 0;
    processingState.totalErrors = 0;
  }
  if (!preserveError) {
    processingState.error = null;
  }
}

export function resetProcessingState() {
  clearProcessingState();
  return getProcessingState();
}

async function ensureProcessingSettingsTable() {
  try {
    await query(PROCESSING_SETTINGS_TABLE_SQL);
    await query(INSERT_PROCESSING_DEFAULTS_SQL, [
      processingConfig.defaultChunkSize,
      processingConfig.defaultDelaySeconds,
    ]);
  } catch (error) {
    console.error('Failed to ensure processing settings table', error);
    throw error;
  }
}

function normalizeSettingsInput({ chunkSize, delaySeconds }) {
  const normalizedChunk = Number.parseInt(chunkSize, 10);
  const normalizedDelay = Number.parseInt(delaySeconds, 10);

  if (!Number.isFinite(normalizedChunk)) {
    throw new Error('Chunk size must be a number.');
  }
  if (!Number.isFinite(normalizedDelay)) {
    throw new Error('Delay must be a number of seconds.');
  }

  if (normalizedChunk < processingConfig.minChunkSize || normalizedChunk > processingConfig.maxChunkSize) {
    throw new Error(
      `Chunk size must be between ${processingConfig.minChunkSize} and ${processingConfig.maxChunkSize}.`
    );
  }

  if (normalizedDelay < processingConfig.minDelaySeconds || normalizedDelay > processingConfig.maxDelaySeconds) {
    throw new Error(
      `Delay must be between ${processingConfig.minDelaySeconds} and ${processingConfig.maxDelaySeconds} seconds.`
    );
  }

  return {
    chunkSize: normalizedChunk,
    delaySeconds: normalizedDelay,
  };
}

export async function getProcessingSettings() {
  try {
    await ensureProcessingSettingsTable();
    const { rows } = await query(
      'SELECT chunk_size, delay_seconds, updated_at FROM processing_settings WHERE id = TRUE LIMIT 1'
    );
    if (!rows.length) {
      return {
        chunkSize: processingConfig.defaultChunkSize,
        delaySeconds: processingConfig.defaultDelaySeconds,
        updatedAt: null,
        error: null,
      };
    }

    const row = rows[0];
    return {
      chunkSize: row.chunk_size,
      delaySeconds: row.delay_seconds,
      updatedAt: row.updated_at,
      error: null,
    };
  } catch (error) {
    console.error('Failed to load processing settings', error);
    return {
      chunkSize: processingConfig.defaultChunkSize,
      delaySeconds: processingConfig.defaultDelaySeconds,
      updatedAt: null,
      error: error.message || 'Unable to load processing settings.',
    };
  }
}

export async function updateProcessingSettings(settings) {
  await ensureProcessingSettingsTable();
  const normalized = normalizeSettingsInput(settings);

  await query(
    'UPDATE processing_settings SET chunk_size = $1, delay_seconds = $2, updated_at = NOW() WHERE id = TRUE',
    [normalized.chunkSize, normalized.delaySeconds]
  );

  if (!processingState.running || processingState.paused) {
    processingState.chunkSize = normalized.chunkSize;
    processingState.delaySeconds = normalized.delaySeconds;
  }

  return getProcessingSettings();
}

export function pauseProcessing() {
  if (!processingState.running) {
    throw new Error('Processing is not currently running.');
  }

  if (processingState.paused) {
    return getProcessingState();
  }

  processingState.paused = true;
  clearNextRun();
  return getProcessingState();
}

export function resumeProcessing() {
  if (!processingState.running) {
    throw new Error('Processing is not currently running.');
  }

  if (!processingState.paused) {
    throw new Error('Processing is not paused.');
  }

  processingState.paused = false;
  clearNextRun();
  return getProcessingState();
}

async function waitWhilePaused() {
  while (processingState.running && processingState.paused) {
    await sleep(processingConfig.pauseCheckIntervalMs);
  }
}

async function waitWithPause(totalMs) {
  if (totalMs <= 0) {
    return;
  }

  let remaining = totalMs;
  while (remaining > 0 && processingState.running) {
    if (processingState.paused) {
      return;
    }
    const slice = Math.min(processingConfig.pauseCheckIntervalMs, remaining);
    await sleep(slice);
    remaining -= slice;
  }
}

async function waitForThrottle(delayMs) {
  const effectiveDelay = Math.max(delayMs, 0);
  if (effectiveDelay <= 0) {
    return;
  }

  const scheduledAt = new Date(Date.now() + effectiveDelay).toISOString();
  setNextRun(scheduledAt, 'throttle');
  try {
    await waitWithPause(effectiveDelay);
  } finally {
    if (processingState.nextRunAt === scheduledAt && processingState.nextRunReason === 'throttle') {
      clearNextRun();
    }
  }
}

async function getActiveBatch(client = pool) {
  const { rows } = await client.query(
    "SELECT * FROM grant_batches ORDER BY created_at DESC LIMIT 1"
  );
  if (!rows.length) {
    throw new Error('No uploaded batch found. Please upload a CSV first.');
  }
  return rows[0];
}

async function getAccessToken(envConfig) {
  const response = await axios.post(
    envConfig.loginUrl,
    {
      identifier: credentials.identifier,
      password: credentials.password,
    },
    {
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    }
  );
  return response.data.accessToken;
}

async function ensureLogDirectoryExists() {
  await fs.promises.mkdir(logDirectory, { recursive: true });
}

async function createCsvWriter(logFileName) {
  await ensureLogDirectoryExists();
  const fullPath = path.join(logDirectory, logFileName);
  let sendHeaders = true;
  try {
    await fs.promises.access(fullPath, fs.constants.F_OK);
    const stats = await fs.promises.stat(fullPath);
    sendHeaders = stats.size === 0;
  } catch (err) {
    // File does not exist; will create and send headers
    sendHeaders = true;
  }

  const writer = csvWriter({ headers: writerHeaders, sendHeaders });
  const stream = fs.createWriteStream(fullPath, { flags: 'a' });
  writer.pipe(stream);
  return { writer, stream, fullPath };
}

async function updateBatchStatus(batchId, status, environment) {
  await query(
    'UPDATE grant_batches SET status = $1, environment = $2 WHERE id = $3',
    [status, environment, batchId]
  );
}

async function processChunk(rows, envConfig, token, writer) {
  let accessToken = token;
  const retryRows = [];

  for (const row of rows) {
    let handled = false;
    while (processingState.running && !handled) {
      if (processingState.paused) {
        await waitWhilePaused();
        if (!processingState.running) {
          break;
        }
        if (processingState.paused) {
          continue;
        }
      }

      let result;
      try {
        result = await processRow(row, envConfig, accessToken, writer);
      } catch (err) {
        console.error('Processing row failed unexpectedly', err);
        processingState.totalErrors += 1;
        handled = true;
        break;
      }

      const value = result || {};
      if (value.success) {
        processingState.totalProcessed += 1;
        handled = true;
      } else if (value.retry && value.reason === 'throttled') {
        const throttleDelayMs = Math.max(processingState.delaySeconds || 0, 1) * 1000;
        await waitForThrottle(throttleDelayMs);
        continue;
      } else if (value.retry) {
        retryRows.push(row);
        handled = true;
      } else {
        processingState.totalErrors += 1;
        handled = true;
      }
    }

    if (!processingState.running) {
      break;
    }
  }

  if (retryRows.length) {
    try {
      accessToken = await getAccessToken(envConfig);
    } catch (authError) {
      console.error('Failed to refresh access token for retry', authError);
      return accessToken;
    }

    for (const row of retryRows) {
      let handled = false;
      while (processingState.running && !handled) {
        if (processingState.paused) {
          await waitWhilePaused();
          if (!processingState.running) {
            break;
          }
          if (processingState.paused) {
            continue;
          }
        }

        let retryResult;
        try {
          retryResult = await processRow(row, envConfig, accessToken, writer);
        } catch (err) {
          console.error('Processing row retry failed', err);
          processingState.totalErrors += 1;
          handled = true;
          break;
        }

        const value = retryResult || {};
        if (value.success) {
          processingState.totalProcessed += 1;
          handled = true;
        } else if (value.retry && value.reason === 'throttled') {
          const throttleDelayMs = Math.max(processingState.delaySeconds || 0, 1) * 1000;
          await waitForThrottle(throttleDelayMs);
          continue;
        } else if (value.retry) {
          // Still unauthorized after refresh; count as error to avoid infinite loop.
          processingState.totalErrors += 1;
          handled = true;
        } else {
          processingState.totalErrors += 1;
          handled = true;
        }
      }

      if (!processingState.running) {
        break;
      }
    }
  }

  return accessToken;
}

async function processRow(row, envConfig, accessToken, writer) {
  const grantMembership = {};
  if (row.base_points !== null && row.base_points !== undefined) {
    grantMembership.basePoint = Number(row.base_points);
  }
  if (row.bonus_points !== null && row.bonus_points !== undefined) {
    grantMembership.bonusPoint = Number(row.bonus_points);
  }

  const payload = {
    title: row.title,
    cardNumber: row.card_number,
    adjustmentType: row.adjustment_type,
    amount: Number(row.amount),
  };

  if (Object.keys(grantMembership).length) {
    payload.grantMembership = grantMembership;
  }

  try {
    const response = await axios.post(envConfig.grantUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'access-token': accessToken,
      },
      timeout: 30000,
    });

    await query(
      `UPDATE grant_requests
       SET status = 'success',
           response_status = $1,
           raw_response = $2::jsonb,
           error_message = NULL,
           raw_error = NULL,
           environment = $3,
           processed_at = NOW(),
           last_attempt_at = NOW()
       WHERE id = $4`,
      [response.status, JSON.stringify(response.data ?? {}), envConfig.key, row.id]
    );

    writer.write([
      row.reference_id || '',
      row.title || '',
      row.card_number || '',
      row.adjustment_type || '',
      row.amount ?? '',
      row.merchant_id || '',
      row.remarks || '',
      row.base_points ?? '',
      row.bonus_points ?? '',
      response.status,
      'N/A',
      'N/A',
    ]);

    return { success: true };
  } catch (error) {
    const responseData = error?.response?.data ?? {};
    const responseStatus = error?.response?.status ?? null;
    const errorMessage = responseData?.message || error.message || 'Unknown error';

    if (responseStatus === 429) {
      await query(
        `UPDATE grant_requests
         SET last_attempt_at = NOW()
         WHERE id = $1`,
        [row.id]
      );
      return { success: false, retry: true, reason: 'throttled' };
    }

    await query(
      `UPDATE grant_requests
       SET status = 'error',
           response_status = $1,
           error_message = $2,
           raw_error = $3::jsonb,
           raw_response = NULL,
           environment = $4,
           processed_at = NOW(),
           last_attempt_at = NOW()
       WHERE id = $5`,
      [responseStatus, errorMessage, JSON.stringify(responseData), envConfig.key, row.id]
    );

    writer.write([
      row.reference_id || `REF-${Date.now()}-${uuidv4().slice(0, 8)}`,
      row.title || '',
      row.card_number || '',
      row.adjustment_type || '',
      row.amount ?? '',
      row.merchant_id || '',
      row.remarks || '',
      row.base_points ?? '',
      row.bonus_points ?? '',
      responseStatus ?? 'N/A',
      errorMessage,
      JSON.stringify(responseData || {}),
    ]);

    const shouldRetry = responseStatus === 401;
    return { success: false, retry: shouldRetry, reason: shouldRetry ? 'unauthorized' : undefined };
  }
}

export async function startProcessing(environment) {
  const envConfig = environments[environment];
  if (!envConfig) {
    throw new Error('Invalid environment specified.');
  }

  if (processingState.running) {
    throw new Error('Processing is already running.');
  }

  const batch = await getActiveBatch();
  const settings = await getProcessingSettings();

  processingState.running = true;
  processingState.paused = false;
  processingState.environment = envConfig.key;
  processingState.batchId = batch.id;
  processingState.startedAt = new Date().toISOString();
  processingState.lastProcessedId = null;
  processingState.lastChunkStartedAt = null;
  processingState.lastChunkCompletedAt = null;
  clearNextRun();
  processingState.chunkSize = settings.chunkSize;
  processingState.delaySeconds = settings.delaySeconds;
  processingState.currentChunkSize = 0;
  processingState.totalProcessed = 0;
  processingState.totalErrors = 0;
  processingState.error = null;

  updateBatchStatus(batch.id, 'processing', envConfig.key).catch((err) => {
    console.error('Failed to update batch status to processing', err);
  });

  (async () => {
    let client;
    let token = null;
    let csvResources;
    let writerEnded = false;

    try {
      client = await pool.connect();
      csvResources = await createCsvWriter(batch.log_file_name);

      while (processingState.running) {
        if (processingState.paused) {
          await waitWhilePaused();
          if (!processingState.running) {
            break;
          }
          if (processingState.paused) {
            continue;
          }
        }

        const { rows } = await client.query(
          `SELECT * FROM grant_requests
           WHERE status = 'pending'
           ORDER BY id
           LIMIT $1`,
          [processingState.chunkSize]
        );

        if (!rows.length) {
          clearNextRun();
          break;
        }

        processingState.currentChunkSize = rows.length;
        processingState.lastChunkStartedAt = new Date().toISOString();
        processingState.lastProcessedId = rows[rows.length - 1].id;

        try {
          token = await getAccessToken(envConfig);
        } catch (authError) {
          processingState.error = 'Failed to obtain access token.';
          throw authError;
        }

        token = await processChunk(rows, envConfig, token, csvResources.writer);

        processingState.lastChunkCompletedAt = new Date().toISOString();
        processingState.currentChunkSize = 0;

        if (!processingState.running) {
          break;
        }

        if (processingState.paused) {
          clearNextRun();
          await waitWhilePaused();
          continue;
        }

        if (processingState.delaySeconds > 0) {
          const delayMs = processingState.delaySeconds * 1000;
          setNextRun(new Date(Date.now() + delayMs).toISOString(), 'delay');
          await waitWithPause(delayMs);
          clearNextRun();
        }
      }

      if (csvResources) {
        csvResources.writer.end();
        writerEnded = true;
        await new Promise((resolve) => csvResources.stream.on('finish', resolve));
      }

      processingState.lastProcessedId = null;

      const { rows: pendingRows } = await client.query(
        "SELECT COUNT(*)::int AS count FROM grant_requests WHERE status = 'pending'"
      );

      const { rows: errorRows } = await client.query(
        "SELECT COUNT(*)::int AS count FROM grant_requests WHERE status = 'error'"
      );

      const batchStatus = pendingRows[0].count === 0
        ? (errorRows[0].count === 0 ? 'completed' : 'completed_with_errors')
        : 'uploaded';

      await updateBatchStatus(batch.id, batchStatus, envConfig.key);
    } catch (err) {
      processingState.error = err.message;
      console.error('Processing failed', err);
      await updateBatchStatus(batch.id, 'failed', envConfig.key).catch((updateErr) => {
        console.error('Failed to update batch status to failed', updateErr);
      });
    } finally {
      clearProcessingState({ preserveCounters: true, preserveError: true });
      if (client) {
        client.release();
      }
      if (csvResources && !writerEnded) {
        await new Promise((resolve) => {
          csvResources.stream.once('finish', resolve);
          csvResources.writer.end();
        });
      }
    }
  })();

  return getProcessingState();
}
