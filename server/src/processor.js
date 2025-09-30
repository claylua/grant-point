import fs from 'fs';
import path from 'path';
import axios from 'axios';
import csvWriter from 'csv-write-stream';
import { v4 as uuidv4 } from 'uuid';
import { credentials, environments, logDirectory } from './config.js';
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

const processingState = {
  running: false,
  environment: null,
  batchId: null,
  startedAt: null,
  lastProcessedId: null,
  error: null,
};

export function getProcessingState() {
  return { ...processingState };
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

async function processRow(row, envConfig, accessToken, writer) {
  const payload = {
    title: row.title,
    cardNumber: row.card_number,
    adjustmentType: row.adjustment_type,
    amount: Number(row.amount),
    grantMembership: {
      basePoint: Number(row.base_points),
      bonusPoint: Number(row.bonus_points),
    },
  };

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

    return { success: false, retry: responseStatus === 401 };
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
  processingState.running = true;
  processingState.environment = envConfig.key;
  processingState.batchId = batch.id;
  processingState.startedAt = new Date().toISOString();
  processingState.lastProcessedId = null;
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
      token = await getAccessToken(envConfig);
      csvResources = await createCsvWriter(batch.log_file_name);

      while (processingState.running) {
        const { rows } = await client.query(
          `SELECT * FROM grant_requests
           WHERE status = 'pending'
           ORDER BY id
           LIMIT 1`
        );

        if (!rows.length) {
          break;
        }

        const currentRow = rows[0];
        processingState.lastProcessedId = currentRow.id;

        const result = await processRow(currentRow, envConfig, token, csvResources.writer);
        if (!result.success && result.retry) {
          try {
            token = await getAccessToken(envConfig);
            await processRow(currentRow, envConfig, token, csvResources.writer);
          } catch (retryError) {
            console.error('Retry after token refresh failed', retryError);
          }
        }
      }

      csvResources.writer.end();
      writerEnded = true;
      await new Promise((resolve) => csvResources.stream.on('finish', resolve));
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
      processingState.running = false;
      processingState.environment = null;
      processingState.batchId = null;
      processingState.startedAt = null;
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
