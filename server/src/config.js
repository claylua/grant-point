import './env.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parsePort(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseBoolean(value) {
  if (!value) {
    return false;
  }
  const normalized = value.toString().trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

export const dbConfig = {
  connectionString: requiredEnv('DATABASE_URL'),
};

export const environments = {
  staging: {
    key: 'staging',
    label: 'Staging',
    loginUrl: 'https://api.staging2.setel.my/api/iam/setel-external-services/auth/login',
    grantUrl: 'https://api.staging2.setel.my/api/loyalty/admin/points/adjustment/autoApprove',
  },
  production: {
    key: 'production',
    label: 'Production',
    loginUrl: 'https://api.prod.setel.my/api/iam/setel-external-services/auth/login',
    grantUrl: 'https://api.prod.setel.my/api/loyalty/admin/points/adjustment/autoApprove',
  },
};

export const credentials = {
  identifier: requiredEnv('SETEL_IDENTIFIER'),
  password: requiredEnv('SETEL_PASSWORD'),
};

export const logDirectory = process.env.LOG_DIRECTORY || path.join(__dirname, '..', '..', 'logs');

const defaultChunkSize = Number.parseInt(process.env.PROCESSING_DEFAULT_CHUNK_SIZE ?? '', 10);
const defaultDelaySeconds = Number.parseInt(process.env.PROCESSING_DEFAULT_DELAY_SECONDS ?? '', 10);
const maxChunkSize = Number.parseInt(process.env.PROCESSING_MAX_CHUNK_SIZE ?? '', 10);
const minDelaySeconds = Number.parseInt(process.env.PROCESSING_MIN_DELAY_SECONDS ?? '', 10);
const maxDelaySeconds = Number.parseInt(process.env.PROCESSING_MAX_DELAY_SECONDS ?? '', 10);
const statusPollIntervalMs = Number.parseInt(process.env.STATUS_POLL_INTERVAL_MS ?? '', 10);

export const processingConfig = {
  batchInsertSize: 500,
  pollIntervalMs: Number.isFinite(statusPollIntervalMs) && statusPollIntervalMs >= 1000
    ? statusPollIntervalMs
    : 5000,
  defaultChunkSize: Number.isFinite(defaultChunkSize) && defaultChunkSize > 0 ? defaultChunkSize : 1000,
  defaultDelaySeconds: Number.isFinite(defaultDelaySeconds) && defaultDelaySeconds >= 30 ? defaultDelaySeconds : 60,
  minChunkSize: 1,
  maxChunkSize: Number.isFinite(maxChunkSize) && maxChunkSize >= 1000 ? maxChunkSize : 10000,
  minDelaySeconds: Number.isFinite(minDelaySeconds) && minDelaySeconds >= 30 ? minDelaySeconds : 30,
  maxDelaySeconds: Number.isFinite(maxDelaySeconds) && maxDelaySeconds >= 60 ? maxDelaySeconds : 7200,
  pauseCheckIntervalMs: 500,
};

const httpsKeyPath = process.env.HTTPS_KEY_PATH || '';
const httpsCertPath = process.env.HTTPS_CERT_PATH || '';
const httpsEnabledRaw = process.env.HTTPS_ENABLED;
const httpsEnabledFlag = parseBoolean(httpsEnabledRaw);
const httpsHasCredentials = Boolean(httpsKeyPath && httpsCertPath);
const httpsEnabled =
  (httpsEnabledRaw === undefined ? httpsHasCredentials : httpsEnabledFlag) && httpsHasCredentials;

export const serverConfig = {
  port: parsePort(process.env.PORT, 4000),
  https: {
    enabled: httpsEnabled,
    port: parsePort(process.env.HTTPS_PORT, 4443),
    keyPath: httpsKeyPath,
    certPath: httpsCertPath,
    passphrase: process.env.HTTPS_PASSPHRASE || '',
    explicitlyEnabled: httpsEnabledRaw !== undefined,
    hasCredentials: httpsHasCredentials,
  },
};
