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

export const processingConfig = {
  batchInsertSize: 500,
  pollIntervalMs: 2000,
};
