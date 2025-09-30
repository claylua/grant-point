import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const dbConfig = {
  connectionString: process.env.DATABASE_URL || 'postgres://admin:admin@localhost:5432/setel',
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
  identifier: process.env.SETEL_IDENTIFIER || 'enterprise-ops',
  password: process.env.SETEL_PASSWORD || '6GA-RYGj)*{^]Usr',
};

export const logDirectory = process.env.LOG_DIRECTORY || path.join(__dirname, '..', '..', 'logs');

export const processingConfig = {
  batchInsertSize: 500,
  pollIntervalMs: 2000,
};
