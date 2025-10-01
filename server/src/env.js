import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, '..', '.env');
const result = dotenv.config({ path: envPath });

if (result.error && process.env.NODE_ENV !== 'production') {
  console.warn(`Could not load .env from ${envPath}:`, result.error.message);
}

export {}; // ensure this module is treated as ESM
